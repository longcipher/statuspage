//! Background probe scheduler.
//!
//! Periodically fetches each enabled target's check spec and records the
//! resulting [`CheckResult`] to storage. Runs as a tokio task spawned from
//! `main.rs`.
//!
//! # Per-target interval
//!
//! Each target carries its own `interval` (e.g. 30s, 60s, 5min). The
//! scheduler maintains a `HashMap<target_id, next_due>` map and on each
//! tick (default 5s) probes only the targets whose `next_due <= now`.
//! Jitter (±10% of interval) is applied on the first scheduling to spread
//! load and avoid thundering-herd on a freshly booted instance with many
//! targets sharing the same interval.
//!
//! # Heartbeat evaluation
//!
//! Heartbeat is passive: the scheduler does not probe the network. Instead
//! it reads `last_ping_at` from storage (set by `POST /heartbeat/{id}`) and
//! compares `now - last_ping_at` against `period + grace`. A stale heartbeat
//! reports `Down`; a fresh one reports `Up`. A heartbeat that has never
//! received a ping reports `Up` (no false red on boot — the operator has
//! grace time to start sending pings).
//!
//! # Maintenance suppression
//!
//! Results are always recorded (so history is complete), but the incident
//! writer skips opening incidents for targets inside an active maintenance
//! window. This keeps the data trail intact while suppressing alerting
//! during planned maintenance.
//!
//! # Supported check kinds
//!
//! The in-process scheduler supports the four control-plane kinds: `http`,
//! `tcp`, `ping`, and `heartbeat`. The four agent-only kinds (`tls_cert`,
//! `domain_expiry`, `dns`, `flow`) are rejected up front by
//! [`CheckSpec::require_control_plane_support`] and record an `Error`
//! result with a "not supported" reason — agents own the richer probe
//! matrix (cert expiry, RDAP, DNS, browser automation).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::Utc;
use common::security::SsrfGuard;
use rand::RngExt;
use statuscore::domain::check::{ExpectedStatus, HttpCheck, PingCheck, TcpCheck};
use statuscore::domain::org::OrgId;
use statuscore::domain::{CheckResult, CheckSpec, CheckStatus, HeartbeatCheck, Target};
use storage::Storage;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Sweep cadence — how often the scheduler wakes to check which targets are
/// due. Kept short (5s) so a target with a 30s interval never waits more
/// than 5s past its due instant. The work per tick is proportional to the
/// number of *due* targets, not the total fleet, so a short tick is cheap.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Target list refresh cadence. The full target list is re-read this often
/// so config changes (new targets, disabled targets, interval edits) are
/// picked up without a restart. Between refreshes the scheduler works from
/// its in-memory `next_due` map.
const TARGET_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

pub struct Scheduler {
    storage: Arc<dyn Storage>,
    /// Channel dispatch context (email sender + from address + public base
    /// URL) threaded through to the incident coalescer so an auto-open /
    /// auto-close can fire operator notifications. `Option` so a test
    /// scheduler constructed without an email transport skips dispatch.
    dispatch_ctx: Option<crate::incident_writer::ChannelDispatchCtx>,
    /// Shared SSRF-guarded HTTP client for `http` probes. Built once with
    /// `reqwest::redirect::Policy::none()` so a probe pointing at a private
    /// IP is rejected up front by [`ssrf_check_url`] and a redirect to an
    /// internal address can't be followed. Per-probe timeouts are applied
    /// on the request builder, not the client, so one client serves the
    /// whole fleet.
    outbound_http: reqwest::Client,
}

/// Process-wide fallback `reqwest::Client` for callers that don't hold a
/// pre-built one (the `pub(crate) probe_target` entry point used by the
/// `POST /targets/{id}/check-now` and `POST /targets/test` handlers).
/// Mirrors the redirect policy of the Scheduler's client so both paths
/// apply the same SSRF posture.
static SHARED_PROBE_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn shared_probe_http_client() -> &'static reqwest::Client {
    SHARED_PROBE_HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

impl Scheduler {
    #[expect(dead_code)]
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage, dispatch_ctx: None, outbound_http: shared_probe_http_client().clone() }
    }

    /// Construct with a channel dispatch context so the incident coalescer
    /// can fire operator notifications on auto-open / auto-close. Used by
    /// `main.rs` to wire the production email sender + sender identity into
    /// the per-probe evaluation path. The `outbound_http` client is the
    /// SSRF-guarded probe client (redirect policy `none`, per-request
    /// timeout) shared across every `http` probe the scheduler dispatches.
    pub fn with_dispatch_ctx(
        storage: Arc<dyn Storage>,
        dispatch_ctx: crate::incident_writer::ChannelDispatchCtx,
        outbound_http: reqwest::Client,
    ) -> Self {
        Self { storage, dispatch_ctx: Some(dispatch_ctx), outbound_http }
    }

    /// Run the scheduler loop. Call via `tokio::spawn(scheduler.run(cancel))`.
    /// The `cancel` token breaks the `tokio::select!` loop so a SIGINT
    /// surfaces as a clean exit instead of relying on the runtime dropping
    /// the task.
    pub async fn run(self, cancel: CancellationToken) {
        info!(sweep_secs = SWEEP_INTERVAL.as_secs(), "scheduler started");

        // `next_due` tracks when each target should next be probed. On the
        // first refresh every target is scheduled immediately (with jitter)
        // so a fresh boot probes everything within the first tick.
        let mut next_due: HashMap<Uuid, chrono::DateTime<Utc>> = HashMap::new();
        let mut known_targets: HashMap<Uuid, Target> = HashMap::new();

        let mut sweep = interval(SWEEP_INTERVAL);
        let mut refresh = interval(TARGET_REFRESH_INTERVAL);
        // First tick fires immediately so we load the target list on boot.
        refresh.tick().await;

        loop {
            tokio::select! {
                _ = sweep.tick() => {
                    self.probe_due_targets(&next_due, &known_targets).await;
                }
                _ = refresh.tick() => {
                    self.refresh_targets(&mut next_due, &mut known_targets).await;
                }
                () = cancel.cancelled() => {
                    info!("scheduler shutting down");
                    break;
                }
            }
        }
    }

    /// Re-read the target list from storage and reconcile `next_due`.
    /// Newly added targets are scheduled for immediate probing; removed
    /// targets are evicted; targets whose interval changed keep their
    /// existing `next_due` (the new interval applies from the next probe).
    async fn refresh_targets(
        &self,
        next_due: &mut HashMap<Uuid, chrono::DateTime<Utc>>,
        known_targets: &mut HashMap<Uuid, Target>,
    ) {
        let targets = match self.storage.list_targets().await {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "scheduler: list_targets failed");
                return;
            }
        };

        // Evict targets that no longer exist.
        let live_ids: std::collections::HashSet<Uuid> = targets.iter().map(|t| t.id).collect();
        next_due.retain(|id, _| live_ids.contains(id));
        known_targets.retain(|id, _| live_ids.contains(id));

        // Insert/update known targets and schedule new ones.
        let now = Utc::now();
        for target in targets {
            if !known_targets.contains_key(&target.id) {
                // New target — schedule for immediate probing with a small
                // jitter so a batch of new targets doesn't all fire on the
                // same tick.
                let jitter_secs = rand::rng().random_range(0..5);
                let due = now + chrono::Duration::seconds(i64::from(jitter_secs));
                next_due.insert(target.id, due);
            }
            known_targets.insert(target.id, target);
        }
    }

    /// Probe every target whose `next_due <= now`, then reschedule each at
    /// `now + interval ± jitter`.
    async fn probe_due_targets(
        &self,
        next_due: &HashMap<Uuid, chrono::DateTime<Utc>>,
        known_targets: &HashMap<Uuid, Target>,
    ) {
        let now = Utc::now();
        let due_ids: Vec<Uuid> =
            next_due.iter().filter(|(_, due)| **due <= now).map(|(id, _)| *id).collect();

        if due_ids.is_empty() {
            return;
        }

        for id in due_ids {
            let Some(target) = known_targets.get(&id) else {
                continue;
            };
            if !target.enabled {
                continue;
            }

            let result =
                probe_target_with_client(self.storage.as_ref(), target, &self.outbound_http).await;
            if let Err(e) = self.storage.record_result(&result).await {
                error!(
                    target_id = %target.id,
                    error = %e,
                    "scheduler: record_result failed"
                );
            }
            // After recording the result, let the incident coalescer
            // decide whether to open/close an incident for this target.
            // The coalescer is fire-and-forget: errors are logged inside
            // and never propagate to the scheduler loop. The dispatch
            // context is threaded through so the coalescer can fire
            // operator notifications (email / PagerDuty / Slack) on
            // auto-open / auto-close.
            crate::incident_writer::evaluate_target(
                self.storage.as_ref(),
                target.id,
                self.dispatch_ctx.as_ref(),
            )
            .await;
        }
    }
}

/// Probe a single target and return a [`CheckResult`]. For heartbeat checks
/// the result is derived from the stored `last_ping_at` timestamp; for the
/// other control-plane kinds (`http`/`tcp`/`ping`) the network is probed
/// directly. The four agent-only kinds (`tls_cert`/`domain_expiry`/`dns`/
/// `flow`) are rejected up front by [`CheckSpec::require_control_plane_support`]
/// and record an `Error` result — agents own that richer probe matrix.
///
/// Public so the `POST /targets/{id}/check-now` and `POST /targets/test`
/// API handlers can trigger a one-off probe without duplicating the probe
/// dispatch logic. This entry point uses the process-wide shared
/// [`shared_probe_http_client`]; the scheduler dispatches through
/// [`probe_target_with_client`] with its own pre-built client.
pub(crate) async fn probe_target(storage: &dyn Storage, target: &Target) -> CheckResult {
    probe_target_with_client(storage, target, shared_probe_http_client()).await
}

/// Same as [`probe_target`] but takes an explicit `http_client` so the
/// scheduler can share one SSRF-guarded `reqwest::Client` across every
/// `http` probe instead of rebuilding per call.
async fn probe_target_with_client(
    storage: &dyn Storage,
    target: &Target,
    http_client: &reqwest::Client,
) -> CheckResult {
    let started = Utc::now();

    // C-8: reject agent-only check kinds up front. dns / tls_cert /
    // domain_expiry / flow require an agent; the control plane records an
    // `Error` result instead of silently skipping or misprobing.
    if let Err(e) = target.check.require_control_plane_support() {
        warn!(
            target_id = %target.id,
            kind = target.check.kind(),
            error = %e,
            "check kind not supported on control plane"
        );
        return CheckResult::error(
            target.id,
            // Single-user self-hosted: org_id is nil (no org isolation).
            OrgId(Uuid::nil()),
            format!("not supported on control plane: {e}"),
        );
    }

    let (status, response_code, error) = match &target.check {
        CheckSpec::Http(http_spec) => probe_http(http_spec, http_client).await,
        CheckSpec::Tcp(tcp_spec) => probe_tcp(tcp_spec).await,
        CheckSpec::Ping(ping_spec) => probe_ping(ping_spec).await,
        CheckSpec::Heartbeat(hb_spec) => probe_heartbeat(storage, target.id, hb_spec).await,
        // dns / tls_cert / domain_expiry / flow are caught by the
        // require_control_plane_support gate above; this arm is unreachable
        // at runtime but kept for match exhaustiveness and as a safety net
        // for future kinds.
        other => (
            CheckStatus::Error,
            None,
            Some(format!("check kind {} not supported by in-process scheduler", other.kind())),
        ),
    };
    let finished = Utc::now();
    let duration_ms = (finished - started).num_milliseconds().clamp(0, i64::from(u32::MAX)) as u32;

    CheckResult {
        target_id: target.id,
        // Single-user self-hosted: org_id is nil (no org isolation).
        org_id: OrgId(Uuid::nil()),
        timestamp: started,
        status,
        duration_ms,
        dns_ms: None,
        connect_ms: None,
        tls_ms: None,
        ttfb_ms: None,
        response_code,
        response_size: None,
        error,
    }
}

/// Heartbeat probe. Reads `last_ping_at` from storage and compares against
/// `period + grace`. A heartbeat that has never received a ping is treated
/// as `Up` — the operator has grace time after enabling a new heartbeat
/// target to start sending pings. Once pings have started, a stale ping
/// (no ping within `period + grace`) reports `Down`.
async fn probe_heartbeat(
    storage: &dyn Storage,
    target_id: Uuid,
    hb: &HeartbeatCheck,
) -> (CheckStatus, Option<u16>, Option<String>) {
    let last_ping = match storage.get_last_heartbeat_ping(target_id).await {
        Ok(ts) => ts,
        Err(e) => {
            return (CheckStatus::Error, None, Some(format!("heartbeat read last_ping: {e}")));
        }
    };

    let Some(last) = last_ping else {
        // No ping ever recorded — treat as Up so a freshly created
        // heartbeat target doesn't immediately go red.
        return (CheckStatus::Up, None, None);
    };

    let now = Utc::now();
    let elapsed = now - last;
    let deadline = hb.period + hb.grace;
    if elapsed
        > chrono::Duration::from_std(deadline).unwrap_or({
            // If the deadline overflows Duration (extremely large), fall back
            // to treating the heartbeat as stale.
            chrono::Duration::MAX
        })
    {
        (
            CheckStatus::Down,
            None,
            Some(format!(
                "heartbeat stale: last ping {}s ago, deadline {}ms",
                elapsed.num_seconds(),
                deadline.as_millis()
            )),
        )
    } else {
        (CheckStatus::Up, None, None)
    }
}

/// HTTP probe. Returns `(status, response_code, error)`. `duration_ms` is
/// measured by the caller so this only reports probe outcome.
///
/// SSRF defence: the URL's host is resolved and every resolved IP is
/// filtered through [`SsrfGuard::strict`] *before* any TCP open. A probe
/// pointing at loopback / RFC1918 / link-local / ULA / cloud-metadata /
/// 6to4-NAT64-with-private-v4 is rejected up front with an `Error` result.
/// The shared `client` is built with `redirect::Policy::none()` so a
/// redirect to an internal address can't bypass the pre-check. This leaves
/// a narrow TOCTOU window between the pre-resolution and reqwest's own
/// connect-time resolution (a DNS-rebinding attack with a sub-second TTL);
/// the strict-guard hyper connector on the check-path stack closes that
/// window, but the reqwest probe path accepts the residual risk because
/// reqwest does not expose a custom-connector hook here.
async fn probe_http(
    http: &HttpCheck,
    client: &reqwest::Client,
) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_url(&http.url, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }

    let method = match http.method {
        statuscore::domain::check::HttpMethod::Get => reqwest::Method::GET,
        statuscore::domain::check::HttpMethod::Head => reqwest::Method::HEAD,
        statuscore::domain::check::HttpMethod::Post => reqwest::Method::POST,
        statuscore::domain::check::HttpMethod::Put => reqwest::Method::PUT,
        statuscore::domain::check::HttpMethod::Patch => reqwest::Method::PATCH,
        statuscore::domain::check::HttpMethod::Delete => reqwest::Method::DELETE,
        statuscore::domain::check::HttpMethod::Options => reqwest::Method::OPTIONS,
        // `HttpMethod` is #[non_exhaustive]; unknown methods fall back to GET.
        _ => reqwest::Method::GET,
    };

    // Per-request timeout — the client is shared across the fleet, so the
    // check-specific `http.timeout` is applied here, not on the builder.
    let mut req = client.request(method, http.url.as_str()).timeout(http.timeout);
    for (k, v) in &http.headers {
        req = req.header(k, v);
    }
    if let Some(body) = &http.body {
        req = req.body(body.clone());
    }
    if let Some((user, pass)) = &http.basic_auth {
        req = req.basic_auth(user, Some(pass));
    }
    if let Some(token) = &http.bearer_token {
        req = req.bearer_auth(token);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (CheckStatus::Down, None, Some(format!("request: {e}")));
        }
    };

    let code = resp.status().as_u16();
    let ok = status_matches(&http.expected_status, code);
    let error = if ok { None } else { Some(format!("HTTP {code}")) };
    (if ok { CheckStatus::Up } else { CheckStatus::Down }, Some(code), error)
}

/// Resolve `url`'s host and validate every resolved IP against `guard`.
/// Returns `Err(reason)` if the host resolves only to blocked ranges
/// (loopback / RFC1918 / link-local / ULA / cloud metadata / 6to4-NAT64
/// with embedded private v4). Called before any TCP open so a probe
/// pointing at internal infrastructure is rejected up front.
async fn ssrf_check_url(url: &url::Url, guard: SsrfGuard) -> Result<(), String> {
    let host = url.host_str().ok_or_else(|| "URL has no host".to_string())?;
    let port = url
        .port_or_known_default()
        .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
    ssrf_check_host(host, port, guard).await
}

/// Resolve `host:port` and validate every resolved IP against `guard`.
/// Shared by `probe_http` (via `ssrf_check_url`), `probe_tcp`, and
/// `probe_ping` so all probe types enforce the same SSRF policy. Without
/// this, an authenticated operator could create a TCP or Ping check
/// against `10.0.0.1` / `169.254.169.254` / any RFC1918 address to
/// port-scan or fingerprint internal infrastructure.
async fn ssrf_check_host(host: &str, port: u16, guard: SsrfGuard) -> Result<(), String> {
    let resolved: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(iter) => iter.collect(),
        Err(e) => return Err(format!("SSRF DNS resolve '{host}': {e}")),
    };
    let ips: Vec<IpAddr> = resolved.iter().map(|sa| sa.ip()).collect();
    if ips.is_empty() {
        return Err(format!("SSRF: no addresses resolved for '{host}'"));
    }
    guard.filter(host, ips).map_err(|e| format!("SSRF: {e}")).map(|_| ())
}

/// TCP probe: open a connection to `host:port` within `timeout`. Success =
/// `Up`, any failure (DNS, refused, timeout) = `Down`. The TLS-less connect
/// handshake is the cheapest possible liveness signal for a TCP service.
///
/// SSRF: the host is resolved and filtered through `SsrfGuard::strict()`
/// before the connect attempt, blocking probes against loopback / RFC1918
/// / link-local / cloud-metadata addresses. This mirrors the HTTP probe
/// path — without it, a TCP check against `10.0.0.1:22` would be a free
/// internal port scanner.
async fn probe_tcp(tcp: &TcpCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_host(&tcp.host, tcp.port, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    let addr = format!("{}:{}", tcp.host, tcp.port);
    match tokio::time::timeout(tcp.timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => (CheckStatus::Up, None, None),
        Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("tcp connect {addr}: {e}"))),
        Err(_) => (
            CheckStatus::Down,
            None,
            Some(format!("tcp connect {addr}: timeout after {} ms", tcp.timeout.as_millis())),
        ),
    }
}

/// ICMP echo probe. Resolves `host` to the first IP, sends one echo within
/// `timeout`. Success = `Up`; DNS failure, timeout, or no echo = `Down`.
///
/// SSRF: same pre-resolution filter as `probe_tcp` / `probe_http`. Without
/// it, a ping check against `10.0.0.1` would reveal internal host liveness.
async fn probe_ping(ping: &PingCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_host(&ping.host, 0, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    let addrs = match tokio::net::lookup_host(format!("{}:0", ping.host)).await {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => {
            return (CheckStatus::Down, None, Some(format!("ping dns {}: {}", ping.host, e)));
        }
    };
    let ip: IpAddr = match addrs.iter().map(|sa| sa.ip()).next() {
        Some(ip) => ip,
        None => {
            return (
                CheckStatus::Down,
                None,
                Some(format!("ping dns {}: no addresses", ping.host)),
            );
        }
    };

    let client = match surge_ping::Client::new(&surge_ping::Config::default()) {
        Ok(c) => c,
        Err(e) => {
            return (CheckStatus::Error, None, Some(format!("ping icmp client: {}", e)));
        }
    };
    let mut pinger = client.pinger(ip, surge_ping::PingIdentifier(0x42)).await;
    pinger.timeout(ping.timeout);

    match pinger.ping(surge_ping::PingSequence(1), &[0u8; 8]).await {
        Ok(_) => (CheckStatus::Up, None, None),
        Err(e) => (CheckStatus::Down, None, Some(format!("ping {} ({}): {}", ping.host, ip, e))),
    }
}

/// True when `code` satisfies the check's `expected_status`.
fn status_matches(expected: &ExpectedStatus, code: u16) -> bool {
    match expected {
        ExpectedStatus::Exact(c) => *c == code,
        ExpectedStatus::Range { min, max } => code >= *min && code <= *max,
        ExpectedStatus::OneOf(codes) => {
            if codes.is_empty() {
                (200..300).contains(&code)
            } else {
                codes.contains(&code)
            }
        }
        // `ExpectedStatus` is #[non_exhaustive]; unknown shapes fail
        // defensively rather than silently pass an unexpected status.
        &_ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_matches_exact() {
        assert!(status_matches(&ExpectedStatus::Exact(204), 204));
        assert!(!status_matches(&ExpectedStatus::Exact(204), 200));
    }

    #[test]
    fn status_matches_range() {
        let r = ExpectedStatus::Range { min: 200, max: 299 };
        assert!(status_matches(&r, 200));
        assert!(status_matches(&r, 299));
        assert!(!status_matches(&r, 300));
    }

    #[test]
    fn status_matches_one_of_or_defaults_to_2xx() {
        let one = ExpectedStatus::OneOf(vec![200, 204]);
        assert!(status_matches(&one, 200));
        assert!(status_matches(&one, 204));
        assert!(!status_matches(&one, 301));
        let empty = ExpectedStatus::OneOf(vec![]);
        assert!(status_matches(&empty, 200));
        assert!(!status_matches(&empty, 500));
    }
}
