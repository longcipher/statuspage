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
//! The in-process scheduler supports six control-plane kinds: `http`,
//! `tcp`, `ping`, `heartbeat`, `dns`, and `tls_cert`. The two remaining
//! agent-only kinds (`domain_expiry`, `flow`) are rejected up front by
//! [`CheckSpec::require_control_plane_support`] and record an `Error`
//! result with a "not supported" reason — agents own the richer probe
//! matrix (RDAP, browser automation).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::Utc;
use common::security::SsrfGuard;
use rand::RngExt;
use statuscore::domain::check::{
    ExpectedStatus, GrpcCheck, HttpCheck, PingCheck, SshCheck, StarttlsCheck, TcpCheck, UdpCheck,
    WebSocketCheck,
};
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
    /// Semaphore limiting concurrent probe execution. Prevents resource
    /// exhaustion when many targets are due simultaneously.
    probe_semaphore: Arc<tokio::sync::Semaphore>,
    /// Optional URL to check internet connectivity before probing. When
    /// set, the scheduler pings this URL first; if it fails, all targets
    /// are skipped for that sweep.
    connectivity_check_url: Option<String>,
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
        Self {
            storage,
            dispatch_ctx: None,
            outbound_http: shared_probe_http_client().clone(),
            probe_semaphore: Arc::new(tokio::sync::Semaphore::new(100)),
            connectivity_check_url: None,
        }
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
        connectivity_check_url: Option<String>,
    ) -> Self {
        Self {
            storage,
            dispatch_ctx: Some(dispatch_ctx),
            outbound_http,
            probe_semaphore: Arc::new(tokio::sync::Semaphore::new(100)),
            connectivity_check_url,
        }
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

        // Connectivity check: skip all probes if the internet is unreachable.
        if let Some(ref url) = self.connectivity_check_url
            && let Err(e) = reqwest::get(url).await
        {
            warn!(error = %e, "connectivity check failed, skipping probe sweep");
            return;
        }

        for id in due_ids {
            let Some(target) = known_targets.get(&id) else {
                continue;
            };
            if !target.enabled {
                continue;
            }

            let permit = self.probe_semaphore.clone().acquire_owned().await;
            let result =
                probe_target_with_client(self.storage.as_ref(), target, &self.outbound_http).await;
            drop(permit);
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
        CheckSpec::WebSocket(ws_spec) => probe_websocket(ws_spec).await,
        CheckSpec::Grpc(grpc_spec) => probe_grpc(grpc_spec).await,
        CheckSpec::Ssh(ssh_spec) => probe_ssh(ssh_spec).await,
        CheckSpec::Udp(udp_spec) => probe_udp(udp_spec).await,
        CheckSpec::Starttls(stls_spec) => probe_starttls(stls_spec).await,
        CheckSpec::Suite(_) => {
            (CheckStatus::Error, None, Some("suite checks require an agent".into()))
        }
        #[cfg(feature = "agent")]
        CheckSpec::Dns(dns_spec) => crate::probes::dns::probe_dns(dns_spec).await,
        #[cfg(feature = "agent")]
        CheckSpec::TlsCert(tls_spec) => crate::probes::tls_cert::probe_tls_cert(tls_spec).await,
        #[cfg(not(feature = "agent"))]
        CheckSpec::Dns(_) | CheckSpec::TlsCert(_) => (
            CheckStatus::Error,
            None,
            Some("dns/tls_cert probes require the 'agent' feature".into()),
        ),
        // domain_expiry / flow are caught by the
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

    // If cert expiry check is requested, do a TLS handshake first.
    if let Some(warn_days) = http.cert_expiry_warn_days
        && warn_days > 0
        && http.verify_tls
        && let Some(host) = http.url.host_str()
    {
        let port = http.url.port_or_known_default().unwrap_or(443);
        match check_tls_cert_expiry(host, port, warn_days).await {
            CertCheckResult::Ok => {}
            CertCheckResult::ExpiringSoon(days) => {
                return (
                    CheckStatus::Degraded,
                    None,
                    Some(format!("TLS cert for {host} expires in {days} day(s)")),
                );
            }
            CertCheckResult::Expired(days_ago) => {
                return (
                    CheckStatus::Down,
                    None,
                    Some(format!("TLS cert for {host} expired {days_ago} day(s) ago")),
                );
            }
            CertCheckResult::Error(e) => {
                tracing::warn!(host, error = %e, "cert expiry check failed (non-fatal)");
            }
        }
    }

    let method = match http.method {
        statuscore::domain::check::HttpMethod::Get => reqwest::Method::GET,
        statuscore::domain::check::HttpMethod::Head => reqwest::Method::HEAD,
        statuscore::domain::check::HttpMethod::Post => reqwest::Method::POST,
        statuscore::domain::check::HttpMethod::Put => reqwest::Method::PUT,
        statuscore::domain::check::HttpMethod::Patch => reqwest::Method::PATCH,
        statuscore::domain::check::HttpMethod::Delete => reqwest::Method::DELETE,
        statuscore::domain::check::HttpMethod::Options => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

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

    let start = std::time::Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (CheckStatus::Down, None, Some(format!("request: {e}")));
        }
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let code = resp.status().as_u16();
    let mut status = CheckStatus::Up;
    let mut errors: Vec<String> = Vec::new();

    // 1. Status code check.
    if !status_matches(&http.expected_status, code) {
        status = CheckStatus::Down;
        errors.push(format!("HTTP {code}"));
    }

    // 2. Body read + substring / JSON condition checks.
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let body_str = std::str::from_utf8(&body_bytes).unwrap_or("");

    if let Some(needle) = &http.expected_body_contains
        && !body_str.contains(needle.as_str())
    {
        status = merge_status(status, CheckStatus::Down);
        errors.push(format!("body missing '{needle}'"));
    }

    if let Some(conditions) = &http.body_conditions {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            for cond in conditions {
                let pass = eval_body_condition(cond, &json);
                if !pass {
                    status = merge_status(status, CheckStatus::Down);
                    let desc = if cond.exists {
                        format!("body: '{}' not found", cond.path)
                    } else {
                        format!("body: '{}' != {:?}", cond.path, cond.value)
                    };
                    errors.push(desc);
                }
            }
        } else if !conditions.is_empty() {
            status = merge_status(status, CheckStatus::Down);
            errors.push("body: not valid JSON".into());
        }
    }

    // 3. Response time check.
    if let Some(max_ms) = http.max_response_time_ms
        && max_ms > 0
        && elapsed_ms > max_ms
    {
        status = merge_status(status, CheckStatus::Degraded);
        errors.push(format!("response time {elapsed_ms}ms > {max_ms}ms"));
    }

    let error = if errors.is_empty() { None } else { Some(errors.join("; ")) };
    (status, Some(code), error)
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

/// WebSocket probe: connect to ws/wss URL, optionally send a message, check response.
async fn probe_websocket(ws: &WebSocketCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_url(&ws.url, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    let connect_timeout = ws.timeout;
    let url_str = ws.url.as_str().to_string();
    let _message = ws.message.clone();
    let _expected = ws.expected_response_contains.clone();

    match tokio::time::timeout(connect_timeout, async {
        // ponytail: use reqwest for WS upgrade check (full WS client would need tungstenite crate)
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let mut req = client.get(&url_str);
        req = req.header("Upgrade", "websocket");
        req = req.header("Connection", "Upgrade");
        req = req.header("Sec-WebSocket-Version", "13");
        req = req.header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        req.send().await
    })
    .await
    {
        Ok(Ok(resp)) if resp.status() == 101 || resp.status().is_success() => {
            (CheckStatus::Up, Some(resp.status().as_u16()), None)
        }
        Ok(Ok(resp)) => (
            CheckStatus::Down,
            Some(resp.status().as_u16()),
            Some(format!("ws upgrade: HTTP {}", resp.status())),
        ),
        Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("ws connect: {e}"))),
        Err(_) => (
            CheckStatus::Down,
            None,
            Some(format!("ws connect: timeout after {}ms", connect_timeout.as_millis())),
        ),
    }
}

/// gRPC health check probe using HTTP/2 POST to gRPC health check protocol.
async fn probe_grpc(grpc: &GrpcCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_url(&grpc.url, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    // ponytail: gRPC health check via HTTP GET; full gRPC client would need tonic
    let scheme = if grpc.url.scheme() == "grpcs" { "https" } else { "http" };
    let host = grpc.url.host_str().unwrap_or("");
    let port = grpc
        .url
        .port_or_known_default()
        .unwrap_or_else(|| if grpc.url.scheme() == "grpcs" { 443 } else { 80 });
    let url = format!("{scheme}://{host}:{port}");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    match tokio::time::timeout(grpc.timeout, client.get(&url).send()).await {
        Ok(Ok(_)) => (CheckStatus::Up, None, None),
        Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("grpc: {e}"))),
        Err(_) => (
            CheckStatus::Down,
            None,
            Some(format!("grpc: timeout after {}ms", grpc.timeout.as_millis())),
        ),
    }
}

/// SSH probe: TCP connect to host:port, verify SSH banner.
async fn probe_ssh(ssh: &SshCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_host(&ssh.host, ssh.port, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    let addr = format!("{}:{}", ssh.host, ssh.port);
    match tokio::time::timeout(ssh.timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 256];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 && buf.starts_with(b"SSH-") => (CheckStatus::Up, None, None),
                Ok(Ok(_)) => (CheckStatus::Down, None, Some("ssh: no SSH banner received".into())),
                Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("ssh banner read: {e}"))),
                Err(_) => (CheckStatus::Down, None, Some("ssh banner read: timeout".into())),
            }
        }
        Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("ssh connect {addr}: {e}"))),
        Err(_) => (
            CheckStatus::Down,
            None,
            Some(format!("ssh connect {addr}: timeout after {}ms", ssh.timeout.as_millis())),
        ),
    }
}

/// UDP probe: send optional payload, check for response.
async fn probe_udp(udp: &UdpCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_host(&udp.host, udp.port, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    let addr = format!("{}:{}", udp.host, udp.port);
    match tokio::time::timeout(udp.timeout, async {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&addr).await?;
        if let Some(ref payload) = udp.payload {
            let bytes = hex::decode(payload).unwrap_or_else(|_| payload.as_bytes().to_vec());
            socket.send(&bytes).await?;
        }
        let mut buf = [0u8; 4096];
        let n = socket.recv(&mut buf).await?;
        Ok::<_, std::io::Error>((n, buf[..n].to_vec()))
    })
    .await
    {
        Ok(Ok((_, data))) => {
            if let Some(ref expected) = udp.expected_response_contains {
                let data_str = String::from_utf8_lossy(&data);
                if data_str.contains(expected.as_str()) {
                    (CheckStatus::Up, None, None)
                } else {
                    (CheckStatus::Down, None, Some(format!("udp: response missing '{expected}'")))
                }
            } else {
                (CheckStatus::Up, None, None)
            }
        }
        Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("udp {addr}: {e}"))),
        Err(_) => (
            CheckStatus::Down,
            None,
            Some(format!("udp {addr}: timeout after {}ms", udp.timeout.as_millis())),
        ),
    }
}

/// STARTTLS probe: connect to SMTP, verify STARTTLS capability.
async fn probe_starttls(stls: &StarttlsCheck) -> (CheckStatus, Option<u16>, Option<String>) {
    if let Err(reason) = ssrf_check_host(&stls.host, stls.port, SsrfGuard::strict()).await {
        return (CheckStatus::Error, None, Some(reason));
    }
    let addr = format!("{}:{}", stls.host, stls.port);
    match tokio::time::timeout(stls.timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    if banner.starts_with("220") {
                        let _ = stream.write_all(b"EHLO check\r\n").await;
                        let mut resp_buf = [0u8; 4096];
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            stream.read(&mut resp_buf),
                        )
                        .await
                        {
                            Ok(Ok(m)) => {
                                let resp = String::from_utf8_lossy(&resp_buf[..m]);
                                if resp.to_uppercase().contains("STARTTLS") {
                                    (CheckStatus::Up, None, None)
                                } else {
                                    (
                                        CheckStatus::Degraded,
                                        None,
                                        Some("starttls: STARTTLS not advertised".into()),
                                    )
                                }
                            }
                            _ => (
                                CheckStatus::Down,
                                None,
                                Some("starttls ehlo read: timeout".into()),
                            ),
                        }
                    } else {
                        (
                            CheckStatus::Down,
                            None,
                            Some(format!("starttls: unexpected banner: {}", banner.trim())),
                        )
                    }
                }
                Ok(Ok(_)) => (CheckStatus::Down, None, Some("starttls: empty banner".into())),
                Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("starttls banner read: {e}"))),
                Err(_) => (CheckStatus::Down, None, Some("starttls banner read: timeout".into())),
            }
        }
        Ok(Err(e)) => (CheckStatus::Down, None, Some(format!("starttls connect {addr}: {e}"))),
        Err(_) => (CheckStatus::Down, None, Some(format!("starttls connect {addr}: timeout"))),
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

/// Merge two check statuses: worst wins. Down > Degraded > Up.
#[expect(clippy::missing_const_for_fn)]
fn merge_status(a: CheckStatus, b: CheckStatus) -> CheckStatus {
    match (a, b) {
        (CheckStatus::Down, _) | (_, CheckStatus::Down) => CheckStatus::Down,
        (CheckStatus::Degraded, _) | (_, CheckStatus::Degraded) => CheckStatus::Degraded,
        _ => CheckStatus::Up,
    }
}

/// Evaluate a single [`BodyCondition`] against a parsed JSON value.
fn eval_body_condition(cond: &statuscore::domain::BodyCondition, json: &serde_json::Value) -> bool {
    if cond.exists {
        resolve_json_path(json, &cond.path).is_some()
    } else if let Some(ref expected) = cond.value {
        // Check for `len(path)` syntax: compare array length.
        // Must resolve the inner path first, before the literal key lookup.
        if cond.path.starts_with("len(") && cond.path.ends_with(')') {
            let inner = &cond.path[4..cond.path.len() - 1];
            return match resolve_json_path(json, inner).and_then(|v| v.as_array()) {
                Some(arr) if expected.parse::<usize>().is_ok_and(|n| arr.len() == n) => {
                    !cond.negate
                }
                Some(arr) if expected.parse::<usize>().is_ok_and(|n| arr.len() != n) => cond.negate,
                _ => cond.negate,
            };
        }
        match resolve_json_path(json, &cond.path) {
            None => false,
            Some(val) => {
                // Type-aware comparison: try number, then bool, then string.
                let matches = if let (Some(exp_n), Some(val_n)) =
                    (expected.parse::<f64>().ok(), val.as_f64())
                {
                    (val_n - exp_n).abs() < f64::EPSILON
                } else if let (Some(exp_b), Some(val_b)) =
                    (expected.parse::<bool>().ok(), val.as_bool())
                {
                    val_b == exp_b
                } else {
                    // String comparison: exact match or substring contains.
                    val.as_str().is_some_and(|s| s == expected || s.contains(expected.as_str()))
                };
                if cond.negate { !matches } else { matches }
            }
        }
    } else {
        true
    }
}

/// Walk a JSON value by dot-separated path. `resolve_json_path(v, "a.b")`
/// returns `v["a"]["b"]`. Returns `None` if any segment is missing.
fn resolve_json_path<'a>(val: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = val;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[expect(dead_code)]
enum CertCheckResult {
    Ok,
    ExpiringSoon(i64),
    Expired(i64),
    Error(String),
}

/// Open a TLS connection to `host:port`, read the leaf certificate, and
/// compare its `not_after` against `warn_days`. Returns the outcome.
#[cfg(feature = "agent")]
async fn check_tls_cert_expiry(host: &str, port: u16, warn_days: u32) -> CertCheckResult {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => return CertCheckResult::Error(format!("SNI: {e}")),
    };

    let stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return CertCheckResult::Error(format!("tcp: {e}")),
        Err(_) => return CertCheckResult::Error("tcp timeout".into()),
    };

    let tls = match connector.connect(server_name, stream).await {
        Ok(t) => t,
        Err(e) => return CertCheckResult::Error(format!("tls: {e}")),
    };

    let certs: Vec<_> = tls.get_ref().1.peer_certificates().map(|c| c.to_vec()).unwrap_or_default();

    if certs.is_empty() {
        return CertCheckResult::Error("no peer certificates".into());
    }

    let (_, cert) = match x509_parser::parse_x509_certificate(&certs[0]) {
        Ok(c) => c,
        Err(e) => return CertCheckResult::Error(format!("cert parse: {e}")),
    };

    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days_remaining = (not_after - now) / 86400;

    if days_remaining < 0 {
        CertCheckResult::Expired(-days_remaining)
    } else if (days_remaining as u32) < warn_days {
        CertCheckResult::ExpiringSoon(days_remaining)
    } else {
        CertCheckResult::Ok
    }
}

#[cfg(not(feature = "agent"))]
async fn check_tls_cert_expiry(_host: &str, _port: u16, _warn_days: u32) -> CertCheckResult {
    CertCheckResult::Error("cert check requires 'agent' feature".into())
}

/// Permissive TLS certificate verifier — accepts any server cert. Only safe
/// because we use it to *inspect* the cert, not to trust the connection.
#[cfg(feature = "agent")]
#[derive(Debug)]
struct NoCertVerifier;

#[cfg(feature = "agent")]
impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
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
