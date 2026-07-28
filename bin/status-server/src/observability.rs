//! Background observability tasks: inventory gauge sampler and dead-man's
//! snitch.
//!
//! Two loops, both spawned from `main.rs` and cancelled by the same
//! `CancellationToken` as the other workers:
//!
//! 1. **Gauge sampler** — periodically reads the configured-monitor and
//!    active-user counts from storage and emits them as Prometheus
//!    gauges. Scrape-cached by Prometheus, so this never reaches storage
//!    on the hot path of a scrape. The cadence is configurable via
//!    `[observability] gauge_sample_interval_ms` (default 1s; bump to
//!    60s in production to keep storage load negligible).
//!
//! 2. **Dead-man's snitch** — pings an external URL on an interval
//!    *only while the process is alive*. An independent watcher
//!    (Healthchecks.io, Dead Man's Snitch, OpenObserve heartbeat) alerts
//!    when the pings stop. This is the one signal that survives the whole
//!    box dying — the in-app metrics/alert path can't page when it's the
//!    thing that's down. The URL carries a capability token, so it is
//!    env-sourced and never logged. Configured under
//!    `[observability.heartbeat]`.

use std::sync::Arc;
use std::time::Duration;

use metrics::gauge;
use statuscore::config::HeartbeatConfig;
use statuscore::domain::CheckSpec;
use storage::Storage;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use common::observability::metrics::names;

/// Run the inventory gauge sampler loop. Emits:
/// - `statuspage_targets_enabled` labelled by `kind`, one series per
///   `CheckSpec::ALL_KINDS` entry (zero for kinds with no enabled monitors
///   so dashboards don't show a hole when a kind is briefly empty).
/// - `statuspage_users_active` (no labels).
///
/// Errors are logged and swallowed — a failed sample just retries on the
/// next tick. Storage unavailability degrades the gauges to staleness,
/// not a crash.
pub async fn run_gauge_sampler(
    storage: Arc<dyn Storage>,
    interval: Duration,
    cancel: CancellationToken,
) {
    if interval.is_zero() {
        info!("observability: gauge sampler disabled (interval = 0)");
        return;
    }
    info!(?interval, "observability: gauge sampler started");
    loop {
        // tokio::select! cancels the sleep on shutdown — clean exit
        // without the wait-for-next-tick latency.
        tokio::select! {
            () = cancel.cancelled() => {
                info!("observability: gauge sampler stopped");
                return;
            }
            () = tokio::time::sleep(interval) => {}
        }

        // Sample targets: count enabled monitors by kind. We list and
        // count in-process rather than a `COUNT(*) GROUP BY kind` query
        // so the storage trait stays portable across the DuckDB and
        // Memory backends (neither needs a custom aggregation method).
        match storage.list_targets().await {
            Ok(targets) => {
                let mut counts: std::collections::HashMap<&'static str, i64> =
                    std::collections::HashMap::new();
                for t in &targets {
                    if t.enabled {
                        *counts.entry(t.check.kind()).or_insert(0) += 1;
                    }
                }
                // Emit a series for every declared kind, including the
                // ones with zero monitors — a missing series would
                // render as "no data" on a dashboard rather than "0",
                // which is misleading.
                for kind in CheckSpec::ALL_KINDS {
                    let n = counts.get(kind).copied().unwrap_or(0);
                    gauge!(names::TARGETS_ENABLED, "kind" => kind).set(n as f64);
                }
            }
            Err(e) => {
                warn!(error = %e, "observability: gauge sampler: list_targets failed");
            }
        }

        // Sample users: count non-deleted accounts.
        match storage.count_users().await {
            Ok(n) => {
                gauge!(names::USERS_ACTIVE).set(n as f64);
            }
            Err(e) => {
                warn!(error = %e, "observability: gauge sampler: count_users failed");
            }
        }

        debug!("observability: gauge sampler tick done");
    }
}

/// Run the dead-man's snitch loop. Pings `cfg.url` every
/// `cfg.interval_seconds` while the process is alive. An external
/// watcher alerts when the pings stop.
///
/// The URL is a capability token — never logged at `info!`. Failures are
/// logged at `warn` so an operator notices if the snitch endpoint is
/// unreachable, but the loop continues: a single failed ping shouldn't
/// cascade into giving up on the snitch entirely.
///
/// `outbound_http` is the shared SSRF-guarded `reqwest::Client` built once
/// at boot. The snitch URL is typically on the public internet
/// (Healthchecks.io, Dead Man's Snitch) and the SSRF guard's
/// private-IP filter doesn't block public hosts — but reusing the shared
/// client keeps the snitch on the same TLS stack / connection pool as the
/// rest of the outbound traffic instead of spinning a second client.
pub async fn run_heartbeat_snitch(
    cfg: HeartbeatConfig,
    cancel: CancellationToken,
    outbound_http: reqwest::Client,
) {
    if !cfg.enabled || cfg.url.trim().is_empty() {
        info!(
            enabled = cfg.enabled,
            url_set = !cfg.url.trim().is_empty(),
            "observability: heartbeat snitch disabled"
        );
        return;
    }
    let interval = Duration::from_secs(cfg.interval_seconds.max(1));

    info!(interval_secs = cfg.interval_seconds, "observability: heartbeat snitch started");
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!("observability: heartbeat snitch stopped");
                return;
            }
            () = tokio::time::sleep(interval) => {}
        }

        // GET, not POST: most snitch watchers (Healthchecks.io, Dead
        // Man's Snitch) treat a plain GET as a successful ping. The
        // response body is irrelevant — only the HTTP status matters.
        match outbound_http.get(&cfg.url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    // Don't log the URL — it carries the capability
                    // token. Status only.
                    warn!(status = %resp.status(), "observability: heartbeat snitch: non-2xx response");
                }
            }
            Err(e) => {
                warn!(error = %e, "observability: heartbeat snitch: request failed");
            }
        }
    }
}
