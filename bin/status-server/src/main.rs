//! StatusPage server entry point.

// Test code legitimately uses `.unwrap()` / `.expect()` / `panic!` for
// assertions and fixture setup. The workspace denies these lints to keep
// production code panic-free; relax them in `#[cfg(test)]` modules only.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::enum_glob_use)
)]
// ponytail: business logic functions (escalation engine, incident writer,
// cleanup, subscriber dispatch) are inherently complex — splitting them
// further would reduce readability without improving correctness.
#![expect(clippy::cognitive_complexity)]

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

mod api;
mod app;
mod assets;
mod auth;
mod cleanup;
mod escalation_engine;
mod idempotency;
mod incident_writer;
mod mcp;
mod observability;
#[cfg(feature = "agent")]
mod probes;
mod public_status_cache;
mod rate_limit;
mod router;
mod scheduler;
mod seed;
mod subscriber_dispatch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load config first so tracing/metrics init can be driven by it.
    let config =
        statuscore::config::AppConfig::load().map_err(|e| format!("failed to load config: {e}"))?;

    // Initialise tracing via the shared helper — honours `log_level` /
    // `log_format` from `[observability]` instead of hard-coding the fmt
    // layer. `TracingGuard` is held for the process lifetime; its
    // `shutdown()` is a no-op in this build (no OTLP exporter to flush).
    let _tracing_guard = common::observability::init_tracing(&config.observability);

    // Initialise the OTLP metrics exporter when `metrics_enabled`. Metrics
    // are pushed to the configured OTLP endpoint on a periodic interval.
    // Disabling keeps the binary zero-overhead for self-hosted dev.
    if config.observability.metrics_enabled {
        if let Err(e) = common::observability::init_metrics(&config.observability) {
            tracing::error!(error = %e, "OTLP metrics exporter init failed; continuing without metrics");
        }
    } else {
        tracing::info!("metrics exporter disabled (observability.metrics_enabled = false)");
    }

    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let duckdb_path = if config.storage.duckdb_path.trim().is_empty() {
        ":memory:"
    } else {
        config.storage.duckdb_path.as_str()
    };

    tracing::info!(addr = %config.server.api_bind, duckdb_path, "starting StatusPage server");

    // Initialize storage (DuckDB). Migration runs on every boot and is
    // idempotent (`CREATE TABLE IF NOT EXISTS`); failures are surfaced but
    // do not abort startup — a degraded instance with read-only access to
    // existing data is preferable to a boot loop that locks operators out.
    //
    // Credential KEK: when `[security] credentials_kek_base64` is set, a
    // `Cipher` is built and handed to the storage layer so notification
    // channel configs and secret variable values are sealed at rest
    // (AES-256-GCM envelope). Empty / unset = plaintext fallback (self-host
    // dev mode). A malformed KEK is a clean startup error — booting without
    // encryption when the operator asked for it would silently downgrade.
    let cipher = if let Some(kek_b64) = config.security.kek() {
        let c = common::security::Cipher::from_base64_str(kek_b64)
            .map_err(|e| format!("invalid credentials_kek_base64: {e}"))?;
        tracing::info!(
            "credentials KEK loaded; notification channel configs and secret variables will be sealed at rest"
        );
        Some(std::sync::Arc::new(c))
    } else {
        tracing::warn!(
            "no credentials KEK configured; notification channel configs and secret variables stored as plaintext (self-host dev mode)"
        );
        None
    };
    let storage = storage::DuckdbStorage::open(duckdb_path)
        .map_err(|e| format!("failed to open duckdb: {e}"))?
        .with_cipher(cipher);
    if let Err(e) = storage.migrate().await {
        tracing::error!(error = %e, "duckdb migration failed; continuing with existing schema");
    }

    // Seed: sync notification channels and targets from config file.
    // Runs once on startup; idempotent (skips existing items by name).
    if let Some(seed_cfg) = seed::load_seed_config() {
        tracing::info!(
            channels = seed_cfg.notification_channels.len(),
            targets = seed_cfg.targets.len(),
            "syncing seed config into storage"
        );
        seed::sync_from_config(&storage, &seed_cfg).await;
    }

    // Build app state. `AppState::new` wraps the concrete `DuckdbStorage` in
    // an `Arc<dyn Storage>` internally, so we pass it by value (not pre-wrapped).
    let state = app::AppState::new(storage, config.clone());

    // Build the SSRF-guarded `reqwest::Client` shared by every `http` probe
    // the scheduler dispatches. `redirect::Policy::none()` is the second
    // layer of SSRF defence: even if a public URL's first response is a
    // 30x to an internal address, reqwest won't follow it. The per-probe
    // timeout is applied on the request builder, not the client, so one
    // client serves the whole fleet. The URL-level guard
    // (`scheduler::ssrf_check_url`) runs before any TCP open.
    let probe_http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // Spawn the in-process probe scheduler. It shares the storage Arc with
    // the API handlers. The scheduler runs until the `shutdown` token fires
    // (graceful shutdown breaks its `tokio::select!` loop). The dispatch
    // context wires the production email sender + sender identity into the
    // per-probe evaluation path so an auto-open / auto-close can fire
    // operator notifications.
    let dispatch_ctx = incident_writer::ChannelDispatchCtx::new(
        state.email_sender.clone(),
        state.from_address.clone(),
        state.public_base_url.clone(),
        state.notifier_http.clone(),
    );
    let scheduler = scheduler::Scheduler::with_dispatch_ctx(
        state.storage.clone(),
        dispatch_ctx,
        probe_http_client,
        state.config.checker.connectivity_check_url.clone(),
    );

    // Collect every long-running worker's JoinHandle so graceful shutdown
    // can wait for each to drain before the process exits. Without this,
    // `tokio::spawn` tasks are dropped silently when `main` returns — a
    // worker mid-write (e.g. subscriber dispatch posting to a webhook)
    // would be cut off, losing the delivery. The signal-handler spawn
    // (ctrl_c) is deliberately NOT collected: it only triggers `cancel`
    // and has no work to drain.
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    handles.push(tokio::spawn(scheduler.run(shutdown.clone())));

    // Spawn the decoupled incident evaluator. The per-probe path
    // (scheduler → `incident_writer::evaluate_target`) still runs for
    // low-latency auto-open, but this background sweeper catches state
    // changes the per-probe path might miss (e.g. an agent pushing results
    // directly to storage). It re-scans the whole fleet every 30s using a
    // single batched read. Cancelled by the same `shutdown` token as the
    // scheduler / HTTP server so it stops cleanly on SIGINT. The dispatch
    // context is shared with the per-probe path so the background sweeper
    // fires the same operator notifications.
    let dispatch_ctx = incident_writer::ChannelDispatchCtx::new(
        state.email_sender.clone(),
        state.from_address.clone(),
        state.public_base_url.clone(),
        state.notifier_http.clone(),
    );
    handles.push(tokio::spawn(incident_writer::run_background_evaluator(
        state.storage.clone(),
        dispatch_ctx,
        shutdown.clone(),
    )));

    // Spawn the subscriber notification dispatch worker. Consumes the
    // `subscriber_deliveries` queue (populated by the incident writer and
    // maintenance triggers) and delivers pending notifications to verified
    // subscribers over their configured channel (email / webhook / slack /
    // sms). Without this worker, queued deliveries stay Pending forever —
    // the subscriber feature is non-functional without it. The outbound
    // HTTP client is the SSRF-guarded one so a subscriber webhook URL
    // pointing at a private IP is dropped at DNS-filter time.
    handles.push(tokio::spawn(subscriber_dispatch::run(
        state.storage.clone(),
        state.email_sender.clone(),
        state.outbound_http.clone(),
        state.public_base_url.clone(),
        shutdown.clone(),
    )));

    // Spawn the escalation engine. Every 30s it walks the escalation
    // ladder for each incident whose `next_check_at` has elapsed: pages
    // the next rung's targets (channel/user/schedule) and reschedules.
    // The engine picks up states created by the incident writer (auto-open
    // on a target with `escalation_policy_id`) and stops paging on ack or
    // resolve (driven by the incident ops API). Cancelled by the same
    // `shutdown` token as the other workers so it stops cleanly on SIGINT.
    handles.push(tokio::spawn(escalation_engine::run_escalation_engine(
        state.storage.clone(),
        state.email_sender.clone(),
        shutdown.clone(),
        state.public_base_url.clone(),
        state.notifier_http.clone(),
    )));

    // Spawn the periodic cleanup worker. Every 6h it deletes:
    // - terminal deliveries (Sent / DeadLetter) older than 30 days,
    // - unverified subscribers older than 7 days,
    // - expired sessions and magic links,
    // - check results older than `retention.check_results_days` (default 30),
    // - API tokens past their post-expiry window (default 30 days).
    // Keeps every time-series and transient table bounded without manual
    // operator intervention.
    handles.push(tokio::spawn(cleanup::run(
        state.storage.clone(),
        state.config.retention,
        shutdown.clone(),
    )));

    // Spawn the rate-limit bucket janitor. Every 6h it evicts per-IP
    // buckets that haven't been touched in 24h so a flood of one-off
    // clients can't grow the map unbounded. No-op when the limiter is
    // disabled (per_minute == 0).
    handles.push(tokio::spawn(cleanup::run_rate_limit_janitor(
        state.auth_rate_limiter.clone(),
        shutdown.clone(),
    )));

    // Spawn the inventory gauge sampler. On a slow cadence (default 1s;
    // bump via `observability.gauge_sample_interval_ms` for production)
    // it counts enabled monitors by kind and active users, emitting
    // Prometheus gauges. Scrape-cached by Prometheus, so this never
    // reaches storage on the scrape hot path. No-op when the interval
    // is 0.
    handles.push(tokio::spawn(observability::run_gauge_sampler(
        state.storage.clone(),
        std::time::Duration::from_millis(config.observability.gauge_sample_interval_ms),
        shutdown.clone(),
    )));

    // Spawn the dead-man's snitch. Pings `observability.heartbeat.url`
    // every `interval_seconds` while the process is alive; an external
    // watcher alerts when the pings stop. The one signal that survives
    // the whole box dying. No-op when `heartbeat.enabled` is false or
    // `url` is empty.
    handles.push(tokio::spawn(observability::run_heartbeat_snitch(
        config.observability.heartbeat.clone(),
        shutdown.clone(),
        state.notifier_http.clone(),
    )));

    // Spawn config hot-reload watcher. Polls the config file every 30s;
    // when the modification time changes, reloads config and restarts
    // the scheduler. ponytail: notify crate's FS watcher would be more
    // efficient, but polling is simpler and 30s is acceptable latency.
    let config_path = std::env::var(statuscore::config::CONFIG_PATH_ENV)
        .unwrap_or_else(|_| statuscore::config::DEFAULT_CONFIG_PATH.to_string());
    handles.push(tokio::spawn(config_hot_reload(
        config_path,
        state.storage.clone(),
        shutdown.clone(),
    )));

    // Build router
    let app = router::build_router(state);

    // Start server
    let listener = TcpListener::bind(&config.server.api_bind).await?;
    tracing::info!("listening on {}", config.server.api_bind);

    tokio::spawn(async move {
        // Catch both SIGINT (Ctrl-C, interactive terminal) and SIGTERM
        // (systemd `KillSignal=SIGTERM`, Kubernetes pod termination, `kill
        // <pid>`). Without the SIGTERM handler, `systemctl stop statuspage`
        // would kill the process immediately — in-flight HTTP requests,
        // background probes, and subscriber deliveries would be dropped
        // without the 30 s worker drain below, and axum's
        // `with_graceful_shutdown` would never fire.
        wait_for_shutdown_signal().await;
        shutdown_clone.cancel();
    });

    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;

    // Wait for every worker to observe the cancellation token and exit.
    // Each worker polls `shutdown` in its loop, so this is bounded by the
    // worker's own shutdown latency (a single in-flight probe / delivery).
    // A 30s ceiling stops a stuck worker from hanging the process — the
    // handle is abandoned (the task is dropped when the runtime shuts
    // down) and a warning is logged so the operator can investigate.
    let shutdown_timeout = std::time::Duration::from_secs(30);
    for handle in handles {
        if tokio::time::timeout(shutdown_timeout, handle).await.is_err() {
            tracing::warn!("worker did not shut down within timeout, abandoning");
        }
    }
    tracing::info!("all workers shut down");

    Ok(())
}

/// Config hot-reload watcher. Polls the config file every 30s; when the
/// file's modification time changes, reloads the config. ponytail: does
/// not restart the scheduler yet — just logs the reload. Full restart
/// requires wiring the new config through to the scheduler, which is a
/// larger refactor. This establishes the detection mechanism.
async fn config_hot_reload(
    path: String,
    _storage: std::sync::Arc<dyn storage::Storage>,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut last_modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    tracing::info!(path = %path, "config hot-reload watcher started");

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::info!("config hot-reload watcher stopped");
                return;
            }
            _ = interval.tick() => {}
        }

        let current_modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();

        if current_modified != last_modified {
            last_modified = current_modified;
            tracing::info!("config file changed, reloading");
            match statuscore::config::AppConfig::load() {
                Ok(new_cfg) => {
                    tracing::info!("config reloaded successfully");
                    // ponytail: full scheduler restart not wired yet.
                    // The scheduler reads targets from storage, so config
                    // changes that write to storage (seed config) are
                    // picked up on the next refresh cycle.
                    drop(new_cfg);
                }
                Err(e) => {
                    tracing::error!(error = %e, "config reload failed; keeping current config");
                }
            }
        }
    }
}

/// Wait for a shutdown signal — SIGINT (Ctrl-C) on all platforms, plus
/// SIGTERM on Unix. Returns on the first signal received.
///
/// SIGTERM is what `systemctl stop` sends (see `deployment/statuspage.service`
/// `KillSignal=SIGTERM`), so catching it is required for the graceful drain
/// path (30 s worker timeout + axum `with_graceful_shutdown`) to actually run.
/// Without it the process is killed immediately by the default SIGTERM
/// disposition, dropping in-flight requests and background tasks.
async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::info!("SIGINT received, initiating graceful shutdown");
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("SIGTERM received, initiating graceful shutdown");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler; falling back to SIGINT only");
                let _ = ctrl_c.await;
                tracing::info!("SIGINT received, initiating graceful shutdown");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
        tracing::info!("shutdown signal received");
    }
}
