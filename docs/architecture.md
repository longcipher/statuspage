# Architecture

> **Binaries:** `status-server` (the single Rust backend binary — API, scheduler, incident engine, MCP) and `status-frontend` (a Leptos CSR WebAssembly bundle built by Trunk, served as static files by `status-server`).
> **Status:** v1 single-process deployment. One embedded DuckDB file holds both configuration and time-series state. No external databases, no agent mode, no multi-region fan-out, no OAuth 2.1 server, no marketing host routing. Deployment is a systemd unit, not a container.

StatusPage is one Rust backend process that runs single-user uptime monitoring and public status pages. A single DuckDB file holds configuration, control-plane state, and check results. The same binary also serves the Leptos CSR frontend (compiled to WASM) as static files with an SPA fallback. This page is the map: what the pieces are, how a request and a check flow through them, and which invariants every feature must respect.

## Goals

- Run periodic checks of four in-process kinds (HTTP, TCP, ping, heartbeat) against an arbitrary, mutable set of targets. The four "agent-only" kinds (`dns`, `tls_cert`, `domain_expiry`, `flow`) are acknowledged but not executed in-process — they record an `Error` result with a "not supported" reason. See [Monitor types](monitor-types.md).
- Turn a run of failing checks into a confirmed incident, notify the right channels, and publish a customer-facing status surface.
- Survive transient target failures and storage flaps, and surface every error through `tracing` rather than swallowing it.
- Drain in-flight work on shutdown rather than lose it.

## Process modes

There is one process mode. `status-server` is the control plane: it owns DuckDB, the REST API, the web UI (served as static files), the MCP server, the in-process probe scheduler, the incident writer, the escalation engine, public status pages, and the periodic jobs. The `[agent]` and `[marketing]` config sections exist but are inert in this build — no agent entry point and no marketing module are compiled in. A `[scheduler] enabled = false` knob exists to turn the in-process scheduler off (turning the process into a pure dashboard that reads stored results), but there is no separate agent binary and no bootstrap CLI subcommand.

## Module layout

```
bin/status-server/src/
├── main.rs            startup: config load, tracing/metrics init, DuckDB open +
│                      migrate, subsystem spawn, axum serve on server.api_bind
├── app.rs             AppState (composition root): Arc<dyn Storage>, notifier,
│                      email sender, outbound HTTP, auth service, rate limiter,
│                      idempotency cache, public status cache
├── router.rs          router assembly: /healthz, /readyz, /api/v1, /api/v1/auth
│                      (rate-limited), /api/v1/heartbeat (unauthenticated),
│                      /api/public/v1, /mcp (conditional),
│                      frontend ServeDir + SPA fallback; http_metrics + CORS layers
├── scheduler.rs       in-process probe scheduler: HashMap<target_id, next_due>,
│                      5s sweep tick + 30s target-list refresh; probes due targets
│                      and records results directly to storage
├── incident_writer.rs per-probe evaluate_target + 30s background fleet sweeper;
│                      FLAP_THRESHOLD consecutive non-Up opens, consecutive Up closes
├── incident_writer/
│   └── channel_dispatch.rs   operator notification dispatch on auto-open / auto-close
├── escalation_engine.rs      feature-flagged paging engine (off by default)
├── subscriber_dispatch.rs    subscriber notification worker (drains subscriber_deliveries)
├── cleanup.rs                6h retention sweep: deliveries, subscribers, sessions,
│                             magic links, check_results, post-expiry API tokens
├── mcp.rs                    in-process MCP server (JSON-RPC 2.0 over HTTP, read-only)
├── observability.rs          gauge sampler (Prometheus) + dead-man's snitch
├── rate_limit.rs             in-process per-IP limiter for auth + heartbeat + public endpoints
├── idempotency.rs            in-process Idempotency-Key cache for bulk endpoints
├── public_status_cache.rs    moka hot cache + stale last-good snapshot per status page
├── assets.rs                 SPA fallback handler for the frontend bundle
├── auth/                     session + API-token + magic-link lifecycle
│   ├── middleware.rs         identity extractor (session cookie / Bearer token) per request
│   ├── routes.rs             bootstrap, magic-link, sessions, tokens, prefs
│   └── service.rs            AuthService used by middleware + routes
├── api/                      REST /api/v1 handlers (components, dashboard, escalation
│   ├── *.rs                  policies, heartbeat, incident ops, maintenance, notification
│   └── mod.rs                channels, on-call, page assets, postmortems, public api,
│                             share links, silence rules, subscribers, variables)
└── probes/                   probe implementations reserved for agent execution
    ├── dns.rs                DNS resolver probe (not wired into the in-process scheduler)
    ├── tls_cert.rs           TLS certificate expiry probe (not wired into the in-process scheduler)
    └── domain_expiry.rs      RDAP domain-expiry probe (not wired into the in-process scheduler)

bin/status-frontend/src/      Leptos CSR WASM frontend (Trunk build → target/site/)
├── app.rs, lib.rs            root component + WASM entry
├── api/                      typed client + request types
├── pages/                    home, targets, incidents, status pages, settings, login, public status page, not_found
└── components/               nav, status badge, latency chart, theme toggle, error state

crates/
├── common/                   shared infrastructure
│   ├── http_client/          poolless probe client (phase-timing connector) +
│   │                         outbound SSRF-guarded HTTPS client for webhooks
│   ├── net/                  happy-eyeballs dial (RFC 8305)
│   ├── security/             AES-GCM envelope crypto + SSRF guard
│   ├── observability/        tracing init + Prometheus exporter + http_metrics
│   ├── notifier/             one transport per channel kind (slack, discord,
│   │                         telegram, msteams, pagerduty, ntfy, pushover, sms,
│   │                         webhook, google_chat, email, whatsapp)
│   └── email/                transactional email (resend, log, memory, smtp)
├── core/                     domain types + config + error
│   ├── domain/               Target, CheckSpec, CheckResult, Incident, on_call,
│   │                         notification_channel, quota, etc. (no I/O)
│   ├── config.rs             typed AppConfig + STATUSPAGE_ env override loader
│   └── error.rs              AppError -> ApiError envelope
└── storage/                  DuckDB + in-memory stores behind a single Storage trait
    ├── traits.rs             Storage trait (one contract for both halves)
    ├── duckdb.rs             DuckDB implementation (bundled feature)
    └── memory.rs             in-memory implementation (tests / dev)
```

## Request path

`router::build_router` assembles a single axum `Router` keyed by `AppState`. There is no host-based dispatch — every host lands on the same router, and public status is path-based (`/p`, `/api/public/v1/*`). The route tree:

- `GET /healthz` — always returns `200 "ok"` while the process is up.
- `GET /readyz` — calls `Storage::ping` (`SELECT 1`); `200 "ready"` on success, `503 "not ready"` on failure.
- `nest /api/v1` — management API (auth-protected). Two middleware layers run on every request under this nest: `require_auth_middleware` (rejects unauthenticated requests with 401) and `csrf_guard_middleware` (rejects state-changing requests without `X-Requested-With` or `Authorization`). An 8 MiB body limit is applied.
- `nest /api/v1/heartbeat` — unauthenticated heartbeat ping endpoint (`POST /{target_id}`), wrapped in a per-IP rate-limit layer (`rate_limit::heartbeat_guard`) so a flood of pings cannot starve the DuckDB mutex.
- `nest /api/v1/auth` — auth API (bootstrap, magic-link, sessions, tokens, prefs), wrapped in the per-IP rate-limit middleware so every auth endpoint shares one bucket per IP.
- `nest /api/public/v1` — public, unauthenticated, read-only API, wrapped in a per-IP rate-limit layer (`rate_limit::public_guard`).
- `merge /mcp` — MCP JSON-RPC server; `mcp::routes()` returns an empty router when `[mcp].enabled = false`, so the merge is a no-op by default. Auth reuses the session cookie or Bearer API token.
- `fallback_service` — `ServeDir::new("target/site")` with an SPA fallback so client-side routing works for the Leptos CSR frontend.

The middleware order is documented at the top of `router.rs`: `http_metrics` (per-route request counters, latency histograms, in-flight gauge; skips `/healthz` and `/readyz`) outermost, then `TraceLayer`, then an optional CORS layer built from `[api.cors]`. There is no host-based dispatch, no tenant-host isolation fence, and no separate CSRF layer — the frontend is a CSR SPA that talks to the API via Bearer tokens / cookies, and writes go through the auth-protected API only.

Authentication resolves a session cookie or an `sm_live_`-prefixed Bearer API token into an authorization extractor (`AuthIdentity` → `RequireAuth` / `RequireSession`). The bootstrap endpoint (`POST /api/v1/auth/bootstrap`) creates the first user when zero users exist.

## Probe path

The in-process scheduler runs every check itself. The pipeline from config to stored result:

```
DuckDB (targets)        Storage::list_targets() — full re-list every 30s, diffed
   │                    into the in-memory HashMap<target_id, next_due>
   ▼
Scheduler               5s sweep tick: collect every target whose next_due <= now,
   │                    skip disabled ones, probe each sequentially
   │ dispatch
   ▼
probe_target            one executor per check kind:
   │                    ├── http / tcp / ping (inline in scheduler.rs)
   │                    ├── heartbeat (passive: reads last_ping_at from storage)
   │                    └── dns / tls_cert / domain_expiry / flow / unknown →
   │                        CheckStatus::Error,
   │                        "check kind <k> not supported on the control plane"
   │ CheckResult
   ▼
Storage::record_result  direct write to DuckDB check_results (no batcher,
   │                    no bounded mpsc, no worker pool)
   ▼
incident_writer::       per-probe evaluate_target: reads recent results,
evaluate_target         FLAP_THRESHOLD consecutive non-Up opens an incident,
                        consecutive Up closes it. Fire-and-forget; errors logged.
```

Each target carries its own `interval`. On the first refresh every target is scheduled immediately with a small jitter (0–5s) so a freshly booted instance with many targets sharing one interval doesn't thunder. Between refreshes the scheduler works from its in-memory `next_due` map; targets removed from storage are evicted on the next refresh, and interval edits take effect from the next probe.

HTTP checks connect fresh every interval. There is no connection pool, because a monitor probes each target once per interval so a pool would rarely reuse a socket, and connecting fresh is exactly what lets the probe time DNS resolution, TCP connect, and the TLS handshake as separate phases. Network probes use the shared `SsrfGuard::strict` via `scheduler::ssrf_check_url`: a target pointing at a private IP (loopback, RFC1918, link-local, cloud metadata, ULA, etc.) is dropped at DNS-filter time before any TCP open — DNS-rebinding safe by construction. See [Monitor types](monitor-types.md).

On-demand checks (`POST /targets/{id}/check-now` and `POST /targets/test`) call `scheduler::probe_target` directly and return the result inline. There is no long-poll to a remote agent and no `503 PROBE_UNAVAILABLE` path — the probe runs in the calling process.

## Detection, incidents, and paging

Results do not page directly. A follower turns them into confirmed incidents:

- **Incident writer** (`incident_writer.rs`) is a follower, not an event listener. Two paths feed it: (1) the per-probe `evaluate_target` call after each `record_result` for low-latency auto-open, and (2) a background sweeper that re-scans the whole fleet every 30s using a single batched read (`Storage::recent_results_for_targets`) so an out-of-band writer is reflected within half a minute. It reads each target's recent results (lookback 10), and `>= FLAP_THRESHOLD` (2) consecutive non-`Up` results opens an incident; `>= FLAP_THRESHOLD` consecutive `Up` results closes it. `find_open_incident_for_target` ensures only one open incident per target exists, so the writer is idempotent. Maintenance windows suppress auto-open: results are still recorded, but no incident is created. This confirmation step is why public status derives from confirmed incidents and never from raw samples.
- **Escalation engine** (`escalation_engine.rs`) is feature-flagged (`[escalation].enabled`, off by default). When on, every 15s it walks the escalation ladder for each incident whose `next_check_at` has elapsed: pages the next rung's targets (channel / user / schedule) and reschedules. It picks up states created by the incident writer (auto-open on a target with `escalation_policy_id`) and stops paging on ack or resolve (driven by the incident ops API). When off, incidents still open and display but the monitor's directly bound channels are notified once as a fallback via `channel_dispatch`.
- **Subscriber dispatch** (`subscriber_dispatch.rs`) is a separate worker that drains the `subscriber_deliveries` queue (populated by the incident writer and maintenance triggers) and delivers pending notifications to verified subscribers over their configured channel (email / webhook / Slack / SMS). The outbound HTTP client is the SSRF-guarded one so a subscriber webhook URL pointing at a private IP is dropped at DNS-filter time.

Internal incident state (Triggered, Acknowledged, Resolved) and the public communication phase are orthogonal tracks and never share a field.

## Data model

One backend, split by access pattern within a single DuckDB file:

- **DuckDB** holds everything: monitors, incidents, paging and on-call, public-status config, auth, ops tables, and the append-only `check_results` time-series. Low-cardinality config tables are mutated by API operations; high-cardinality results are appended by the scheduler. Migrations are idempotent `CREATE TABLE IF NOT EXISTS` statements run by `DuckdbStorage::migrate` on every boot. Editing a shipped statement is a silent no-op on existing volumes, so schema changes are validated against a fresh volume. Migration failures are surfaced but do not abort startup — a degraded instance with read-only access to existing data is preferable to a boot loop that locks operators out.

Erasure is single-store: soft-deleted users are purged by the cleanup worker after `[tenancy].deletion_grace_period_days` (default 30), and `check_results` rows older than `[retention].check_results_days` (default 30) are hard-deleted in the same sweep. There is no two-store outbox and no cross-store settle step.

## Key design choices

- **Sealed secrets.** Channel and variable secrets are sealed with one AES-256-GCM envelope at the storage edge when `[security] credentials_kek_base64` is set, and redacted on every read. Empty / unset KEK is a plaintext fallback for self-host dev mode; a malformed KEK is a clean startup error — booting without encryption when the operator asked for it would silently downgrade.
- **SSRF guard everywhere outbound.** Network probes (`http`) use `SsrfGuard::strict` via `ssrf_check_url`; subscriber webhook / Slack delivery uses a separate SSRF-guarded outbound client built with `SsrfGuard::strict`.
- **Poolless probe client.** Checks connect fresh each interval so each result can carry per-phase timings (DNS, TCP, TLS) and so a stale pooled socket can never mask a connectivity flap.
- **Cancellation tokens for shutdown.** A root `CancellationToken` is cloned into the scheduler, incident evaluator, subscriber dispatcher, escalation engine, cleanup worker, gauge sampler, dead-man's snitch, and the graceful axum shutdown. SIGINT or SIGTERM cancels the root and subsystems drain together.
- **Idempotent incident writer.** `find_open_incident_for_target` guarantees at most one open incident per target, so the per-probe path and the 30s background sweeper can both run without coordination and never double-open.
- **Sticky last-good for domain expiry.** The `domain_expiry_state` table persists `(expiry_at, registrar, last_success_at)` per target. A subsequent transient failure serves the cached verdict rather than flipping the monitor; only staleness past a threshold escalates to an alert-eligible error. (Note: in this build the `domain_expiry` kind is not executed in-process — it records an `Error` result. The sticky-last-good plumbing remains for an agent path.)

## Concurrency model

- One multi-threaded Tokio runtime.
- The scheduler is a single task driven by `tokio::select!` over a 5s sweep tick and a 30s target-list refresh tick. It owns a `HashMap<target_id, next_due>`; on each sweep it collects every due target and probes them sequentially. There is no per-target task, no min-heap, no worker pool, and no semaphore — concurrency is bounded by `checker.max_concurrent_checks` only insofar as the probes themselves are awaited in sequence within one task.
- The incident evaluator, subscriber dispatcher, escalation engine, cleanup worker, gauge sampler, and dead-man's snitch are each single tasks driven by `tokio::select!` over their trigger and the cancellation token.
- `AppState` is `Clone` (it holds `Arc`s internally) and shared across handlers via axum's state extractor.

## Observability

- **Logging:** `tracing` only, initialised by `common::observability::init_tracing` which honours `[observability] log_level` / `log_format` (`json` or `pretty`). Structured JSON to journald is the production default. `RUST_LOG` always wins over the config file.
- **Metrics:** `metrics` + `metrics-exporter-prometheus`. The exporter binds its own HTTP listener on `server.metrics_bind` (default `127.0.0.1:9091`) and serves `/metrics` — scrape it with Prometheus or OpenObserve. An inventory gauge sampler (`observability::run_gauge_sampler`, default 1s cadence) emits `statuspage_targets_enabled{kind}` and `statuspage_users_active`. Per-route HTTP metrics (request counters, latency histograms, in-flight gauge) are recorded by the `http_metrics` middleware. A small `GET /api/v1/metrics` endpoint exposes two derived gauges for ad-hoc single-port scrapes.
- **Trace export (optional):** OTLP/HTTP export to OpenObserve (or any OTLP collector) is supported via `[observability.openobserve]`, active only when both `observability.tracing_enabled` and `openobserve.enabled` are true. Off by default. Credentials are env-sourced, never in TOML.
- **Dead-man's snitch:** `observability::run_heartbeat_snitch` pings `[observability.heartbeat].url` every `interval_seconds` while the process is alive. An independent watcher (Healthchecks.io, Dead Man's Snitch, OpenObserve heartbeat) alerts when the pings stop — the one signal that survives the whole box dying.

## Deployment

Deployment is a systemd unit (`deployment/statuspage.service`), not a container. The unit runs `/usr/local/bin/status-server` as a dedicated `statuspage` user with `WorkingDirectory=/opt/statuspage`, loads environment from `/etc/statuspage/env`, sends SIGTERM for graceful shutdown (axum drains in-flight requests, systemd sends SIGKILL after `TimeoutStopSec=30`), restarts on failure, and pipes structured JSON logs to journald. Hardening includes `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and `ReadWritePaths=/opt/statuspage`. An optional rpxy reverse-proxy unit (`deployment/rpxy.service`) fronts the server for TLS termination and per-IP rate limiting at the edge; the in-process per-IP limiter is the second line of defence for auth, heartbeat, and public endpoints. See [Development](development.md) for the local workflow.
