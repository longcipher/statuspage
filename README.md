# StatusPage

Single-user, self-hosted status page and uptime monitoring. Probes HTTP,
TCP, ICMP, and heartbeat endpoints, renders results on a public status
page with latency charts and incident tracking, and ships as **one binary
with embedded DuckDB** — no external database, no Redis, no container.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

---

## Highlights

- **One binary, one DuckDB file.** Backend, scheduler, incident engine,
  public status page, and the Leptos CSR frontend (compiled to WASM) all
  live in `status-server`. No external services to operate.
- **Four in-process probe kinds.** `http`, `tcp`, `ping`, `heartbeat` run
  inside the process; `dns`, `tls_cert`, `domain_expiry`, `flow` are
  defined for forward compatibility with an agent runtime.
- **SSRF-safe by construction.** Network probes resolve through a strict
  guard that drops loopback / RFC1918 / link-local / cloud-metadata
  targets at DNS-filter time — DNS-rebinding safe.
- **Sealed secrets at rest.** Channel credentials and secret variables are
  AES-256-GCM envelope-encrypted when a KEK is provisioned.
- **Graceful shutdown.** SIGINT/SIGTERM cancel a root token; scheduler,
  incident writer, subscriber dispatch, and axum drain together within a
  30 s ceiling.
- **MCP server built in.** Read-only Model Context Protocol surface at
  `/mcp` for LLM clients (off by default).
- **systemd deployment.** Production runs as a unit behind an `rpxy`
  reverse proxy (TLS-ALPN-01 ACME, HTTP/2 + HTTP/3).

---

## Architecture

StatusPage is one Rust backend process that owns DuckDB, the REST API,
the web UI (served as static files), the MCP server, the in-process probe
scheduler, the incident writer, the escalation engine, public status
pages, and the periodic cleanup jobs. The same binary serves the Leptos
CSR frontend (compiled to WASM) as static files with an SPA fallback.

```
                    ┌──────────────────────── status-server (one binary) ────────────────────────┐
                    │                                                                          │
  browser ───────►  │  axum router                                                             │
  (WASM UI)         │   ├── /healthz, /readyz                       (unauthenticated)            │
                    │   ├── /api/v1/*        management API        (auth + CSRF + 8 MiB limit)  │
                    │   ├── /api/v1/auth/*   bootstrap, sessions   (per-IP rate limit)         │
                    │   ├── /api/v1/heartbeat/*  passive heartbeat  (per-IP rate limit)         │
                    │   ├── /api/public/v1/*  public status JSON    (per-IP rate limit)         │
                    │   ├── /mcp              MCP JSON-RPC          (off by default)            │
                    │   └── fallback          ServeDir + SPA fallback (target/site/)            │
                    │                                                                          │
                    │  AppState ──► Arc<dyn Storage> (DuckdbStorage | MemoryStorage)            │
                    │                + notifier + email sender + outbound SSRF HTTP + auth     │
                    │                                                                          │
                    │  Workers (tokio::spawn, share CancellationToken):                         │
                    │   ├── scheduler            5 s sweep + 30 s target refresh                 │
                    │   ├── incident_writer      per-probe eval + 30 s fleet sweeper            │
                    │   ├── subscriber_dispatch  drains subscriber_deliveries                  │
                    │   ├── escalation_engine    feature-flagged paging (off by default)        │
                    │   ├── cleanup              6 h retention sweep                             │
                    │   ├── rate_limit janitor   6 h idle-bucket eviction                       │
                    │   ├── gauge sampler        1 s Prometheus gauges                           │
                    │   └── heartbeat snitch     dead-man's-switch pings                        │
                    └──────────────────────────────────────────────────────────────────────────────┘
                                                │
                                                ▼
                                       DuckDB file (statuspage.db)
                                       — config, incidents, check_results, auth, ops
```

### Workspace layout

```
bin/status-server    Axum HTTP server: REST API, scheduler, incident engine, MCP, static serving.
bin/status-frontend  Leptos CSR WASM frontend (Trunk dev, cargo-leptos release build → target/site/).
crates/core          Domain models, typed AppConfig, AppError → ApiError envelope.
crates/storage       Storage trait + DuckDB (bundled) and in-memory implementations.
crates/common        Shared infra: SSRF-guarded HTTP client, crypto, notifier, email, observability.
```

### Request path

`router::build_router` assembles one axum `Router` keyed by `AppState`.
There is no host-based dispatch — every host lands on the same router and
the public status surface is path-based (`/p`, `/api/public/v1/*`).

- `GET /healthz` — always `200 "ok"` while the process is up.
- `GET /readyz` — `Storage::ping` (`SELECT 1`); `503` on failure.
- `nest /api/v1` — management API. `require_auth_middleware` (session
  cookie or `sm_live_` Bearer token) + `csrf_guard_middleware` +
  8 MiB body limit on every request.
- `nest /api/v1/heartbeat` — unauthenticated heartbeat ping endpoint,
  wrapped in a per-IP rate-limit layer.
- `nest /api/v1/auth` — bootstrap, magic-link, sessions, tokens, prefs;
  per-IP rate-limited.
- `nest /api/public/v1` — public, unauthenticated, read-only API;
  per-IP rate-limited.
- `merge /mcp` — MCP JSON-RPC server; no-op when `[mcp].enabled = false`.
- `fallback_service` — `ServeDir::new("target/site")` with SPA fallback
  so client-side routes (`/p`, `/targets`, `/status-pages`, ...) return
  200 instead of 404.

Middleware order (outermost first): `http_metrics` (skips `/healthz` and
`/readyz`) → `TraceLayer` → optional CORS from `[api.cors]`.

### Probe path

```
DuckDB (targets)        Storage::list_targets() — full re-list every 30 s,
   │                    diffed into HashMap<target_id, next_due>.
   ▼
Scheduler              5 s sweep tick: collect every target whose
   │                    next_due <= now, skip disabled, probe sequentially.
   ▼
probe_target           one executor per kind:
   │                    ├── http / tcp / ping (inline in scheduler.rs)
   │                    ├── heartbeat (passive: reads last_ping_at)
   │                    └── dns / tls_cert / domain_expiry / flow →
   │                        CheckStatus::Error, "not supported on the
   │                        control plane; it requires an agent"
   ▼
Storage::record_result direct write to DuckDB check_results (no batcher).
   ▼
incident_writer::      per-probe evaluate_target: ≥ FLAP_THRESHOLD (2)
evaluate_target        consecutive non-Up opens an incident; consecutive
                       Up closes it. Idempotent — one open incident per
                       target. Maintenance windows suppress auto-open.
```

HTTP probes connect fresh every interval (no pool) so each result can
carry per-phase timings (DNS / TCP / TLS) and a stale socket can never
mask a flap. Network probes route through `SsrfGuard::strict` — a target
that resolves to a private IP is dropped before any TCP open.

### Key design choices

- **Sealed secrets.** Channel/variable secrets are AES-256-GCM
  envelope-sealed at the storage edge when `credentials_kek_base64` is
  set; empty KEK is a plaintext dev fallback, malformed KEK fails boot.
- **Idempotent incident writer.** `find_open_incident_for_target`
  guarantees at most one open incident per target, so the per-probe path
  and the 30 s background sweeper never double-open.
- **Cancellation-token shutdown.** A root `CancellationToken` is cloned
  into every worker; SIGINT/SIGTERM cancels it and subsystems drain
  together within a 30 s ceiling.
- **Poolless probe client.** Connecting fresh each interval is what makes
  per-phase timing meaningful and what prevents rebinding through a
  pooled socket.

> Full design notes (data model, concurrency, observability, deployment)
> live in [`docs/architecture.md`](docs/architecture.md).

---

## Quick Start (Demo in ~5 minutes)

The default config boots out of the box: DuckDB writes to
`statuspage.db` in the working directory, the email provider is `log`
(magic-link URLs printed to the console), and the server binds
`127.0.0.1:8081`. No external accounts required.

### 1. Prerequisites

- Rust 1.95+ (edition 2024) via `rustup`.
- [`just`](https://github.com/casey/just) — `brew install just` or
  `cargo install just`.
- `wasm32-unknown-unknown` target and a few dev tools — installed by
  `just setup` (next step).

### 2. One-time setup

```bash
git clone https://github.com/longcipher/statuspage
cd statuspage
just setup        # trunk, cargo-leptos, leptosfmt, rumdl, typos, wasm target, linker
```

### 3. Build the frontend + start the server

```bash
just fe-build     # build WASM + JS glue + Tailwind + Plotly into target/site/
just run          # cargo run -p status-server, binds 127.0.0.1:8081
```

First full build takes 2–3 min (DuckDB bundled + WASM compile from
source). Incremental rebuilds are ~3 s.

### 4. Verify it's up

```bash
just smoke
# or manually:
curl -sS http://localhost:8081/healthz    # 200 ok
curl -sS http://localhost:8081/readyz     # 200 ready
```

Open <http://localhost:8081/> in a browser — the operator dashboard
(Leptos CSR WASM) loads.

### 5. Create the first admin user (bootstrap)

With zero users, the bootstrap endpoint is open. Easiest path is the
UI: visit <http://localhost:8081/>, the frontend calls
`GET /api/v1/auth/bootstrap` and shows the first-user setup form when
`bootstrap_needed` is true. Submit an email + display name → you are
logged in (session cookie `_sm_session` is set).

CLI equivalent:

```bash
curl -sS -X POST http://localhost:8081/api/v1/auth/bootstrap \
  -H 'content-type: application/json' \
  -H 'X-Requested-With: curl' \
  -d '{"email":"admin@example.test","display_name":"Admin"}'
```

### 6. Mint a Bearer API token

In the UI: **Settings → API tokens → Create**. The token format is
`sm_live_…` and is shown once. Or via the API once logged in:

```bash
curl -sS -X POST http://localhost:8081/api/v1/auth/tokens \
  -H 'content-type: application/json' \
  -H 'X-Requested-With: curl' \
  -b 'cookies.txt' \
  -d '{"name":"demo"}'
```

Export it for the next steps:

```bash
export TOKEN=sm_live_…   # paste the value from the previous step
```

### 7. Seed a monitor target

```bash
curl -sS -X POST http://localhost:8081/api/v1/targets \
  -H 'content-type: application/json' \
  -H 'X-Requested-With: curl' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "example.com",
    "check": {
      "type": "http",
      "url": "https://example.com/",
      "method": "GET",
      "timeout": 5000,
      "follow_redirects": false,
      "max_redirects": 0,
      "expected_status": {"kind": "exact", "value": 200},
      "headers": {},
      "verify_tls": true
    },
    "interval": 60,
    "enabled": true,
    "tags": []
  }'
```

Notes:

- `X-Requested-With` is the CSRF guard header. The frontend sets it on
  every mutation; a manual `curl` without it (and without a Bearer token)
  is rejected. With a Bearer token it is optional but harmless.
- The scheduler lists targets every 30 s, so the first probe runs within
  ~30 s of creation. Watch the server logs for the `record_result` line.

### 8. View results

- **Operator dashboard:** <http://localhost:8081/> → targets list, latency
  charts, incident history.
- **Public status JSON:** <http://localhost:8081/api/public/v1/status>
- **Public status page:** <http://localhost:8081/status> (renders once a
  status page is configured and components are bound to it).

That's the demo: a single binary, embedded DB, one monitor up and
reporting, public status surface live.

---

## Demo configuration

The defaults in [`config/default.toml`](config/default.toml) are already a
working demo config — `just run` boots with no edits. The most useful
knobs for a local demo:

```toml
# config/default.toml  (defaults — already demo-ready)

[server]
api_bind = "127.0.0.1:8081"          # loopback only; flip to 0.0.0.0:8081 to expose

[storage]
duckdb_path = "statuspage.db"         # local file; ":memory:" for tests/dev

[scheduler]
enabled = true                        # off = pure dashboard, no probing

[checker]
default_check_interval_secs = 120     # per-target `interval` overrides this
max_concurrent_checks = 1024
default_timeout_ms = 10000

[security]
allow_private_targets = false        # SSRF guard — keep false
credentials_kek_base64 = ""           # empty = plaintext (dev only)

[email]
provider = "log"                     # magic-link URLs printed to console
from_name = "Statuspage"
from_address = "no-reply@example.invalid"

[observability]
log_level = "info"
log_format = "json"                   # pretty for human reading
metrics_enabled = true
tracing_enabled = false               # OTLP off
```

### Override anything via env vars

Every config key is overridable with the `STATUSPAGE_` prefix and `__`
as the nested separator:

```bash
# Bind on all interfaces, use an in-memory DB for a throwaway demo
STATUSPAGE_SERVER__API_BIND=0.0.0.0:8081 \
STATUSPAGE_STORAGE__DUCKDB_PATH=":memory:" \
just run

# Pretty logs for a human-readable demo
RUST_LOG="status_server=debug,common=info,tower_http=info,info" just run
```

`RUST_LOG` always wins over `[observability].log_level`. `STATUSPAGE_CONFIG_PATH`
points at an alternate base config file.

### Generate a KEK (recommended even for dev once you store credentials)

```bash
openssl rand -base64 32
# then either set STATUSPAGE_SECURITY__CREDENTIALS_KEK_BASE64=…
# or paste into [security] credentials_kek_base64
```

Full configuration reference: [`docs/configuration.md`](docs/configuration.md).

---

## Configuration reference (essentials)

| Key | Default | Purpose |
|---|---|---|
| `server.api_bind` | `127.0.0.1:8081` | HTTP listen address |
| `storage.duckdb_path` | `statuspage.db` | DuckDB file path (`:memory:` for tests) |
| `scheduler.enabled` | `true` | Off = pure dashboard, no probing |
| `checker.default_check_interval_secs` | `120` | Fallback interval when target omits one |
| `checker.max_concurrent_checks` | `1024` | In-flight probe cap (memory bulkhead) |
| `security.allow_private_targets` | `false` | SSRF guard — block private/loopback/link-local |
| `security.credentials_kek_base64` | `""` | Base64 AES-256-GCM KEK for sealed credentials |
| `security.trusted_proxies` | `[]` | CIDRs whose `X-Forwarded-For` is honored |
| `email.provider` | `log` | `log` / `resend` / `memory` |
| `auth.enabled_methods` | `[github_oauth, google_oauth, magic_link]` | Sign-in methods |
| `mcp.enabled` | `false` | MCP server at `/mcp` |
| `observability.metrics_enabled` | `true` | Prometheus exporter + OTLP push |
| `observability.tracing_enabled` | `false` | OTLP trace export (also needs `openobserve.enabled`) |

Secrets that must never live in the config file are env-only:
`STATUSPAGE_OPERATOR__ADMIN_TOKEN`, `STATUSPAGE_AGENT__TOKEN`,
`STATUSPAGE_TELEGRAM__*`, `STATUSPAGE_OBSERVABILITY__OPENOBSERVE__API_KEY`,
`STATUSPAGE_AUTH__FINGERPRINT_SALT` (load-bearing — rotation is audited).

---

## Monitor types

| You want to know | Use | In-process? | Min interval |
|---|---|---|---|
| Is my site/API answering correctly | HTTP | yes | 10 s |
| Is this port open | TCP | yes | 10 s |
| Is this host reachable | Ping | yes | 10 s |
| Did my cron/worker run | Heartbeat | yes | 60 s |
| Is my certificate expiring | TLS cert | no (agent-only) | 1 h |
| Is my domain expiring | Domain expiry | no (agent-only) | 1 h |
| Does this name still resolve | DNS | no (agent-only) | 10 s |
| Can a real user still log in | Flow | no (agent-only) | 5 min |

Agent-only kinds are accepted and stored, but every scheduled tick records
`CheckStatus::Error` with `check kind '<k>' is not supported on the
control plane; it requires an agent`. See
[`docs/monitor-types.md`](docs/monitor-types.md).

---

## API

All management endpoints under `/api/v1` require auth (session cookie or
`sm_live_…` Bearer token). Health probes and the public status API are
unauthenticated.

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |
| `GET` | `/api/v1/auth/bootstrap` | Bootstrap status (`bootstrap_needed`) |
| `POST` | `/api/v1/auth/bootstrap` | Create first admin user (409 once any user exists) |
| `POST` | `/api/v1/auth/magic-link/request` | Request magic-link sign-in |
| `POST` | `/api/v1/auth/magic-link/verify` | Verify magic-link token |
| `POST` | `/api/v1/auth/tokens` | Mint a Bearer API token |
| `GET` | `/api/v1/targets` | List monitor targets |
| `POST` | `/api/v1/targets` | Create a monitor target |
| `POST` | `/api/v1/targets/{id}/check-now` | On-demand probe (inline) |
| `POST` | `/api/v1/targets/test` | Ad-hoc test probe (no persistence) |
| `GET` | `/api/v1/targets/{id}/results` | Recent check results |
| `GET` | `/api/v1/status-pages` | List status pages |
| `POST` | `/api/v1/status-pages` | Create a status page |
| `GET` | `/api/v1/status-pages/{id}/history` | Latency history |
| `GET` | `/api/v1/incidents` | List incidents |
| `POST` | `/api/v1/incidents` | Create an incident |
| `POST` | `/api/v1/incidents/{id}/updates` | Add incident update |
| `POST` | `/api/v1/heartbeat/{target_id}` | Passive heartbeat ping (unauthenticated) |
| `GET` | `/api/public/v1/status` | Public status JSON (unauthenticated) |

Full endpoint reference: [`docs/api.md`](docs/api.md).

---

## Development

DuckDB is embedded — no external database to bring up.

```bash
# Hot-reload workflow — run both in separate terminals
just fe-dev       # frontend dev server (http://localhost:3002, proxies /api → :8081)
just run          # backend server (http://localhost:8081)

# Quality gate (run before committing — CI runs `just ci`)
just format       # rumdl + cargo sort + leptosfmt + cargo fmt
just lint         # typos + rumdl + cargo sort -c + fmt-check + leptosfmt + clippy + cargo shear
just test         # cargo test --workspace
just ci           # lint + test + build
```

Run `just` with no args to list all recipes.

### Common recipes

| Recipe | What it does |
|--------|--------------|
| `just setup` | install all dev tools + linker + wasm target |
| `just run` | run the backend on `:8081` |
| `just build` | release build of `status-server` |
| `just check` | `cargo check --workspace` (compile gate) |
| `just fe-dev` | Trunk dev server on `:3002` (hot reload, `/api` proxy) |
| `just fe-build` | release WASM build into `target/site/` |
| `just fe-serve` | serve `target/site/` on `:3002` (after `fe-build`) |
| `just test` | `cargo test --workspace` |
| `just smoke` | curl `/healthz`, `/readyz`, `/api/v1/targets` on `:8081` |
| `just clean` | `cargo sweep --time 0` (reclaim disk) |
| `just docs` | `cargo doc --no-deps --open` |

### Database access

```bash
duckdb statuspage.db     # inspect the embedded DB with the DuckDB CLI
```

Migrations run on startup (`CREATE TABLE IF NOT EXISTS`, idempotent) —
there is no separate migration step. Editing a shipped migration is a
no-op on existing volumes; write a new migration file instead.

Full dev guide: [`docs/development.md`](docs/development.md).

---

## Deployment

Production is a systemd unit behind an `rpxy` reverse proxy (TLS-ALPN-01
ACME, HTTP/2 + HTTP/3), not a container.

```bash
# Build on a build host
just fe-build
cargo build -p status-server --release

# Install on the target host (see deployment/README.md for full steps)
sudo cp target/release/status-server /usr/local/bin/
sudo cp -r target/site config /opt/statuspage/
sudo cp deployment/statuspage.service /etc/systemd/system/
sudo systemctl enable --now statuspage
```

systemd handles SIGTERM, `TimeoutStopSec=30` aligns with the worker drain
ceiling, and `ProtectSystem=strict` / `ProtectHome` / `PrivateTmp` harden
the unit. Backups = copy the single DuckDB file. See
[`deployment/`](deployment/) for unit files, rpxy config, TLS setup, and
the production guide.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `address already in use` on `just run` | A previous `status-server` is still on `:8081`. `pkill status-server` and retry. |
| Frontend loads but API calls return 401 | Not logged in. Run the bootstrap flow or set `Authorization: Bearer sm_live_…`. |
| Frontend loads but API calls fail with CSRF error | Mutation missing `X-Requested-With` header. The frontend sets it; a manual `curl` must add it. |
| Ping checks report `error` on Linux | ICMP socket permission missing. Set `net.ipv4.ping_group_range` to cover the process GID (sysctl, including under systemd) or grant `CAP_NET_RAW`. |
| `trunk serve` can't reach the backend | Backend not running on `:8081`. Start `just run` first. |
| `tls_cert` / `domain_expiry` / `dns` / `flow` monitors always show `error` | Expected — these kinds are agent-only and not executed in-process. |
| WASM build fails with `linking with rust-lld failed` | Stale `target/`. `cargo clean -p status-frontend` and retry; if it persists, `just clean`. |

---

## License

[Apache License 2.0](LICENSE).
