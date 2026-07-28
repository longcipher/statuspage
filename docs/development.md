# Development

Local setup for iterating on the service. For production deployment see
`deployment/README.md` (systemd units + rpxy reverse proxy).

## Prerequisites

- Rust 1.95+ (edition 2024) via `rustup`
- [`just`](https://github.com/casey/just) (`brew install just`) — every workflow
  below has a one-word `just` recipe equivalent. Run `just` (no args) to list
  them.
- `just setup` installs the rest: `cargo-nextest`, `cargo-sweep`, `cargo-sort`,
  `cargo-shear`, `typos-cli`, `rumdl`, `leptosfmt`, `git-cliff`, `cargo-leptos`,
  `trunk`, the `wasm32-unknown-unknown` target, and the linker (`mold` on Linux,
  `lld` opt-in on macOS).

## Workflow

DuckDB is embedded in the process — no external database to bring up. Run the
backend natively:

```bash
just run          # cargo run -p status-server, binds 127.0.0.1:8081
```

`config/default.toml` already points at `statuspage.db` (a local DuckDB file),
so no env overrides are needed. Edit code → Ctrl-C → `just run` again. First
build takes ~2 min; incremental `cargo check --lib` is a few seconds after a
one-file edit.

For hot-reload frontend iteration, run the frontend dev server in a second
terminal — Trunk proxies `/api` to the axum backend on `:8081` (see
`bin/status-frontend/Trunk.toml`):

```bash
# Terminal 1 — backend (http://localhost:8081)
just run

# Terminal 2 — frontend dev server with hot reload (http://localhost:3002)
just fe-dev
```

For a production-shaped build (WASM + JS glue + Tailwind + Plotly.js copied into
`target/site/`), served by the backend itself:

```bash
just fe-build      # cargo-leptos build --frontend-only --release
just run           # backend serves target/site/ at /
```

## Verify it's up

```bash
just smoke         # curls /healthz, /readyz, /api/v1/targets on :8081
# or manually:
curl http://localhost:8081/healthz   # liveness — 200 ok
curl http://localhost:8081/readyz    # readiness — 200 ready / 503 not ready
```

Browse:

- `http://localhost:8081/` — operator dashboard (Leptos CSR WASM)
- `http://localhost:8081/status` — public status page
- `http://localhost:8081/api/v1/...` — management API (see [REST API](api.md))
- `http://localhost:8081/api/public/v1/status` — public status JSON

## First login

The first user is created via the bootstrap endpoint. With the default
`[email].provider = "log"`, magic-link URLs are printed to tracing rather than
sent, so `cargo run` works with no external accounts.

1. Visit `http://localhost:8081/` — the frontend calls
   `GET /api/v1/auth/bootstrap`. When `bootstrap_needed` is true it shows the
   first-user setup form.
2. Submit an email + display name → `POST /api/v1/auth/bootstrap` creates the
   admin user and sets the `_sm_session` cookie (HttpOnly, SameSite=Lax). You
   are now logged in.
3. Subsequent logins use `POST /api/v1/auth/magic-link/request` +
   `POST /api/v1/auth/magic-link/verify`. With `provider = "log"` the magic-link
   token is logged — copy it from the console and submit it in the verify form
   (or `curl` the verify endpoint).

For API/CLI access, mint a Bearer token in the UI (Settings → API tokens) or via
`POST /api/v1/auth/tokens`. The token format is `sm_live_…` (returned once).

## Seed a target

```bash
curl -sS -X POST http://localhost:8081/api/v1/targets \
  -H 'content-type: application/json' \
  -H 'X-Requested-With: curl' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "example",
    "check": {"type":"http","url":"https://example.com/","method":"GET",
              "timeout":5000,"follow_redirects":false,"max_redirects":0,
              "expected_status":{"kind":"exact","value":200},
              "headers":{},"verify_tls":true},
    "interval": 60, "enabled": true, "tags": []
  }'
```

Note the `X-Requested-With` header — the CSRF guard requires it on every
state-changing request from a non-Bearer client. With a Bearer token it is
optional but harmless.

## Database access

The DuckDB file lives at the path configured by `[storage].duckdb_path` (default
`statuspage.db` in the working directory; `:memory:` for tests). Inspect it with
the `duckdb` CLI:

```bash
duckdb statuspage.db
```

Migrations run on startup; there is no separate migration step. Editing a
migration in place is not supported — write a new migration file instead.

## Logging

The default `RUST_LOG` (set by `just run`) is:

```
status_server=debug,common=info,tower_http=info,info
```

Override directly:

```bash
RUST_LOG="status_server=trace,tower_http=info" just run
```

`RUST_LOG` always wins over `[observability].log_level` in the config file.
Under systemd, logs go to journald — view with `journalctl -u statuspage -f`.

## Configuration

`config/default.toml` is the single config source. Override any key via the
`STATUSPAGE_` env prefix (double underscore separates sections, e.g.
`STATUSPAGE_OBSERVABILITY__OPENOBSERVE__API_KEY`). Capabilities that must never
live in the config file (API keys, tokens, KEK) are env-only — see the comments
inline. Full reference: [configuration.md](configuration.md).

## Frontend (Leptos CSR WASM)

The backend serves both the `/api/v1/*` JSON surface and the frontend bundle
(static files + SPA fallback) at `/`. Stack:

- **Leptos CSR** — pure client-side rendering compiled to `wasm32-unknown-unknown`.
  `cargo-leptos` (`--frontend-only`) drives the release build: WASM compilation,
  wasm-bindgen glue generation, JS minification. Source lives in
  `bin/status-frontend/src/` (`api/`, `pages/`, `components/`).
- **Trunk** — dev server with hot reload and a built-in `/api` proxy to the
  axum backend on `:8081` (see `bin/status-frontend/Trunk.toml`).
- **Tailwind CSS v4** — standalone CLI, scans `.rs` sources for class names.
  Source stylesheet: `bin/status-frontend/style/main.css`. Compiled to
  `target/site/style/main.css` by `just fe-build`.
- **Plotly.js** — vendored as `bin/status-frontend/assets/plotly.min.js`,
  copied into `target/site/pkg/` for the latency charts.
- **`index.html`** — bootstrap at `bin/status-frontend/index.html`, copied to
  `target/site/index.html`. Loads the WASM glue + Plotly.

`just fe-build` runs the steps in the right order (cargo-leptos cleans
`site-root`, so Tailwind + asset copies must run **after** the WASM build). The
backend's `ServeDir` serves `target/site/` with an SPA fallback that returns
200 OK so client-side routes (`/p`, `/targets`, `/status-pages`, ...) work
without a 404.

## Tests

```bash
just test          # cargo test --workspace
just test-one status-server --some-filter   # cargo nextest run -p status-server -- ...
just test-coverage # cargo tarpaulin (all features, workspace, 300s timeout)
```

The in-memory storage backend (`storage.duckdb_path = ":memory:"`) is used for
tests — no external services are required. Unit tests are colocated with
implementation (`#[cfg(test)]`); integration tests live in crate-level
`tests/` directories.

## Lints and formatting

```bash
just format   # rumdl fmt, cargo sort, leptosfmt, cargo fmt
just fix      # rumdl check --fix, cargo fmt
just lint     # typos, rumdl, cargo sort -c, cargo fmt --check, leptosfmt --check,
              # cargo clippy --workspace --all-targets -- -D warnings, cargo shear
just check-cn # search for Han characters (English-only requirement)
```

Run `just lint` before committing — CI runs `just ci` (= `lint test build`).

## Faster builds

```bash
just setup     # once: tools + linker (mold on Linux; lld opt-in on macOS)
just check     # cargo check --workspace — the compile gate
```

- **Linker**: `.cargo/config.toml` selects `mold` for Linux targets, so `just`,
  bare `cargo`, and rust-analyzer share one build fingerprint. A Linux build
  needs `mold` installed — `just setup`. macOS is opt-in (`just setup` prints
  the `lld` snippet for `~/.cargo/config.toml`).
- **kache**: `.cargo/config.toml` sets `rustc-wrapper = "kache"`. Useful for
  CI; on macOS it can deadlock the cold lib compile, so prefer incremental for
  local iteration.
- **Incremental**: set `incremental = true` in `~/.cargo/config.toml`
  (machine-scoped) for faster `cargo check --lib`.

## Common recipes

| Recipe | What it does |
|--------|--------------|
| `just setup` | install all dev tools + linker + wasm target |
| `just run` | run the backend on `:8081` |
| `just build` | release build of `status-server` |
| `just check` | `cargo check --workspace` |
| `just fe-dev` | Trunk dev server on `:3002` (hot reload, `/api` proxy) |
| `just fe-build` | release WASM build into `target/site/` |
| `just fe-build-dev` | debug WASM build into `target/site/` |
| `just fe-serve` | serve `target/site/` on `:3002` (after `fe-build`) |
| `just fe-build-wasm` | raw `cargo build -p status-frontend --target wasm32-unknown-unknown --release` (no glue) |
| `just test` | `cargo test --workspace` |
| `just test-coverage` | `cargo tarpaulin` |
| `just format` / `just fix` / `just lint` | formatting + lints |
| `just ci` | `lint test build` (the CI gate) |
| `just smoke` | curl health/ready/targets on `:8081` |
| `just clean` | `cargo sweep --time 0` (reclaim disk) |
| `just docs` | `cargo doc --no-deps --open` |

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `address already in use` on `just run` | A previous `status-server` is still on `:8081`. Stop it (`pkill status-server` or `kill <pid>`) and retry. |
| Frontend loads but API calls 401 | Not logged in. Run the bootstrap flow (see [First login](#first-login)) or set `Authorization: Bearer sm_live_…`. |
| Frontend loads but API calls fail with CSRF error | Browser fetch missing `X-Requested-With` header. The frontend sets it on every request; a stale bundle or a manual `curl` without the header triggers the guard. |
| Ping checks report `error` on Linux | ICMP socket permission missing. Set `net.ipv4.ping_group_range` to cover the process GID (sysctl, including under systemd) or grant `CAP_NET_RAW`. |
| `trunk serve` can't reach the backend | Backend not running on `:8081`, or `Trunk.toml` proxy misconfigured. Start `just run` first. |
| WASM build fails with `linking with rust-lld failed` | Stale `target/`. `cargo clean -p status-frontend` and retry; if it persists, `just clean`. |
| `tls_cert` / `domain_expiry` / `dns` / `flow` monitors always show `error` | Expected — these kinds are agent-only and not executed in-process. See [Monitor types](monitor-types.md). |
