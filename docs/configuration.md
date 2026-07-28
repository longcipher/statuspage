# Configuration

Defaults live in `config/default.toml`. Every key can be overridden by an environment variable using the prefix `STATUSPAGE_` and `__` as the nested separator.

Example: `STATUSPAGE_SERVER__API_BIND=0.0.0.0:8081`

Override `STATUSPAGE_CONFIG_PATH` to point at an alternate base config file.

## Sections

| Section | Key | Purpose |
|---------|-----|---------|
| `server` | `api_bind`, `metrics_bind` | bind addresses for REST API and Prometheus exporter (defaults `127.0.0.1:8081`, `127.0.0.1:9091`) |
| `runtime` | `worker_threads`, `max_blocking_threads` | Tokio runtime sizing (`0` = `num_cpus`) |
| `checker` | `max_concurrent_checks` | in-flight probe cap; each permit is a socket + TLS buffers, so it bounds probe memory |
| `checker` | `default_timeout_ms`, `connect_timeout_ms` | client-side timeouts applied to outbound checks |
| `checker` | `default_check_interval_secs` | fallback interval when target spec omits it |
| `checker` | `per_host_max_inflight`, `rdap_max_inflight` | per-`(host, port)` and per-TLD RDAP concurrency caps. Fail-fast bulkhead — over-cap checks return a `degraded` result instead of queueing |
| `http_client` | `tcp_keepalive_secs`, `user_agent` | per-check connection keep-alive (one request's lifetime — checks connect fresh, no pool) and the outbound `User-Agent`, which defaults to the crate version and only needs setting to override it |
| `dns` | `cache_size`, `positive_ttl_secs`, `negative_ttl_secs`, `servers` | hickory resolver — point at internal resolvers when needed |
| `security` | `allow_private_targets` | SSRF guard: when `false` (default) any target resolving to loopback / private / link-local / reserved IPs is rejected |
| `security` | `credentials_kek_base64` | 32-byte base64 key encrypting `basic_auth` / `bearer_token` / channel secrets / secret variables at rest. Empty (default) stores plaintext — dev only |
| `security` | `trusted_proxies` | CIDR ranges whose `X-Forwarded-For` is honoured for client-IP extraction. Empty means "no reverse proxy — trust the TCP peer" |
| `circuit_breaker` | `failure_threshold`, `success_threshold`, `open_duration_secs`, `half_open_max_calls` | per-host breaker state machine |
| `storage` | `duckdb_path` | DuckDB file path. Use `:memory:` for tests/dev |
| `scheduler` | `enabled` | Off = no in-process probing (pure dashboard); on = this process probes its own region |
| `scheduler` | `target_refresh_interval_secs` | how often the target list is reconciled against storage (default 30) |
| `scheduler` | `region`, `default_region` | this control plane's own region id (default `"default"`) and the region new targets are assigned to (empty falls back to `region`) |
| `observability` | `log_level`, `log_format` | tracing-subscriber filter + JSON vs pretty output (`RUST_LOG` always wins) |
| `observability` | `metrics_enabled`, `gauge_sample_interval_ms` | Prometheus exporter toggle and sampler cadence |
| `observability` | `tracing_enabled` | Master on/off for OTLP trace export. Export is active only when this **and** `observability.openobserve.enabled` are true |
| `observability.openobserve` | `enabled`, `otlp_endpoint`, `instance_id`, `api_key`, `trace_sample_ratio` | OTLP/HTTP trace export to OpenObserve / any OTLP collector. `api_key` is env-only. See [Trace export](#trace-export) below |
| `observability.heartbeat` | `enabled`, `url`, `interval_seconds` | External dead-man's-switch. `url` is env-only (`STATUSPAGE_OBSERVABILITY__HEARTBEAT__URL`) |
| `notifications.slack` | `enabled`, `webhook_url` | Outbound Slack webhook for legacy global notifier. Per-target channels are managed via the API |
| `notifications.webhook` | `enabled`, `url` | Outbound generic webhook for legacy global notifier |
| `notifications.email` | `enabled`, `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `from`, `starttls` | Outbound alert SMTP channel for legacy global notifier |
| `api.cors` | `enabled`, `allowed_origins`, `allowed_methods`, `allow_any_origin` | browser CORS for `/api/v1/*`. Disabled by default. Wildcard only via `allow_any_origin = true` |
| `tenancy` | `path_based_public_routes`, `subdomain_public_routes`, `free_tier_owner_org_limit`, `deletion_grace_period_days` | Public-status routing shape + grace. See [Public status routing](#public-status-routing) below |
| `retention` | `check_results_days`, `api_tokens_post_expiry_days` | Long-horizon data-retention windows for the periodic 6h purge job |
| `public_status` | `base_domain`, `cache_max_orgs`, `cache_ttl_secs`, `last_good_ttl_secs`, `logo_dir`, `max_logo_size_bytes`, `allowed_logo_mime_types`, `max_logo_dimension_px`, `default_brand_color`, `default_show_powered_by`, `public_per_ip_rate_limit_per_min` | Public status page surface. See [Public status page](#public-status-page) below |
| `email` | `provider`, `from_name`, `from_address` | Transactional email backend. `provider` ∈ `"resend" \| "log" \| "memory"` |
| `email.resend` | `api_key` | Required when `email.provider = "resend"` |
| `auth` | `enabled_methods`, `fingerprint_salt` | Sign-in methods + HMAC salt for IP/UA hashes. See [Auth configuration](#auth-configuration) below |
| `auth.session` | `idle_timeout_days`, `absolute_timeout_days`, `cookie_name`, `cookie_secure`, `cookie_domain`, `renew_on_use` | Session cookie shape + lifetime. `cookie_secure = true` in production |
| `auth.github` | `client_id`, `client_secret`, `redirect_url`, `scopes` | GitHub OAuth client. The button renders on `/login` only when client_id, client_secret, and redirect_url are all set |
| `auth.google` | `client_id`, `client_secret`, `redirect_url`, `scopes` | Google OAuth client, same gating as `auth.github`. Email is trusted only with Google's `email_verified` attestation |
| `auth.invitations` | `expiry_hours` | Invitation lifetime |
| `auth.api_tokens` | `prefix_visible_chars` | Indexed prefix length for token lookup (floor 16) |
| `auth.magic_link` | `expiry_minutes`, `rate_limit_seconds` | Magic-link token lifetime. Routes only mount when `enabled_methods` includes `"magic_link"` |
| `quotas` | `plan_cache_ttl_secs`, `usage_cache_ttl_secs` | Cache TTLs for plan / usage lookups |
| `rate_limits.per_ip` | `public_pages_per_min`, `auth_endpoints_per_min`, `org_creations_per_day`, `heartbeat_per_ip_per_min` | In-process per-IP limits. The reverse proxy enforces its own in front |
| `rate_limits.janitor` | `cleanup_interval_hours`, `idle_threshold_hours` | Janitor cadence for evicting idle per-IP buckets |
| `marketing` | `enabled`, `app_url`, `canonical_origin`, `reserved_subdomains`, `blog_enabled` | Inert in this build — no marketing module is compiled in |
| `mcp` | `enabled`, `allowed_origins` | LLM connector (MCP) server at `/mcp`. Off by default. See [Architecture](architecture.md) |
| `escalation` | `enabled`, `tick_interval_secs`, `max_pages_per_tick`, `max_attempts` | Escalation engine. Off by default; the per-target notifier still runs |
| `agent` | `enabled`, `control_plane_url`, `region`, `pull_interval_secs`, `flush_interval_secs`, `buffer_capacity` | Inert in this build — no agent entry point is compiled in. `token` is **env-only** (`STATUSPAGE_AGENT__TOKEN`) |
| `operator` | `admin_token` | Static bearer secret for the instance-admin `/operator/*` surface. **Env-only** (`STATUSPAGE_OPERATOR__ADMIN_TOKEN`); empty disables the surface (404s) |
| `telegram` | `bot_token`, `bot_username`, `webhook_secret` | Operator-owned central Telegram bot. All three are env-only (`STATUSPAGE_TELEGRAM__*`); empty leaves the feature absent |

## Public status routing

StatusPage is a single-user self-hosted deploy: there is one operator and the public status surface lives on the operator host. The `[tenancy]` section configures which routing shape the public surface uses — both flags exist, but only path-based routing is used in this build.

- `tenancy.path_based_public_routes` — serve `/p` and `/api/public/v1/*` on the operator host. Defaults to `true`. This is the only mode used in this build.
- `tenancy.subdomain_public_routes` — serve one page per org at `{slug}.{public_status.base_domain}` (apex wildcard). Defaults to `false`. **Inert in this build** — the dispatcher is path-based only.
- `free_tier_owner_org_limit` — kept for forward compatibility; not enforced in single-user mode.
- `deletion_grace_period_days` (default `30`) — how long a soft-deleted user is held and how long the original deleter has to restore it. The cleanup worker hard-purges past-grace users.

The `[retention]` section sets the long-horizon windows. Defaults: `check_results_days = 30`, `api_tokens_post_expiry_days = 30`. The periodic cleanup worker runs every 6h and enforces these windows alongside its other sweeps (terminal deliveries, unverified subscribers, expired sessions, expired magic links). Session idle/absolute reaping uses `[auth.session]`; soft-deleted user grace uses `tenancy.deletion_grace_period_days`.

## Auth configuration

```toml
[auth]
enabled_methods = ["github_oauth", "google_oauth", "magic_link"]
fingerprint_salt = ""                # HMAC salt for IP/UA hashes; rotate-aware

[auth.session]
idle_timeout_days = 30
absolute_timeout_days = 90
cookie_name = "_sm_session"
cookie_secure = true                 # set false only for plain-HTTP local dev
cookie_domain = ""                   # empty = host-only cookie
renew_on_use = true

[auth.github]
client_id = ""                       # from https://github.com/settings/developers
client_secret = ""
redirect_url = "https://status.example.test/auth/github/callback"
scopes = ["user:email", "read:user"]

[auth.google]
client_id = ""                       # Google Cloud Console OAuth web client
client_secret = ""
redirect_url = "https://status.example.test/auth/google/callback"
scopes = ["openid", "email", "profile"]

[auth.invitations]
expiry_hours = 168                   # 7 days

[auth.api_tokens]
prefix_visible_chars = 16            # floor; lower values fail boot

[auth.magic_link]
expiry_minutes = 15
rate_limit_seconds = 60                # per-email send throttle; 0 disables

[email]
provider = "log"                     # "resend" in prod, "log" in dev, "memory" in tests
from_name = "Statuspage"
from_address = "no-reply@example.invalid"

[email.resend]
api_key = ""                         # required when provider = "resend"
```

`auth.enabled_methods` is the policy switch per sign-in method: removing an entry disables that method's login start/callback (404) and hides its button. OAuth providers additionally need `client_id` + `client_secret` + `redirect_url` set — a listed but incompletely configured provider stays hidden and logs a warning on probe. `"magic_link"` mounts the magic-link request/verify endpoints and the login-page email form.

The bootstrap endpoint (`POST /api/v1/auth/bootstrap`) creates the first user when zero users exist; afterwards it returns 409. Bootstrap also opens a session for the new user.

`auth.fingerprint_salt` is paired with the `auth_salt_history` table. Rotating the value mid-deployment refuses to boot unless the override env var `STATUSPAGE_AUTH_ACCEPT_SALT_ROTATION=1` is set — this is deliberate so audit-trail breakage is loud.

## Central Telegram bot

```toml
[telegram]
bot_token = ""            # env STATUSPAGE_TELEGRAM__BOT_TOKEN; presence enables the feature
bot_username = ""         # verified against the Bot API at boot; used for t.me deep links
webhook_secret = ""       # random, 32+ chars; Telegram echoes it on every webhook delivery
```

Setting `bot_token` switches on one-tap Telegram channel linking: the type card in the channel form, the link-code API, and the `/hooks/telegram` receiver. Empty token (the default) leaves the feature absent entirely — self-host deployments keep the bring-your-own `telegram` transport, which needs no operator config.

When enabled, boot validates the trio: non-empty `bot_username`, `webhook_secret` of 32+ characters, and an `https://` `auth.public_base_url` (Telegram only delivers webhooks to public https endpoints). The app then verifies the token against the Bot API and registers the webhook on every boot; a Telegram outage logs a warning and disables the bot for that boot instead of failing the deploy.

All three values are operator secrets: env-only in production, never in a committed config file.

## Public status page

The `[public_status]` block configures the public surface. The defaults are safe to leave untouched for self-host (path-based routing on the operator host).

```toml
[public_status]
base_domain = ""                       # required when subdomain_public_routes = true; inert otherwise
cache_max_orgs = 1000                  # hot + last-good cache bound
cache_ttl_secs = 10                    # per-page rendered-page TTL
last_good_ttl_secs = 3600              # idle eviction for the stale-fallback layer
logo_dir = "/var/lib/statuspage/logos"
max_logo_size_bytes = 1048576          # 1 MiB byte ceiling (pre-decode)
allowed_logo_mime_types = ["image/png", "image/jpeg", "image/webp"]
max_logo_dimension_px = 1200           # larger uploads are downscaled; decode
                                       # is also allocation-bounded (bomb guard)
default_brand_color = "#3b82f6"        # used when a page sets no colour
default_show_powered_by = true
public_per_ip_rate_limit_per_min = 60  # in-app limit behind the reverse-proxy one
```

| Key | Purpose |
|---|---|
| `base_domain` | parent domain for `{slug}.{base_domain}`. Required when `subdomain_public_routes = true`; inert otherwise |
| `cache_max_orgs` / `cache_ttl_secs` | page cache size and freshness window |
| `last_good_ttl_secs` | how long an idle page's last-known-good snapshot is retained before eviction |
| `logo_dir`, `max_logo_size_bytes`, `allowed_logo_mime_types`, `max_logo_dimension_px` | logo upload storage and limits |
| `default_brand_color`, `default_show_powered_by` | fallbacks when a page leaves branding unset |
| `public_per_ip_rate_limit_per_min` | second-layer rate limit behind the reverse proxy's |

History-strip length (90 days) and the recent-incidents horizon (30 days) are hard-coded defaults in the public-status aggregator. What a page publishes is curated per-page — a monitor appears as a component only while it's bound to that page, and its presentation lives on the binding:

| Per-page component field | Purpose |
|---|---|
| (binding exists) | the monitor is published as a component on that page |
| `public_name` | display name (falls back to operator-side monitor name) |
| `public_description` | optional one-liner |
| `public_group` | optional group label; ungrouped components render last |
| `sort_order` | ASC integer sort within a group |

## Trace export

OpenTelemetry spans are exported over OTLP/HTTP (protobuf) when **both** `observability.tracing_enabled` and `observability.openobserve.enabled` are `true`. Disabled by default and zero-cost when off.

```toml
[observability]
tracing_enabled = false                # master on/off for trace export

[observability.openobserve]
enabled = false                        # second switch; both must be true
otlp_endpoint = ""                     # OTLP base, no /v1/traces suffix; e.g.
                                       # http://localhost:5080/api/default
instance_id = ""                       # OpenObserve instance / stream id
trace_sample_ratio = 1.0               # parent-based head sampling, [0.0, 1.0]
# api_key                              # NEVER in TOML — env var only (below)
```

| Key | Purpose |
|---|---|
| `tracing_enabled` | master switch; with `openobserve.enabled` gates all export |
| `openobserve.enabled` | second switch (kept separate so the block is inert until explicitly turned on) |
| `openobserve.otlp_endpoint` | OTLP/HTTP **base** URL; the service appends `/v1/traces` (a value already ending in it is left as-is). Empty fails boot when export is on |
| `openobserve.instance_id` | basic-auth username (OpenObserve instance id). Empty fails boot when export is on |
| `openobserve.api_key` | basic-auth password. **Env-only**: `STATUSPAGE_OBSERVABILITY__OPENOBSERVE__API_KEY`. Never read from a config file; redacted in any serialised config |
| `openobserve.trace_sample_ratio` | head sampling ratio under a parent-based sampler. Must be in `[0.0, 1.0]` or boot fails |

Auth is `Authorization: Basic base64(instance_id:api_key)`. Resource attributes `service.name = statuspage` and `service.version` are attached. The batch exporter is flushed and stopped on graceful shutdown. A transport build failure logs a warning and the service continues without traces — telemetry never takes down monitoring. Inconsistent settings (export on with a missing endpoint / instance / key, or an out-of-range ratio) are a clean startup config error.

## Tuning notes

- **`max_concurrent_checks`** caps simultaneous in-flight checks. Per-check memory is small (a tokio task plus an in-flight hyper request), so the practical ceiling is set by file descriptors and ephemeral ports rather than RAM.
- **`per_host_max_inflight`** (default `2`) is the per-`(host, port)` in-flight cap. A burst of checks at the same upstream looks like a probe; this cap keeps that fingerprint flat. Fail-fast: a check that would exceed the cap is recorded as `degraded` with `error="throttled: host concurrency cap"` and skipped (no alert fired — the upstream is fine, the back-pressure is operator-side). Counters: `statuspage_host_throttle_waits_total{kind="host"}` (attempts) and `statuspage_host_throttle_drops_total` (rejections).
- **`rdap_max_inflight`** (default `1`) is the process-wide per-TLD registry-lookup concurrency cap, covering RDAP and the WHOIS fallback. Daily check cadence + per-TLD slot means deep queues drain quickly without bursting any registry. Same fail-fast behavior + counters as the per-host cap.
- **`dns.servers`** accepts either bare IPs (`"1.1.1.1"`) or `ip:port` form. Used as is — no system resolver fallback.
- **`security.allow_private_targets`** is the SSRF guard. Default `false` blocks:
  - Loopback (`127.0.0.0/8`, `::1`)
  - RFC1918 private (`10/8`, `172.16/12`, `192.168/16`)
  - Link-local (`169.254/16`, `fe80::/10`) — covers AWS/GCP metadata `169.254.169.254`
  - Carrier-grade NAT (`100.64/10`)
  - IPv6 ULA (`fc00::/7`), discard, IPv4-mapped private, documentation ranges
  - Multicast, broadcast, unspecified, reserved-for-future-use
  - IPv6 transition mechanisms: `2002::/16` (6to4) and `64:ff9b::/96` (NAT64) are decoded to their embedded IPv4 and rejected when the inner IPv4 falls in any blocked range
  The guard runs both at API submission (rejects IP-literal URLs synchronously) and after DNS resolution at connect time (catches DNS rebinding). Flip to `true` for internal monitoring where private targets are the goal — operators are then responsible for network segmentation.
- **`security.credentials_kek_base64`** enables AES-256-GCM encryption of HTTP `basic_auth` and `bearer_token` values, notification channel secrets, and secret variable values. Generate with `openssl rand -base64 32`. Each write produces a fresh 12-byte random nonce; the on-disk shape is `{"$enc":"v1:<nonce>:<ciphertext>"}`. When the key is unset the service logs a startup warning and stores credentials plaintext (dev-friendly upgrade path — existing plaintext rows continue to read after a key is provisioned). Rotation and KMS integration are out of scope for the current version; treat the KEK as long-lived and protect it via your secret-management of choice (env file with restricted mode, systemd credential, etc.). A malformed KEK fails the process at startup.
- **`api.cors`** opens `/api/v1/*` to browser-origin access. Each entry in `allowed_origins` must be a full origin (`https://app.example.com`) — wildcards are not parsed; set `allow_any_origin = true` to send `Access-Control-Allow-Origin: *` explicitly. The two are mutually exclusive — combining them or enabling CORS with an empty list aborts startup. `allowed_methods` is echoed in the preflight response (`Access-Control-Allow-Methods`); `Access-Control-Allow-Headers` is fixed to `content-type`, `authorization`, `x-requested-with`, `idempotency-key`, which is what the JSON API needs. `/healthz` and `/readyz` are not wrapped, so liveness probes are unaffected.
