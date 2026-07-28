# REST API

Mounted under `/api/v1` on the configured API bind (`server.api_bind`, default
`127.0.0.1:8081`). JSON in, JSON out. Every `/api/v1/*` endpoint is
authenticated; the health probes and the public surface are the exceptions.

All responses use `Content-Type: application/json; charset=utf-8`.

## Authentication

Two credentials are accepted on `/api/v1/*`:

- **Session cookie** — set by `POST /api/v1/auth/bootstrap` or
  `POST /api/v1/auth/magic-link/verify`. Cookie name is `_sm_session`
  (configurable via `[auth.session].cookie_name`). `HttpOnly`, `SameSite=Lax`,
  90-day `Max-Age`, `Secure` when `cookie_secure = true`.
- **Bearer API token** — `Authorization: Bearer sm_live_…`. Token format is
  `sm_live_` + 32 random bytes base64url-no-pad (51 chars total). The DB stores
  an argon2id hash; the raw token is returned **once** at creation and is
  unrecoverable. Mint and revoke via `/api/v1/auth/tokens`.

A CSRF guard runs on every state-changing request (POST/PATCH/DELETE/PUT) under
`/api/v1/*` and `/api/v1/auth/*`: browser sessions must send the
`X-Requested-With` header (the frontend sets it on every fetch), and Bearer
clients are admitted via the `Authorization` header. GET/HEAD pass through.

## Endpoints

### Health (open)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | liveness — always `200 ok` once the process is up |
| `GET` | `/readyz` | readiness — `200 ready` after a storage `SELECT 1`; `503` with the error on failure |

### Management API (`/api/v1/*` — authenticated)

Every route below sits behind `require_auth_middleware` + `csrf_guard_middleware`

- an 8 MiB `RequestBodyLimitLayer`.

#### Targets

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/targets` | list targets (`tag`, `group`, `enabled`, `status` filters, all optional, AND semantics) |
| `POST` | `/targets` | create one target (201) |
| `GET` | `/targets/{id}` | one target |
| `PATCH` | `/targets/{id}` | partial update (name, check, interval, enabled, tags, alerts, group, owner, escalation policy) |
| `DELETE` | `/targets/{id}` | delete (204) |
| `GET` | `/targets/{id}/results?limit=N` | recent check results, newest-first (default 100, cap 1000) |
| `POST` | `/targets/{id}/check-now` | run an immediate probe using stored credentials, persist the result, return it |
| `POST` | `/targets/test` | dry-run a `CheckSpec` without persisting (heartbeat/domain_expiry → `400 NOT_TESTABLE`; agent-only kinds → `400 NOT_SUPPORTED_ON_CONTROL_PLANE`) |
| `POST` | `/targets/bulk` | create up to 200 targets; per-item failures collected, supports `Idempotency-Key` |
| `POST` | `/targets/bulk/action` | enable/disable/delete up to 500 ids; supports `Idempotency-Key` |

#### Status pages & components

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/status-pages` | list pages |
| `POST` | `/status-pages` | create a page (201) |
| `GET` | `/status-pages/{id}` | one page |
| `PATCH` | `/status-pages/{id}` | rename, change slug, enable/disable, branding |
| `DELETE` | `/status-pages/{id}` | delete (204) |
| `GET` | `/status-pages/{id}/history` | `(iso8601 ts, duration_ms)` series, ascending |
| `GET` | `/status-pages/{id}/components` | components curated onto the page |
| `POST` | `/status-pages/{id}/components` | add a monitor (201) |
| `PATCH` | `/status-pages/{id}/components/{target_id}` | per-page `public_name` / `public_description` / `public_group` / `sort_order` |
| `DELETE` | `/status-pages/{id}/components/{target_id}` | remove (204) |
| `POST` | `/status-pages/{id}/components/reorder` | body `{ "target_ids": [...] }`, rewrites each `sort_order` to its index |

#### Incidents & postmortems

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/incidents` | list incidents |
| `POST` | `/incidents` | open a manual incident (201) |
| `GET` | `/incidents/{id}` | one incident |
| `PATCH` | `/incidents/{id}` | update severity / status / `ended_at` / narration |
| `POST` | `/incidents/{id}/updates` | append a timeline update (`phase`, `message`) |

Postmortem and silence-rule routes are merged from their own modules in the
same way; see `bin/status-server/src/api/postmortems.rs` and `silence_rules.rs`
for the exact paths.

#### Maintenance, channels, schedules, variables, shares, assets

The following subsystems are each mounted via `merge(...)` from
`bin/status-server/src/api/`:

- `maintenance.rs` — schedule/list/edit/cancel maintenance windows
- `notification_channels.rs` — CRUD + test for delivery channels (slack,
  webhook, email, discord, msteams, google_chat, telegram, whatsapp, pagerduty,
  ntfy, pushover, sms) + email verification flow
- `escalation_policies.rs`, `on_call_schedules.rs` — escalation ladders and
  on-call rotations (gated by `[escalation].enabled`)
- `subscribers.rs` — public status page email subscribers
- `variables.rs` — reusable named values referenced as `{{key}}` in HTTP check
  fields; secret variables sealed at rest and write-only on read
- `share_links.rs` — capability-URL share links for a single monitor
- `page_assets.rs` — logo upload (multipart) for status pages
- `silence_rules.rs` — silence rules

#### Account export & metrics

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/export/account` | full configuration dump (targets, pages, components, incidents, maintenance, channels, silence rules) as JSON; time-series results excluded |
| `GET` | `/metrics` | small bounded Prometheus exposition (target/incident gauges) on the API port |

The canonical Prometheus scrape target is the separate exporter on
`server.metrics_bind` (default `127.0.0.1:9091`); `/api/v1/metrics` covers
ad-hoc same-port scrapes.

### Auth API (`/api/v1/auth/*` — rate-limited per-IP)

Mounted as a sibling nest so the whole subtree shares one per-IP rate-limit
bucket. Bootstrap and magic-link request/verify are unauthenticated; the rest
require a session or Bearer token.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/bootstrap` | `{ "bootstrap_needed": bool }` — first-user setup still available? |
| `POST` | `/bootstrap` | create the first admin user + open a session (409 once any user exists) |
| `POST` | `/magic-link/request` | request a magic-link email (always 202, anti-enum) |
| `POST` | `/magic-link/verify` | consume a token, open a session, set the cookie |
| `GET` | `/session` | current user + session marker |
| `DELETE` | `/session` | log out, clear cookie (204) |
| `GET` | `/sessions` | list the current user's active sessions |
| `DELETE` | `/sessions/{id_hash}` | revoke another session |
| `GET` | `/tokens` | list the user's API tokens (safe fields only) |
| `POST` | `/tokens` | create a token — raw token returned once (201) |
| `GET` | `/tokens/{id}` | one token's safe info |
| `PATCH` | `/tokens/{id}` | rename (scopes and expiry immutable; rotate by delete + create) |
| `DELETE` | `/tokens/{id}` | delete a token (204, idempotent) |
| `GET` | `/me` | profile + preferences |
| `PATCH` | `/me` | update `display_name` / `theme` / `time_format` |

### Heartbeat (`/api/v1/heartbeat/{target_id}` — unauthenticated)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/heartbeat/{target_id}` | record a heartbeat ping for the target |

Mounted as a separate nest with its own per-IP rate-limit layer
(`[rate_limits.per_ip].heartbeat_per_ip_per_min`, default 30). The `target_id`
UUID (122 bits of entropy) is the shared secret — operators treat the ping URL
as a capability token. A non-heartbeat target returns `400 NOT_HEARTBEAT_TARGET`.

### Public API (`/api/public/v1/*` — unauthenticated, read-only)

Rate-limited per-IP (`[public_status].public_per_ip_rate_limit_per_min`,
default 60). Wire types cannot serialise sensitive target fields (`url`,
`headers`, `basic_auth`, `bearer_token`).

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/status?page={id}` | overall status + component breakdown + 90-day day-strip per component; first enabled page when `?page` omitted |
| `GET` | `/incidents` | recent public incidents |
| `GET` | `/incidents/{id}` | one public incident with its update timeline |
| `GET` | `/incidents.rss` | RSS 2.0 feed (`application/rss+xml`) |
| `GET` | `/components/{id}/history` | 90-day day-strip history for one component (target id) |
| `GET` | `/maintenance` | active + upcoming maintenance windows |
| `GET` | `/badge.svg?type=status\|uptime` | shields.io-style SVG badge |
| `POST` | `/subscribers/{subscriber_id}/unsubscribe` | one-click unsubscribe (204 / 404) |
| `GET` | `/notification-channels/verify?token=…` | confirm an email channel (single-use bearer) |
| `GET` | `/notification-channels/decline?token=…` | refuse an email channel |
| `GET` | `/shared/{token}` | read-only shared monitor view (token = 32 random bytes base64url, hashed at rest) |
| `GET` | `/pages/{id}/assets/{slot}` | public page asset (logo); 404 if page disabled or slot empty |

### MCP (`/mcp` — optional, authenticated)

JSON-RPC 2.0 over HTTP. Off by default; flip `[mcp].enabled = true` to expose
MCP tools to LLM clients. Auth reuses the session cookie or Bearer API token.
`allowed_origins` is an RFC 6454 Origin allow-list (DNS-rebinding defense);
empty disables the check.

## Check specs

Tagged enum, `type` discriminator. Eight variants are defined; **four run
in-process** on the control plane (`http`, `tcp`, `ping`, `heartbeat`) and
**four are agent-only** (`dns`, `tls_cert`, `domain_expiry`, `flow`) — they are
accepted at create/update time but the scheduler and `POST /targets/test`
reject them with `check kind '<k>' is not supported on the control plane; it
requires an agent`. There is no agent runtime in this deployment, so the four
agent-only kinds record `CheckStatus::Error` on every tick. See
[Monitor types](monitor-types.md) for which to reach for.

### HTTP

```jsonc
{
  "type": "http",
  "url": "https://example.com/healthz",
  "method": "GET",
  "timeout": 5000,                              // ms, total request budget
  "follow_redirects": false,
  "max_redirects": 0,                           // cap 10
  "expected_status": { "kind": "exact", "value": 200 },
  "expected_body_contains": null,               // optional substring match
  "headers": {},
  "body": null,
  "verify_tls": true,
  "basic_auth": null,                           // ["user", "pass"] or null
  "bearer_token": null
}
```

`url`, `headers`, `body`, and `expected_body_contains` may carry `{{key}}`
references to [variables](#variables) resolved before the check runs. A secret
variable is allowed only in a header value or the body.

`expected_status` variants:

```jsonc
{ "kind": "exact", "value": 200 }
{ "kind": "range", "value": { "min": 200, "max": 299 } }
{ "kind": "one_of", "value": [200, 204] }
```

#### Credential redaction

`GET`/`POST`/`PATCH`/`bulk` responses replace populated `basic_auth` /
`bearer_token` fields with the sentinel `"***"`. A `null` field stays `null`.
When you `PATCH` a target's `check`, re-supply the real credential — a body
containing `"***"` is rejected with `400 REDACTION_SENTINEL`. If you only need
to change other fields, omit `check` from the `PATCH` body. Encryption at rest
is gated on `[security].credentials_kek_base64`; the redaction behaviour applies
in either mode.

#### Rate-limited responses

A `429` or `503` is recorded as `degraded`, not `down` — the upstream is
answering and asking us to back off. A check that explicitly accepts 429/503
via `expected_status` is honoured first and stays `up`.

#### Per-host throttle

In-flight checks against the same `(host, port)` are capped
(`[checker].per_host_max_inflight`, default 2). An over-cap tick is **dropped**:
no `CheckResult` is written, so it never counts as a failure and never alerts.

### TCP

```jsonc
{ "type": "tcp", "host": "db.internal", "port": 5432, "timeout": 2000 }
```

### Ping (ICMP)

```jsonc
{ "type": "ping", "host": "gateway.internal", "timeout": 3000 }
```

Sends one ICMP echo per resolved (SSRF-filtered) address until a reply arrives;
the round-trip time is recorded as `duration_ms`. Silence for the full timeout
is `down`. The probe opens an unprivileged `SOCK_DGRAM` ICMP socket, so on
Linux the process needs `net.ipv4.ping_group_range` to cover its GID
(configure via sysctl, including under systemd) or `CAP_NET_RAW`; without
either, ping checks report `error`.

### Heartbeat (inbound dead-man's-switch)

```jsonc
{ "type": "heartbeat", "period": 300000, "grace": 60000 }
```

Reverses the direction: your system pings the platform. Creating a heartbeat
monitor mints a capability URL `POST /api/v1/heartbeat/{target_id}`; call it at
the end of each successful run (e.g. `curl -fsS $URL` from cron). The scheduler
compares the age of the last ping against `period + grace` (both ms): inside
the window the monitor is `up`, past it the monitor goes `down` through the
normal incident pipeline. A fresh or newly re-enabled monitor gets a full
`period + grace` before it can go down. Heartbeats never run on regional
probes and reject `test`/`check-now` (`NOT_TESTABLE`).

### DNS (agent-only — not supported in-process)

```jsonc
{
  "type": "dns",
  "domain": "api.example.com",
  "record_type": "A",
  "resolver": "1.1.1.1",            // optional; ip or ip:port
  "expected_contains": "192.0.2.1", // optional substring match
  "timeout": 3000
}
```

`record_type` is one of `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`, `PTR`,
`CAA`, `SRV`. The spec is accepted and stored, but every tick records
`CheckStatus::Error` with `check kind 'dns' is not supported on the control
plane; it requires an agent`.

### TLS certificate expiry (agent-only — not supported in-process)

```jsonc
{
  "type": "tls_cert",
  "host": "example.com",
  "port": 443,
  "server_name": null,         // optional SNI override; defaults to host
  "warn_days": 14,
  "critical_days": 7,
  "timeout": 5000
}
```

`warn_days` must be strictly greater than `critical_days`. Stored but not
executed in-process — every tick records `CheckStatus::Error`.

### Domain expiration (agent-only — not supported in-process)

```jsonc
{
  "type": "domain_expiry",
  "domain": "example.com",
  "warn_days": 30,
  "critical_days": 7,
  "timeout": 10000
}
```

Queries RDAP for the registry expiration date. `warn_days` must be strictly
greater than `critical_days`. Stored but not executed in-process — every tick
records `CheckStatus::Error`. Also rejected by `POST /targets/test` with
`NOT_TESTABLE` (needs cached RDAP state).

### Flow (agent-only — not supported in-process)

```jsonc
{
  "type": "flow",
  "start_url": "https://app.example.com/login",
  "steps": [
    { "op": "fill",        "selector": "#username", "value": "monitor@example.com" },
    { "op": "fill",        "selector": "#password", "value": "{{login_password}}" },
    { "op": "click",       "selector": "button[type=submit]" },
    { "op": "assert_url",  "contains": "/dashboard" },
    { "op": "assert_text", "selector": null, "contains": "Signed in" }
  ],
  "timeout": 30000,        // whole-run budget, 1000..=120000 ms
  "step_timeout": 5000,    // per-step wait for a selector, 100..=60000 ms
  "verify_tls": true
}
```

Drives a headless browser through the step sequence. Steps: `goto`, `fill`,
`click`, `wait_for`, `assert_text`, `assert_url`. At least one `assert_*` step
is required. Up to 30 steps (`FlowCheck::MAX_STEPS`). `fill.value` may carry a
`{{secret}}` reference resolved at probe time. Stored but not executed
in-process — every tick records `CheckStatus::Error`.

## Target payload

```jsonc
{
  "name": "internal-api",
  "check": { /* check spec */ },
  "interval": 60,             // seconds between ticks; floor is
                              // max(kind_min, ...) — see below.
  "enabled": true,
  "tags": ["prod", "tier1"],
  "group_name": null,         // optional grouping for the dashboard
  "alerts": [ /* optional channel bindings */ ],
  "alert_confirmations": 2,   // consecutive failures before an incident opens
  "notify_recovery": true,
  "renotify_interval_secs": 3600,
  "region_policy": "majority", // "any" | "majority" | "all" | { "count": N }
  "owner_user_id": null,
  "escalation_policy_id": null
}
```

Server returns the full `Target` including `id` (UUIDv7), `created_at`,
`updated_at`, and `write_source`.

### Interval floor by kind

`min_interval_secs_for_kind` enforces a per-kind floor:

| Kind | Floor |
|------|-------|
| `http`, `tcp`, `ping`, `dns` | 10 seconds |
| `heartbeat` | 60 seconds (evaluation cadence) |
| `flow` | 300 seconds |
| `tls_cert`, `domain_expiry` | 3600 seconds |

### Alert config

`alerts` is an optional array of `{ "channel_id": <uuid> }` bindings to
notification channels. An empty/omitted array disables channel alerting for
that target (incidents still open and show on status pages).

- `alert_confirmations` — consecutive failing checks before an incident opens
  (and the same number of passing checks before it closes). Default `2`, must
  be `>= 1`.
- `notify_recovery` — when `true` (default), recovery is announced to the
  monitor's channels.
- `renotify_interval_secs` — seconds between reminder notifications while an
  outage stays unacknowledged. `0` disables reminders; otherwise `>= 60`.
  Default `3600`.
- `region_policy` — how many probe regions must agree the target is down
  before an incident opens: `"any"`, `"majority"` (default), `"all"`, or
  `{ "count": N }`.

Notifications are driven by the incident engine: one notification per incident
open (then reminders per `renotify_interval_secs`), one on recovery.

## Variables

A variable is a reusable named value referenced as `{{key}}` in HTTP check
fields (`url`, `headers`, `body`, `expected_body_contains`); the reference
resolves to the value before a check runs. A secret variable's value is sealed
at rest (AES-256-GCM under the credentials KEK) and write-only: every read path
returns `value: null` for it.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/variables` | list variables (each with `used_by` count) |
| `GET` | `/variables/{id}` | one variable with its `used_by` |
| `POST` | `/variables` | create; body `{ "key", "is_secret"?, "value" }` |
| `PATCH` | `/variables/{id}` | rotate the value; body `{ "value" }` |
| `DELETE` | `/variables/{id}` | delete; `409 VARIABLE_IN_USE` while a monitor references it |

A key must match `^[a-z][a-z0-9_]{0,62}$` (`400 INVALID_VARIABLE_KEY`); a
duplicate key is `409 VARIABLE_KEY_EXISTS`. The `is_secret` flag is fixed at
create. A monitor whose `{{key}}` references do not all resolve is rejected at
save with `422 UNRESOLVED_VARIABLE`.

## Notification channels

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/notification-channels` | create (201) |
| `GET` | `/notification-channels` | list |
| `GET` | `/notification-channels/{id}` | one |
| `PATCH` | `/notification-channels/{id}` | partial update |
| `DELETE` | `/notification-channels/{id}` | delete (204); removes the binding from every monitor |
| `POST` | `/notification-channels/test` | test an **unsaved** transport config |
| `POST` | `/notification-channels/{id}/test` | send a synthetic test alert through a saved channel |
| `POST` | `/notification-channels/{id}/resend-verification` | resend the email verification |

`config` is `type`-tagged. Supported transports: `slack`, `webhook`, `email`,
`discord`, `msteams`, `google_chat`, `telegram`, `telegram_app`, `whatsapp`,
`whatsapp_app`, `pagerduty`, `ntfy`, `pushover`, `sms`.

Behaviour:

- **Secrets sealed at rest** with the credentials KEK; **never echoed back**.
  Every read path masks secret-bearing fields with `***`.
- **Redaction-sentinel guard**: submitting a `config` that still contains `***`
  returns `400 REDACTION_SENTINEL`. Omit `config` on `PATCH` to keep the stored
  secret unchanged.
- **Email verification gate**: an `email` channel is created unverified and a
  single-use 24 h link is sent; until confirmed, every delivery fails with
  `email address not verified`.
- **Webhook signing**: a `webhook` channel with a `secret` (>= 16 chars) signs
  every delivery with `X-Statuspage-Timestamp` and
  `X-Statuspage-Signature: sha256=<hex>` (HMAC-SHA256 over
  `"{timestamp}.{body}"`).

## Idempotency

`POST /api/v1/targets/bulk` and `POST /api/v1/targets/bulk/action` accept an
optional `Idempotency-Key` header. The server stores the response for 24 hours
keyed by `(header value, body hash)`. A retry with the same key and body
returns the original response without re-executing. The cache is in-process;
entries are lost on restart.

```http
POST /api/v1/targets/bulk/action HTTP/1.1
Idempotency-Key: 01h7m8z4n6v0e1m7v7y6x8x8x8
Content-Type: application/json

{ "ids": ["..."], "action": { "type": "disable" } }
```

## Rate limiting

Three per-IP rate-limit layers run in-process (the reverse proxy adds its own
on top):

- `/api/v1/auth/*` — `[rate_limits.per_ip].auth_endpoints_per_min` (default 10)
- `/api/v1/heartbeat/*` — `[rate_limits.per_ip].heartbeat_per_ip_per_min` (default 30)
- `/api/public/v1/*` — `[public_status].public_per_ip_rate_limit_per_min` (default 60)

A trip returns `429 Too Many Requests` with a `Retry-After` header (seconds)
and `code: RATE_LIMITED`. `/healthz` and `/readyz` are never throttled.

## CORS

Disabled by default. When `[api.cors].enabled = true`, `/api/v1/*` answers
preflight `OPTIONS` with `Access-Control-Allow-Origin` (matching
`allowed_origins` or `*` when `allow_any_origin = true`),
`Access-Control-Allow-Methods` (the configured list), and
`Access-Control-Allow-Headers: content-type, authorization, x-requested-with,
idempotency-key`. `/healthz` and `/readyz` carry no CORS headers regardless.

## Error envelope

Every 4xx and 5xx response uses one wire shape:

```jsonc
{
  "error": {
    "code": "INVALID_URL_SCHEME",
    "message": "url scheme 'ftp' not allowed",
    "field": "check.url",
    "details": null,
    "trace_id": null
  }
}
```

- `code` is stable, machine-readable, UPPER_SNAKE_CASE.
- `field` is a JSON pointer to the offending input for 400s; `null` for
  non-field errors.
- `details` carries optional structured context (e.g.
  `{ "range": "127.0.0.0/8" }` for SSRF rejections).
- `trace_id` is the W3C `traceparent` when tracing is enabled.

Common codes: `INVALID_URL_SCHEME`, `SSRF_BLOCKED`, `INVALID_INTERVAL`,
`INVALID_TIMEOUT`, `INVALID_TCP_PORT`, `INVALID_HEARTBEAT_PARAMS`,
`NOT_TESTABLE`, `NOT_SUPPORTED_ON_CONTROL_PLANE`, `NOT_HEARTBEAT_TARGET`,
`INVALID_ALERT_CONFIG`, `REDACTION_SENTINEL`, `ABUSE_GUARD`, `EMPTY_BATCH`,
`BATCH_TOO_LARGE`, `BAD_TIME_RANGE`, `TARGET_NOT_FOUND`, `CHANNEL_NOT_FOUND`,
`CHANNEL_NAME_TAKEN`, `INVALID_CHANNEL_CONFIG`, `CHANNEL_TEST_FAILED`,
`MAGIC_LINK_INVALID`, `TOKEN_NOT_FOUND`, `SESSION_NOT_FOUND`, `RATE_LIMITED`,
`INTERNAL`.

### Validation errors

`POST` and `PATCH` return `400 Bad Request` for:

- Unsupported URL scheme (only `http`/`https`)
- Missing URL host, empty TCP host, or TCP/TLS port `0`
- `tls_cert` / `domain_expiry` `warn_days` not `> critical_days`
- SSRF guard — `target address ... is in a blocked range` (loopback / private /
  link-local / reserved / cloud-metadata). Hostname literals are re-checked at
  connect time after DNS resolution, so DNS rebinding cannot bypass the guard.
- Redaction sentinel — `basic_auth contains redaction sentinel — re-supply the
  real credential` (or the equivalent for `bearer_token`).
- `verify_tls = false` combined with `basic_auth` or `bearer_token` over https.
