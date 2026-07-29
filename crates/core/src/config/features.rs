use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::empty_secret;
use super::secret_str;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TenancyConfig {
    /// Path-based public surface (`/status/<slug>`, `/api/public/v1/*` on the
    /// operator host). The slug always identifies the org; there is no
    /// ambient "default tenant".
    pub path_based_public_routes: bool,
    /// Wildcard subdomain public surface (`*.{public_status.base_domain}`).
    /// Requires a well-formed `public_status.base_domain`; a startup
    /// assertion refuses to boot otherwise.
    pub subdomain_public_routes: bool,
    /// Free-tier cap on the number of orgs a single user can own.
    pub free_tier_owner_org_limit: u32,
    /// Grace period before soft-deleted orgs *and users* are purged. Single
    /// source of truth for the recovery window: the daily retention job binds
    /// this, and the Privacy Policy's "recoverable for 30 days" line is
    /// asserted equal to it in tests.
    pub deletion_grace_period_days: u32,
}

impl Default for TenancyConfig {
    fn default() -> Self {
        Self {
            path_based_public_routes: true,
            subdomain_public_routes: false,
            free_tier_owner_org_limit: 3,
            deletion_grace_period_days: 30,
        }
    }
}

/// Long-horizon data-retention windows for the periodic purge job. Every
/// field here is honoured by `cleanup.rs`; an unhonoured knob is worse than a
/// missing one. Other cadences live with their owner: OAuth-state and
/// magic-link tokens have their own short-cadence security purge;
/// session idle/absolute timeouts live in `[auth.session]`; server/app log
/// retention in journald (or your log collector).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default)]
pub struct RetentionConfig {
    /// `check_results` rows older than this are hard-deleted. The time-series
    /// table grows unbounded without a purge; 30 days keeps enough history for
    /// the 90-day day-strip (which backfills from incidents + the latest
    /// result, not raw results) while bounding disk usage.
    pub check_results_days: u32,
    /// Days after an API token's `expires_at` before its row is
    /// hard-deleted. Live tokens never count against the per-user cap
    /// (`api_tokens::count_for_user` filters by expiry) so the only purpose
    /// of this window is to bound table growth and shrink the
    /// rotation-pattern leak from a compromised user reading their own
    /// `token_prefix` / `name` history.
    pub api_tokens_post_expiry_days: u32,
    /// Whether CSV/PDF export is enabled.
    #[serde(default)]
    pub export_enabled: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self { check_results_days: 30, api_tokens_post_expiry_days: 30, export_enabled: false }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PublicStatusConfig {
    /// Base domain for `*.{base_domain}` per-org status pages (apex-wildcard
    /// shape). Used only when `tenancy.subdomain_public_routes = true`. A
    /// startup assertion refuses to boot when this is empty or has no dot in
    /// that mode — without that, the strip-suffix parser collapses to a bare
    /// dot match and accepts arbitrary `Host` headers.
    pub base_domain: String,

    pub cache_max_orgs: u32,
    pub cache_ttl_secs: u64,
    /// Idle eviction caps memory when tenants churn faster than the purge
    /// worker can reach them.
    pub last_good_ttl_secs: u64,

    pub max_logo_size_bytes: u32,
    pub allowed_logo_mime_types: Vec<String>,
    pub max_logo_dimension_px: u32,

    pub default_brand_color: String,
    pub default_show_powered_by: bool,

    /// Second line of defence behind the Caddy-side limit.
    pub public_per_ip_rate_limit_per_min: u32,

    /// Optional custom CSS injected into the public status page.
    pub custom_css: Option<String>,
}

impl Default for PublicStatusConfig {
    fn default() -> Self {
        Self {
            base_domain: String::new(),
            cache_max_orgs: 1000,
            cache_ttl_secs: 10,
            last_good_ttl_secs: 3600,
            max_logo_size_bytes: 1_048_576,
            allowed_logo_mime_types: vec![
                "image/png".into(),
                "image/jpeg".into(),
                "image/webp".into(),
            ],
            max_logo_dimension_px: 1200,
            default_brand_color: "#3b82f6".into(),
            default_show_powered_by: true,
            public_per_ip_rate_limit_per_min: 60,
            custom_css: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TransactionalEmailConfig {
    /// Backend: "resend" (HTTP API), "log" (tracing only, dev default), or
    /// "memory" (in-process buffer for tests).
    pub provider: String,
    pub from_name: String,
    pub from_address: String,
    pub resend: ResendConfig,
}

impl Default for TransactionalEmailConfig {
    fn default() -> Self {
        Self {
            provider: "log".into(),
            from_name: "Statuspage".into(),
            from_address: "no-reply@example.invalid".into(),
            resend: ResendConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ResendConfig {
    #[serde(default = "empty_secret", with = "secret_str")]
    pub api_key: SecretString,
    /// Svix signing secret (`whsec_…`) of the Resend webhook endpoint.
    /// Empty = the `/hooks/resend` receiver is absent and bounce events
    /// are not consumed.
    #[serde(default = "empty_secret", with = "secret_str")]
    pub webhook_secret: SecretString,
}

impl ResendConfig {
    pub fn webhook_enabled(&self) -> bool {
        !self.webhook_secret.expose_secret().trim().is_empty()
    }
}

impl Default for ResendConfig {
    fn default() -> Self {
        Self { api_key: empty_secret(), webhook_secret: empty_secret() }
    }
}

/// `[quotas]`. Cache TTLs for plan/usage lookups.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct QuotasConfig {
    /// Plans change rarely; a few minutes of staleness is acceptable.
    pub plan_cache_ttl_secs: u64,
    /// Usage counts move fast under bursty creates; short TTL only.
    pub usage_cache_ttl_secs: u64,
}

impl Default for QuotasConfig {
    fn default() -> Self {
        Self { plan_cache_ttl_secs: 300, usage_cache_ttl_secs: 10 }
    }
}

/// `[rate_limits]`. Most numbers come from the `plans` table; these are the
/// janitor cadence and the per-IP values Caddy enforces (kept here for
/// reference / parity). Validated `>= 1` at load (I6).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitsConfig {
    pub per_ip: PerIpRateLimits,
    pub janitor: RateLimitJanitorConfig,
    /// Maximum API requests per minute per API token. 0 = unlimited.
    #[serde(default)]
    pub api_token_per_min: u64,
}

/// Per-IP limits Caddy enforces. Mirrored here so docs/ops have one place to
/// read the numbers; the app does not key on the TCP peer.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PerIpRateLimits {
    pub public_pages_per_min: u32,
    pub auth_endpoints_per_min: u32,
    pub org_creations_per_day: u32,
    /// Per-IP cap on `POST /api/v1/heartbeat/{target_id}`. Heartbeat pings
    /// are unauthenticated; without a per-IP cap an attacker could exhaust
    /// the DuckDB mutex throughput and starve legitimate API traffic. 0 =
    /// disabled (rely on the reverse proxy). Default 30/min allows one
    /// ping every 2s — plenty for any heartbeat schedule (typical period is
    /// 60s–5min).
    pub heartbeat_per_ip_per_min: u32,
}

impl Default for PerIpRateLimits {
    fn default() -> Self {
        Self {
            public_pages_per_min: 60,
            auth_endpoints_per_min: 10,
            org_creations_per_day: 3,
            heartbeat_per_ip_per_min: 30,
        }
    }
}

/// Idle-entry janitor cadence for the in-process rate-limit map.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitJanitorConfig {
    pub cleanup_interval_hours: u64,
    pub idle_threshold_hours: u64,
}

impl Default for RateLimitJanitorConfig {
    fn default() -> Self {
        Self { cleanup_interval_hours: 6, idle_threshold_hours: 24 }
    }
}

/// `[marketing]`. Optional apex/`www` marketing site + blog served from
/// the same binary. Hard-isolated module — see `src/marketing/`. Disabled
/// by default; when enabled, the dispatch seam routes the apex and `www`
/// hosts to the marketing router and leaves every other host on the app
/// router unchanged. Boot invariants live in `AppConfig::validate_marketing`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MarketingConfig {
    pub enabled: bool,
    /// CTA + login link target on every marketing page. The marketing
    /// module never imports app code — this is the only handle it has on
    /// the app surface, so the extracted service points anywhere with one
    /// config change.
    pub app_url: String,
    /// Fully-qualified canonical origin (scheme + host, no trailing
    /// slash). Used for `<link rel="canonical">`, OG / JSON-LD absolute
    /// URLs, and the sitemap.
    pub canonical_origin: String,
    /// Belt-and-braces guard for subdomain labels that must never alias a
    /// tenant slug (`www`, `app`). The dispatch seam already routes
    /// apex/`www`/`app` explicitly; this list is asserted to be a subset
    /// of `domain::reserved_slugs::RESERVED` at boot so the two lists
    /// can't drift.
    pub reserved_subdomains: Vec<String>,
    pub blog_enabled: bool,
}

impl Default for MarketingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            app_url: String::new(),
            canonical_origin: String::new(),
            reserved_subdomains: vec!["www".into(), "app".into()],
            blog_enabled: true,
        }
    }
}

/// `[mcp]`. Read-only Model Context Protocol server at `/mcp` (JSON-RPC
/// 2.0 over HTTP). Disabled by default; flip `enabled = true` to mount.
/// Auth reuses the app's existing session cookie or Bearer API token
/// (single-tenant — no OAuth, no scopes, no audit log). Read tools only
/// in v1: the operator's existing dashboard / API already owns writes.
///
/// `allowed_origins` feeds the transport's RFC 6454 Origin check
/// (DNS-rebinding defense): empty disables it, and a request with no
/// `Origin` header always passes — non-browser clients like `mcp-remote`
/// send none, browser connectors send their own origin.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[derive(Default)]
pub struct McpConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
}

/// `[escalation]`. Incident paging engine and its operator surfaces (escalation
/// policies, on-call schedules). Off by default: a single-responder deployment
/// gets direct alerting and the engine + its UI stay hidden. When `enabled`, an
/// open incident pages the monitor's bound notification channels and the legacy
/// direct alert dispatch is suppressed (the incident becomes the single source
/// of down/up notification), and the escalation + on-call UI is mounted. When
/// disabled, incidents still open and show in the console but page no one — the
/// legacy alert path keeps firing.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct EscalationConfig {
    pub enabled: bool,
    /// Retry-sweep cadence: how often failed pages are re-attempted.
    pub tick_interval_secs: u64,
    /// Backpressure: max pages re-sent per sweep.
    pub max_pages_per_tick: u32,
    /// Give up paging a channel after this many failed attempts.
    pub max_attempts: u32,
    /// Base delay for the exponential retry backoff: attempt n waits
    /// `base * 2^(n-1)` (capped) before the next try.
    pub retry_backoff_base_secs: u64,
    /// Ceiling on a single retry's backoff delay.
    pub retry_backoff_cap_secs: u64,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_interval_secs: 15,
            max_pages_per_tick: 500,
            max_attempts: 5,
            retry_backoff_base_secs: 30,
            retry_backoff_cap_secs: 3600,
        }
    }
}

/// `[agent]`. Turns this process into a stateless regional probe: it pulls its
/// region's monitor config from a control plane and ships results back, running
/// no web/DuckDB/alerting of its own. Off by default (the process
/// is a normal dashboard). `token` carries a capability — env only, never a
/// config file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AgentConfig {
    pub enabled: bool,
    pub control_plane_url: String,
    #[serde(default = "empty_secret", with = "secret_str")]
    pub token: SecretString,
    pub region: String,
    pub pull_interval_secs: u64,
    pub flush_interval_secs: u64,
    pub buffer_capacity: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            control_plane_url: String::new(),
            token: empty_secret(),
            region: String::new(),
            pull_interval_secs: 30,
            flush_interval_secs: 5,
            buffer_capacity: 10_000,
        }
    }
}

/// `[flow]`. Browser-driven flow monitors, off by default. Runs where `enabled`
/// is set and the Lightpanda engine is at `lightpanda_path`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FlowConfig {
    pub enabled: bool,
    pub lightpanda_path: String,
    pub max_concurrency: usize,
    /// Per-check browser RSS ceiling (MB); over it the run is killed as `Error`
    /// so one heavy page can't OOM the node. 0 = off.
    pub mem_limit_mb: u64,
    /// Runtime SSRF guard: block private/internal IPs after DNS resolution, which
    /// the save-time URL check can't (redirects/`fetch`/rebinding resolve later).
    pub block_private_networks: bool,
    /// Extra CIDRs to block, comma-separated (`-` exempts). Defaults add metadata,
    /// loopback, CGNAT, and IPv6 ULA (Fly 6PN = `fc00::/7`)/link-local.
    pub block_cidrs: String,
    /// In-engine V8 heap cap per browser (MB); 0 = engine default. A belt for the
    /// RSS watchdog — set below `mem_limit_mb` to trip on JS-heap runaway first.
    pub v8_max_heap_mb: u64,
    /// Reject any single browser response larger than this (MB); 0 = no limit.
    pub max_response_mb: u64,
    /// Appended to the browser User-Agent for attribution; empty = none.
    pub user_agent_suffix: String,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lightpanda_path: "lightpanda".into(),
            max_concurrency: 2,
            mem_limit_mb: 250,
            block_private_networks: true,
            block_cidrs: "169.254.0.0/16,127.0.0.0/8,100.64.0.0/10,::1/128,fc00::/7,fe80::/10"
                .into(),
            v8_max_heap_mb: 0,
            max_response_mb: 0,
            user_agent_suffix: String::new(),
        }
    }
}

/// `[operator]`. Instance-admin surface (`/operator/*`) for managing regions
/// and agents across all tenants. Gated by a static bearer secret — env only,
/// never a config file. Empty `admin_token` disables the surface entirely.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OperatorConfig {
    #[serde(default = "empty_secret", with = "secret_str")]
    pub admin_token: SecretString,
    /// An agent with no successful pull/push for this long is reported stale
    /// (dead-man's-switch): a Prometheus gauge flips and the operator surface
    /// flags it. Default 3× the agent's default pull interval.
    #[serde(default = "default_agent_stale_after_secs")]
    pub agent_stale_after_secs: u64,
}

const fn default_agent_stale_after_secs() -> u64 {
    90
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            admin_token: empty_secret(),
            agent_stale_after_secs: default_agent_stale_after_secs(),
        }
    }
}

/// `[telegram]`. Operator-owned central bot shared by every org: customers
/// link a chat by tapping a deep link instead of running their own BotFather
/// bot. A non-empty `bot_token` enables the whole surface — the connect
/// button, the `/hooks/telegram` receiver, and the boot webhook handshake.
/// Empty leaves it absent; the bring-your-own `telegram` channel is
/// unaffected either way. All three values are capabilities — env only,
/// never a config file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TelegramBotConfig {
    #[serde(default = "empty_secret", with = "secret_str")]
    pub bot_token: SecretString,
    /// Verified against `getMe` at boot so a mismatched deep link can't be
    /// minted against the wrong bot.
    pub bot_username: String,
    /// Echoed back by Telegram in `X-Telegram-Bot-Api-Secret-Token` on every
    /// update; the only thing authenticating the receiver.
    #[serde(default = "empty_secret", with = "secret_str")]
    pub webhook_secret: SecretString,
}

impl Default for TelegramBotConfig {
    fn default() -> Self {
        Self {
            bot_token: empty_secret(),
            bot_username: String::new(),
            webhook_secret: empty_secret(),
        }
    }
}

impl TelegramBotConfig {
    pub fn enabled(&self) -> bool {
        !self.bot_token.expose_secret().trim().is_empty()
    }

    /// Bot token for linked-channel delivery; `None` when not configured.
    pub fn delivery_token(&self) -> Option<&str> {
        self.enabled().then(|| self.bot_token.expose_secret())
    }
}

/// Operator-owned WhatsApp business number (Meta Cloud API) behind the
/// one-tap `whatsapp_app` channels. `enabled` is a deliberate spend gate:
/// template sends ride the operator's WABA at per-message Meta pricing, so
/// creds alone never switch the surface on.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WhatsAppAppBotConfig {
    pub enabled: bool,
    #[serde(default = "empty_secret", with = "secret_str")]
    pub access_token: SecretString,
    /// Cloud API id messages are sent from.
    pub phone_number_id: String,
    /// Display number in international digits — the `wa.me` deep-link
    /// target (NOT the phone_number_id).
    pub public_number: String,
    /// Meta app secret; signs every webhook delivery
    /// (`X-Hub-Signature-256`).
    #[serde(default = "empty_secret", with = "secret_str")]
    pub app_secret: SecretString,
    /// Echoed by Meta's one-time GET subscribe handshake.
    #[serde(default = "empty_secret", with = "secret_str")]
    pub verify_token: SecretString,
    /// Approved alert template with a single body parameter.
    pub template_name: String,
    pub language_code: String,
}

impl Default for WhatsAppAppBotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            access_token: empty_secret(),
            phone_number_id: String::new(),
            public_number: String::new(),
            app_secret: empty_secret(),
            verify_token: empty_secret(),
            template_name: String::new(),
            language_code: "en".into(),
        }
    }
}

impl WhatsAppAppBotConfig {
    pub fn enabled(&self) -> bool {
        self.enabled
            && !self.access_token.expose_secret().trim().is_empty()
            && !self.phone_number_id.trim().is_empty()
            && !self.app_secret.expose_secret().trim().is_empty()
            && !self.verify_token.expose_secret().trim().is_empty()
    }
}

/// `[slack_oauth]` / `[discord_oauth]`. Credentials of an operator-owned
/// OAuth app behind a one-click connect button: the dance hands back a
/// ready-made webhook URL so the user never copies one by hand. Empty
/// credentials hide the button; the manual-paste kind works either way.
/// Env only, never a config file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ConnectOauthConfig {
    pub client_id: String,
    #[serde(default = "empty_secret", with = "secret_str")]
    pub client_secret: SecretString,
}

impl Default for ConnectOauthConfig {
    fn default() -> Self {
        Self { client_id: String::new(), client_secret: empty_secret() }
    }
}

impl ConnectOauthConfig {
    pub fn enabled(&self) -> bool {
        !self.client_id.trim().is_empty() && !self.client_secret.expose_secret().trim().is_empty()
    }
}
