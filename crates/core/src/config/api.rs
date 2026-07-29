use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    // Per-IP API rate limiting moved to Caddy (it sees the real peer); the
    // in-process limiter is now per-org / per-user via [rate_limits] and the
    // plans table. The old `api.rate_limit` (PeerIpKeyExtractor) layer is
    // gone — behind a proxy it collapsed to one global bucket.
    #[serde(default)]
    pub cors: CorsConfig,
    /// When false, all `/api/v1/*` management routes return 404. Public
    /// routes (`/api/public/v1/*`) and heartbeat remain accessible.
    /// Targets and notification channels are managed exclusively via the
    /// config file (`[[seed.targets]]` / `[[seed.notification_channels]]`).
    #[serde(default = "default_true")]
    pub management_api_enabled: bool,
}

const fn default_true() -> bool {
    true
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self { cors: CorsConfig::default(), management_api_enabled: true }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CorsConfig {
    pub enabled: bool,
    /// Origins allowed when `allow_any_origin` is false. Each entry must be a
    /// full origin (`https://app.example.com`) — wildcards are not parsed here.
    pub allowed_origins: Vec<String>,
    /// HTTP methods returned in `Access-Control-Allow-Methods`.
    pub allowed_methods: Vec<String>,
    /// When true, returns `Access-Control-Allow-Origin: *`. Mutually exclusive
    /// with `allowed_origins`.
    pub allow_any_origin: bool,
}
