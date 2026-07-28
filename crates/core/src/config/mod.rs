mod api;
mod auth;
mod checker;
mod features;
mod observability;
mod runtime;
mod security;
mod server;
mod storage_config;

pub use api::*;
pub use auth::*;
pub use checker::*;
pub use features::*;
pub use observability::*;
pub use runtime::*;
pub use security::*;
pub use server::*;
pub use storage_config::*;

use std::path::PathBuf;

use config::{Config, Environment, File};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Default for a secret-bearing config field: an empty secret. Used by
/// `#[serde(default = "empty_secret")]` so a missing key deserialises to an
/// empty value rather than failing.
fn empty_secret() -> SecretString {
    SecretString::from(String::new())
}

/// (De)serialisation for `SecretString` config fields. `secrecy` deliberately
/// gives `SecretString` no `Serialize`, so `AppConfig`'s derive needs this:
/// it reads a plain string in and writes a fixed placeholder out, ensuring a
/// serialised config can never carry a real secret.
mod secret_str {
    use secrecy::SecretString;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(_v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("[redacted]")
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        Ok(SecretString::from(String::deserialize(d)?))
    }
}

const ENV_PREFIX: &str = "STATUSPAGE";
const ENV_SEPARATOR: &str = "__";
const DEFAULT_CONFIG_PATH: &str = "config/default.toml";
const CONFIG_PATH_ENV: &str = "STATUSPAGE_CONFIG_PATH";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub runtime: RuntimeConfig,
    pub checker: CheckerConfig,
    pub http_client: HttpClientConfig,
    pub dns: DnsConfig,
    pub security: SecurityConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    pub scheduler: SchedulerConfig,
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub tenancy: TenancyConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub public_status: PublicStatusConfig,
    #[serde(default)]
    pub email: TransactionalEmailConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub quotas: QuotasConfig,
    #[serde(default)]
    pub rate_limits: RateLimitsConfig,
    #[serde(default)]
    pub marketing: MarketingConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub escalation: EscalationConfig,
    #[serde(default)]
    pub agent: AgentConfig,

    #[serde(default)]
    pub flow: FlowConfig,
    #[serde(default)]
    pub operator: OperatorConfig,
    #[serde(default)]
    pub telegram: TelegramBotConfig,
    #[serde(default)]
    pub whatsapp_app: WhatsAppAppBotConfig,
    #[serde(default)]
    pub slack_oauth: ConnectOauthConfig,
    #[serde(default)]
    pub discord_oauth: ConnectOauthConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let primary = std::env::var(CONFIG_PATH_ENV)
            .map_or_else(|_| PathBuf::from(DEFAULT_CONFIG_PATH), PathBuf::from);

        let builder = Config::builder().add_source(File::from(primary).required(false)).add_source(
            Environment::with_prefix(ENV_PREFIX)
                .prefix_separator("_")
                .separator(ENV_SEPARATOR)
                .try_parsing(true)
                .list_separator(",")
                .with_list_parse_key("dns.servers")
                .with_list_parse_key("security.trusted_proxies"),
        );

        let cfg = builder.build()?;
        Ok(cfg.try_deserialize()?)
    }

    /// Reject `< 1` quota / rate / interval values at load with a
    /// field-named error (I6). A bad number is a clean startup *config*
    /// error, never a `.expect()` crash-loop in router/layer construction.
    pub fn validate_quotas_and_limits(&self) -> Result<()> {
        fn ge1_u64(v: u64, field: &str) -> Result<()> {
            if v < 1 {
                return Err(crate::error::AppError::Other(eyre::eyre!(
                    "{field} must be >= 1 (got {v})"
                )));
            }
            Ok(())
        }
        ge1_u64(self.quotas.plan_cache_ttl_secs, "quotas.plan_cache_ttl_secs")?;
        ge1_u64(self.quotas.usage_cache_ttl_secs, "quotas.usage_cache_ttl_secs")?;
        ge1_u64(
            self.rate_limits.janitor.cleanup_interval_hours,
            "rate_limits.janitor.cleanup_interval_hours",
        )?;
        ge1_u64(
            self.rate_limits.janitor.idle_threshold_hours,
            "rate_limits.janitor.idle_threshold_hours",
        )?;
        ge1_u64(
            self.scheduler.target_refresh_interval_secs,
            "scheduler.target_refresh_interval_secs",
        )?;
        if self.checker.per_host_max_inflight == 0 {
            return Err(crate::error::AppError::Other(eyre::eyre!(
                "checker.per_host_max_inflight must be >= 1"
            )));
        }
        if self.checker.rdap_max_inflight == 0 {
            return Err(crate::error::AppError::Other(eyre::eyre!(
                "checker.rdap_max_inflight must be >= 1"
            )));
        }
        if self.escalation.enabled {
            ge1_u64(self.escalation.tick_interval_secs, "escalation.tick_interval_secs")?;
            if self.escalation.max_attempts < 1 {
                return Err(crate::error::AppError::Other(eyre::eyre!(
                    "escalation.max_attempts must be >= 1 (got {})",
                    self.escalation.max_attempts
                )));
            }
        }
        Ok(())
    }

    /// Marketing-site boot invariants. Cheap startup errors, never
    /// panics in router construction. Skipped wholesale when
    /// `marketing.enabled = false` so self-host deployments need not set
    /// any of these.
    pub fn validate_marketing(&self) -> Result<()> {
        fn err(msg: String) -> crate::error::AppError {
            crate::error::AppError::Other(eyre::eyre!(msg))
        }
        let m = &self.marketing;
        if !m.enabled {
            return Ok(());
        }
        let base = self.public_status.base_domain.trim();
        if base.is_empty() || !base.contains('.') {
            return Err(err(format!(
                "marketing.enabled = true requires public_status.base_domain to be a non-empty FQDN (got {base:?})"
            )));
        }
        for (field, value) in [
            ("marketing.canonical_origin", m.canonical_origin.as_str()),
            ("marketing.app_url", m.app_url.as_str()),
        ] {
            let v = value.trim();
            if v.is_empty() {
                return Err(err(format!("{field} is required when marketing.enabled = true")));
            }
            if !v.starts_with("https://") {
                return Err(err(format!("{field} must start with https:// (got {v:?})")));
            }
            if v.ends_with('/') {
                return Err(err(format!("{field} must not end with a trailing slash (got {v:?})")));
            }
        }
        for sub in &m.reserved_subdomains {
            let lower = sub.to_ascii_lowercase();
            if !crate::domain::reserved_slugs::is_reserved(&lower) {
                return Err(err(format!(
                    "marketing.reserved_subdomains entry {sub:?} is not in \
                     domain::reserved_slugs::RESERVED_SLUGS — keep the two lists aligned"
                )));
            }
        }
        // The session cookie must not be scoped to a parent zone that the
        // marketing host inherits; otherwise the app's session ID rides
        // along to the apex and the marketing CDN cache becomes Vary:
        // Cookie. Host-only (empty Domain) is always safe.
        let cd = self.auth.session.cookie_domain.trim();
        if !cd.is_empty() {
            let stripped = cd.trim_start_matches('.');
            if stripped == base || base.ends_with(&format!(".{stripped}")) {
                return Err(err(format!(
                    "auth.session.cookie_domain={cd:?} overlaps marketing host {base:?}; \
                     leave cookie_domain empty (host-only) so the apex marketing surface \
                     is not Vary: Cookie"
                )));
            }
        }
        Ok(())
    }

    /// Trace-export config is a clean startup error when inconsistent,
    /// never a runtime panic. Credentials are required only when export
    /// is actually active (`tracing_enabled` AND `openobserve.enabled`); the
    /// sample ratio is always range-checked.
    pub fn validate_observability(&self) -> Result<()> {
        fn err(msg: String) -> crate::error::AppError {
            crate::error::AppError::Other(eyre::eyre!(msg))
        }
        let g = &self.observability.openobserve;
        let r = g.trace_sample_ratio;
        if !(0.0..=1.0).contains(&r) {
            return Err(err(format!(
                "observability.openobserve.trace_sample_ratio must be in [0.0, 1.0] (got {r})"
            )));
        }
        if self.observability.tracing_enabled && g.enabled {
            if g.otlp_endpoint.trim().is_empty() {
                return Err(err(
                    "observability.openobserve.otlp_endpoint is required when tracing_enabled and openobserve.enabled are true".into(),
                ));
            }
            if g.instance_id.trim().is_empty() {
                return Err(err(
                    "observability.openobserve.instance_id is required when tracing_enabled and openobserve.enabled are true".into(),
                ));
            }
            if g.api_key.expose_secret().trim().is_empty() {
                return Err(err(
                    "STATUSPAGE_OBSERVABILITY__OPENOBSERVE__API_KEY is required when tracing_enabled and openobserve.enabled are true".into(),
                ));
            }
        }
        let hb = &self.observability.heartbeat;
        if hb.enabled {
            if hb.url.trim().is_empty() {
                return Err(err(
                    "STATUSPAGE_OBSERVABILITY__HEARTBEAT__URL is required when observability.heartbeat.enabled is true".into(),
                ));
            }
            if hb.interval_seconds == 0 {
                return Err(err("observability.heartbeat.interval_seconds must be > 0".into()));
            }
        }
        Ok(())
    }

    /// Central-bot invariants, enforced only when `telegram.bot_token` is set.
    /// A misconfigured bot here is a clean startup error rather than a half-up
    /// feature that mints dead deep links.
    pub fn validate_telegram(&self) -> Result<()> {
        fn err(msg: &str) -> crate::error::AppError {
            crate::error::AppError::Other(eyre::eyre!(msg.to_string()))
        }
        let t = &self.telegram;
        if !t.enabled() {
            return Ok(());
        }
        if t.bot_username.trim().is_empty() {
            return Err(err("telegram.bot_username is required when telegram.bot_token is set"));
        }
        if t.webhook_secret.expose_secret().trim().len() < 32 {
            return Err(err(
                "STATUSPAGE_TELEGRAM__WEBHOOK_SECRET must be at least 32 chars when telegram.bot_token is set",
            ));
        }
        let base = self.auth.public_base_url.trim();
        match url::Url::parse(base) {
            Ok(u) if u.scheme() == "https" && u.host_str().is_some() => {}
            _ => {
                return Err(err(
                    "auth.public_base_url must be an https:// URL with a host for the telegram webhook",
                ));
            }
        }
        Ok(())
    }

    /// A half-configured Resend sender is a clean startup error, not a
    /// per-send failure after cutover. The webhook secret alone is fine —
    /// the bounce receiver works regardless of the sending provider.
    pub fn validate_email(&self) -> Result<()> {
        fn err(msg: &str) -> crate::error::AppError {
            crate::error::AppError::Other(eyre::eyre!(msg.to_string()))
        }
        let e = &self.email;
        if e.provider != "resend" {
            return Ok(());
        }
        if e.resend.api_key.expose_secret().trim().is_empty() {
            return Err(err("email.resend.api_key is required when email.provider = \"resend\""));
        }
        if e.from_address.trim().is_empty() {
            return Err(err("email.from_address is required when email.provider = \"resend\""));
        }
        Ok(())
    }

    /// A half-configured operator WhatsApp number is a clean startup error,
    /// not a dead webhook or a failing send after the flag flip.
    pub fn validate_whatsapp_app(&self) -> Result<()> {
        fn err(msg: &str) -> crate::error::AppError {
            crate::error::AppError::Other(eyre::eyre!(msg.to_string()))
        }
        let w = &self.whatsapp_app;
        if !w.enabled {
            return Ok(());
        }
        if w.access_token.expose_secret().trim().is_empty()
            || w.phone_number_id.trim().is_empty()
            || w.app_secret.expose_secret().trim().is_empty()
            || w.verify_token.expose_secret().trim().is_empty()
        {
            return Err(err(
                "whatsapp_app.enabled needs access_token, phone_number_id, app_secret and verify_token set",
            ));
        }
        if w.verify_token.expose_secret().trim().len() < 32 {
            return Err(err("STATUSPAGE_WHATSAPP_APP__VERIFY_TOKEN must be at least 32 chars"));
        }
        let n = w.public_number.trim();
        if !(5..=20).contains(&n.len()) || !n.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err(
                "whatsapp_app.public_number must be the display number as international digits",
            ));
        }
        if w.template_name.is_empty()
            || !w
                .template_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(err(
                "whatsapp_app.template_name is required (lowercase letters, digits, and _ only)",
            ));
        }
        if w.language_code.is_empty()
            || !w.language_code.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(err("whatsapp_app.language_code must be a code like en or en_US"));
        }
        // Deliberate: sends are operator-paid Meta template messages with no
        // per-org cap yet — the flag flip is the only spend control.
        tracing::warn!(
            "whatsapp_app.enabled — operator-paid template sends are UNCAPPED; \
             monitor spend until per-org send caps land"
        );
        Ok(())
    }

    /// Validate the regional-agent section. Only enforced when `agent.enabled`.
    pub fn validate_runtime(&self) -> Result<()> {
        fn err(msg: &str) -> crate::error::AppError {
            crate::error::AppError::Other(eyre::eyre!(msg.to_string()))
        }
        let agent = &self.agent;
        if !agent.enabled {
            return Ok(());
        }
        if agent.control_plane_url.trim().is_empty() {
            return Err(err("agent.control_plane_url is required when agent.enabled"));
        }
        // Resolved secrets and decrypted credentials ride the config-pull
        // response, so the control-plane transport must be encrypted. Cleartext
        // is permitted only when private targets are explicitly opted in (a
        // trusted private-network or localhost control plane for dev/integration).
        let url = url::Url::parse(agent.control_plane_url.trim())
            .map_err(|_| err("agent.control_plane_url is not a valid URL"))?;
        if url.scheme() != "https" && !self.security.allow_private_targets {
            return Err(err("agent.control_plane_url must use https; cleartext is permitted \
                 only with security.allow_private_targets for a trusted \
                 private-network or localhost control plane"));
        }
        if agent.region.trim().is_empty() {
            return Err(err("agent.region is required when agent.enabled"));
        }
        if agent.token.expose_secret().trim().is_empty() {
            return Err(err("STATUSPAGE_AGENT__TOKEN is required when agent.enabled is true"));
        }
        if agent.pull_interval_secs == 0 {
            return Err(err("agent.pull_interval_secs must be > 0"));
        }
        if agent.buffer_capacity == 0 {
            return Err(err("agent.buffer_capacity must be > 0"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::FileFormat;

    fn scheduler_from(toml: &str) -> SchedulerConfig {
        Config::builder()
            .add_source(File::from_str(toml, FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }

    #[test]
    fn scheduler_enabled_defaults_true_and_parses_false() {
        assert!(scheduler_from("target_refresh_interval_secs = 30").enabled);
        assert!(!scheduler_from("enabled = false\ntarget_refresh_interval_secs = 30").enabled);
    }

    fn agent_cfg(url: &str) -> AppConfig {
        // `AppConfig::load()` reads `config/default.toml` relative to the
        // current working directory. Tests run from varying cwds (workspace
        // root for `cargo test --workspace`, crate dir for `cargo test -p
        // statuscore`), so resolve an absolute path via `CARGO_MANIFEST_DIR`
        // (this crate = `crates/core`, workspace root is two levels up).
        let cfg_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/default.toml");
        // SAFETY: tests in this module are single-threaded w.r.t. config
        // loading (they all call `agent_cfg` sequentially within one test
        // binary). If this ever becomes parallel, switch to a builder that
        // accepts the path directly instead of using the env var.
        unsafe {
            // Set via env var so `AppConfig::load()` picks it up.
            std::env::set_var(CONFIG_PATH_ENV, &cfg_path);
        }
        let mut cfg = AppConfig::load().expect("load");
        cfg.agent.enabled = true;
        cfg.agent.control_plane_url = url.to_string();
        cfg.agent.region = "eu-helsinki".into();
        cfg.agent.token = SecretString::from("agent-token".to_string());
        cfg
    }

    #[test]
    fn agent_https_control_plane_passes() {
        agent_cfg("https://app.example.com").validate_runtime().expect("https passes");
    }

    #[test]
    fn agent_cleartext_control_plane_rejected() {
        let err =
            agent_cfg("http://app.example.com").validate_runtime().expect_err("cleartext rejected");
        assert!(err.to_string().contains("https"), "{err}");
    }

    #[test]
    fn agent_cleartext_allowed_with_private_targets_optin() {
        let mut cfg = agent_cfg("http://127.0.0.1:8080");
        cfg.security.allow_private_targets = true;
        cfg.validate_runtime().expect("cleartext ok when private opted in");
    }
}
