use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::empty_secret;
use super::secret_str;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub allow_private_targets: bool,
    #[serde(default = "empty_secret", with = "secret_str")]
    pub credentials_kek_base64: SecretString,
    /// CIDR ranges whose `X-Forwarded-For` header is honoured for client-IP
    /// extraction. The TCP peer's address is checked against this list; if
    /// it matches, the rightmost untrusted hop in XFF wins. Anything else
    /// falls back to the TCP peer (no spoofable header). Empty by default
    /// — operators behind a reverse proxy (Caddy / nginx / a CDN) MUST set
    /// this, otherwise every `ip_hash` written to the database collapses to
    /// the proxy's address and IP-keyed abuse/audit signals are useless.
    #[serde(default)]
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl SecurityConfig {
    /// Returns Some(trimmed KEK string) if a non-empty value is configured, None otherwise.
    pub fn kek(&self) -> Option<&str> {
        let t = self.credentials_kek_base64.expose_secret().trim();
        (!t.is_empty()).then_some(t)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub open_duration_secs: u64,
    pub half_open_max_calls: u32,
}
