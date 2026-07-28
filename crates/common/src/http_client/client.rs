use std::sync::Arc;

use rustls::crypto::CryptoProvider;

use statuscore::config::{CheckerConfig, DnsConfig, HttpClientConfig, SecurityConfig};
use statuscore::error::Result;

use crate::http_client::dns::HickoryDnsResolver;
use crate::security::SsrfGuard;

/// Shared, cheaply-clonable handles for the check path: the Hickory DNS
/// resolver, the SSRF guard, and the outbound `User-Agent` string.
#[derive(Clone, Debug)]
pub struct HttpClients {
    pub(crate) user_agent: Arc<str>,
    pub(crate) resolver: Arc<HickoryDnsResolver>,
    pub(crate) ssrf_guard: SsrfGuard,
}

impl HttpClients {
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub const fn resolver(&self) -> &Arc<HickoryDnsResolver> {
        &self.resolver
    }

    pub const fn ssrf_guard(&self) -> SsrfGuard {
        self.ssrf_guard
    }
}

pub fn build_clients(
    http_cfg: &HttpClientConfig,
    _checker_cfg: &CheckerConfig,
    dns_cfg: &DnsConfig,
    security_cfg: &SecurityConfig,
) -> Result<HttpClients> {
    install_default_crypto_provider();

    let resolver = Arc::new(HickoryDnsResolver::new(dns_cfg)?);
    let ssrf_guard = SsrfGuard::new(security_cfg.allow_private_targets);

    Ok(HttpClients { user_agent: Arc::from(http_cfg.user_agent.as_str()), resolver, ssrf_guard })
}

pub(crate) fn install_default_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
