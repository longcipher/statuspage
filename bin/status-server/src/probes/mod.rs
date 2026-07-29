//! In-process probe implementations for the scheduler.
//!
//! Each probe kind lives in its own module and exposes a single `probe_*`
//! function returning the `(status, response_code, error)` triple the
//! scheduler fits into a [`statuscore::domain::CheckResult`]. The scheduler
//! measures overall `duration_ms` and stamps the result envelope; probes
//! only report probe outcome.
//!
//! # SSRF
//!
//! Network probes (tls_cert) use the shared [`common::security::SsrfGuard`]
//! via [`resolve_with_guard`]: a target pointing at a private IP (loopback,
//! RFC1918, link-local, cloud metadata, 6to4 / NAT64-embedded private v4)
//! is dropped at DNS-filter time before any TCP open — DNS-rebinding safe
//! by construction. The RDAP probe rides on `reqwest`, which doesn't expose
//! its connector to the guard, so it relies on the public nature of the
//! RDAP bootstrap (`https://rdap.org/...`) — never user-supplied URLs.

pub mod dns;
pub mod domain_expiry;
pub mod tls_cert;

use std::net::SocketAddr;

use common::security::SsrfGuard;

/// Resolve `host:port` and drop every IP the SSRF guard blocks. Returns the
/// remaining socket addresses. An empty `Vec` (no error) signals "every
/// resolved address is in a blocked range" — callers report it as `Error`
/// rather than retrying against a private target.
///
/// Uses the strict (production-default) guard: loopback, RFC1918, link-local,
/// ULA, multicast, broadcast, reserved, documentation, and cloud-metadata
/// ranges are all rejected regardless of how the hostname was supplied.
// ponytail: SSRF guard always strict here; allow_private_targets only applies
// to the scheduler's HTTP/TCP/ping probes via the shared reqwest client.
pub(crate) async fn resolve_with_guard(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let guard = SsrfGuard::strict();
    let target = format!("{host}:{port}");
    let resolved: Vec<SocketAddr> = match tokio::net::lookup_host(&target).await {
        Ok(it) => it.collect(),
        Err(e) => return Err(format!("dns lookup '{host}': {e}")),
    };
    let ips: Vec<std::net::IpAddr> = resolved.iter().map(|sa| sa.ip()).collect();
    let allowed = match guard.filter(host, ips) {
        Ok(v) => v,
        Err(e) => return Err(format!("ssrf '{host}': {e}")),
    };
    Ok(resolved.into_iter().filter(|sa| allowed.contains(&sa.ip())).collect())
}
