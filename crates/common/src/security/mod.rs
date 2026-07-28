//! Security primitives: reversible encryption (AES-256-GCM), SSRF defence,
//! and the SSRF-aware HTTP connector used by outbound non-check traffic.

pub mod crypto;
pub mod outbound_connector;
pub mod ssrf;

pub use crypto::{
    Cipher, CryptoError, ENC_KEY, envelope_str, is_envelope, open_str, seal_str, wrap_envelope,
};
pub use outbound_connector::SsrfHttpConnector;
pub use ssrf::{SsrfError, SsrfGuard, is_blocked_ip};

/// Strip the surrounding `[ ]` of a bracketed IPv6 literal host. The SSRF IP
/// check MUST normalise a host identically — a single shared definition keeps
/// the connector and the guard from drifting apart.
pub(crate) fn unbracket(host: &str) -> &str {
    host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host)
}
