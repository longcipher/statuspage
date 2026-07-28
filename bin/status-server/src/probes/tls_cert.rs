#![expect(dead_code)]
// Agent-only probe: the control plane rejects these check kinds via
// `require_control_plane_support()` before reaching this code. Kept as
// the implementation site for a future agent runtime.

//! TLS certificate expiry probe.
//!
//! Connects to `host:port`, completes a TLS handshake, parses the server's
//! leaf certificate, and reports Up/Degraded/Down based on the days until
//! `not_after`.
//!
//! # SSRF
//!
//! DNS resolution is filtered through [`common::security::SsrfGuard::strict`]
//! (via [`super::resolve_with_guard`]) before any TCP open — a target
//! pointing at a private IP (loopback, RFC1918, link-local, cloud metadata)
//! is rejected regardless of how the hostname was supplied.
//!
//! # Certificate verification
//!
//! The probe must succeed at the TLS handshake even when the cert is
//! expired — the whole point is to read the expiry off the leaf cert. A
//! standard rustls client rejects expired certs before exposing them, so we
//! install a no-op verifier that accepts any server cert presented during
//! the handshake, then parse the cert ourselves to judge expiry. We do not
//! send credentials over the resulting stream, and we re-validate expiry
//! against the system clock ourselves after parsing.

use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use statuscore::domain::CheckStatus;
use statuscore::domain::check::TlsCertCheck;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::parse_x509_certificate;

/// Outcome tuple shared with the other probes:
/// `(status, response_code, error)`.
type ProbeOutcome = (CheckStatus, Option<u16>, Option<String>);

/// Probe the TLS certificate at `spec.host:spec.port`.
///
/// Returns `(status, None, error)`:
/// - `Up` when `days_remaining >= warn_days`
/// - `Degraded` when `0 <= days_remaining < warn_days`
/// - `Down` when the certificate has already expired
/// - `Error` for transport / DNS / parse failures
pub async fn probe_tls_cert(spec: &TlsCertCheck) -> ProbeOutcome {
    let connector = match build_accepting_connector() {
        Ok(c) => c,
        Err(e) => {
            return (CheckStatus::Error, None, Some(format!("tls connector build: {e}")));
        }
    };

    let server_name = spec.server_name.clone().unwrap_or_else(|| spec.host.clone());
    let sni = match ServerName::try_from(server_name.clone()) {
        Ok(n) => n,
        Err(e) => {
            return (CheckStatus::Error, None, Some(format!("tls sni '{server_name}': {e}")));
        }
    };

    // Resolve + SSRF filter, then connect to the first allowed address.
    let addrs = match super::resolve_with_guard(&spec.host, spec.port).await {
        Ok(a) => a,
        Err(e) => {
            return (
                CheckStatus::Error,
                None,
                Some(format!("tls resolve '{}:{}': {e}", spec.host, spec.port)),
            );
        }
    };
    if addrs.is_empty() {
        return (
            CheckStatus::Error,
            None,
            Some(format!(
                "tls '{}:{}': every resolved address is in a blocked range",
                spec.host, spec.port
            )),
        );
    }

    let handshake = tls_handshake(&connector, sni, &addrs, spec.timeout).await;

    let leaf_der = match handshake {
        Ok(der) => der,
        Err(e) => {
            return (
                CheckStatus::Down,
                None,
                Some(format!("tls handshake '{}:{}': {e}", spec.host, spec.port)),
            );
        }
    };

    let days_remaining = match cert_days_remaining(&leaf_der) {
        Ok(d) => d,
        Err(e) => {
            return (
                CheckStatus::Error,
                None,
                Some(format!("tls cert parse '{}': {e}", spec.host)),
            );
        }
    };

    if days_remaining < 0 {
        let days_ago = -days_remaining;
        (
            CheckStatus::Down,
            None,
            Some(format!(
                "certificate for '{}:{}' expired {days_ago} day(s) ago",
                spec.host, spec.port,
            )),
        )
    } else if (days_remaining as u32) < spec.warn_days {
        (
            CheckStatus::Degraded,
            None,
            Some(format!(
                "certificate for '{}:{}' expires in {days_remaining} day(s)",
                spec.host, spec.port,
            )),
        )
    } else {
        (CheckStatus::Up, None, None)
    }
}

// ─────────────────────────── internal helpers ─────────────────────────────

/// Install rustls's ring crypto provider exactly once. Idempotent — repeated
/// calls are no-ops. Required because `tokio-rustls` 0.26 does not install a
/// default provider; without it, `ClientConfig::builder()` panics.
fn install_crypto_provider() {
    if CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// A permissive verifier that accepts any server cert. Only safe because
/// the probe's *purpose* is to inspect the cert — we do not send credentials
/// over the resulting stream, and we re-validate expiry against the system
/// clock ourselves after parsing.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Returning an empty slice makes rustls fall back to its default
        // scheme list, which is what we want — we are not actually verifying.
        Vec::new()
    }
}

/// Cached `TlsConnector` built from a `ClientConfig` that uses
/// [`AcceptAnyCert`]. The connector is cheaply-clonable and stateless, so a
/// process-wide singleton avoids rebuilding the config on every probe.
fn build_accepting_connector_once() -> Result<TlsConnector, String> {
    install_crypto_provider();
    // We deliberately skip native roots: we are not validating the chain,
    // only reading the leaf's `not_after`. Skipping root loading avoids a
    // ~50 ms native-certs read on every cold probe.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    Ok(TlsConnector::from(std::sync::Arc::new(config)))
}

static ACCEPTING_CONNECTOR: OnceLock<Result<TlsConnector, String>> = OnceLock::new();

fn build_accepting_connector() -> Result<TlsConnector, String> {
    ACCEPTING_CONNECTOR.get_or_init(build_accepting_connector_once).clone()
}

/// Drive the TLS handshake against `addrs`, trying them in order until one
/// succeeds. Returns the leaf cert DER on success.
async fn tls_handshake(
    connector: &TlsConnector,
    sni: ServerName<'static>,
    addrs: &[std::net::SocketAddr],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut last_err: Option<String> = None;
    for sa in addrs {
        let attempt = async {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(sa))
                .await
                .map_err(|_| format!("tcp connect {sa}: timeout after {} ms", timeout.as_millis()))?
                .map_err(|e| format!("tcp connect {sa}: {e}"))?;
            let stream = connector
                .connect(sni.clone(), stream)
                .await
                .map_err(|e| format!("tls handshake {sa}: {e}"))?;
            let (_, session) = stream.get_ref();
            let chain = session
                .peer_certificates()
                .ok_or_else(|| "server presented no certificate".to_string())?;
            let leaf = chain.first().ok_or_else(|| "empty peer certificate chain".to_string())?;
            Ok::<Vec<u8>, String>(leaf.as_ref().to_vec())
        };
        match attempt.await {
            Ok(der) => return Ok(der),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| "no addresses to connect to".to_string()))
}

/// Parse a DER-encoded leaf cert and return whole days until `not_after`
/// (negative if already expired).
fn cert_days_remaining(der: &[u8]) -> Result<i64, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| format!("x509 parse: {e}"))?;
    // `ASN1Time::timestamp()` returns the Unix seconds directly, avoiding
    // the `time::OffsetDateTime` → `chrono::DateTime` conversion mismatch.
    let not_after_ts = cert.validity().not_after.timestamp();
    let not_after: DateTime<Utc> = DateTime::<Utc>::from_timestamp(not_after_ts, 0)
        .ok_or_else(|| "x509 not_after: invalid timestamp".to_string())?;
    let now = Utc::now();
    Ok((not_after - now).num_days())
}
