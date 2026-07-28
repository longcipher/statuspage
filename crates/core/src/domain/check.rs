use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

/// Errors raised by [`CheckSpec`] capability gating. Used by the control-plane
/// scheduler and the `POST /targets/test` handler to reject probe kinds they
/// cannot execute locally (the four "agent-only" kinds).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckSpecError {
    /// The check kind requires an agent and cannot run on the control plane.
    /// Carries the kind string (as returned by [`CheckSpec::kind`]) for
    /// diagnostic context.
    #[error("check kind '{0}' is not supported on the control plane; it requires an agent")]
    NotSupportedOnControlPlane(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckSpec {
    Http(HttpCheck),
    Tcp(TcpCheck),
    Ping(PingCheck),
    Heartbeat(HeartbeatCheck),
    TlsCert(TlsCertCheck),
    DomainExpiry(DomainExpiryCheck),
    Dns(DnsCheck),
    Flow(FlowCheck),
}

impl CheckSpec {
    /// Every kind string `kind()` can return. Bounded set — safe as a metric
    /// label and lets inventory emit a 0 for kinds with no enabled monitors.
    pub const ALL_KINDS: [&'static str; 8] =
        ["http", "tcp", "ping", "heartbeat", "dns", "tls_cert", "domain_expiry", "flow"];

    /// The subset of [`ALL_KINDS`] that the in-process control-plane scheduler
    /// can execute without a remote agent. The four agent-only kinds
    /// (`tls_cert`, `domain_expiry`, `dns`, `flow`) are excluded.
    pub const CONTROL_PLANE_KINDS: [&'static str; 4] = ["http", "tcp", "ping", "heartbeat"];

    /// Kind strings the control-plane scheduler can run locally — used by UI
    /// affordances that need to flag agent-only kinds. Mirrors
    /// [`CONTROL_PLANE_KINDS`] as a slice for call-site convenience.
    pub const fn kinds_control_plane() -> &'static [&'static str] {
        Self::CONTROL_PLANE_KINDS.as_slice()
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Tcp(_) => "tcp",
            Self::Ping(_) => "ping",
            Self::Heartbeat(_) => "heartbeat",
            Self::Dns(_) => "dns",
            Self::TlsCert(_) => "tls_cert",
            Self::DomainExpiry(_) => "domain_expiry",
            Self::Flow(_) => "flow",
        }
    }

    /// A passive kind evaluates in-memory state instead of probing the
    /// network: no circuit breaker, no host throttle, never runs on agents.
    pub const fn is_passive(&self) -> bool {
        matches!(self, Self::Heartbeat(_))
    }

    /// Returns true if this check kind can be executed on the control plane
    /// (i.e. without a remote agent). The four "agent-only" kinds —
    /// `TlsCert`, `DomainExpiry`, `Dns`, `Flow` — require capabilities the
    /// in-process scheduler does not provide and must return a
    /// "not supported" error when dispatched locally.
    pub const fn supported_on_control_plane(&self) -> bool {
        matches!(self, Self::Http(_) | Self::Tcp(_) | Self::Ping(_) | Self::Heartbeat(_))
    }

    /// Returns `Err` with a "not supported" error if this check kind cannot
    /// run on the control plane. The control-plane scheduler and the
    /// `POST /targets/test` handler MUST call this before attempting to
    /// execute a probe locally.
    pub fn require_control_plane_support(&self) -> Result<(), CheckSpecError> {
        if self.supported_on_control_plane() {
            Ok(())
        } else {
            Err(CheckSpecError::NotSupportedOnControlPlane(self.kind().to_string()))
        }
    }
}

/// Per-kind check-interval floor. Expiry state (tls_cert / domain_expiry)
/// moves slowly, so hourly minimum. Heartbeat's interval is its evaluation
/// cadence, which can't be finer than the grace it judges, so a minute floor.
pub fn min_interval_secs_for_kind(kind: &str) -> u64 {
    match kind {
        "tls_cert" | "domain_expiry" => 3_600,
        // A headless-browser run is far heavier than a single probe.
        "flow" => 300,
        "heartbeat" => 60,
        _ => 10,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExpectedStatus {
    Exact(u16),
    Range {
        #[schema(minimum = 100, maximum = 599)]
        min: u16,
        #[schema(minimum = 100, maximum = 599)]
        max: u16,
    },
    OneOf(Vec<u16>),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HttpCheck {
    #[schema(value_type = String, format = "uri", example = "https://example.com/healthz")]
    pub url: Url,
    pub method: HttpMethod,
    /// Request timeout in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 100, maximum = 60000, example = 5000)]
    pub timeout: Duration,
    pub follow_redirects: bool,
    #[schema(maximum = 10)]
    pub max_redirects: u8,
    pub expected_status: ExpectedStatus,
    #[schema(nullable = true)]
    pub expected_body_contains: Option<String>,
    pub headers: HashMap<String, String>,
    #[schema(nullable = true)]
    pub body: Option<String>,
    pub verify_tls: bool,
    /// On read, returns `["***","***"]` if set. On write, send real values or omit the field.
    #[schema(value_type = Option<[String; 2]>, nullable = true)]
    pub basic_auth: Option<(String, String)>,
    /// On read, returns `"***"` if set. On write, send real value or omit the field.
    #[schema(nullable = true)]
    pub bearer_token: Option<String>,
}

impl HttpCheck {
    /// Redirect-hop ceiling: rejected above this on write, clamped to it on probe.
    pub const MAX_REDIRECTS: u8 = 10;
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TcpCheck {
    #[schema(example = "db.example.com")]
    pub host: String,
    #[serde(default, deserialize_with = "deserialize_port")]
    #[schema(minimum = 1, maximum = 65535, example = 5432)]
    pub port: u16,
    /// Connect timeout in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 100, maximum = 60000, example = 3000)]
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PingCheck {
    #[schema(example = "gateway.example.com")]
    pub host: String,
    /// Echo-reply timeout in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 100, maximum = 60000, example = 3000)]
    pub timeout: Duration,
}

/// Inbound dead-man's-switch: the customer's system pings a token URL; the
/// scheduled evaluation opens an incident once the last ping is older than
/// `period + grace`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeartbeatCheck {
    /// Expected ping cadence in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 60000, example = 300_000)]
    pub period: Duration,
    /// Extra allowance past `period` before the monitor counts as down,
    /// in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, example = 60000)]
    pub grace: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TlsCertCheck {
    pub host: String,
    #[serde(default, deserialize_with = "deserialize_port")]
    #[schema(minimum = 1, maximum = 65535)]
    pub port: u16,
    /// SNI to send if different from `host` (e.g. when the cert is served
    /// against a virtual host name).
    #[serde(default)]
    #[schema(nullable = true)]
    pub server_name: Option<String>,
    pub warn_days: u32,
    pub critical_days: u32,
    /// Connect timeout in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64)]
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DomainExpiryCheck {
    pub domain: String,
    pub warn_days: u32,
    pub critical_days: u32,
    /// Query timeout in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64)]
    pub timeout: Duration,
}

impl DomainExpiryCheck {
    /// Registrable domain to surface in the UI, only when it actually reduces
    /// the input (`app.example.co.uk` → `example.co.uk`); an apex yields `None`.
    pub fn reduced_domain_hint(&self) -> Option<String> {
        reduced_domain_hint(&self.domain)
    }
}

/// Registrable domain (public suffix + one label) for the RDAP query. An
/// unrecognised suffix falls through normalised so the registry returns a
/// precise error instead of a silent wrong lookup.
pub fn registered_domain(domain: &str) -> String {
    resolve_registrable(&normalize_domain(domain))
}

/// Registrable domain only when it differs from the normalised input — the
/// signal that a real subdomain was reduced, for UI hints (mixed-case or a
/// trailing dot alone is not a reduction).
pub fn reduced_domain_hint(domain: &str) -> Option<String> {
    let normalized = normalize_domain(domain);
    let registered = resolve_registrable(&normalized);
    (registered != normalized).then_some(registered)
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn resolve_registrable(normalized: &str) -> String {
    psl::domain_str(normalized).map_or_else(|| normalized.to_owned(), str::to_owned)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
    Ptr,
    Caa,
    Srv,
}

impl DnsRecordType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Caa => "CAA",
            Self::Srv => "SRV",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DnsCheck {
    /// Name to resolve (FQDN; trailing dot tolerated).
    #[schema(example = "api.example.com")]
    pub domain: String,
    pub record_type: DnsRecordType,
    /// Optional custom resolver as `ip` or `ip:port` (e.g. `1.1.1.1`,
    /// `8.8.8.8:53`). `None` uses the process default resolver.
    #[serde(default)]
    #[schema(nullable = true, example = "1.1.1.1")]
    pub resolver: Option<String>,
    /// Optional substring that must appear in at least one answer value.
    /// Empty answers, NXDOMAIN, or a missing substring all fail the check.
    #[serde(default)]
    #[schema(nullable = true, example = "192.0.2.1")]
    pub expected_contains: Option<String>,
    /// Query timeout in milliseconds.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 100, maximum = 60000, example = 3000)]
    pub timeout: Duration,
}

/// A browser-driven login/transaction flow: a step sequence replayed against a
/// real page through a headless engine. It carries cookies across steps and runs
/// page JavaScript, so it verifies a login *session* (form → submit →
/// authenticated page), not just that a login endpoint responds.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FlowCheck {
    #[schema(value_type = String, format = "uri", example = "https://app.example.com/login")]
    pub start_url: Url,
    pub steps: Vec<FlowStep>,
    /// Whole-flow budget.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 1000, maximum = 120_000, example = 30000)]
    pub timeout: Duration,
    /// Per-step wait for a selector to appear.
    #[serde(with = "duration_ms")]
    #[schema(value_type = u64, minimum = 100, maximum = 60000, example = 5000)]
    pub step_timeout: Duration,
    pub verify_tls: bool,
}

impl FlowCheck {
    pub const MAX_STEPS: usize = 30;
}

/// One action in a [`FlowCheck`]. `Fill.value` may carry a `{{secret}}` token
/// resolved at probe time; every other field is literal.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FlowStep {
    Goto {
        #[schema(value_type = String, format = "uri")]
        url: Url,
    },
    Click {
        selector: String,
    },
    Fill {
        selector: String,
        value: String,
    },
    WaitFor {
        selector: String,
    },
    /// Assert that a substring is present, optionally scoped to a selector's
    /// text rather than the whole page.
    AssertText {
        #[schema(nullable = true)]
        selector: Option<String>,
        contains: String,
    },
    AssertUrl {
        contains: String,
    },
}

// Null or absent port becomes 0 so port validation flags it, not serde.
fn deserialize_port<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
    Ok(Option::<u16>::deserialize(d)?.unwrap_or(0))
}

mod duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Duration::from_millis(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Adding a CheckSpec variant breaks this exhaustive match, forcing ALL_KINDS
    // (and the count asserted below) to be updated in the same change.
    #[expect(dead_code)]
    fn variant_guard(spec: &CheckSpec) {
        match spec {
            CheckSpec::Http(_)
            | CheckSpec::Tcp(_)
            | CheckSpec::Ping(_)
            | CheckSpec::Heartbeat(_)
            | CheckSpec::Dns(_)
            | CheckSpec::TlsCert(_)
            | CheckSpec::DomainExpiry(_)
            | CheckSpec::Flow(_) => {}
        }
    }

    #[test]
    fn all_kinds_unique_and_complete() {
        let mut seen = std::collections::HashSet::new();
        for k in CheckSpec::ALL_KINDS {
            assert!(seen.insert(k), "duplicate kind in ALL_KINDS: {k}");
        }
        assert_eq!(CheckSpec::ALL_KINDS.len(), 8);
    }

    #[test]
    fn control_plane_kinds_exclude_agent_only_variants() {
        // The four agent-only kinds must be absent from the control-plane set.
        assert_eq!(CheckSpec::kinds_control_plane().len(), 4);
        for agent_only in ["dns", "tls_cert", "domain_expiry", "flow"] {
            assert!(
                !CheckSpec::CONTROL_PLANE_KINDS.contains(&agent_only),
                "agent-only kind '{agent_only}' must not be control-plane supported"
            );
        }
    }

    #[test]
    fn require_control_plane_support_accepts_local_kinds() {
        let tcp = CheckSpec::Tcp(TcpCheck {
            host: "db.example.com".into(),
            port: 5432,
            timeout: Duration::from_secs(3),
        });
        assert!(tcp.supported_on_control_plane());
        assert!(tcp.require_control_plane_support().is_ok());

        let ping = CheckSpec::Ping(PingCheck {
            host: "gw.example.com".into(),
            timeout: Duration::from_secs(3),
        });
        assert!(ping.supported_on_control_plane());
        assert!(ping.require_control_plane_support().is_ok());
    }

    #[test]
    fn require_control_plane_support_rejects_agent_only_kinds() {
        let dns = CheckSpec::Dns(DnsCheck {
            domain: "api.example.com".into(),
            record_type: DnsRecordType::A,
            resolver: None,
            expected_contains: None,
            timeout: Duration::from_secs(3),
        });
        assert!(!dns.supported_on_control_plane());
        let err = dns.require_control_plane_support().unwrap_err();
        assert!(
            err.to_string().contains("not supported on the control plane"),
            "unexpected error message: {err}"
        );
        assert!(err.to_string().contains("dns"));

        let tls = CheckSpec::TlsCert(TlsCertCheck {
            host: "api.example.com".into(),
            port: 443,
            server_name: None,
            warn_days: 30,
            critical_days: 7,
            timeout: Duration::from_secs(3),
        });
        assert!(!tls.supported_on_control_plane());
        assert!(matches!(
            tls.require_control_plane_support(),
            Err(CheckSpecError::NotSupportedOnControlPlane(_))
        ));
    }

    #[test]
    fn registered_domain_reduces_subdomains() {
        assert_eq!(registered_domain("app.example.dev"), "example.dev");
        assert_eq!(registered_domain("example.dev"), "example.dev");
        assert_eq!(registered_domain("fra.my-app.com"), "my-app.com");
    }

    #[test]
    fn registered_domain_keeps_multi_level_suffixes_intact() {
        assert_eq!(registered_domain("shop.com.ua"), "shop.com.ua");
        assert_eq!(registered_domain("www.shop.com.ua"), "shop.com.ua");
        assert_eq!(registered_domain("sub.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn registered_domain_normalises_case_and_trailing_dot() {
        assert_eq!(registered_domain("APP.Statuspage.DEV."), "statuspage.dev");
    }

    #[test]
    fn reduced_domain_hint_none_for_apex_or_normalisation_only() {
        assert_eq!(reduced_domain_hint("example.com"), None);
        assert_eq!(reduced_domain_hint("Example.com."), None);
        assert_eq!(reduced_domain_hint("  example.co.uk  "), None);
    }

    #[test]
    fn reduced_domain_hint_some_for_real_subdomain() {
        assert_eq!(reduced_domain_hint("app.example.com").as_deref(), Some("example.com"));
        assert_eq!(reduced_domain_hint("www.shop.com.ua").as_deref(), Some("shop.com.ua"));
    }

    #[test]
    fn tcp_port_null_or_missing_deserialises_to_zero() {
        let null_port: CheckSpec = serde_json::from_str(
            r#"{"type":"tcp","host":"db.example.com","port":null,"timeout":3000}"#,
        )
        .unwrap();
        let missing_port: CheckSpec =
            serde_json::from_str(r#"{"type":"tcp","host":"db.example.com","timeout":3000}"#)
                .unwrap();
        let real_port: CheckSpec = serde_json::from_str(
            r#"{"type":"tcp","host":"db.example.com","port":5432,"timeout":3000}"#,
        )
        .unwrap();
        assert!(matches!(null_port, CheckSpec::Tcp(TcpCheck { port: 0, .. })));
        assert!(matches!(missing_port, CheckSpec::Tcp(TcpCheck { port: 0, .. })));
        assert!(matches!(real_port, CheckSpec::Tcp(TcpCheck { port: 5432, .. })));
    }
}
