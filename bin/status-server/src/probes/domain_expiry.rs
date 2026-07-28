#![expect(dead_code)]
// Agent-only probe: the control plane rejects these check kinds via
// `require_control_plane_support()` before reaching this code. Kept as
// the implementation site for a future agent runtime.

//! Domain expiry probe (RDAP).
//!
//! Queries the IANA RDAP bootstrap for the registrable domain, extracts the
//! registrar's expiration date, and reports Up/Degraded/Down based on the
//! days until expiry.
//!
//! # Stale-cache fallback
//!
//! RDAP servers rate-limit (HTTP 429) and occasionally return transient
//! 5xx errors. To avoid a false "down" on a transient RDAP outage, the
//! probe caches the last-good [`DomainExpiryState`] in storage and serves
//! it (with a `served_stale:` prefix on the error string) when a fresh
//! query fails. The prefix is the operator-only annotation stripped by
//! [`statuscore::domain::strip_served_stale`] before any customer-facing
//! render.

use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use statuscore::domain::check::{DomainExpiryCheck, registered_domain};
use statuscore::domain::result::SERVED_STALE_PREFIX;
use statuscore::domain::{CheckStatus, DomainExpiryState};
use storage::Storage;
use uuid::Uuid;

/// Outcome tuple shared with the other probes:
/// `(status, response_code, error)`.
type ProbeOutcome = (CheckStatus, Option<u16>, Option<String>);

/// Hard ceiling on RDAP queries — 15 s covers the slowest registries (.br,
/// .cn) under load without pinning a scheduler worker indefinitely.
const RDAP_TIMEOUT: Duration = Duration::from_secs(15);

/// Short backoff when an RDAP server returns 429 (Too Many Requests). Long
/// enough to let the registry bucket refill, short enough to fit inside the
/// overall probe budget.
const RATE_LIMIT_BACKOFF: Duration = Duration::from_millis(750);

/// Probe the domain expiry for `spec.domain`.
///
/// On a successful RDAP query the cached [`DomainExpiryState`] is refreshed.
/// On a transient failure (network, 429, 5xx) the cached state is served
/// with a `served_stale:` prefix on the error string. When there is no
/// cached state to fall back to, the probe returns `Error`.
pub async fn probe_domain_expiry(
    storage: &dyn Storage,
    target_id: Uuid,
    spec: &DomainExpiryCheck,
) -> ProbeOutcome {
    let domain = registered_domain(&spec.domain);

    match query_rdap(&domain).await {
        Ok(info) => {
            // Refresh the cached state so the next stale fallback has data.
            let state = DomainExpiryState {
                target_id,
                domain: domain.clone(),
                expires_at: info.expires_at,
                registrar: info.registrar.clone(),
                fetched_at: Utc::now(),
            };
            if let Err(e) = storage.set_domain_expiry_state(&state).await {
                tracing::warn!(
                    target_id = %target_id,
                    domain = %domain,
                    error = %e,
                    "domain_expiry: failed to persist cached state"
                );
            }
            evaluate(&domain, info.expires_at, info.registrar.as_deref(), spec.warn_days, None)
        }
        Err(e) => {
            // Transient RDAP failure — try to serve the cached state.
            match storage.get_domain_expiry_state(target_id).await {
                Ok(Some(cached)) => {
                    let age_days = (Utc::now() - cached.fetched_at).num_days().max(0);
                    let stale_error = format!(
                        "{SERVED_STALE_PREFIX} age={age_days}d; {{\"domain\":\"{domain}\",\"rdap_error\":\"{e}\"}}"
                    );
                    evaluate(
                        &cached.domain,
                        cached.expires_at,
                        cached.registrar.as_deref(),
                        spec.warn_days,
                        Some(stale_error),
                    )
                }
                Ok(None) => (
                    CheckStatus::Error,
                    None,
                    Some(format!("rdap '{domain}' failed and no cached state: {e}")),
                ),
                Err(storage_err) => (
                    CheckStatus::Error,
                    None,
                    Some(format!(
                        "rdap '{domain}' failed ({e}) and cache read failed: {storage_err}"
                    )),
                ),
            }
        }
    }
}

/// Per-query RDAP result: the registrar's expiration date (when known) and
/// the registrar's display name (when known). Either may be `None` if the
/// registry's RDAP response omits the field.
struct RdapInfo {
    expires_at: Option<NaiveDate>,
    registrar: Option<String>,
}

/// Query `https://rdap.org/domain/<domain>` and parse the expiry date and
/// registrar out of the response. `rdap.org` is the IANA-recommended
/// bootstrap that redirects (HTTP 302) to the authoritative registry RDAP
/// server for the TLD, so we don't need a per-TLD bootstrap table here.
async fn query_rdap(domain: &str) -> Result<RdapInfo, String> {
    let client = reqwest::Client::builder()
        .timeout(RDAP_TIMEOUT)
        .user_agent("statuspage-domain-expiry/1.0 (+https://github.com/longcipher/statuspage)")
        .build()
        .map_err(|e| format!("client build: {e}"))?;

    let url = format!("https://rdap.org/domain/{domain}");

    // One retry on 429 — RDAP rate limits are short, the backoff is enough
    // for the bucket to refill for a single request.
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("GET {url}: {e}")),
    };
    let resp = if resp.status().as_u16() == 429 {
        tokio::time::sleep(RATE_LIMIT_BACKOFF).await;
        match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Err(format!("GET {url} (retry after 429): {e}")),
        }
    } else {
        resp
    };

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}"));
    }

    // reqwest 0.13 in this workspace does not enable the `json` feature, so
    // we read the body to a string and parse with serde_json.
    let body = resp.text().await.map_err(|e| format!("GET {url}: body read: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("GET {url}: json parse: {e}"))?;

    Ok(parse_rdap_response(&value))
}

/// Pull the expiration date and registrar name out of a parsed RDAP response.
///
/// RDAP shape (RFC 7483):
/// ```jsonc
/// {
///   "events": [
///     { "eventAction": "expiration", "eventDate": "2025-12-31T23:59:59Z" }
///   ],
///   "entities": [
///     {
///       "roles": ["registrar"],
///       "vcardArray": [ "vcard", [ ["version", {}, "text", "4.0"],
///                                  ["fn", {}, "text", "Example Registrar"] ] ]
///     }
///   ]
/// }
/// ```
fn parse_rdap_response(value: &serde_json::Value) -> RdapInfo {
    let expires_at = value
        .get("events")
        .and_then(serde_json::Value::as_array)
        .and_then(|events| {
            events.iter().find_map(|ev| {
                let action = ev.get("eventAction").and_then(serde_json::Value::as_str)?;
                if action == "expiration" {
                    ev.get("eventDate").and_then(serde_json::Value::as_str)
                } else {
                    None
                }
            })
        })
        .and_then(parse_rdap_date);

    let registrar =
        value.get("entities").and_then(serde_json::Value::as_array).and_then(|entities| {
            entities.iter().find_map(|entity| {
                let roles = entity.get("roles").and_then(serde_json::Value::as_array)?;
                if !roles.iter().any(|r| r.as_str().is_some_and(|s| s == "registrar")) {
                    return None;
                }
                entity_name_from_vcard(entity)
            })
        });

    RdapInfo { expires_at, registrar }
}

/// Extract the `fn` (full name) field from a vCard array. The vCard array
/// is `[ "vcard", [ ["version", ...], ["fn", {}, "text", "Name"], ... ] ]`.
fn entity_name_from_vcard(entity: &serde_json::Value) -> Option<String> {
    let vcard_array = entity.get("vcardArray").and_then(serde_json::Value::as_array)?;
    // First element is the literal "vcard"; second is the array of properties.
    let props = vcard_array.get(1).and_then(serde_json::Value::as_array)?;
    for prop in props {
        let prop_arr = prop.as_array()?;
        // Each property is [name, params, type, value, ...].
        let name = prop_arr.first().and_then(serde_json::Value::as_str)?;
        if name == "fn" {
            // The value is the 4th element (index 3) for `text`-typed props.
            if let Some(value) = prop_arr.get(3) {
                if let Some(s) = value.as_str() {
                    return Some(s.to_owned());
                }
                // Some registries put the value in an array: ["text", "Name"].
                if let Some(arr) = value.as_array()
                    && let Some(s) = arr.iter().find_map(serde_json::Value::as_str)
                {
                    return Some(s.to_owned());
                }
            }
        }
    }
    None
}

/// Parse an RDAP `eventDate` (RFC 3339 / ISO 8601) into a `NaiveDate`. RDAP
/// dates are full RFC 3339 timestamps (`2025-12-31T23:59:59Z`); we discard
/// the time because the warning threshold is in days, not seconds.
fn parse_rdap_date(s: &str) -> Option<NaiveDate> {
    // Try the full RFC 3339 parse first (handles the `Z`/offset forms), then
    // fall back to a plain date for registries that emit only `YYYY-MM-DD`.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.date_naive());
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

/// Build the probe outcome from a known expiry date. When `stale_error` is
/// `Some`, the cached state is being served — the status is computed from
/// the cached expiry, and the error string carries the `served_stale:`
/// annotation so renderers can strip it for customers.
fn evaluate(
    domain: &str,
    expires_at: Option<NaiveDate>,
    registrar: Option<&str>,
    warn_days: u32,
    stale_error: Option<String>,
) -> ProbeOutcome {
    let Some(expiry) = expires_at else {
        // No expiry known — even a fresh RDAP query may not return one for
        // ccTLDs that don't expose expiry through RDAP. Treat as Error so
        // the operator notices and switches to a different probe.
        let detail =
            registrar.map_or_else(|| "no registrar".to_string(), |r| format!("registrar={r}"));
        let msg = format!("rdap '{domain}': no expiration date ({detail})");
        return (CheckStatus::Error, None, Some(msg));
    };

    let today = Utc::now().date_naive();
    let days_remaining = (expiry - today).num_days();

    let registrar_suffix = registrar.map(|r| format!(" (registrar: {r})")).unwrap_or_default();

    if days_remaining < 0 {
        let days_ago = -days_remaining;
        let msg = format!("domain '{domain}' expired {days_ago} day(s) ago{registrar_suffix}");
        let error = match stale_error {
            Some(s) => format!("{s}; expired {days_ago}d ago"),
            None => msg,
        };
        (CheckStatus::Down, None, Some(error))
    } else if (days_remaining as u32) < warn_days {
        let msg = format!("domain '{domain}' expires in {days_remaining} day(s){registrar_suffix}");
        let error = match stale_error {
            Some(s) => format!("{s}; expires in {days_remaining}d"),
            None => msg,
        };
        (CheckStatus::Degraded, None, Some(error))
    } else {
        // Up — but if we are serving stale, surface that as a Degraded so
        // the operator notices the RDAP path is broken even though the
        // cached expiry still looks healthy.
        match stale_error {
            Some(s) => (CheckStatus::Degraded, None, Some(s)),
            None => (CheckStatus::Up, None, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rdap_response_extracts_expiry_and_registrar() {
        let raw = r#"{
            "events": [
                {"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},
                {"eventAction":"expiration","eventDate":"2099-12-31T23:59:59Z"}
            ],
            "entities": [
                {"roles":["registrar"],
                 "vcardArray":["vcard",[["version",{},"text","4.0"],
                                        ["fn",{},"text","Example Registrar, LLC"],
                                        ["org",{},"text","Example Registrar"]]]}
            ]
        }"#;
        let value: serde_json::Value = serde_json::from_str(raw).unwrap();
        let info = parse_rdap_response(&value);
        assert_eq!(info.expires_at, NaiveDate::from_ymd_opt(2099, 12, 31));
        assert_eq!(info.registrar.as_deref(), Some("Example Registrar, LLC"));
    }

    #[test]
    fn parse_rdap_response_handles_date_only_event() {
        let raw = r#"{"events":[{"eventAction":"expiration","eventDate":"2030-06-15"}]}"#;
        let value: serde_json::Value = serde_json::from_str(raw).unwrap();
        let info = parse_rdap_response(&value);
        assert_eq!(info.expires_at, NaiveDate::from_ymd_opt(2030, 6, 15));
        assert!(info.registrar.is_none());
    }

    #[test]
    fn parse_rdap_response_missing_events_returns_none() {
        let raw = r#"{"ldhName":"example.com"}"#;
        let value: serde_json::Value = serde_json::from_str(raw).unwrap();
        let info = parse_rdap_response(&value);
        assert!(info.expires_at.is_none());
        assert!(info.registrar.is_none());
    }

    #[test]
    fn evaluate_up_when_far_from_expiry() {
        let expiry = Utc::now().date_naive() + chrono::Duration::days(365);
        let (status, _, error) = evaluate("example.com", Some(expiry), Some("ACME"), 30, None);
        assert_eq!(status, CheckStatus::Up);
        assert!(error.is_none());
    }

    #[test]
    fn evaluate_degraded_when_inside_warn_window() {
        let expiry = Utc::now().date_naive() + chrono::Duration::days(10);
        let (status, _, error) = evaluate("example.com", Some(expiry), None, 30, None);
        assert_eq!(status, CheckStatus::Degraded);
        let error = error.unwrap();
        assert!(error.contains("expires in 10"));
    }

    #[test]
    fn evaluate_down_when_expired() {
        let expiry = Utc::now().date_naive() - chrono::Duration::days(5);
        let (status, _, error) = evaluate("example.com", Some(expiry), None, 30, None);
        assert_eq!(status, CheckStatus::Down);
        let error = error.unwrap();
        assert!(error.contains("expired 5"));
    }

    #[test]
    fn evaluate_stale_falls_back_to_degraded_when_otherwise_up() {
        let expiry = Utc::now().date_naive() + chrono::Duration::days(365);
        let (status, _, error) = evaluate(
            "example.com",
            Some(expiry),
            None,
            30,
            Some("served_stale: age=2d; {}".to_string()),
        );
        // Stale fallback surfaces as Degraded even when expiry is far away,
        // so the operator notices the RDAP path is broken.
        assert_eq!(status, CheckStatus::Degraded);
        let error = error.unwrap();
        assert!(error.starts_with("served_stale:"));
    }

    #[test]
    fn evaluate_error_when_no_expiry_known() {
        let (status, _, error) = evaluate("example.com", None, None, 30, None);
        assert_eq!(status, CheckStatus::Error);
        assert!(error.unwrap().contains("no expiration date"));
    }
}
