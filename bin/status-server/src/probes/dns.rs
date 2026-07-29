//! DNS resolution probe.
//!
//! Resolves `spec.domain` for `spec.record_type` and reports Up when at
//! least one answer record contains `spec.expected_contains` (when set) or
//! when any answer is returned (when `expected_contains` is unset). An
//! NXDOMAIN, timeout, or missing-substring all fail the check.
//!
//! # Resolver selection
//!
//! When `spec.resolver` is `None`, the probe uses a fresh system-default
//! resolver (read of `/etc/resolv.conf` on Unix). When set to an `ip` or
//! `ip:port` string, the probe builds a one-shot resolver pointed at that
//! nameserver via [`common::http_client::build_single_resolver`] — bypassing
//! the system resolver so the probe measures *that* resolver's view.

use std::time::Duration;

use hickory_resolver::TokioResolver;
use statuscore::domain::CheckStatus;
use statuscore::domain::check::{DnsCheck, DnsRcode, DnsRecordType};

/// Outcome tuple shared with the other probes:
/// `(status, response_code, error)`.
type ProbeOutcome = (CheckStatus, Option<u16>, Option<String>);

/// Probe the DNS records for `spec.domain`.
///
/// Returns `(status, None, error)`:
/// - `Up` when records resolve, RCODE matches, and (when set) at least one
///   contains `expected_contains` as a substring
/// - `Down` on NXDOMAIN, wrong RCODE, timeout, missing substring, or empty answer
/// - `Error` for resolver construction failures
pub async fn probe_dns(spec: &DnsCheck) -> ProbeOutcome {
    let resolver = match build_resolver(&spec.resolver, spec.timeout) {
        Ok(r) => r,
        Err(e) => {
            let detail = match &spec.resolver {
                Some(addr) => format!("dns resolver '{addr}': {e}"),
                None => format!("dns resolver system: {e}"),
            };
            return (CheckStatus::Error, None, Some(detail));
        }
    };

    // Use the standard lookup API. For RCODE checking, we extract the
    // response code from the error when the query fails (NXDOMAIN, SERVFAIL).
    let record_type = map_record_type(spec.record_type);
    let lookup = match resolver.lookup(&spec.domain, record_type).await {
        Ok(l) => l,
        Err(e) => {
            // If an RCODE was expected (e.g. NXDOMAIN), check if the error
            // matches that expectation.
            if let Some(expected) = spec.expected_rcode {
                let expected_str = format!("{expected:?}").to_uppercase();
                let err_str = format!("{e}").to_uppercase();
                if err_str.contains(&expected_str)
                    || (expected == DnsRcode::Nxdomain && err_str.contains("NXDOMAIN"))
                {
                    return (CheckStatus::Up, None, None);
                }
                return (
                    CheckStatus::Down,
                    None,
                    Some(format!("dns '{}': expected {:?}, got error: {e}", spec.domain, expected)),
                );
            }
            return (
                CheckStatus::Down,
                None,
                Some(format!("dns resolve '{}' {}: {e}", spec.domain, spec.record_type.as_str())),
            );
        }
    };

    // If expected_rcode is set and we got a successful response, verify
    // it matches NOERROR.
    if let Some(expected) = spec.expected_rcode {
        if expected != DnsRcode::Noerror {
            return (
                CheckStatus::Down,
                None,
                Some(format!("dns '{}': expected {:?}, got NOERROR", spec.domain, expected)),
            );
        }
    }

    // Collect answers.
    let answers: Vec<String> = lookup
        .answers()
        .iter()
        .map(|record| record.data.to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if answers.is_empty() {
        return (
            CheckStatus::Down,
            None,
            Some(format!(
                "dns '{}': no {} records in answer",
                spec.domain,
                spec.record_type.as_str()
            )),
        );
    }

    match &spec.expected_contains {
        Some(needle) if !needle.is_empty() => {
            let matched = answers.iter().any(|a| a.contains(needle.as_str()));
            if matched {
                (CheckStatus::Up, None, None)
            } else {
                (
                    CheckStatus::Down,
                    None,
                    Some(format!(
                        "dns '{}': no {} record contains '{}'",
                        spec.domain,
                        spec.record_type.as_str(),
                        needle
                    )),
                )
            }
        }
        _ => (CheckStatus::Up, None, None),
    }
}

/// Map the domain [`DnsRecordType`] enum onto hickory's [`RecordType`].
const fn map_record_type(rt: DnsRecordType) -> hickory_resolver::proto::rr::RecordType {
    use hickory_resolver::proto::rr::RecordType;
    match rt {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::Cname => RecordType::CNAME,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Soa => RecordType::SOA,
        DnsRecordType::Ptr => RecordType::PTR,
        DnsRecordType::Caa => RecordType::CAA,
        DnsRecordType::Srv => RecordType::SRV,
        // `DnsRecordType` is #[non_exhaustive]; unknown record types fall
        // back to A (defensive — the probe resolves and reports findings).
        _ => RecordType::A,
    }
}

/// Build the resolver. When `addr` is `None`, use the system default
/// (reads `/etc/resolv.conf` on Unix). When `addr` is `Some`, build a
/// one-shot resolver pointed at that nameserver via the shared
/// [`common::http_client::build_single_resolver`] so the probe measures
/// *that* resolver's view of the zone.
fn build_resolver(addr: &Option<String>, timeout: Duration) -> Result<TokioResolver, String> {
    if let Some(addr_str) = addr {
        common::http_client::build_single_resolver(addr_str, timeout)
            .map_err(|e| format!("build single resolver: {e}"))
    } else {
        // System-default resolver. `ResolverConfig::default()` reads
        // `/etc/resolv.conf` (or the platform equivalent) and applies
        // the OS defaults. Mirrors the construction in
        // `common::http_client::dns::HickoryDnsResolver::new`.
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.try_tcp_on_error = true;
        hickory_resolver::Resolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .build()
        .map_err(|e| format!("system resolver build: {e}"))
    }
}
