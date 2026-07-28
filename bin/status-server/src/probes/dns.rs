#![expect(dead_code)]
// Agent-only probe: the control plane rejects these check kinds via
// `require_control_plane_support()` before reaching this code. Kept as
// the implementation site for a future agent runtime.

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
use statuscore::domain::check::{DnsCheck, DnsRecordType};

/// Outcome tuple shared with the other probes:
/// `(status, response_code, error)`.
type ProbeOutcome = (CheckStatus, Option<u16>, Option<String>);

/// Probe the DNS records for `spec.domain`.
///
/// Returns `(status, None, error)`:
/// - `Up` when records resolve and (when set) at least one contains
///   `expected_contains` as a substring
/// - `Down` on NXDOMAIN, timeout, missing substring, or empty answer
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

    let record_type = map_record_type(spec.record_type);
    let lookup = match resolver.lookup(&spec.domain, record_type).await {
        Ok(l) => l,
        Err(e) => {
            return (
                CheckStatus::Down,
                None,
                Some(format!("dns resolve '{}' {}: {e}", spec.domain, spec.record_type.as_str())),
            );
        }
    };

    // Collect the string forms of each answer record. We format the record
    // *data* (not the whole `name TTL IN TYPE value` line) so an operator
    // can put the expected IP / hostname in `expected_contains` and have it
    // match regardless of the TTL the resolver cached.
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
