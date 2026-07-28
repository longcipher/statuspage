//! HTTP client stack for StatusPage.
//!
//! Two distinct clients live here:
//!
//! * [`client::HttpClients`] — shared handles for the check path: the
//!   Hickory DNS resolver, SSRF guard, and `User-Agent` string.
//!
//! * [`outbound::OutboundHttpClient`] — shared HTTPS client for non-check
//!   traffic (notification webhooks, RDAP lookups). Uses
//!   [`crate::security::SsrfHttpConnector`] so a webhook URL pointing at a
//!   private IP is dropped at DNS-filter time before any TCP open. Distinct
//!   from the check-path client: its connector does not record the per-probe
//!   histograms (which would poison check metrics when emitted from
//!   non-check paths).
//!
//! Both clients enforce SSRF defence — resolved IPs go through
//! [`crate::security::SsrfGuard`] before any TCP open — and use Happy Eyeballs
//! v2 (RFC 8305) to race v6/v4 connects.

pub mod client;
pub mod dns;
pub mod outbound;

pub use client::{HttpClients, build_clients};
pub use dns::{HickoryDnsResolver, build_single_resolver, parse_resolver_addr};
pub use outbound::{
    OutboundHttpClient, build_outbound_client, get_json, get_ok, post_bytes_with_headers,
    post_form_with_headers, post_json, post_json_capture, post_json_with_headers, post_text,
};
