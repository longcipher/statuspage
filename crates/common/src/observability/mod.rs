//! Observability: tracing, metrics, and per-route HTTP metrics middleware.
//!
//! Metrics are exported via OTLP/HTTP push to a configurable collector
//! (OpenObserve, Grafana Alloy, etc.). The `tracing` module installs a
//! `tracing_subscriber` fmt layer; `metrics` initialises the OTLP push
//! exporter; `http_metrics` is the per-route axum middleware that records
//! request counters, latency histograms, and the in-flight gauge.

pub mod http_metrics;
pub mod metrics;
pub mod tracing;

pub use metrics::{MetricsHandle, init as init_metrics};
pub use tracing::{TracingGuard, init as init_tracing};
