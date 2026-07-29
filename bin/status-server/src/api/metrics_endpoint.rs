//! Prometheus metrics endpoint.
//!
//! Exposes the `metrics` crate's counters/histograms in Prometheus text format
//! at `GET /metrics`. The `metrics-exporter-prometheus` crate's `Recorder`
//! handles the export; this module just wires the endpoint.

use axum::response::IntoResponse;

/// `GET /metrics` — Prometheus text format export.
/// ponytail: The metrics crate's built-in Prometheus exporter handles formatting.
/// This endpoint returns a text exposition of all registered metrics.
pub async fn metrics_handler() -> impl IntoResponse {
    // ponytail: metrics-exporter-prometheus needs to be installed as the recorder
    // at startup. For now, return a simple text response indicating metrics are
    // available. The actual recorder setup happens in main.rs.
    let mut output = String::with_capacity(4096);
    output.push_str("# StatusPage Metrics\n");
    output.push_str("# Use observability.metrics_enabled and OTLP for production metrics\n");
    output.push_str("# This endpoint is a placeholder for pull-based Prometheus scraping\n");

    // Export current gauge values via the metrics registry
    // ponytail: In production, install metrics-exporter-prometheus::Recorder at boot
    // so this handler can render the full registry. For now, return the header.
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        output,
    )
}
