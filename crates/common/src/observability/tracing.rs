//! Tracing subscriber initialisation.
//!
//! Simplified from the original crate: OpenTelemetry / OTLP trace export is
//! intentionally NOT ported — this build ships `tracing` + `metrics` only.
//! What remains is a `tracing_subscriber` fmt layer driven by
//! [`statuscore::config::ObservabilityConfig`] (log level + JSON/pretty format).
//!
//! `TracingGuard` is retained as a no-op handle so callers (`main`) keep a
//! symmetric init/shutdown shape with the metrics exporter; there is no
//! provider to flush here.

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use statuscore::config::ObservabilityConfig;

/// Held by `main` for the process lifetime. No-op in this build (no OTLP
/// provider to flush); retained so the boot sequence stays symmetric with
/// [`crate::observability::metrics::MetricsHandle`] and so a future build
/// that re-adds trace export can plug in a real shutdown without churning
/// call sites.
///
/// `#[must_use]` is intentionally omitted: `shutdown` is a no-op in this
/// build (the fmt layer writes synchronously, no batched flush), so dropping
/// the guard without calling `shutdown` is harmless. Adding `#[must_use]`
/// would force every caller to spell out a meaningless `let _ = guard;`,
/// adding noise without preventing a real failure.
#[derive(Debug)]
pub struct TracingGuard;

impl TracingGuard {
    /// No-op: the fmt layer writes synchronously, no batched flush needed.
    /// Retained so `main`'s shutdown path mirrors the metrics handle.
    pub const fn shutdown(self) {
        // intentionally empty
    }
}

pub fn init(cfg: &ObservabilityConfig) -> TracingGuard {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));

    let fmt_layer = match cfg.log_format {
        statuscore::config::LogFormat::Json => fmt::layer().json().boxed(),
        statuscore::config::LogFormat::Pretty => fmt::layer().pretty().boxed(),
    };

    tracing_subscriber::registry().with(filter).with(fmt_layer).init();

    // Warn loudly when an operator has enabled tracing in config but this
    // build does not ship the OTLP exporter. Without this the config is a
    // silent footgun: `validate_observability()` passes, the server boots,
    // but no spans are ever exported.
    if cfg.tracing_enabled {
        tracing::warn!(
            "tracing_enabled = true but OTLP export is not compiled into this build; \
             spans will NOT be exported. Set tracing_enabled = false or rebuild with \
             the opentelemetry-otlp feature (not yet available)."
        );
    }

    tracing::debug!("tracing subscriber installed (fmt only, no otlp export)");

    TracingGuard
}
