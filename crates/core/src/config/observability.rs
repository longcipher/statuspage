use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::empty_secret;
use super::secret_str;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityConfig {
    pub log_level: String,
    pub log_format: LogFormat,
    pub metrics_enabled: bool,
    /// Master on/off for OpenTelemetry trace export. Export is active
    /// only when this AND `openobserve.enabled` are true.
    pub tracing_enabled: bool,
    #[serde(default)]
    pub openobserve: OpenObserveConfig,
    #[serde(default = "default_gauge_sample_interval_ms")]
    pub gauge_sample_interval_ms: u64,
    /// OTLP/HTTP endpoint for metrics push (e.g. `http://localhost:4317`).
    /// When empty, falls back to `openobserve.otlp_endpoint` if set.
    #[serde(default)]
    pub metrics_otlp_endpoint: String,
    /// How often to push metrics to the OTLP endpoint, in seconds.
    #[serde(default = "default_metrics_push_interval_secs")]
    pub metrics_push_interval_secs: u64,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

const fn default_gauge_sample_interval_ms() -> u64 {
    1000
}

const fn default_metrics_push_interval_secs() -> u64 {
    60
}

const fn default_trace_sample_ratio() -> f64 {
    // Capture every trace by default: request volume is low and a head
    // sample rate that drops 95% of an already-sparse stream leaves the
    // trace view effectively empty. Lower this once volume justifies the
    // ingest cost.
    1.0
}

/// OTLP trace/metrics export to OpenObserve (or any OTLP/HTTP collector).
/// Credentials never live in TOML — `api_key` is sourced only from
/// `STATUSPAGE_OBSERVABILITY__OPENOBSERVE__API_KEY`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OpenObserveConfig {
    #[serde(default)]
    pub enabled: bool,
    /// OTLP/HTTP base, no signal suffix (e.g.
    /// `http://localhost:5080/api/default`). The service
    /// appends `/v1/traces` (a value already ending in it is left as-is).
    #[serde(default)]
    pub otlp_endpoint: String,
    /// OpenObserve org name used as the basic-auth username prefix.
    #[serde(default)]
    pub instance_id: String,
    #[serde(default = "empty_secret", with = "secret_str")]
    pub api_key: SecretString,
    /// Head sampling ratio applied under a parent-based sampler.
    #[serde(default = "default_trace_sample_ratio")]
    pub trace_sample_ratio: f64,
}

impl Default for OpenObserveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: String::new(),
            instance_id: String::new(),
            api_key: empty_secret(),
            trace_sample_ratio: default_trace_sample_ratio(),
        }
    }
}

/// External dead-man's-switch heartbeat. The app pings `url` on an interval
/// *only while every critical dependency is reachable*; an independent
/// watcher (Healthchecks.io, Dead Man's Snitch, OpenObserve heartbeat)
/// alerts when the pings stop. This is the one signal that survives the whole
/// box dying — the in-app metrics/alert path can't page when it's the thing
/// that's down. `url` carries a capability token, so it is env-sourced
/// (`STATUSPAGE_OBSERVABILITY__HEARTBEAT__URL`) and never logged.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeartbeatConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_heartbeat_interval_seconds")]
    pub interval_seconds: u64,
}

const fn default_heartbeat_interval_seconds() -> u64 {
    60
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            interval_seconds: default_heartbeat_interval_seconds(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}
