use serde::{Deserialize, Serialize};

/// `[storage]`. DuckDB-backed storage. A single embedded database holds
/// both OLTP and time-series data. The DuckDB storage layer uses a single
/// connection, so there are no pool/batch knobs.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Path to the DuckDB database file. Empty = in-memory (`:memory:`),
    /// useful for tests and ephemeral runs.
    pub duckdb_path: String,
    /// PostgreSQL connection string.
    #[serde(default)]
    pub postgres_url: Option<String>,
    /// Maximum number of check results to keep per target. Older results
    /// are purged by the cleanup worker. 0 = unlimited (default 1000).
    #[serde(default = "default_max_results")]
    pub max_results_per_target: u32,
    /// Maximum number of incident events to keep per incident. 0 = unlimited
    /// (default 100).
    #[serde(default = "default_max_events")]
    pub max_events_per_incident: u32,
}

const fn default_max_results() -> u32 {
    1000
}

const fn default_max_events() -> u32 {
    100
}
