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
}
