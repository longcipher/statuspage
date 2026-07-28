use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckerConfig {
    pub max_concurrent_checks: usize,
    pub default_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub default_check_interval_secs: u64,
    /// Per-(org, host, port) in-flight cap. Tenant-scoped, fail-fast.
    #[serde(default = "default_per_host_max_inflight")]
    pub per_host_max_inflight: usize,
    /// Process-wide RDAP concurrency cap (per TLD).
    #[serde(default = "default_rdap_max_inflight")]
    pub rdap_max_inflight: usize,
}

const fn default_per_host_max_inflight() -> usize {
    2
}

const fn default_rdap_max_inflight() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpClientConfig {
    /// TCP keep-alive for the in-flight connection. Checks connect fresh each
    /// run (no pool), so this only spans one request's body read.
    pub tcp_keepalive_secs: u64,
    /// Identifiable so site owners allowlist our probes instead of blocking them.
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

fn default_user_agent() -> String {
    concat!("statuspage/", env!("CARGO_PKG_VERSION"), " (+https://statuspage.dev/bot)").to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    pub cache_size: usize,
    pub positive_ttl_secs: u64,
    pub negative_ttl_secs: u64,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SchedulerConfig {
    /// Off = this process probes nothing in-process (pure dashboard/brain);
    /// agents do all probing. On = the in-process scheduler probes `region`.
    #[serde(default = "default_scheduler_enabled")]
    pub enabled: bool,
    pub target_refresh_interval_secs: u64,
    /// This control plane's own region id. Its scheduler runs the targets
    /// assigned to this region and stamps results with it — the same query an
    /// agent pulls for its region. Boot reconciles the row into `regions`.
    #[serde(default = "default_region_id")]
    pub region: String,
    /// Region assigned to newly-created targets. Empty falls back to `region`.
    #[serde(default)]
    pub default_region: String,
}

fn default_region_id() -> String {
    "default".to_string()
}

const fn default_scheduler_enabled() -> bool {
    true
}

impl SchedulerConfig {
    /// Region new targets are assigned to: explicit `default_region`, else the
    /// control plane's own `region`.
    pub fn effective_default_region(&self) -> &str {
        if self.default_region.trim().is_empty() { &self.region } else { &self.default_region }
    }
}
