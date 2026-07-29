//! SLA (Service Level Agreement) tracking and breach alerting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// An SLA target definition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SlaTarget {
    pub id: Uuid,
    /// Human-readable name (e.g. "99.9% uptime").
    pub name: String,
    /// Target uptime percentage (e.g. 99.9).
    pub target_pct: f64,
    /// Measurement window in days (e.g. 30 for monthly).
    pub window_days: u32,
    /// FK to the target this SLA applies to. Null = org-wide SLA.
    #[serde(default)]
    #[schema(nullable = true)]
    pub target_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SLA compliance status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SlaStatus {
    /// The SLA target definition.
    pub target: SlaTarget,
    /// Actual uptime percentage in the current window.
    pub actual_pct: f64,
    /// Whether the SLA is currently met.
    pub met: bool,
    /// Minutes of downtime allowed in the window before breach.
    pub allowed_downtime_minutes: u64,
    /// Minutes of downtime so far in the window.
    pub actual_downtime_minutes: u64,
    /// When the window resets.
    pub window_end: DateTime<Utc>,
}
