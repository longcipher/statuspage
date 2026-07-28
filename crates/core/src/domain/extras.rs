//! Additional domain types needed by the extended storage layer and feature
//! modules (dashboard aggregations, subscriber dispatch, domain-expiry state,
//! notification channel bindings, app secrets).
//!
//! These are kept in a single file rather than spread across the existing
//! domain modules so the storage-trait extension is a single coherent change.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::public::{DayState, IncidentSeverity};
use super::result::CheckStatus;
use super::subscriber::SubscriberChannel;

// ───────────────────────── Dashboard / results aggregations ────────────────

/// One latency bucket in a time-series. Used by the latency chart on the
/// target detail page and the dashboard sparkline.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LatencyBucket {
    /// Bucket start (inclusive), UTC.
    pub ts: DateTime<Utc>,
    /// p50 / p95 / p99 latency in milliseconds, or `None` when the bucket
    /// had zero checks (no data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p50: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p99: Option<f64>,
    /// Number of checks that fell into this bucket.
    pub count: u64,
}

/// One row in the dashboard rollup table. Each row corresponds to one target
/// and carries its current status plus trailing-window aggregates.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardRow {
    pub target_id: Uuid,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub current_status: CheckStatus,
    /// Last check timestamp, or `None` if no check has ever run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check_at: Option<DateTime<Utc>>,
    /// Trailing 24h uptime percentage [0, 100]. `None` when no data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_pct_24h: Option<f64>,
    /// Trailing 24h p95 latency in ms. `None` when no data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_24h: Option<f64>,
    /// 90-day day-strip history, oldest first.
    #[serde(default)]
    pub history: Vec<DayState>,
}

/// Fleet-wide dashboard summary: counts by status + totals.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DashboardSummary {
    pub total: u64,
    pub up: u64,
    pub down: u64,
    pub degraded: u64,
    pub error: u64,
    pub disabled: u64,
}

/// Per-day history entry for a single component (used by the 90-day strip).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComponentDayHistory {
    pub target_id: Uuid,
    pub day: chrono::NaiveDate,
    pub state: DayState,
}

/// Uptime result for a single target over a window.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UptimeResult {
    pub target_id: Uuid,
    /// [0, 100]
    pub uptime_pct: f64,
    /// Total checks in the window.
    pub total_checks: u64,
    /// Failed checks in the window.
    pub failed_checks: u64,
}

// ───────────────────────── Subscriber deliveries ───────────────────────────

/// Delivery status for a subscriber notification (one row per attempt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeliveryStatus {
    Pending,
    Claimed,
    Sent,
    Failed,
    DeadLetter,
}

impl DeliveryStatus {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::DeadLetter => "dead_letter",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "claimed" => Self::Claimed,
            "sent" => Self::Sent,
            "failed" => Self::Failed,
            "dead_letter" => Self::DeadLetter,
            _ => Self::Pending,
        }
    }
}

/// What triggered the delivery (incident opened / resolved / maintenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeliveryReason {
    IncidentOpened,
    IncidentResolved,
    IncidentUpdate,
    MaintenanceStarted,
    MaintenanceEnded,
}

impl DeliveryReason {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::IncidentOpened => "incident_opened",
            Self::IncidentResolved => "incident_resolved",
            Self::IncidentUpdate => "incident_update",
            Self::MaintenanceStarted => "maintenance_started",
            Self::MaintenanceEnded => "maintenance_ended",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "incident_resolved" => Self::IncidentResolved,
            "incident_update" => Self::IncidentUpdate,
            "maintenance_started" => Self::MaintenanceStarted,
            "maintenance_ended" => Self::MaintenanceEnded,
            _ => Self::IncidentOpened,
        }
    }
}

/// One queued subscriber delivery. The dispatcher claims pending rows,
/// attempts delivery, and marks them sent/failed/dead-letter.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SubscriberDelivery {
    pub id: Uuid,
    pub subscriber_id: Uuid,
    pub status_page_id: Uuid,
    pub channel: SubscriberChannel,
    pub target: String,
    /// Serialised payload to deliver (JSON for webhook/slack, plain text for email).
    pub payload: String,
    pub reason: DeliveryReason,
    pub status: DeliveryStatus,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<DateTime<Utc>>,
    /// When the retry sweep will next attempt a failed delivery. `None` once
    /// dead-lettered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<Utc>>,
}

// ───────────────────────── Domain expiry state ─────────────────────────────

/// Cached last-good state for a domain-expiry check. When a fresh RDAP query
/// fails, the executor serves this cached state (with a `served_stale:` prefix
/// on the error) so a transient RDAP outage doesn't cause a false "down".
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DomainExpiryState {
    pub target_id: Uuid,
    /// Registered domain (e.g. `example.com`) this state belongs to.
    pub domain: String,
    /// Expiry date from the registrar, or `None` if never fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::NaiveDate>,
    /// Registrar name, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    /// When this state was last refreshed by a successful RDAP query.
    pub fetched_at: DateTime<Utc>,
}

// ───────────────────────── Target ↔ notification channel binding ───────────

/// Binding between a target and a notification channel. A target can have
/// multiple channels; a channel can be bound to multiple targets.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TargetChannelBinding {
    pub target_id: Uuid,
    pub channel_id: Uuid,
    pub created_at: DateTime<Utc>,
}

// ───────────────────────── Incident ops (public-facing projection) ─────────

/// Public-facing incident ops patch. Maps to the internal `IncidentTransition`
/// state machine but carries only the fields an API caller can set.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct IncidentOpsPatch {
    /// Transition the incident state: `acknowledge`, `resolve`, `reopen`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<String>,
    /// Assign or unassign the incident.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee_id: Option<Uuid>,
    /// Toggle public visibility.
    #[serde(default)]
    pub publish: Option<bool>,
    /// Severity change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<IncidentSeverity>,
    /// Free-text note appended to the internal timeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Incident metrics rollup (simplified for self-hosted single-tenant).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct IncidentMetricsRollup {
    pub window_days: u32,
    pub total: u64,
    pub open: u64,
    pub resolved: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mttr_secs: Option<f64>,
}
