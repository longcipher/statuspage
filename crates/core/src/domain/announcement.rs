//! System-wide announcements displayed on the public status page.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Severity level of an announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnnouncementSeverity {
    #[default]
    Info,
    Warning,
    Critical,
}

/// A system-wide announcement.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Announcement {
    pub id: Uuid,
    pub title: String,
    pub body: String,
    pub severity: AnnouncementSeverity,
    /// Whether this announcement is currently visible.
    pub visible: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Optional scheduled start time (null = immediate).
    #[serde(default)]
    #[schema(nullable = true)]
    pub starts_at: Option<DateTime<Utc>>,
    /// Optional scheduled end time (null = no expiry).
    #[serde(default)]
    #[schema(nullable = true)]
    pub ends_at: Option<DateTime<Utc>>,
}

/// Create a new announcement.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewAnnouncement {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub severity: AnnouncementSeverity,
    #[serde(default = "default_true")]
    pub visible: bool,
    #[serde(default)]
    #[schema(nullable = true)]
    pub starts_at: Option<DateTime<Utc>>,
    #[serde(default)]
    #[schema(nullable = true)]
    pub ends_at: Option<DateTime<Utc>>,
}

const fn default_true() -> bool {
    true
}
