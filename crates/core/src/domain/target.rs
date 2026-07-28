use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::WriteSource;
use super::alert::TargetAlerts;
use super::check::CheckSpec;
use super::serde_helpers::double_option;

/// How many regions must agree a monitor is down before it alerts. `Any`,
/// `Majority`, and `All` track the live region count; `Count` is a fixed number
/// the user chose. Resolved to a concrete threshold by [`Self::required`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RegionIncidentPolicy {
    /// One region down is enough.
    Any,
    /// More than half the regions (`n/2 + 1`).
    #[default]
    Majority,
    /// Every region.
    All,
    /// A fixed number of regions.
    Count(u32),
}

impl RegionIncidentPolicy {
    /// The concrete number of down regions needed, given how many are in play.
    /// Always clamped to `1..=region_count` so it can never be impossible.
    pub fn required(&self, region_count: usize) -> usize {
        let n = match self {
            Self::Any => 1,
            Self::Majority => region_count / 2 + 1,
            Self::All => region_count,
            Self::Count(c) => *c as usize,
        };
        n.clamp(1, region_count.max(1))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub check: CheckSpec,
    /// Check interval in seconds.
    #[serde(with = "duration_secs")]
    #[schema(value_type = u64, example = 60, minimum = 10)]
    pub interval: Duration,
    pub enabled: bool,
    pub tags: Vec<String>,
    #[serde(default)]
    pub alerts: TargetAlerts,
    /// Consecutive failing checks before this monitor alerts. Min 1.
    #[serde(default = "default_alert_confirmations")]
    pub alert_confirmations: u32,
    /// Whether a recovery is announced to the monitor's channels.
    #[serde(default = "default_true")]
    pub notify_recovery: bool,
    /// Seconds between reminders while an outage stays unacknowledged. 0 = off.
    #[serde(default = "default_renotify_interval_secs")]
    pub renotify_interval_secs: u32,
    /// How multi-region health folds into incidents for this monitor.
    #[serde(default)]
    pub region_policy: RegionIncidentPolicy,
    /// Operator-side grouping (independent of any status page's grouping).
    #[serde(default)]
    #[schema(example = "API & Web", nullable = true, max_length = 50)]
    pub group_name: Option<String>,
    /// FK to `users.id`. Nullable; cleared if the user is removed.
    #[serde(default)]
    #[schema(nullable = true)]
    pub owner_user_id: Option<Uuid>,
    /// FK to `escalation_policies.id`. Nullable; the policy the engine walks
    /// when an incident on this target goes unacknowledged.
    #[serde(default)]
    #[schema(nullable = true)]
    pub escalation_policy_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Where this target was last changed from (UI, API, or Terraform).
    #[serde(default)]
    pub write_source: WriteSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NewTarget {
    pub name: String,
    pub check: CheckSpec,
    /// Check interval in seconds.
    #[serde(with = "duration_secs")]
    #[schema(value_type = u64, example = 60, minimum = 10)]
    pub interval: Duration,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub alerts: TargetAlerts,
    /// Consecutive failing checks before this monitor alerts. Min 1.
    #[serde(default = "default_alert_confirmations")]
    pub alert_confirmations: u32,
    #[serde(default = "default_true")]
    pub notify_recovery: bool,
    /// Seconds between reminders while an outage stays unacknowledged. 0 = off.
    #[serde(default = "default_renotify_interval_secs")]
    pub renotify_interval_secs: u32,
    /// Detection policy. Omit to take the derived default — quorum-majority when
    /// the monitor lands in more than one region, any-down for a single region.
    #[serde(default)]
    pub region_policy: Option<RegionIncidentPolicy>,
    #[serde(default)]
    #[schema(nullable = true, max_length = 50)]
    pub group_name: Option<String>,
    #[serde(default)]
    #[schema(nullable = true)]
    pub owner_user_id: Option<Uuid>,
    /// FK to `escalation_policies.id`. Omit to leave the binding unset.
    #[serde(default)]
    #[schema(nullable = true)]
    pub escalation_policy_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct TargetUpdate {
    pub name: Option<String>,
    pub check: Option<CheckSpec>,
    /// Check interval in seconds.
    #[serde(default, with = "duration_secs_opt")]
    #[schema(value_type = Option<u64>)]
    pub interval: Option<Duration>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub region_policy: Option<RegionIncidentPolicy>,
    pub alert_confirmations: Option<u32>,
    pub notify_recovery: Option<bool>,
    pub renotify_interval_secs: Option<u32>,
    pub tags: Option<Vec<String>>,
    pub alerts: Option<TargetAlerts>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(nullable = true, value_type = Option<String>)]
    pub group_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(nullable = true, value_type = Option<Uuid>)]
    pub owner_user_id: Option<Option<Uuid>>,
    /// Double-option: `None` = leave alone, `Some(None)` = clear, `Some(Some(id))` = set.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(nullable = true, value_type = Option<Uuid>)]
    pub escalation_policy_id: Option<Option<Uuid>>,
}

impl TargetUpdate {
    pub fn apply_to(self, target: &mut Target) {
        if let Some(v) = self.name {
            target.name = v;
        }
        if let Some(v) = self.check {
            target.check = v;
        }
        if let Some(v) = self.interval {
            target.interval = v;
        }
        if let Some(v) = self.enabled {
            target.enabled = v;
        }
        if let Some(v) = self.tags {
            target.tags = v;
        }
        if let Some(v) = self.alerts {
            target.alerts = v;
        }
        if let Some(v) = self.alert_confirmations {
            target.alert_confirmations = v;
        }
        if let Some(v) = self.notify_recovery {
            target.notify_recovery = v;
        }
        if let Some(v) = self.renotify_interval_secs {
            target.renotify_interval_secs = v;
        }
        if let Some(v) = self.region_policy {
            target.region_policy = v;
        }
        if let Some(v) = self.group_name {
            target.group_name = v;
        }
        if let Some(v) = self.owner_user_id {
            target.owner_user_id = v;
        }
        if let Some(v) = self.escalation_policy_id {
            target.escalation_policy_id = v;
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_alert_confirmations() -> u32 {
    2
}

const fn default_renotify_interval_secs() -> u32 {
    3600
}

mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

mod duration_secs_opt {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(v) => s.serialize_some(&v.as_secs()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        let secs = Option::<u64>::deserialize(d)?;
        Ok(secs.map(Duration::from_secs))
    }
}
