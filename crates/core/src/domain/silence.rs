//! Silence rules: operator-defined windows that suppress notification
//! delivery for matching incidents without affecting probing or incident
//! state. A silence rule is active when `starts_at <= now < ends_at`.
//!
//! Match semantics:
//! - `target_id = None` matches every target; `Some(id)` matches only that
//!   target.
//! - `channel_id = None` matches every channel; `Some(id)` matches only that
//!   channel.
//! - `reasons` empty matches every reason; non-empty matches only the listed
//!   reasons (whitelist).
//!
//! A rule suppresses a notification iff it is active AND every matcher above
//! matches. The dispatch path (`incident_writer::channel_dispatch`) queries
//! the active rules once per incident and filters in-memory per channel.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::DeliveryReason;
use super::WriteSource;
use super::serde_helpers::double_option;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SilenceRule {
    pub id: Uuid,
    pub title: String,
    #[schema(nullable = true)]
    pub description: Option<String>,
    /// `None` = all targets. `Some(id)` = only that target.
    #[schema(nullable = true)]
    pub target_id: Option<Uuid>,
    /// `None` = all channels. `Some(id)` = only that channel.
    #[schema(nullable = true)]
    pub channel_id: Option<Uuid>,
    /// Empty = all reasons. Non-empty = whitelist of reasons to silence.
    #[serde(default)]
    pub reasons: Vec<DeliveryReason>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Where this rule was last changed from (UI, API, or Terraform).
    #[serde(default)]
    pub write_source: WriteSource,
}

impl SilenceRule {
    /// True if this rule is active at `now`.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.starts_at <= now && self.ends_at > now
    }

    /// True if this rule suppresses a notification for the given
    /// `(target_id, channel_id, reason)`. Does NOT check the time window —
    /// the caller is expected to have already filtered to active rules, or
    /// call [`Self::is_active_at`] first.
    pub fn matches(
        &self,
        target_id: Uuid,
        channel_id: Option<Uuid>,
        reason: DeliveryReason,
    ) -> bool {
        if let Some(rule_target) = self.target_id
            && rule_target != target_id
        {
            return false;
        }
        if let (Some(rule_channel), Some(ch)) = (self.channel_id, channel_id)
            && rule_channel != ch
        {
            return false;
        }
        // If the rule targets a specific channel but the dispatch path
        // hasn't resolved one yet (channel_id = None), the rule still
        // matches at the per-incident level — the per-channel check in the
        // dispatch loop will refine. This lets a single "silence channel X
        // for target Y" query suppress only that channel.
        if !self.reasons.is_empty() && !self.reasons.contains(&reason) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NewSilenceRule {
    #[schema(example = "Silence DB alerts during migration", max_length = 200)]
    pub title: String,
    #[serde(default)]
    #[schema(nullable = true)]
    pub description: Option<String>,
    #[serde(default)]
    #[schema(nullable = true)]
    pub target_id: Option<Uuid>,
    #[serde(default)]
    #[schema(nullable = true)]
    pub channel_id: Option<Uuid>,
    #[serde(default)]
    pub reasons: Vec<DeliveryReason>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SilenceRuleUpdate {
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub target_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double_option")]
    pub channel_id: Option<Option<Uuid>>,
    pub reasons: Option<Vec<DeliveryReason>>,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SilenceFilter {
    Active,
    Upcoming,
    Past,
    #[default]
    All,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        target_id: Option<Uuid>,
        channel_id: Option<Uuid>,
        reasons: Vec<DeliveryReason>,
    ) -> SilenceRule {
        SilenceRule {
            id: Uuid::max(),
            title: "test".into(),
            description: None,
            target_id,
            channel_id,
            reasons,
            starts_at: Utc::now() - chrono::Duration::minutes(5),
            ends_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            write_source: WriteSource::Ui,
        }
    }

    #[test]
    fn global_rule_matches_everything() {
        let r = rule(None, None, vec![]);
        assert!(r.matches(Uuid::nil(), None, DeliveryReason::IncidentOpened));
        assert!(r.matches(Uuid::nil(), Some(Uuid::max()), DeliveryReason::IncidentResolved));
    }

    #[test]
    fn target_scoped_rule_only_matches_that_target() {
        let t = Uuid::max();
        let r = rule(Some(t), None, vec![]);
        assert!(r.matches(t, None, DeliveryReason::IncidentOpened));
        assert!(!r.matches(Uuid::nil(), None, DeliveryReason::IncidentOpened));
    }

    #[test]
    fn reason_whitelist_filters() {
        let r = rule(None, None, vec![DeliveryReason::IncidentOpened]);
        assert!(r.matches(Uuid::nil(), None, DeliveryReason::IncidentOpened));
        assert!(!r.matches(Uuid::nil(), None, DeliveryReason::IncidentResolved));
    }

    #[test]
    fn channel_scoped_rule_matches_when_channel_resolved() {
        let ch = Uuid::max();
        let r = rule(None, Some(ch), vec![]);
        // Per-incident check (channel not yet resolved): still matches.
        assert!(r.matches(Uuid::nil(), None, DeliveryReason::IncidentOpened));
        // Per-channel check: only the scoped channel matches.
        assert!(r.matches(Uuid::nil(), Some(ch), DeliveryReason::IncidentOpened));
        assert!(!r.matches(Uuid::nil(), Some(Uuid::nil()), DeliveryReason::IncidentOpened));
    }

    #[test]
    fn is_active_at_respects_window() {
        let mut r = rule(None, None, vec![]);
        let now = Utc::now();
        r.starts_at = now + chrono::Duration::minutes(5);
        r.ends_at = now + chrono::Duration::minutes(10);
        assert!(!r.is_active_at(now));
        assert!(r.is_active_at(now + chrono::Duration::minutes(7)));
    }
}
