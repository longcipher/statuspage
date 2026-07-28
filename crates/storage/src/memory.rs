//! In-memory storage for tests and development.
//!
//! Implements the same [`Storage`] contract as [`crate::DuckdbStorage`] backed
//! by plain `HashMap`s. The semantics mirror the DuckDB version so tests can
//! swap one for the other without behaviour drift: `create` rejects duplicates
//! with [`StorageError::Conflict`]; `update`/`delete` reject missing ids with
//! [`StorageError::NotFound`]; `list_results` returns newest-first; the
//! incident list is capped at 200 like the DuckDB query.

// ponytail: test double — lock contention is irrelevant for in-memory HashMaps
#![expect(clippy::significant_drop_tightening)]

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, Utc};
use parking_lot::RwLock;

use statuscore::domain::{
    ApiTokenRow, ApiTokenUpdate, AppTheme, AssetSlot, CheckResult, CheckStatus,
    ComponentDayHistory, CreatedShare, DashboardRow, DashboardSummary, DayState, DeliveryReason,
    DeliveryStatus, DomainExpiryState, EscalationPolicy, EscalationPolicySummary, Incident,
    IncidentEscalationState, IncidentMetricsRollup, IncidentOpsPatch, IncidentPostmortem,
    IncidentState, IncidentStatusPhase, IncidentTransition, LatencyBucket, MagicLinkRow,
    MaintenanceFilter, MaintenanceWindow, MonitorShare, MonitorShareId, NewApiToken,
    NewNotificationChannel, NewSilenceRule, NewUser, NotificationChannel,
    NotificationChannelUpdate, OnCallOverride, OnCallSchedule, OnCallScheduleDetail,
    OnCallScheduleSummary, OrgId, PageAsset, PostmortemUpsert, PublicIncidentUpdate, ResolvedShare,
    ScopeSet, SessionRow, SilenceFilter, SilenceRule, SilenceRuleUpdate, StatusPage,
    StatusPageComponent, Subscriber, SubscriberChannel, SubscriberDelivery, Target,
    TargetChannelBinding, TimeFormat, UptimeResult, User, UserId, UserUpdate, Variable,
    WriteSource, generate_cookie_value, hash_cookie_value, next_state, normalize_oauth_email,
};
use statuscore::error::Result;
use uuid::Uuid;

use crate::{Storage, StorageError};

/// In-memory row for a channel verification token. Mirrors the
/// `channel_verification_tokens` DuckDB table.
#[derive(Debug, Clone)]
struct ChannelVerificationTokenRow {
    id: Uuid,
    channel_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

/// In-memory row for a monitor share link. Mirrors the `monitor_shares`
/// DuckDB table. The raw token is never stored — only `token_hash`.
#[derive(Debug, Clone)]
struct MonitorShareRow {
    id: Uuid,
    target_id: Uuid,
    label: Option<String>,
    token_hash: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    view_count: i64,
    last_viewed_at: Option<DateTime<Utc>>,
}

/// In-memory storage for tests and development.
pub struct MemoryStorage {
    targets: Arc<RwLock<HashMap<Uuid, Target>>>,
    results: Arc<RwLock<Vec<CheckResult>>>,
    incidents: Arc<RwLock<HashMap<Uuid, Incident>>>,
    status_pages: Arc<RwLock<HashMap<Uuid, StatusPage>>>,
    // New collections for the extended storage contract.
    status_page_components: Arc<RwLock<HashMap<(Uuid, Uuid), StatusPageComponent>>>,
    heartbeat_pings: Arc<RwLock<HashMap<Uuid, chrono::DateTime<Utc>>>>,
    maintenance_windows: Arc<RwLock<HashMap<Uuid, MaintenanceWindow>>>,
    silence_rules: Arc<RwLock<HashMap<Uuid, SilenceRule>>>,
    subscribers: Arc<RwLock<HashMap<Uuid, Subscriber>>>,
    variables: Arc<RwLock<HashMap<Uuid, Variable>>>,
    notification_channels: Arc<RwLock<HashMap<Uuid, NotificationChannel>>>,
    channel_verification_tokens: Arc<RwLock<HashMap<Uuid, ChannelVerificationTokenRow>>>,
    target_channels: Arc<RwLock<Vec<TargetChannelBinding>>>,
    subscriber_deliveries: Arc<RwLock<Vec<SubscriberDelivery>>>,
    domain_expiry_states: Arc<RwLock<HashMap<Uuid, DomainExpiryState>>>,
    // Auth collections.
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    sessions: Arc<RwLock<HashMap<String, SessionRow>>>,
    api_tokens: Arc<RwLock<HashMap<Uuid, ApiTokenRow>>>,
    magic_links: Arc<RwLock<HashMap<Uuid, MagicLinkRow>>>,
    // Escalation / on-call collections.
    escalation_policies: Arc<RwLock<HashMap<Uuid, EscalationPolicy>>>,
    on_call_schedules: Arc<RwLock<HashMap<Uuid, OnCallScheduleDetail>>>,
    on_call_overrides: Arc<RwLock<HashMap<Uuid, (Uuid, OnCallOverride)>>>,
    escalation_states: Arc<RwLock<HashMap<Uuid, IncidentEscalationState>>>,
    // Postmortems (one per incident).
    postmortems: Arc<RwLock<HashMap<Uuid, IncidentPostmortem>>>,
    // Monitor share links (capability URLs for single-monitor public views).
    monitor_shares: Arc<RwLock<Vec<MonitorShareRow>>>,
    // Page assets (logo etc.). Keyed by (page, slot).
    page_assets: Arc<RwLock<HashMap<(Uuid, String), PageAsset>>>,
}

impl std::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStorage").finish_non_exhaustive()
    }
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            targets: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(Vec::new())),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            status_pages: Arc::new(RwLock::new(HashMap::new())),
            status_page_components: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_pings: Arc::new(RwLock::new(HashMap::new())),
            maintenance_windows: Arc::new(RwLock::new(HashMap::new())),
            silence_rules: Arc::new(RwLock::new(HashMap::new())),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            variables: Arc::new(RwLock::new(HashMap::new())),
            notification_channels: Arc::new(RwLock::new(HashMap::new())),
            channel_verification_tokens: Arc::new(RwLock::new(HashMap::new())),
            target_channels: Arc::new(RwLock::new(Vec::new())),
            subscriber_deliveries: Arc::new(RwLock::new(Vec::new())),
            domain_expiry_states: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            api_tokens: Arc::new(RwLock::new(HashMap::new())),
            magic_links: Arc::new(RwLock::new(HashMap::new())),
            escalation_policies: Arc::new(RwLock::new(HashMap::new())),
            on_call_schedules: Arc::new(RwLock::new(HashMap::new())),
            on_call_overrides: Arc::new(RwLock::new(HashMap::new())),
            escalation_states: Arc::new(RwLock::new(HashMap::new())),
            postmortems: Arc::new(RwLock::new(HashMap::new())),
            monitor_shares: Arc::new(RwLock::new(Vec::new())),
            page_assets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn list_targets(&self) -> Result<Vec<Target>> {
        let map = self.targets.read();
        let mut out: Vec<Target> = map.values().cloned().collect();
        out.sort_by_key(|a| a.created_at);
        Ok(out)
    }

    async fn get_target(&self, id: Uuid) -> Result<Target> {
        let map = self.targets.read();
        map.get(&id).cloned().ok_or_else(|| StorageError::NotFound(format!("target {id}")).into())
    }

    async fn create_target(&self, target: &Target) -> Result<Target> {
        let mut map = self.targets.write();
        if map.contains_key(&target.id) {
            return Err(StorageError::Conflict(format!("target {} exists", target.id)).into());
        }
        map.insert(target.id, target.clone());
        Ok(target.clone())
    }

    async fn update_target(&self, target: &Target) -> Result<Target> {
        let mut map = self.targets.write();
        if !map.contains_key(&target.id) {
            return Err(StorageError::NotFound(format!("target {}", target.id)).into());
        }
        map.insert(target.id, target.clone());
        Ok(target.clone())
    }

    async fn delete_target(&self, id: Uuid) -> Result<()> {
        let mut map = self.targets.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("target {id}")).into());
        }
        Ok(())
    }

    async fn record_result(&self, result: &CheckResult) -> Result<()> {
        let mut results = self.results.write();
        // Same (target_id, timestamp) overwrites the prior entry — mirrors the
        // DuckDB `INSERT OR REPLACE` semantics.
        if let Some(existing) = results
            .iter_mut()
            .find(|r| r.target_id == result.target_id && r.timestamp == result.timestamp)
        {
            *existing = result.clone();
        } else {
            results.push(result.clone());
        }
        Ok(())
    }

    async fn list_results(&self, target_id: Uuid, limit: u32) -> Result<Vec<CheckResult>> {
        let results = self.results.read();
        let mut filtered: Vec<CheckResult> =
            results.iter().filter(|r| r.target_id == target_id).cloned().collect();
        filtered.sort_by_key(|r| Reverse(r.timestamp));
        filtered.truncate(limit as usize);
        Ok(filtered)
    }

    async fn list_incidents(&self) -> Result<Vec<Incident>> {
        let map = self.incidents.read();
        let mut out: Vec<Incident> = map.values().cloned().collect();
        out.sort_by_key(|i| Reverse(i.started_at));
        out.truncate(200);
        Ok(out)
    }

    async fn create_incident(&self, incident: &Incident) -> Result<Incident> {
        let mut map = self.incidents.write();
        if map.contains_key(&incident.id) {
            return Err(StorageError::Conflict(format!("incident {} exists", incident.id)).into());
        }
        map.insert(incident.id, incident.clone());
        Ok(incident.clone())
    }

    async fn list_status_pages(&self) -> Result<Vec<StatusPage>> {
        let map = self.status_pages.read();
        let mut out: Vec<StatusPage> = map.values().cloned().collect();
        out.sort_by_key(|a| a.created_at);
        Ok(out)
    }

    async fn get_status_page(&self, id: Uuid) -> Result<StatusPage> {
        let map = self.status_pages.read();
        map.get(&id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("status page {id}")).into())
    }

    async fn create_status_page(&self, page: &StatusPage) -> Result<StatusPage> {
        let mut map = self.status_pages.write();
        if map.contains_key(&page.id.0) {
            return Err(StorageError::Conflict(format!("status page {} exists", page.id.0)).into());
        }
        map.insert(page.id.0, page.clone());
        Ok(page.clone())
    }

    async fn update_status_page(&self, page: &StatusPage) -> Result<StatusPage> {
        let mut map = self.status_pages.write();
        if !map.contains_key(&page.id.0) {
            return Err(StorageError::NotFound(format!("status page {}", page.id.0)).into());
        }
        map.insert(page.id.0, page.clone());
        Ok(page.clone())
    }

    async fn delete_status_page(&self, id: Uuid) -> Result<()> {
        let mut map = self.status_pages.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("status page {id}")).into());
        }
        Ok(())
    }

    async fn list_recent_results(&self, limit: u32) -> Result<Vec<CheckResult>> {
        let results = self.results.read();
        let mut out: Vec<CheckResult> = results.clone();
        out.sort_by_key(|r| Reverse(r.timestamp));
        out.truncate(limit as usize);
        Ok(out)
    }

    async fn get_incident(&self, id: Uuid) -> Result<Incident> {
        let map = self.incidents.read();
        map.get(&id).cloned().ok_or_else(|| StorageError::NotFound(format!("incident {id}")).into())
    }

    async fn update_incident(&self, incident: &Incident) -> Result<Incident> {
        let mut map = self.incidents.write();
        if !map.contains_key(&incident.id) {
            return Err(StorageError::NotFound(format!("incident {}", incident.id)).into());
        }
        map.insert(incident.id, incident.clone());
        Ok(incident.clone())
    }

    async fn add_incident_update(
        &self,
        incident_id: Uuid,
        update: &PublicIncidentUpdate,
    ) -> Result<Incident> {
        let mut map = self.incidents.write();
        let Some(incident) = map.get_mut(&incident_id) else {
            return Err(StorageError::NotFound(format!("incident {incident_id}")).into());
        };
        incident.updates.push(update.clone());
        Ok(incident.clone())
    }

    async fn find_open_incident_for_target(&self, target_id: Uuid) -> Result<Option<Incident>> {
        let map = self.incidents.read();
        let mut open: Vec<Incident> = map
            .values()
            .filter(|i| i.target_id == target_id && i.ended_at.is_none())
            .cloned()
            .collect();
        open.sort_by_key(|i| Reverse(i.started_at));
        Ok(open.into_iter().next())
    }

    // ── Status page components ───────────────────────────────────────────

    async fn list_status_page_components(
        &self,
        status_page_id: Uuid,
    ) -> Result<Vec<StatusPageComponent>> {
        let map = self.status_page_components.read();
        let mut out: Vec<StatusPageComponent> = map
            .iter()
            .filter(|((sp, _), _)| *sp == status_page_id)
            .map(|(_, c)| c.clone())
            .collect();
        out.sort_by(|a, b| {
            a.sort_order.cmp(&b.sort_order).then_with(|| a.monitor_name.cmp(&b.monitor_name))
        });
        Ok(out)
    }

    async fn set_status_page_component(
        &self,
        status_page_id: Uuid,
        component: &StatusPageComponent,
    ) -> Result<()> {
        let mut map = self.status_page_components.write();
        map.insert((status_page_id, component.target_id), component.clone());
        Ok(())
    }

    async fn delete_status_page_component(
        &self,
        status_page_id: Uuid,
        target_id: Uuid,
    ) -> Result<()> {
        let mut map = self.status_page_components.write();
        map.remove(&(status_page_id, target_id));
        Ok(())
    }

    async fn reorder_status_page_components(
        &self,
        status_page_id: Uuid,
        ordered_target_ids: &[Uuid],
    ) -> Result<()> {
        let mut map = self.status_page_components.write();
        for (i, target_id) in ordered_target_ids.iter().enumerate() {
            if let Some(component) = map.get_mut(&(status_page_id, *target_id)) {
                component.sort_order = i as i32;
            }
        }
        Ok(())
    }

    // ── Page assets ──────────────────────────────────────────────────────

    async fn upload_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
        content_type: &str,
        data: &[u8],
    ) -> Result<PageAsset> {
        let hash = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(data);
            hex::encode(digest)
        };
        let now = Utc::now();
        let key = (status_page_id, slot.as_str().to_string());
        let mut map = self.page_assets.write();
        // Preserve `created_at` on replace, mirroring the DuckDB impl.
        let created_at = map.get(&key).map_or(now, |a| a.created_at);
        let asset = PageAsset {
            status_page_id,
            slot,
            content_type: content_type.to_string(),
            data: data.to_vec(),
            hash,
            created_at,
            updated_at: now,
        };
        map.insert(key, asset.clone());
        Ok(asset)
    }

    async fn get_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
    ) -> Result<Option<PageAsset>> {
        let map = self.page_assets.read();
        Ok(map.get(&(status_page_id, slot.as_str().to_string())).cloned())
    }

    async fn delete_page_asset(&self, status_page_id: Uuid, slot: AssetSlot) -> Result<()> {
        let mut map = self.page_assets.write();
        map.remove(&(status_page_id, slot.as_str().to_string()));
        Ok(())
    }

    async fn list_page_assets(&self, status_page_id: Uuid) -> Result<Vec<PageAsset>> {
        let map = self.page_assets.read();
        let mut out: Vec<PageAsset> = map
            .iter()
            .filter(|((sp, _), _)| *sp == status_page_id)
            .map(|(_, a)| a.clone())
            .collect();
        // Stable order by slot name, matching the DuckDB impl.
        out.sort_by(|a, b| a.slot.as_str().cmp(b.slot.as_str()));
        Ok(out)
    }

    // ── Heartbeat pings ──────────────────────────────────────────────────

    async fn record_heartbeat_ping(&self, target_id: Uuid) -> Result<()> {
        let mut map = self.heartbeat_pings.write();
        map.insert(target_id, Utc::now());
        Ok(())
    }

    async fn get_last_heartbeat_ping(
        &self,
        target_id: Uuid,
    ) -> Result<Option<chrono::DateTime<Utc>>> {
        let map = self.heartbeat_pings.read();
        Ok(map.get(&target_id).copied())
    }

    // ── Maintenance windows ──────────────────────────────────────────────

    async fn list_maintenance_windows(
        &self,
        filter: MaintenanceFilter,
    ) -> Result<Vec<MaintenanceWindow>> {
        let map = self.maintenance_windows.read();
        let now = Utc::now();
        let mut out: Vec<MaintenanceWindow> = map
            .values()
            .filter(|w| match filter {
                MaintenanceFilter::Active => w.starts_at <= now && w.ends_at > now,
                MaintenanceFilter::Upcoming => w.starts_at > now,
                MaintenanceFilter::Past => w.ends_at <= now,
                MaintenanceFilter::All => true,
                // `MaintenanceFilter` is `#[non_exhaustive]`; future variants
                // fall back to "no match" rather than failing to compile.
                _ => false,
            })
            .cloned()
            .collect();
        out.sort_by_key(|a| a.starts_at);
        Ok(out)
    }

    async fn get_maintenance_window(&self, id: Uuid) -> Result<MaintenanceWindow> {
        let map = self.maintenance_windows.read();
        map.get(&id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("maintenance window {id}")).into())
    }

    async fn create_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        let mut map = self.maintenance_windows.write();
        if map.contains_key(&window.id) {
            return Err(
                StorageError::Conflict(format!("maintenance window {} exists", window.id)).into()
            );
        }
        map.insert(window.id, window.clone());
        Ok(window.clone())
    }

    async fn update_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        let mut map = self.maintenance_windows.write();
        if !map.contains_key(&window.id) {
            return Err(StorageError::NotFound(format!("maintenance window {}", window.id)).into());
        }
        map.insert(window.id, window.clone());
        Ok(window.clone())
    }

    async fn delete_maintenance_window(&self, id: Uuid) -> Result<()> {
        let mut map = self.maintenance_windows.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("maintenance window {id}")).into());
        }
        Ok(())
    }

    async fn is_target_in_active_maintenance(&self, target_id: Uuid) -> Result<bool> {
        let map = self.maintenance_windows.read();
        let now = Utc::now();
        let in_maint = map
            .values()
            .any(|w| w.starts_at <= now && w.ends_at > now && w.component_ids.contains(&target_id));
        Ok(in_maint)
    }

    // ── Silence rules ───────────────────────────────────────────────────

    async fn list_silence_rules(&self, filter: SilenceFilter) -> Result<Vec<SilenceRule>> {
        let map = self.silence_rules.read();
        let now = Utc::now();
        let mut out: Vec<SilenceRule> = map
            .values()
            .filter(|r| match filter {
                SilenceFilter::Active => r.starts_at <= now && r.ends_at > now,
                SilenceFilter::Upcoming => r.starts_at > now,
                SilenceFilter::Past => r.ends_at <= now,
                SilenceFilter::All => true,
                // `SilenceFilter` is `#[non_exhaustive]`; future variants fall
                // back to "no match" rather than failing to compile.
                _ => false,
            })
            .cloned()
            .collect();
        out.sort_by_key(|a| a.starts_at);
        Ok(out)
    }

    async fn get_silence_rule(&self, id: Uuid) -> Result<SilenceRule> {
        let map = self.silence_rules.read();
        map.get(&id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("silence rule {id}")).into())
    }

    async fn create_silence_rule(&self, new_rule: &NewSilenceRule) -> Result<SilenceRule> {
        let mut map = self.silence_rules.write();
        let now = Utc::now();
        let id = Uuid::new_v4();
        if map.contains_key(&id) {
            return Err(StorageError::Conflict(format!("silence rule {id} exists")).into());
        }
        let rule = SilenceRule {
            id,
            title: new_rule.title.clone(),
            description: new_rule.description.clone(),
            target_id: new_rule.target_id,
            channel_id: new_rule.channel_id,
            reasons: new_rule.reasons.clone(),
            starts_at: new_rule.starts_at,
            ends_at: new_rule.ends_at,
            created_at: now,
            updated_at: now,
            write_source: WriteSource::Ui,
        };
        map.insert(id, rule.clone());
        Ok(rule)
    }

    async fn update_silence_rule(
        &self,
        id: Uuid,
        update: &SilenceRuleUpdate,
    ) -> Result<SilenceRule> {
        let mut map = self.silence_rules.write();
        let Some(rule) = map.get_mut(&id) else {
            return Err(StorageError::NotFound(format!("silence rule {id}")).into());
        };
        // Validate the post-patch time window BEFORE mutating any field, so a
        // rejected patch leaves the stored rule untouched (no partially
        // applied state). `starts_at >= ends_at` is a 400 input error, not a
        // 409 conflict — the rule itself is fine, the caller's request is not.
        let new_starts_at = update.starts_at.unwrap_or(rule.starts_at);
        let new_ends_at = update.ends_at.unwrap_or(rule.ends_at);
        if new_starts_at >= new_ends_at {
            return Err(StorageError::InvalidInput(
                "silence rule: starts_at must be before ends_at".into(),
            )
            .into());
        }
        if let Some(title) = &update.title {
            rule.title.clone_from(title);
        }
        if let Some(description) = &update.description {
            rule.description = Some(description.clone());
        }
        if let Some(target_id) = update.target_id {
            rule.target_id = target_id;
        }
        if let Some(channel_id) = update.channel_id {
            rule.channel_id = channel_id;
        }
        if let Some(reasons) = &update.reasons {
            rule.reasons.clone_from(reasons);
        }
        if let Some(starts_at) = update.starts_at {
            rule.starts_at = starts_at;
        }
        if let Some(ends_at) = update.ends_at {
            rule.ends_at = ends_at;
        }
        rule.updated_at = Utc::now();
        Ok(rule.clone())
    }

    async fn delete_silence_rule(&self, id: Uuid) -> Result<()> {
        let mut map = self.silence_rules.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("silence rule {id}")).into());
        }
        Ok(())
    }

    async fn list_active_silences_for_target(&self, target_id: Uuid) -> Result<Vec<SilenceRule>> {
        let map = self.silence_rules.read();
        let now = Utc::now();
        let mut out: Vec<SilenceRule> = map
            .values()
            .filter(|r| {
                r.is_active_at(now) && (r.target_id.is_none() || r.target_id == Some(target_id))
            })
            .cloned()
            .collect();
        out.sort_by_key(|a| a.starts_at);
        Ok(out)
    }

    // ── Subscribers ──────────────────────────────────────────────────────

    async fn list_subscribers(&self, status_page_id: Uuid) -> Result<Vec<Subscriber>> {
        let map = self.subscribers.read();
        let mut out: Vec<Subscriber> =
            map.values().filter(|s| s.status_page_id == status_page_id).cloned().collect();
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    async fn create_subscriber(&self, subscriber: &Subscriber) -> Result<Subscriber> {
        let mut map = self.subscribers.write();
        if map.contains_key(&subscriber.id) {
            return Err(
                StorageError::Conflict(format!("subscriber {} exists", subscriber.id)).into()
            );
        }
        map.insert(subscriber.id, subscriber.clone());
        Ok(subscriber.clone())
    }

    async fn verify_subscriber(&self, id: Uuid) -> Result<Subscriber> {
        let mut map = self.subscribers.write();
        let sub =
            map.get_mut(&id).ok_or_else(|| StorageError::NotFound(format!("subscriber {id}")))?;
        sub.verified_at = Some(Utc::now());
        Ok(sub.clone())
    }

    async fn delete_subscriber(&self, id: Uuid) -> Result<()> {
        let mut map = self.subscribers.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("subscriber {id}")).into());
        }
        Ok(())
    }

    // ── Variables ────────────────────────────────────────────────────────

    async fn list_variables(&self) -> Result<Vec<Variable>> {
        let map = self.variables.read();
        let mut out: Vec<Variable> = map
            .values()
            .map(|v| {
                // Redact secrets on read.
                let mut v = v.clone();
                if v.is_secret {
                    v.value = None;
                }
                v
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    async fn create_variable(&self, variable: &Variable) -> Result<Variable> {
        let mut map = self.variables.write();
        if map.values().any(|v| v.key == variable.key) {
            return Err(
                StorageError::Conflict(format!("variable key '{}' exists", variable.key)).into()
            );
        }
        map.insert(variable.id.0, variable.clone());
        let mut out = variable.clone();
        if out.is_secret {
            out.value = None;
        }
        Ok(out)
    }

    async fn update_variable(&self, variable: &Variable) -> Result<Variable> {
        let mut map = self.variables.write();
        if !map.contains_key(&variable.id.0) {
            return Err(StorageError::NotFound(format!("variable {}", variable.id.0)).into());
        }
        map.insert(variable.id.0, variable.clone());
        let mut out = variable.clone();
        if out.is_secret {
            out.value = None;
        }
        Ok(out)
    }

    async fn delete_variable(&self, id: Uuid) -> Result<()> {
        let mut map = self.variables.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("variable {id}")).into());
        }
        Ok(())
    }

    // ── Results aggregations ─────────────────────────────────────────────

    async fn latency_buckets(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_count: u32,
    ) -> Result<Vec<LatencyBucket>> {
        let results = self.results.read();
        let n = bucket_count.max(1) as usize;
        let total_secs = (to - from).num_seconds().max(1) as f64;
        let bucket_secs = total_secs / n as f64;

        let mut buckets: Vec<Vec<f64>> = vec![Vec::new(); n];
        for r in results
            .iter()
            .filter(|r| r.target_id == target_id && r.timestamp >= from && r.timestamp <= to)
        {
            let idx = ((r.timestamp - from).num_seconds() as f64 / bucket_secs).floor() as usize;
            let idx = idx.min(n - 1);
            buckets[idx].push(f64::from(r.duration_ms));
        }

        let mut out = Vec::with_capacity(n);
        for (i, mut durations) in buckets.into_iter().enumerate() {
            let ts = from + ChronoDuration::seconds((i as f64 * bucket_secs) as i64);
            if durations.is_empty() {
                out.push(LatencyBucket { ts, p50: None, p95: None, p99: None, count: 0 });
            } else {
                durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let count = durations.len() as u64;
                out.push(LatencyBucket {
                    ts,
                    p50: Some(percentile(&durations, 0.5)),
                    p95: Some(percentile(&durations, 0.95)),
                    p99: Some(percentile(&durations, 0.99)),
                    count,
                });
            }
        }
        Ok(out)
    }

    async fn uptime(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Option<UptimeResult>> {
        let results = self.results.read();
        let in_window: Vec<&CheckResult> = results
            .iter()
            .filter(|r| r.target_id == target_id && r.timestamp >= from && r.timestamp <= to)
            .collect();
        if in_window.is_empty() {
            return Ok(None);
        }
        let total = in_window.len() as u64;
        let up = in_window.iter().filter(|r| r.status == CheckStatus::Up).count() as u64;
        let failed = total - up;
        let uptime_pct = (up as f64 / total as f64) * 100.0;
        Ok(Some(UptimeResult { target_id, uptime_pct, total_checks: total, failed_checks: failed }))
    }

    async fn dashboard_rollup(&self) -> Result<Vec<DashboardRow>> {
        let targets = self.targets.read();
        let results = self.results.read();
        let now = Utc::now();
        let day_ago = now - ChronoDuration::hours(24);
        let ninety_days_ago = now - ChronoDuration::days(90);

        let mut out = Vec::with_capacity(targets.len());
        for target in targets.values() {
            let target_results: Vec<&CheckResult> =
                results.iter().filter(|r| r.target_id == target.id).collect();

            // Latest result for current status.
            let latest =
                target_results.iter().max_by_key(|r| r.timestamp).map(|r| (r.timestamp, r.status));

            // Trailing 24h uptime.
            let window: Vec<&CheckResult> =
                target_results.iter().filter(|r| r.timestamp >= day_ago).copied().collect();
            let uptime_pct_24h = if window.is_empty() {
                None
            } else {
                let up = window.iter().filter(|r| r.status == CheckStatus::Up).count();
                Some((up as f64 / window.len() as f64) * 100.0)
            };

            // Trailing 24h p95.
            let p95_24h = if window.is_empty() {
                None
            } else {
                let mut durations: Vec<f64> =
                    window.iter().map(|r| f64::from(r.duration_ms)).collect();
                durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                Some(percentile(&durations, 0.95))
            };

            // 90-day day-strip history.
            let history_results: Vec<&CheckResult> =
                target_results.iter().filter(|r| r.timestamp >= ninety_days_ago).copied().collect();
            let history = day_strip(&history_results, ninety_days_ago, now);

            out.push(DashboardRow {
                target_id: target.id,
                name: target.name.clone(),
                kind: target.check.kind().to_string(),
                enabled: target.enabled,
                current_status: latest.map_or(CheckStatus::Up, |(_, s)| s),
                last_check_at: latest.map(|(ts, _)| ts),
                uptime_pct_24h,
                p95_24h,
                history,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn dashboard_summary(&self) -> Result<DashboardSummary> {
        let targets = self.targets.read();
        let results = self.results.read();
        let mut summary = DashboardSummary { total: targets.len() as u64, ..Default::default() };
        for target in targets.values() {
            if !target.enabled {
                summary.disabled += 1;
                continue;
            }
            let latest =
                results.iter().filter(|r| r.target_id == target.id).max_by_key(|r| r.timestamp);
            match latest.map(|r| r.status) {
                Some(CheckStatus::Up) => summary.up += 1,
                Some(CheckStatus::Down) => summary.down += 1,
                Some(CheckStatus::Degraded) => summary.degraded += 1,
                Some(CheckStatus::Error) => summary.error += 1,
                None => {}
                // `CheckStatus` is `#[non_exhaustive]`; unknown future
                // variants are ignored for counting purposes.
                Some(_) => {}
            }
        }
        Ok(summary)
    }

    async fn component_day_history(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ComponentDayHistory>> {
        let results = self.results.read();
        let target_results: Vec<&CheckResult> = results
            .iter()
            .filter(|r| r.target_id == target_id && r.timestamp >= from && r.timestamp <= to)
            .collect();
        Ok(day_strip_dated(target_id, &target_results, from, to))
    }

    async fn recent_results_for_targets(
        &self,
        target_ids: &[Uuid],
        limit_per_target: u32,
    ) -> Result<HashMap<Uuid, Vec<CheckResult>>> {
        let results = self.results.read();
        let limit = limit_per_target as usize;
        let mut out = HashMap::new();
        for &tid in target_ids {
            let mut filtered: Vec<CheckResult> =
                results.iter().filter(|r| r.target_id == tid).cloned().collect();
            filtered.sort_by_key(|r| Reverse(r.timestamp));
            filtered.truncate(limit);
            out.insert(tid, filtered);
        }
        Ok(out)
    }

    // ── Notification channels ────────────────────────────────────────────

    async fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        let map = self.notification_channels.read();
        let mut out: Vec<NotificationChannel> = map.values().cloned().collect();
        out.sort_by_key(|c| c.created_at);
        Ok(out)
    }

    async fn get_notification_channel(&self, id: Uuid) -> Result<NotificationChannel> {
        let map = self.notification_channels.read();
        map.get(&id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("notification channel {id}")).into())
    }

    async fn create_notification_channel(
        &self,
        channel: &NewNotificationChannel,
    ) -> Result<NotificationChannel> {
        let mut map = self.notification_channels.write();
        let now = Utc::now();
        let created = NotificationChannel {
            id: Uuid::now_v7(),
            name: channel.name.clone(),
            kind: channel.config.kind(),
            config: channel.config.clone(),
            enabled: channel.enabled,
            disabled_reason: None,
            verified_at: None,
            created_at: now,
            updated_at: now,
            write_source: WriteSource::Ui,
        };
        map.insert(created.id, created.clone());
        Ok(created)
    }

    async fn update_notification_channel(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel> {
        let mut map = self.notification_channels.write();
        let channel = map
            .get_mut(&id)
            .ok_or_else(|| StorageError::NotFound(format!("notification channel {id}")))?;
        if let Some(name) = &update.name {
            channel.name.clone_from(name);
        }
        if let Some(config) = &update.config {
            channel.config = config.clone();
            channel.kind = config.kind();
        }
        if let Some(enabled) = update.enabled {
            channel.enabled = enabled;
            if enabled {
                channel.disabled_reason = None;
            }
        }
        channel.updated_at = Utc::now();
        Ok(channel.clone())
    }

    async fn delete_notification_channel(&self, id: Uuid) -> Result<()> {
        let mut map = self.notification_channels.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("notification channel {id}")).into());
        }
        drop(map);
        // Clean up all bindings for this channel.
        let mut bindings = self.target_channels.write();
        bindings.retain(|b| b.channel_id != id);
        Ok(())
    }

    // ── Channel verification tokens ─────────────────────────────────────

    async fn create_channel_verification_token(
        &self,
        channel_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let now = Utc::now();
        let row = ChannelVerificationTokenRow {
            id: Uuid::now_v7(),
            channel_id,
            token_hash: token_hash.to_string(),
            expires_at,
            used_at: None,
            created_at: now,
        };
        let mut map = self.channel_verification_tokens.write();
        map.insert(row.id, row);
        Ok(())
    }

    async fn consume_channel_verification_token(&self, token_hash: &str) -> Result<Option<Uuid>> {
        let now = Utc::now();
        let mut map = self.channel_verification_tokens.write();
        // Find the oldest unused, non-expired row matching the hash and mark
        // it used in a single mutable pass under the write lock — avoids the
        // second `get_mut` lookup (and the `expect` it required) entirely.
        let chosen = map
            .values_mut()
            .filter(|t| t.token_hash == token_hash && t.used_at.is_none() && t.expires_at > now)
            .min_by_key(|t| t.created_at);
        let Some(row) = chosen else {
            return Ok(None);
        };
        row.used_at = Some(now);
        Ok(Some(row.channel_id))
    }

    async fn set_channel_verified(&self, channel_id: Uuid) -> Result<()> {
        let mut map = self.notification_channels.write();
        let channel = map
            .get_mut(&channel_id)
            .ok_or_else(|| StorageError::NotFound(format!("notification channel {channel_id}")))?;
        channel.verified_at = Some(Utc::now());
        channel.updated_at = Utc::now();
        Ok(())
    }

    async fn set_channel_disabled_reason(&self, channel_id: Uuid, reason: &str) -> Result<()> {
        let mut map = self.notification_channels.write();
        let channel = map
            .get_mut(&channel_id)
            .ok_or_else(|| StorageError::NotFound(format!("notification channel {channel_id}")))?;
        channel.disabled_reason = if reason.is_empty() { None } else { Some(reason.to_string()) };
        channel.updated_at = Utc::now();
        Ok(())
    }

    // ── Target ↔ notification channel bindings ───────────────────────────

    async fn list_target_channels(&self, target_id: Uuid) -> Result<Vec<TargetChannelBinding>> {
        let bindings = self.target_channels.read();
        let mut out: Vec<TargetChannelBinding> =
            bindings.iter().filter(|b| b.target_id == target_id).cloned().collect();
        out.sort_by_key(|b| b.created_at);
        Ok(out)
    }

    async fn bind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()> {
        let mut bindings = self.target_channels.write();
        // Idempotent: if the binding already exists, do nothing.
        if bindings.iter().any(|b| b.target_id == target_id && b.channel_id == channel_id) {
            return Ok(());
        }
        bindings.push(TargetChannelBinding { target_id, channel_id, created_at: Utc::now() });
        Ok(())
    }

    async fn unbind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()> {
        let mut bindings = self.target_channels.write();
        bindings.retain(|b| !(b.target_id == target_id && b.channel_id == channel_id));
        Ok(())
    }

    async fn unbind_channel_everywhere(&self, channel_id: Uuid) -> Result<()> {
        let mut bindings = self.target_channels.write();
        bindings.retain(|b| b.channel_id != channel_id);
        Ok(())
    }

    // ── Incident ops ─────────────────────────────────────────────────────

    async fn apply_incident_ops(
        &self,
        incident_id: Uuid,
        patch: &IncidentOpsPatch,
    ) -> Result<Incident> {
        let mut map = self.incidents.write();
        let incident = map
            .get_mut(&incident_id)
            .ok_or_else(|| StorageError::NotFound(format!("incident {incident_id}")))?;

        // Determine current state from ended_at (Resolved iff ended_at is set).
        let current_state = if incident.ended_at.is_some() {
            IncidentState::Resolved
        } else {
            IncidentState::Triggered
        };

        // Apply transition.
        if let Some(transition_str) = &patch.transition {
            let transition = match transition_str.as_str() {
                "acknowledge" => IncidentTransition::Acknowledge,
                "resolve" => IncidentTransition::Resolve,
                "reopen" => IncidentTransition::Reopen,
                other => {
                    return Err(
                        StorageError::Conflict(format!("unknown transition: {other}")).into()
                    );
                }
            };
            let new_state = next_state(current_state, transition)
                .map_err(|e| StorageError::Conflict(e.to_string()))?;
            match new_state {
                IncidentState::Resolved => {
                    let now = Utc::now();
                    let duration = (now - incident.started_at).num_seconds().max(0) as u64;
                    incident.ended_at = Some(now);
                    incident.duration_secs = Some(duration);
                }
                IncidentState::Triggered => {
                    incident.ended_at = None;
                    incident.duration_secs = None;
                }
                IncidentState::Acknowledged => {
                    // No dedicated field on the public Incident projection;
                    // acknowledgement is an internal-only state.
                }
                // `IncidentState` is `#[non_exhaustive]`; unknown future
                // states require no special handling here.
                _ => {}
            }
        }

        // Apply severity change.
        if let Some(severity) = patch.severity {
            incident.severity = severity;
        }

        // Apply note (append as a public update since the public Incident
        // type has no separate internal timeline).
        if let Some(note) = &patch.note {
            incident.updates.push(PublicIncidentUpdate {
                posted_at: Utc::now(),
                phase: IncidentStatusPhase::Investigating,
                message: note.clone(),
            });
        }

        // assignee_id and publish operate on the internal OpsIncident
        // projection which is not modelled on the public Incident type;
        // they are accepted but have no effect here.

        incident.updated_at = Some(Utc::now());
        Ok(incident.clone())
    }

    async fn incident_metrics(&self, window_days: u32) -> Result<IncidentMetricsRollup> {
        let map = self.incidents.read();
        let now = Utc::now();
        let cutoff = now - ChronoDuration::days(i64::from(window_days));
        let in_window: Vec<&Incident> = map.values().filter(|i| i.started_at >= cutoff).collect();
        let total = in_window.len() as u64;
        let open = in_window.iter().filter(|i| i.ended_at.is_none()).count() as u64;
        let resolved = in_window.iter().filter(|i| i.ended_at.is_some()).count() as u64;
        let mttr_secs = if resolved == 0 {
            None
        } else {
            let sum: f64 = in_window.iter().filter_map(|i| i.duration_secs.map(|s| s as f64)).sum();
            Some(sum / resolved as f64)
        };
        Ok(IncidentMetricsRollup { window_days, total, open, resolved, mttr_secs })
    }

    // ── Subscriber deliveries ────────────────────────────────────────────

    async fn list_pending_deliveries(&self, limit: u32) -> Result<Vec<SubscriberDelivery>> {
        let deliveries = self.subscriber_deliveries.read();
        let now = Utc::now();
        let mut out: Vec<SubscriberDelivery> = deliveries
            .iter()
            .filter(|d| {
                d.status == DeliveryStatus::Pending
                    || (d.status == DeliveryStatus::Failed
                        && d.next_attempt_at.is_some_and(|t| t <= now))
            })
            .cloned()
            .collect();
        out.sort_by_key(|d| d.created_at);
        out.truncate(limit as usize);
        Ok(out)
    }

    async fn claim_delivery(&self, id: Uuid) -> Result<Option<SubscriberDelivery>> {
        let mut deliveries = self.subscriber_deliveries.write();
        let now = Utc::now();
        for d in deliveries.iter_mut() {
            if d.id == id {
                let claimable = d.status == DeliveryStatus::Pending
                    || (d.status == DeliveryStatus::Failed
                        && d.next_attempt_at.is_some_and(|t| t <= now));
                if !claimable {
                    return Ok(None);
                }
                d.status = DeliveryStatus::Claimed;
                return Ok(Some(d.clone()));
            }
        }
        Ok(None)
    }

    async fn mark_delivery(
        &self,
        id: Uuid,
        status: DeliveryStatus,
        error: Option<&str>,
    ) -> Result<()> {
        let mut deliveries = self.subscriber_deliveries.write();
        for d in deliveries.iter_mut() {
            if d.id == id {
                d.status = status;
                d.attempts += 1;
                d.last_error = error.map(|e| e.to_string());
                let now = Utc::now();
                match status {
                    DeliveryStatus::Sent => {
                        d.sent_at = Some(now);
                        d.next_attempt_at = None;
                    }
                    DeliveryStatus::DeadLetter => {
                        d.next_attempt_at = None;
                    }
                    DeliveryStatus::Failed => {
                        // Exponential backoff: 30s * 2^attempts, capped at 1h.
                        let backoff_secs = (30 * 2u64.pow(d.attempts.min(7))).min(3600);
                        d.next_attempt_at =
                            Some(now + ChronoDuration::seconds(backoff_secs as i64));
                    }
                    _ => {}
                }
                return Ok(());
            }
        }
        Err(StorageError::NotFound(format!("delivery {id}")).into())
    }

    async fn enqueue_delivery(
        &self,
        subscriber_id: Uuid,
        status_page_id: Uuid,
        channel: SubscriberChannel,
        target: &str,
        payload: &str,
        reason: DeliveryReason,
    ) -> Result<()> {
        let mut deliveries = self.subscriber_deliveries.write();
        let now = Utc::now();
        deliveries.push(SubscriberDelivery {
            id: Uuid::now_v7(),
            subscriber_id,
            status_page_id,
            channel,
            target: target.to_string(),
            payload: payload.to_string(),
            reason,
            status: DeliveryStatus::Pending,
            attempts: 0,
            last_error: None,
            created_at: now,
            sent_at: None,
            next_attempt_at: Some(now),
        });
        Ok(())
    }

    async fn delete_old_deliveries(&self, older_than: chrono::DateTime<Utc>) -> Result<u64> {
        let mut deliveries = self.subscriber_deliveries.write();
        let before = deliveries.len();
        // Purge by the most recent activity timestamp: prefer `sent_at`
        // (when the delivery actually went out), fall back to `created_at`.
        // Matches the DuckDB `COALESCE(sent_at, created_at)` filter so both
        // backends retire the same set of rows for a given cutoff.
        deliveries.retain(|d| {
            !(matches!(d.status, DeliveryStatus::Sent | DeliveryStatus::DeadLetter)
                && d.sent_at.unwrap_or(d.created_at) < older_than)
        });
        Ok((before - deliveries.len()) as u64)
    }

    async fn delete_unverified_subscribers(
        &self,
        older_than: chrono::DateTime<Utc>,
    ) -> Result<u64> {
        let mut subs = self.subscribers.write();
        let before = subs.len();
        subs.retain(|_, s| !(s.verified_at.is_none() && s.created_at < older_than));
        Ok((before - subs.len()) as u64)
    }

    async fn delete_old_check_results(&self, older_than: chrono::DateTime<Utc>) -> Result<u64> {
        let mut results = self.results.write();
        let before = results.len();
        results.retain(|r| r.timestamp >= older_than);
        Ok((before - results.len()) as u64)
    }

    // ── Domain expiry state ──────────────────────────────────────────────

    async fn get_domain_expiry_state(&self, target_id: Uuid) -> Result<Option<DomainExpiryState>> {
        let map = self.domain_expiry_states.read();
        Ok(map.get(&target_id).cloned())
    }

    async fn set_domain_expiry_state(&self, state: &DomainExpiryState) -> Result<()> {
        let mut map = self.domain_expiry_states.write();
        map.insert(state.target_id, state.clone());
        Ok(())
    }

    // ── Auth: users ──────────────────────────────────────────────────────

    async fn create_user(&self, new: &NewUser) -> Result<User> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let email = normalize_oauth_email(&new.email);
        let email_verified_at = new.email_verified.then_some(now);
        let user = User {
            id: UserId(id),
            email: email.clone(),
            display_name: new.display_name.clone(),
            email_verified_at,
            last_seen_at: None,
            theme: AppTheme::Default,
            time_format: TimeFormat::Auto,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let mut map = self.users.write();
        // Conflict on duplicate email among non-deleted users.
        let exists = map.values().any(|u| u.email == email && u.deleted_at.is_none());
        if exists {
            return Err(StorageError::Conflict(format!("user email '{}' exists", email)).into());
        }
        map.insert(id, user.clone());
        Ok(user)
    }

    async fn get_user(&self, id: Uuid) -> Result<User> {
        let map = self.users.read();
        let user = map
            .get(&id)
            .filter(|u| u.deleted_at.is_none())
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("user {id}")))?;
        Ok(user)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let normalized = normalize_oauth_email(email);
        let map = self.users.read();
        Ok(map.values().find(|u| u.email == normalized && u.deleted_at.is_none()).cloned())
    }

    async fn count_users(&self) -> Result<i64> {
        let map = self.users.read();
        Ok(map.values().filter(|u| u.deleted_at.is_none()).count() as i64)
    }

    async fn update_user(&self, id: Uuid, update: &UserUpdate) -> Result<User> {
        let mut map = self.users.write();
        let user = map
            .get_mut(&id)
            .filter(|u| u.deleted_at.is_none())
            .ok_or_else(|| StorageError::NotFound(format!("user {id}")))?;
        if let Some(display_name) = &update.display_name {
            user.display_name = Some(display_name.clone());
        }
        if let Some(theme) = update.theme {
            user.theme = theme;
        }
        if let Some(time_format) = update.time_format {
            user.time_format = time_format;
        }
        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn touch_user(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        let mut map = self.users.write();
        if let Some(user) = map.get_mut(&id).filter(|u| u.deleted_at.is_none()) {
            user.last_seen_at = Some(at);
        }
        Ok(())
    }

    // ── Auth: sessions ───────────────────────────────────────────────────

    async fn create_session(
        &self,
        id_hash: &str,
        new: &statuscore::domain::NewSession,
    ) -> Result<SessionRow> {
        let now = Utc::now();
        let row = SessionRow {
            id_hash: id_hash.to_string(),
            user_id: new.user_id,
            created_at: now,
            last_used_at: now,
            expires_at: new.expires_at,
            ip_hash: new.ip_hash.clone(),
            user_agent_hash: new.user_agent_hash.clone(),
        };
        let mut map = self.sessions.write();
        if map.contains_key(&row.id_hash) {
            return Err(StorageError::Conflict(format!(
                "session id_hash '{}' exists",
                row.id_hash
            ))
            .into());
        }
        map.insert(row.id_hash.clone(), row.clone());
        Ok(row)
    }

    async fn lookup_session(&self, id_hash: &str) -> Result<Option<SessionRow>> {
        let map = self.sessions.read();
        Ok(map.get(id_hash).cloned())
    }

    async fn touch_session(&self, id_hash: &str, at: DateTime<Utc>) -> Result<()> {
        let mut map = self.sessions.write();
        if let Some(session) = map.get_mut(id_hash) {
            session.last_used_at = at;
        }
        Ok(())
    }

    async fn delete_session(&self, id_hash: &str) -> Result<()> {
        let mut map = self.sessions.write();
        map.remove(id_hash);
        Ok(())
    }

    async fn delete_other_sessions(&self, user_id: Uuid, keep_id_hash: &str) -> Result<u64> {
        let mut map = self.sessions.write();
        let before = map.len();
        map.retain(|id_hash, session| !(session.user_id.0 == user_id && id_hash != keep_id_hash));
        Ok((before - map.len()) as u64)
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRow>> {
        let map = self.sessions.read();
        let mut out: Vec<SessionRow> =
            map.values().filter(|s| s.user_id.0 == user_id).cloned().collect();
        out.sort_by_key(|s| Reverse(s.created_at));
        Ok(out)
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<u64> {
        let mut map = self.sessions.write();
        let before = map.len();
        map.retain(|_, session| session.expires_at >= now);
        Ok((before - map.len()) as u64)
    }

    // ── Auth: API tokens ─────────────────────────────────────────────────

    async fn create_api_token(
        &self,
        user_id: Uuid,
        new: &NewApiToken,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<ApiTokenRow> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let scopes = new.scopes.clone().unwrap_or_else(ScopeSet::full_access);
        let expires_at =
            new.expires_in_days.map(|days| now + ChronoDuration::days(i64::from(days)));
        let row = ApiTokenRow {
            id,
            user_id: UserId(user_id),
            name: new.name.clone(),
            token_hash: token_hash.to_string(),
            token_prefix: token_prefix.to_string(),
            scopes,
            created_at: now,
            last_used_at: None,
            expires_at,
        };
        let mut map = self.api_tokens.write();
        if map.contains_key(&id) {
            return Err(StorageError::Conflict(format!("api token {id} exists")).into());
        }
        map.insert(id, row.clone());
        Ok(row)
    }

    async fn find_api_tokens_by_prefix(&self, prefix: &str) -> Result<Vec<ApiTokenRow>> {
        let map = self.api_tokens.read();
        let mut out: Vec<ApiTokenRow> =
            map.values().filter(|t| t.token_prefix == prefix).cloned().collect();
        out.sort_by_key(|t| Reverse(t.created_at));
        Ok(out)
    }

    async fn list_api_tokens(&self, user_id: Uuid) -> Result<Vec<ApiTokenRow>> {
        let map = self.api_tokens.read();
        let mut out: Vec<ApiTokenRow> =
            map.values().filter(|t| t.user_id.0 == user_id).cloned().collect();
        out.sort_by_key(|t| Reverse(t.created_at));
        Ok(out)
    }

    async fn update_api_token(&self, id: Uuid, update: &ApiTokenUpdate) -> Result<ApiTokenRow> {
        let mut map = self.api_tokens.write();
        let token =
            map.get_mut(&id).ok_or_else(|| StorageError::NotFound(format!("api token {id}")))?;
        token.name.clone_from(&update.name);
        Ok(token.clone())
    }

    async fn touch_api_token(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        let mut map = self.api_tokens.write();
        if let Some(token) = map.get_mut(&id) {
            token.last_used_at = Some(at);
        }
        Ok(())
    }

    async fn delete_api_token(&self, id: Uuid) -> Result<()> {
        let mut map = self.api_tokens.write();
        map.remove(&id);
        Ok(())
    }

    async fn delete_api_tokens_for_user(&self, user_id: Uuid) -> Result<u64> {
        let mut map = self.api_tokens.write();
        let before = map.len();
        map.retain(|_, token| token.user_id.0 != user_id);
        Ok((before - map.len()) as u64)
    }

    async fn delete_expired_api_tokens(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        let mut map = self.api_tokens.write();
        let before = map.len();
        map.retain(|_, token| {
            // Keep tokens with no expiry or whose expiry is still in the future.
            token.expires_at.is_none_or(|exp| exp >= cutoff)
        });
        Ok((before - map.len()) as u64)
    }

    // ── Auth: magic links ────────────────────────────────────────────────

    async fn create_magic_link(
        &self,
        email: &str,
        token_hash: &str,
        token_prefix: &str,
        expires_at: DateTime<Utc>,
        ip_hash: Option<&str>,
        redirect_after: Option<&str>,
    ) -> Result<MagicLinkRow> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let normalized = normalize_oauth_email(email);
        let row = MagicLinkRow {
            id,
            email: normalized,
            token_hash: token_hash.to_string(),
            token_prefix: token_prefix.to_string(),
            created_at: now,
            expires_at,
            used_at: None,
            ip_hash: ip_hash.map(|s| s.to_string()),
            redirect_after: redirect_after.map(|s| s.to_string()),
        };
        let mut map = self.magic_links.write();
        if map.contains_key(&id) {
            return Err(StorageError::Conflict(format!("magic link {id} exists")).into());
        }
        map.insert(id, row.clone());
        Ok(row)
    }

    async fn find_magic_links_by_prefix(&self, prefix: &str) -> Result<Vec<MagicLinkRow>> {
        let map = self.magic_links.read();
        let mut out: Vec<MagicLinkRow> = map
            .values()
            .filter(|m| m.token_prefix == prefix && m.used_at.is_none())
            .cloned()
            .collect();
        out.sort_by_key(|m| Reverse(m.created_at));
        Ok(out)
    }

    async fn consume_magic_link(&self, id: Uuid) -> Result<Option<MagicLinkRow>> {
        let mut map = self.magic_links.write();
        let Some(link) = map.get_mut(&id) else {
            return Ok(None);
        };
        if link.used_at.is_some() {
            return Ok(None);
        }
        link.used_at = Some(Utc::now());
        Ok(Some(link.clone()))
    }

    async fn delete_expired_magic_links(&self, now: DateTime<Utc>) -> Result<u64> {
        let mut map = self.magic_links.write();
        let before = map.len();
        map.retain(|_, link| !(link.expires_at < now && link.used_at.is_none()));
        Ok((before - map.len()) as u64)
    }

    // ── Escalation policies ──────────────────────────────────────────────

    async fn list_escalation_policies(&self) -> Result<Vec<EscalationPolicySummary>> {
        let map = self.escalation_policies.read();
        let mut out: Vec<EscalationPolicySummary> = map
            .values()
            .map(|p| EscalationPolicySummary {
                id: p.id,
                name: p.name.clone(),
                description: p.description.clone(),
                repeat_count: p.repeat_count,
                step_count: p.steps.len() as i64,
                created_at: p.created_at,
                updated_at: p.updated_at,
            })
            .collect();
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    async fn get_escalation_policy(&self, id: Uuid) -> Result<EscalationPolicy> {
        let map = self.escalation_policies.read();
        map.get(&id)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("escalation policy {id}")).into())
    }

    async fn upsert_escalation_policy(
        &self,
        policy: &EscalationPolicy,
    ) -> Result<EscalationPolicy> {
        let mut map = self.escalation_policies.write();
        map.insert(policy.id, policy.clone());
        Ok(policy.clone())
    }

    async fn delete_escalation_policy(&self, id: Uuid) -> Result<()> {
        let mut map = self.escalation_policies.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("escalation policy {id}")).into());
        }
        Ok(())
    }

    // ── On-call schedules ────────────────────────────────────────────────

    async fn list_on_call_schedules(&self) -> Result<Vec<OnCallScheduleSummary>> {
        let map = self.on_call_schedules.read();
        let mut out: Vec<OnCallScheduleSummary> = map
            .values()
            .map(|d| OnCallScheduleSummary {
                id: d.schedule.id,
                name: d.schedule.name.clone(),
                timezone: d.schedule.timezone.clone(),
                layer_count: d.layers.len() as i64,
                created_at: d.schedule.created_at,
                updated_at: d.schedule.updated_at,
            })
            .collect();
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    async fn get_on_call_schedule(&self, id: Uuid) -> Result<OnCallScheduleDetail> {
        let map = self.on_call_schedules.read();
        let detail =
            map.get(&id).ok_or_else(|| StorageError::NotFound(format!("on-call schedule {id}")))?;
        // Overrides are stored separately so the schedule aggregate stays
        // editable without round-tripping the calendar — load them here so
        // the detail returned to the resolver matches the DuckDB path.
        let overrides = self.overrides_for_schedule(id);
        Ok(OnCallScheduleDetail {
            schedule: detail.schedule.clone(),
            layers: detail.layers.clone(),
            overrides,
        })
    }

    async fn upsert_on_call_schedule(
        &self,
        detail: &OnCallScheduleDetail,
    ) -> Result<OnCallSchedule> {
        let mut map = self.on_call_schedules.write();
        // Store schedule + layers only — overrides are managed separately.
        map.insert(
            detail.schedule.id,
            OnCallScheduleDetail {
                schedule: detail.schedule.clone(),
                layers: detail.layers.clone(),
                overrides: Vec::new(),
            },
        );
        Ok(detail.schedule.clone())
    }

    async fn delete_on_call_schedule(&self, id: Uuid) -> Result<()> {
        let mut map = self.on_call_schedules.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("on-call schedule {id}")).into());
        }
        drop(map);
        // Cascade-delete overrides for the schedule (matches DuckDB behaviour).
        let mut overrides = self.on_call_overrides.write();
        overrides.retain(|_, (sid, _)| *sid != id);
        Ok(())
    }

    // ── On-call overrides ───────────────────────────────────────────────

    async fn list_on_call_overrides(&self, schedule_id: Uuid) -> Result<Vec<OnCallOverride>> {
        Ok(self.overrides_for_schedule(schedule_id))
    }

    async fn create_on_call_override(
        &self,
        schedule_id: Uuid,
        r#override: &OnCallOverride,
    ) -> Result<OnCallOverride> {
        let mut map = self.on_call_overrides.write();
        if map.contains_key(&r#override.id) {
            return Err(StorageError::Conflict(format!(
                "on-call override {} exists",
                r#override.id
            ))
            .into());
        }
        map.insert(r#override.id, (schedule_id, r#override.clone()));
        Ok(r#override.clone())
    }

    async fn delete_on_call_override(&self, id: Uuid) -> Result<()> {
        let mut map = self.on_call_overrides.write();
        if map.remove(&id).is_none() {
            return Err(StorageError::NotFound(format!("on-call override {id}")).into());
        }
        Ok(())
    }

    // ── Incident escalation state ────────────────────────────────────────

    async fn get_escalation_state(
        &self,
        incident_id: Uuid,
    ) -> Result<Option<IncidentEscalationState>> {
        let map = self.escalation_states.read();
        Ok(map.get(&incident_id).cloned())
    }

    async fn upsert_escalation_state(&self, state: &IncidentEscalationState) -> Result<()> {
        let mut map = self.escalation_states.write();
        map.insert(state.incident_id, state.clone());
        Ok(())
    }

    async fn list_due_escalation_states(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<IncidentEscalationState>> {
        let map = self.escalation_states.read();
        let mut out: Vec<IncidentEscalationState> =
            map.values().filter(|s| !s.acked && s.next_check_at <= now).cloned().collect();
        out.sort_by_key(|s| s.next_check_at);
        Ok(out)
    }

    async fn ack_escalation_state(&self, incident_id: Uuid) -> Result<()> {
        let mut map = self.escalation_states.write();
        let state = map.get_mut(&incident_id).ok_or_else(|| {
            StorageError::NotFound(format!("escalation state for incident {incident_id}"))
        })?;
        state.acked = true;
        Ok(())
    }

    async fn delete_escalation_state(&self, incident_id: Uuid) -> Result<()> {
        let mut map = self.escalation_states.write();
        // Idempotent — mirrors the DuckDB path. A resolve-before-page race
        // shouldn't surface as NotFound.
        map.remove(&incident_id);
        Ok(())
    }

    // ── Postmortems ─────────────────────────────────────────────────────

    async fn get_postmortem(&self, incident_id: Uuid) -> Result<Option<IncidentPostmortem>> {
        let map = self.postmortems.read();
        Ok(map.get(&incident_id).cloned())
    }

    async fn upsert_postmortem(
        &self,
        incident_id: Uuid,
        author_id: Option<Uuid>,
        body: &PostmortemUpsert,
    ) -> Result<IncidentPostmortem> {
        let now = Utc::now();
        let mut map = self.postmortems.write();
        // Preserve an existing `published_at` across the replace so an
        // operator can edit a published postmortem without un-publishing it.
        let published_at = map.get(&incident_id).and_then(|p| p.published_at);
        // Preserve the original `created_at` on update; stamp `now` on insert.
        let created_at = map.get(&incident_id).map_or(now, |p| p.created_at);
        let pm = IncidentPostmortem {
            incident_id,
            summary: body.summary.clone(),
            root_cause: body.root_cause.clone(),
            impact: body.impact.clone(),
            action_items: body.action_items.clone(),
            author_id: author_id.map(UserId),
            created_at,
            updated_at: now,
            published_at,
        };
        map.insert(incident_id, pm.clone());
        Ok(pm)
    }

    async fn publish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem> {
        let now = Utc::now();
        let mut map = self.postmortems.write();
        let pm = map.get_mut(&incident_id).ok_or_else(|| {
            StorageError::NotFound(format!("postmortem for incident {incident_id}"))
        })?;
        pm.published_at = Some(now);
        pm.updated_at = now;
        Ok(pm.clone())
    }

    async fn unpublish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem> {
        let now = Utc::now();
        let mut map = self.postmortems.write();
        let pm = map.get_mut(&incident_id).ok_or_else(|| {
            StorageError::NotFound(format!("postmortem for incident {incident_id}"))
        })?;
        pm.published_at = None;
        pm.updated_at = now;
        Ok(pm.clone())
    }

    async fn delete_postmortem(&self, incident_id: Uuid) -> Result<()> {
        let mut map = self.postmortems.write();
        map.remove(&incident_id);
        Ok(())
    }

    // ── Monitor share links ─────────────────────────────────────────────

    async fn list_monitor_shares(&self, target_id: Uuid) -> Result<Vec<MonitorShare>> {
        let rows = self.monitor_shares.read();
        let mut out: Vec<MonitorShare> = rows
            .iter()
            .filter(|r| r.target_id == target_id)
            .map(|r| MonitorShare {
                id: MonitorShareId(r.id),
                org_id: OrgId(Uuid::nil()),
                target_id: r.target_id,
                label: r.label.clone(),
                // Raw token is never persisted; always `None` on read.
                token: None,
                created_at: r.created_at,
                expires_at: r.expires_at,
                view_count: r.view_count,
                last_viewed_at: r.last_viewed_at,
            })
            .collect();
        // Newest-first, matching DuckDB's ORDER BY created_at DESC.
        out.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        Ok(out)
    }

    async fn create_monitor_share(
        &self,
        target_id: Uuid,
        label: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedShare> {
        // Generate the raw capability token + its sha256_hex hash. Only the
        // hash is stored; the raw token returns once via `CreatedShare.token`.
        let raw_token = generate_cookie_value();
        let token_hash = hash_cookie_value(&raw_token);
        let now = Utc::now();
        let id = Uuid::now_v7();
        let row = MonitorShareRow {
            id,
            target_id,
            label: label.map(|s| s.to_string()),
            token_hash,
            created_at: now,
            expires_at,
            view_count: 0,
            last_viewed_at: None,
        };
        let mut rows = self.monitor_shares.write();
        // Detect token-hash collision (vanishingly unlikely with 256 bits,
        // but mirror DuckDB's UNIQUE constraint for parity).
        if rows.iter().any(|r| r.token_hash == row.token_hash) {
            return Err(StorageError::Conflict(format!(
                "monitor share token collision for target {target_id}"
            ))
            .into());
        }
        rows.push(row);
        let share = MonitorShare {
            id: MonitorShareId(id),
            org_id: OrgId(Uuid::nil()),
            target_id,
            label: label.map(|s| s.to_string()),
            token: None,
            created_at: now,
            expires_at,
            view_count: 0,
            last_viewed_at: None,
        };
        Ok(CreatedShare { share, token: raw_token })
    }

    async fn delete_monitor_share(&self, id: Uuid) -> Result<()> {
        let mut rows = self.monitor_shares.write();
        rows.retain(|r| r.id != id);
        Ok(())
    }

    async fn resolve_monitor_share(&self, token_hash: &str) -> Result<Option<ResolvedShare>> {
        let now = Utc::now();
        let mut rows = self.monitor_shares.write();
        // Find the matching, non-expired row. A token is invalid when the
        // hash is unknown or `expires_at` is in the past.
        let candidate = rows
            .iter_mut()
            .find(|r| r.token_hash == token_hash && r.expires_at.is_none_or(|e| e > now));
        let Some(row) = candidate else {
            return Ok(None);
        };
        row.view_count += 1;
        row.last_viewed_at = Some(now);
        Ok(Some(ResolvedShare {
            share_id: MonitorShareId(row.id),
            target_id: row.target_id,
            org: OrgId(Uuid::nil()),
        }))
    }

    // ── Health check ─────────────────────────────────────────────────────

    async fn ping(&self) -> Result<()> {
        Ok(())
    }
}

impl MemoryStorage {
    /// Snapshot of overrides for `schedule_id`, ordered by `starts_at`
    /// descending (matches DuckDB's listing order).
    fn overrides_for_schedule(&self, schedule_id: Uuid) -> Vec<OnCallOverride> {
        let map = self.on_call_overrides.read();
        let mut out: Vec<OnCallOverride> =
            map.values().filter(|(sid, _)| *sid == schedule_id).map(|(_, o)| o.clone()).collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.starts_at));
        out
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Linear-interpolation percentile on a pre-sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let rank = p * (n - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let frac = rank - lower as f64;
        sorted[upper].mul_add(frac, sorted[lower] * (1.0 - frac))
    }
}

/// Map a single check status to its day-strip state.
const fn check_status_to_day_state(status: CheckStatus) -> DayState {
    match status {
        CheckStatus::Up => DayState::Operational,
        CheckStatus::Degraded => DayState::Degraded,
        CheckStatus::Down | CheckStatus::Error => DayState::MajorOutage,
        // `CheckStatus` is `#[non_exhaustive]`; unknown future variants map to
        // `NoData` so they neither over- nor under-state impact.
        _ => DayState::NoData,
    }
}

/// Rank a DayState for "worst per day" comparison (higher = worse).
const fn day_state_rank(s: DayState) -> u8 {
    match s {
        DayState::Operational => 0,
        DayState::Maintenance => 1,
        DayState::Degraded => 2,
        DayState::PartialOutage => 3,
        DayState::MajorOutage => 4,
        DayState::NoData => 5, // shouldn't appear in inputs
        // `DayState` is `#[non_exhaustive]`; unknown future variants rank
        // below `Operational` so they never win the "worst per day" vote.
        _ => 0,
    }
}

/// Build a 90-day (or arbitrary window) day strip from a set of results.
/// Returns one entry per day in `[from, to]`, with the worst observed
/// `DayState` for that day, or `NoData` when the day had no checks.
fn day_strip(results: &[&CheckResult], from: DateTime<Utc>, to: DateTime<Utc>) -> Vec<DayState> {
    use std::collections::BTreeMap;
    let mut by_day: BTreeMap<NaiveDate, DayState> = BTreeMap::new();
    for r in results {
        let day = r.timestamp.date_naive();
        let state = check_status_to_day_state(r.status);
        let entry = by_day.entry(day).or_insert(DayState::Operational);
        if day_state_rank(state) > day_state_rank(*entry) {
            *entry = state;
        }
    }
    // Fill in every day in the window.
    let mut out = Vec::new();
    let mut cursor = from.date_naive();
    let end = to.date_naive();
    while cursor <= end {
        out.push(*by_day.get(&cursor).unwrap_or(&DayState::NoData));
        cursor += chrono::Duration::days(1);
    }
    out
}

/// Same as [`day_strip`] but returns dated entries for `component_day_history`.
fn day_strip_dated(
    target_id: Uuid,
    results: &[&CheckResult],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Vec<ComponentDayHistory> {
    use std::collections::BTreeMap;
    let mut by_day: BTreeMap<NaiveDate, DayState> = BTreeMap::new();
    for r in results {
        let day = r.timestamp.date_naive();
        let state = check_status_to_day_state(r.status);
        let entry = by_day.entry(day).or_insert(DayState::Operational);
        if day_state_rank(state) > day_state_rank(*entry) {
            *entry = state;
        }
    }
    let mut out = Vec::new();
    let mut cursor = from.date_naive();
    let end = to.date_naive();
    while cursor <= end {
        let state = *by_day.get(&cursor).unwrap_or(&DayState::NoData);
        out.push(ComponentDayHistory { target_id, day: cursor, state });
        cursor += chrono::Duration::days(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use statuscore::domain::{
        ActionItem, CheckResult, CheckSpec, CheckStatus, EscalationPolicy, EscalationStep,
        EscalationTarget, EscalationTargetType, Incident, IncidentEscalationState,
        IncidentSeverity, IncidentStatusPhase, OnCallLayer, OnCallOverride, OnCallParticipant,
        OnCallSchedule, OnCallScheduleDetail, OrgId, PingCheck, PostmortemUpsert,
        PublicIncidentUpdate, PublicOrgBranding, RotationType, StatusPage, StatusPageId, Target,
        UserId, WriteSource,
    };
    use std::time::Duration;
    use uuid::Uuid;

    fn make_target(name: &str) -> Target {
        Target {
            id: Uuid::now_v7(),
            name: name.into(),
            check: CheckSpec::Ping(PingCheck {
                host: "example.com".into(),
                timeout: Duration::from_secs(3),
            }),
            interval: Duration::from_mins(1),
            enabled: true,
            tags: vec!["edge".into()],
            alerts: Default::default(),
            alert_confirmations: 2,
            notify_recovery: true,
            renotify_interval_secs: 3600,
            region_policy: Default::default(),
            group_name: Some("API".into()),
            owner_user_id: None,
            escalation_policy_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            write_source: WriteSource::Ui,
        }
    }

    fn make_result(target_id: Uuid, org_id: Uuid, ts_ms: i64) -> CheckResult {
        CheckResult {
            target_id,
            org_id: OrgId(org_id),
            timestamp: chrono::DateTime::from_timestamp(0, 0).unwrap()
                + chrono::Duration::milliseconds(ts_ms),
            status: CheckStatus::Up,
            duration_ms: 42,
            dns_ms: Some(1),
            connect_ms: Some(2),
            tls_ms: None,
            ttfb_ms: Some(3),
            response_code: Some(200),
            response_size: Some(1024),
            error: None,
        }
    }

    fn make_incident(target_id: Uuid) -> Incident {
        Incident {
            id: Uuid::now_v7(),
            target_id,
            started_at: Utc::now(),
            ended_at: None,
            status: CheckStatus::Down,
            duration_secs: None,
            check_count: 1,
            error_sample: Some("timeout".into()),
            severity: IncidentSeverity::Major,
            public_title: Some("Major outage".into()),
            public_description: None,
            created_at: Some(Utc::now()),
            updated_at: None,
            updates: Vec::new(),
            regions_down: Vec::new(),
            regions_up: Vec::new(),
        }
    }

    fn make_status_page(slug: &str, org_id: Uuid) -> StatusPage {
        StatusPage {
            id: StatusPageId(Uuid::now_v7()),
            org_id: OrgId(org_id),
            slug: slug.into(),
            name: format!("Page {slug}"),
            enabled: true,
            branding: PublicOrgBranding {
                public_display_name: Some("Display".into()),
                ..PublicOrgBranding::default()
            },
            write_source: WriteSource::Ui,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_incident_update(message: &str) -> PublicIncidentUpdate {
        PublicIncidentUpdate {
            posted_at: Utc::now(),
            phase: IncidentStatusPhase::Investigating,
            message: message.into(),
        }
    }

    #[tokio::test]
    async fn target_crud_roundtrip() {
        let s = MemoryStorage::new();
        let t = make_target("api");
        let created = s.create_target(&t).await.unwrap();
        assert_eq!(created.id, t.id);

        let got = s.get_target(t.id).await.unwrap();
        assert_eq!(got.name, t.name);
        assert_eq!(got.tags, t.tags);
        assert_eq!(got.check.kind(), "ping");
        assert_eq!(got.group_name.as_deref(), Some("API"));

        let listed = s.list_targets().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, t.id);

        let mut updated = t.clone();
        updated.name = "api-v2".into();
        updated.enabled = false;
        let r = s.update_target(&updated).await.unwrap();
        assert_eq!(r.name, "api-v2");
        assert!(!r.enabled);
        let got2 = s.get_target(t.id).await.unwrap();
        assert_eq!(got2.name, "api-v2");
        assert!(!got2.enabled);

        s.delete_target(t.id).await.unwrap();
        let err = s.get_target(t.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn target_create_conflict_and_update_not_found() {
        let s = MemoryStorage::new();
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let err = s.create_target(&t).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));

        let other = make_target("other");
        let err = s.update_target(&other).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        let err = s.delete_target(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn results_record_list_sorted_and_limited() {
        let s = MemoryStorage::new();
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let org = Uuid::now_v7();
        for i in 0..5 {
            s.record_result(&make_result(t.id, org, i * 1000)).await.unwrap();
        }
        let listed = s.list_results(t.id, 3).await.unwrap();
        assert_eq!(listed.len(), 3);
        // DESC by timestamp — the largest ts_ms lands first.
        assert!(listed[0].timestamp > listed[1].timestamp);
        assert!(listed[1].timestamp > listed[2].timestamp);

        // Empty for an unknown target.
        let none = s.list_results(Uuid::now_v7(), 10).await.unwrap();
        assert!(none.is_empty());

        // Re-recording the same (target_id, timestamp) overwrites, not appends.
        let mut dup = make_result(t.id, org, 0);
        dup.duration_ms = 999;
        s.record_result(&dup).await.unwrap();
        let all = s.list_results(t.id, 100).await.unwrap();
        assert_eq!(all.len(), 5); // no duplicate row
        let first = all.iter().find(|r| r.timestamp == dup.timestamp).unwrap();
        assert_eq!(first.duration_ms, 999);
    }

    #[tokio::test]
    async fn incident_create_and_list() {
        let s = MemoryStorage::new();
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let inc = make_incident(t.id);
        s.create_incident(&inc).await.unwrap();

        let listed = s.list_incidents().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, inc.id);
        assert_eq!(listed[0].public_title.as_deref(), Some("Major outage"));
        assert_eq!(listed[0].severity, IncidentSeverity::Major);

        let err = s.create_incident(&inc).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));
    }

    #[tokio::test]
    async fn status_page_roundtrip_preserves_org_id() {
        let s = MemoryStorage::new();
        let org = Uuid::now_v7();
        let sp = make_status_page("acme", org);
        let created = s.create_status_page(&sp).await.unwrap();
        assert_eq!(created.id.0, sp.id.0);

        let got = s.get_status_page(sp.id.0).await.unwrap();
        assert_eq!(got.id.0, sp.id.0);
        assert_eq!(got.org_id.0, org);
        assert_eq!(got.slug, "acme");
        assert_eq!(got.branding.public_display_name.as_deref(), Some("Display"));

        let listed = s.list_status_pages().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].org_id.0, org);

        let err = s.get_status_page(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn status_page_crud_roundtrip() {
        let s = MemoryStorage::new();
        let org = Uuid::now_v7();
        let sp = make_status_page("acme", org);

        // create
        let created = s.create_status_page(&sp).await.unwrap();
        assert_eq!(created.id.0, sp.id.0);

        // create conflict (same id)
        let err = s.create_status_page(&sp).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));

        // update
        let mut updated = sp.clone();
        updated.name = "Acme v2".into();
        updated.enabled = false;
        let r = s.update_status_page(&updated).await.unwrap();
        assert_eq!(r.name, "Acme v2");
        assert!(!r.enabled);
        let got = s.get_status_page(sp.id.0).await.unwrap();
        assert_eq!(got.name, "Acme v2");
        assert!(!got.enabled);

        // update not found
        let other = make_status_page("other", org);
        let err = s.update_status_page(&other).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete
        s.delete_status_page(sp.id.0).await.unwrap();
        let err = s.get_status_page(sp.id.0).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete not found
        let err = s.delete_status_page(sp.id.0).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn incident_get_update_roundtrip() {
        let s = MemoryStorage::new();
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let inc = make_incident(t.id);
        s.create_incident(&inc).await.unwrap();

        // get
        let got = s.get_incident(inc.id).await.unwrap();
        assert_eq!(got.id, inc.id);
        assert_eq!(got.public_title.as_deref(), Some("Major outage"));

        // get not found
        let err = s.get_incident(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // update
        let mut updated = inc.clone();
        updated.public_title = Some("Updated title".into());
        updated.severity = IncidentSeverity::Critical;
        let r = s.update_incident(&updated).await.unwrap();
        assert_eq!(r.public_title.as_deref(), Some("Updated title"));
        assert_eq!(r.severity, IncidentSeverity::Critical);
        let got2 = s.get_incident(inc.id).await.unwrap();
        assert_eq!(got2.public_title.as_deref(), Some("Updated title"));
        assert_eq!(got2.severity, IncidentSeverity::Critical);

        // update not found
        let other = make_incident(t.id);
        let err = s.update_incident(&other).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn add_incident_update_appends_to_vec() {
        let s = MemoryStorage::new();
        let t = make_target("api");
        s.create_target(&t).await.unwrap();
        let inc = make_incident(t.id);
        s.create_incident(&inc).await.unwrap();

        assert!(inc.updates.is_empty());

        let u1 = make_incident_update("looking into it");
        let r1 = s.add_incident_update(inc.id, &u1).await.unwrap();
        assert_eq!(r1.updates.len(), 1);
        assert_eq!(r1.updates[0].message, "looking into it");

        let u2 = make_incident_update("identified");
        let r2 = s.add_incident_update(inc.id, &u2).await.unwrap();
        assert_eq!(r2.updates.len(), 2);
        assert_eq!(r2.updates[1].message, "identified");

        // persists across reads
        let got = s.get_incident(inc.id).await.unwrap();
        assert_eq!(got.updates.len(), 2);

        // not found when incident missing
        let err = s.add_incident_update(Uuid::now_v7(), &u1).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn list_recent_results_across_targets() {
        let s = MemoryStorage::new();
        let t1 = make_target("api");
        let t2 = make_target("web");
        s.create_target(&t1).await.unwrap();
        s.create_target(&t2).await.unwrap();
        let org = Uuid::now_v7();
        // t1: ts=1000, 2000 ; t2: ts=1500
        s.record_result(&make_result(t1.id, org, 1000)).await.unwrap();
        s.record_result(&make_result(t2.id, org, 1500)).await.unwrap();
        s.record_result(&make_result(t1.id, org, 2000)).await.unwrap();

        let recent = s.list_recent_results(100).await.unwrap();
        assert_eq!(recent.len(), 3);
        // DESC by timestamp
        assert!(recent[0].timestamp > recent[1].timestamp);
        assert!(recent[1].timestamp > recent[2].timestamp);

        // limit honored
        let limited = s.list_recent_results(2).await.unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].timestamp, recent[0].timestamp);

        // empty when nothing recorded
        let s2 = MemoryStorage::new();
        assert!(s2.list_recent_results(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn default_impl_matches_new() {
        let a = MemoryStorage::new();
        let b = MemoryStorage::default();
        // Both should start empty and behave identically.
        assert!(a.list_targets().await.unwrap().is_empty());
        assert!(b.list_targets().await.unwrap().is_empty());
    }

    // ── Escalation / on-call fixtures ───────────────────────────────────

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn make_escalation_policy(name: &str, repeat: i32) -> EscalationPolicy {
        EscalationPolicy {
            id: Uuid::now_v7(),
            name: name.into(),
            description: Some("test policy".into()),
            repeat_count: repeat,
            steps: vec![
                EscalationStep {
                    id: Uuid::now_v7(),
                    level: 1,
                    delay_secs: 300,
                    targets: vec![EscalationTarget {
                        id: Uuid::now_v7(),
                        target_type: EscalationTargetType::Channel,
                        user_id: None,
                        schedule_id: None,
                        channel_id: Some(Uuid::now_v7()),
                    }],
                },
                EscalationStep {
                    id: Uuid::now_v7(),
                    level: 2,
                    delay_secs: 900,
                    targets: vec![
                        EscalationTarget {
                            id: Uuid::now_v7(),
                            target_type: EscalationTargetType::User,
                            user_id: Some(Uuid::now_v7()),
                            schedule_id: None,
                            channel_id: None,
                        },
                        EscalationTarget {
                            id: Uuid::now_v7(),
                            target_type: EscalationTargetType::Channel,
                            user_id: None,
                            schedule_id: None,
                            channel_id: Some(Uuid::now_v7()),
                        },
                    ],
                },
            ],
            created_at: ts("2026-01-01T00:00:00Z"),
            updated_at: ts("2026-01-01T00:00:00Z"),
        }
    }

    fn make_on_call_schedule_detail(name: &str, tz: &str) -> OnCallScheduleDetail {
        let now = ts("2026-06-01T00:00:00Z");
        OnCallScheduleDetail {
            schedule: OnCallSchedule {
                id: Uuid::now_v7(),
                name: name.into(),
                timezone: tz.into(),
                created_at: now,
                updated_at: now,
            },
            layers: vec![OnCallLayer {
                id: Uuid::now_v7(),
                name: Some("primary".into()),
                rotation_type: RotationType::Daily,
                rotation_length_secs: 86_400,
                handoff_at: ts("2026-06-01T09:00:00Z"),
                layer_order: 0,
                created_at: now,
                participants: vec![
                    OnCallParticipant {
                        id: Uuid::now_v7(),
                        user_id: UserId(Uuid::from_u128(1)),
                        position: 0,
                    },
                    OnCallParticipant {
                        id: Uuid::now_v7(),
                        user_id: UserId(Uuid::from_u128(2)),
                        position: 1,
                    },
                ],
            }],
            overrides: Vec::new(),
        }
    }

    fn make_on_call_override(user: u128) -> OnCallOverride {
        OnCallOverride {
            id: Uuid::now_v7(),
            user_id: UserId(Uuid::from_u128(user)),
            starts_at: ts("2026-06-02T00:00:00Z"),
            ends_at: ts("2026-06-02T12:00:00Z"),
            created_by: None,
            created_at: ts("2026-06-01T00:00:00Z"),
        }
    }

    fn make_escalation_state(incident_id: Uuid, policy_id: Uuid) -> IncidentEscalationState {
        IncidentEscalationState {
            incident_id,
            policy_id,
            current_level: 0,
            current_round: 0,
            last_paged_at: ts("2026-06-01T00:00:00Z"),
            next_check_at: ts("2026-06-01T00:05:00Z"),
            acked: false,
        }
    }

    #[tokio::test]
    async fn escalation_policy_crud_roundtrip() {
        let s = MemoryStorage::new();
        let policy = make_escalation_policy("default", 1);

        // upsert (create)
        let created = s.upsert_escalation_policy(&policy).await.unwrap();
        assert_eq!(created.id, policy.id);

        // get
        let got = s.get_escalation_policy(policy.id).await.unwrap();
        assert_eq!(got.name, "default");
        assert_eq!(got.repeat_count, 1);
        assert_eq!(got.steps.len(), 2);
        assert_eq!(got.steps[0].level, 1);
        assert_eq!(got.steps[1].targets.len(), 2);
        assert_eq!(got.steps[0].targets[0].target_type, EscalationTargetType::Channel);

        // list — step_count derived from the in-memory steps vector
        let listed = s.list_escalation_policies().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, policy.id);
        assert_eq!(listed[0].name, "default");
        assert_eq!(listed[0].step_count, 2);
        assert_eq!(listed[0].repeat_count, 1);

        // upsert (replace) — bump repeat_count + swap step list
        let mut updated = policy.clone();
        updated.repeat_count = 3;
        updated.steps.truncate(1);
        updated.name = "default-v2".into();
        let r = s.upsert_escalation_policy(&updated).await.unwrap();
        assert_eq!(r.repeat_count, 3);
        let got2 = s.get_escalation_policy(policy.id).await.unwrap();
        assert_eq!(got2.repeat_count, 3);
        assert_eq!(got2.name, "default-v2");
        assert_eq!(got2.steps.len(), 1);
        let listed2 = s.list_escalation_policies().await.unwrap();
        assert_eq!(listed2[0].step_count, 1);
        assert_eq!(listed2[0].repeat_count, 3);

        // delete + NotFound
        s.delete_escalation_policy(policy.id).await.unwrap();
        let err = s.get_escalation_policy(policy.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
        let err = s.delete_escalation_policy(policy.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn on_call_schedule_crud_roundtrip() {
        let s = MemoryStorage::new();
        let detail = make_on_call_schedule_detail("primary", "UTC");

        // upsert (create)
        let sched = s.upsert_on_call_schedule(&detail).await.unwrap();
        assert_eq!(sched.id, detail.schedule.id);
        assert_eq!(sched.timezone, "UTC");

        // list — layer_count derived from the in-memory layers vector
        let listed = s.list_on_call_schedules().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, detail.schedule.id);
        assert_eq!(listed[0].layer_count, 1);
        assert_eq!(listed[0].timezone, "UTC");

        // get detail — layers survive the round trip
        let got = s.get_on_call_schedule(detail.schedule.id).await.unwrap();
        assert_eq!(got.schedule.name, "primary");
        assert_eq!(got.layers.len(), 1);
        assert_eq!(got.layers[0].participants.len(), 2);
        assert_eq!(got.layers[0].rotation_type, RotationType::Daily);
        // No overrides yet
        assert!(got.overrides.is_empty());

        // upsert (replace) — change tz + drop layers
        let mut updated = detail.clone();
        updated.schedule.timezone = "America/New_York".into();
        updated.layers.clear();
        let r = s.upsert_on_call_schedule(&updated).await.unwrap();
        assert_eq!(r.timezone, "America/New_York");
        let got2 = s.get_on_call_schedule(detail.schedule.id).await.unwrap();
        assert_eq!(got2.schedule.timezone, "America/New_York");
        assert!(got2.layers.is_empty());
        let listed2 = s.list_on_call_schedules().await.unwrap();
        assert_eq!(listed2[0].layer_count, 0);

        // delete + NotFound
        s.delete_on_call_schedule(detail.schedule.id).await.unwrap();
        let err = s.get_on_call_schedule(detail.schedule.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
        let err = s.delete_on_call_schedule(detail.schedule.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn on_call_override_crud() {
        let s = MemoryStorage::new();
        let detail = make_on_call_schedule_detail("primary", "UTC");
        s.upsert_on_call_schedule(&detail).await.unwrap();

        // create override on the schedule
        let ov = make_on_call_override(9);
        let created = s.create_on_call_override(detail.schedule.id, &ov).await.unwrap();
        assert_eq!(created.id, ov.id);
        assert_eq!(created.user_id, ov.user_id);

        // conflict on duplicate id
        let err = s.create_on_call_override(detail.schedule.id, &ov).await.unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));

        // list by schedule — single row
        let listed = s.list_on_call_overrides(detail.schedule.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, ov.id);

        // list for an unknown schedule is empty
        let none = s.list_on_call_overrides(Uuid::now_v7()).await.unwrap();
        assert!(none.is_empty());

        // overrides show up in get_on_call_schedule too
        let got = s.get_on_call_schedule(detail.schedule.id).await.unwrap();
        assert_eq!(got.overrides.len(), 1);
        assert_eq!(got.overrides[0].id, ov.id);

        // delete + NotFound
        s.delete_on_call_override(ov.id).await.unwrap();
        assert!(s.list_on_call_overrides(detail.schedule.id).await.unwrap().is_empty());
        let err = s.delete_on_call_override(ov.id).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
    }

    #[tokio::test]
    async fn escalation_state_lifecycle() {
        let s = MemoryStorage::new();
        let incident_id = Uuid::now_v7();
        let policy_id = Uuid::now_v7();

        // initially absent
        assert!(s.get_escalation_state(incident_id).await.unwrap().is_none());

        // upsert
        let mut state = make_escalation_state(incident_id, policy_id);
        s.upsert_escalation_state(&state).await.unwrap();
        let got = s.get_escalation_state(incident_id).await.unwrap().unwrap();
        assert_eq!(got.policy_id, policy_id);
        assert!(!got.acked);
        assert_eq!(got.current_level, 0);

        // re-upsert (replace) — advance level + next_check_at
        state.current_level = 1;
        state.next_check_at = ts("2026-06-01T00:10:00Z");
        s.upsert_escalation_state(&state).await.unwrap();
        let got2 = s.get_escalation_state(incident_id).await.unwrap().unwrap();
        assert_eq!(got2.current_level, 1);

        // Make a second incident that is acked (should not appear in due list).
        let incident2 = Uuid::now_v7();
        let acked_state = IncidentEscalationState {
            incident_id: incident2,
            policy_id,
            current_level: 0,
            current_round: 0,
            last_paged_at: ts("2026-06-01T00:00:00Z"),
            next_check_at: ts("2026-06-01T00:05:00Z"),
            acked: true,
        };
        s.upsert_escalation_state(&acked_state).await.unwrap();

        // now = 00:06 → first state: next_check_at = 00:10, acked = false → NOT due.
        let due_before = s.list_due_escalation_states(ts("2026-06-01T00:06:00Z")).await.unwrap();
        assert!(due_before.is_empty());

        // now = 00:11 → first state due (00:10 ≤ 00:11), acked state filtered.
        let due = s.list_due_escalation_states(ts("2026-06-01T00:11:00Z")).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].incident_id, incident_id);

        // ack stops further paging — state remains but acked = true.
        s.ack_escalation_state(incident_id).await.unwrap();
        let acked_got = s.get_escalation_state(incident_id).await.unwrap().unwrap();
        assert!(acked_got.acked);
        // acked state is no longer "due" even if next_check_at is in the past.
        let due_after = s.list_due_escalation_states(ts("2026-06-01T00:20:00Z")).await.unwrap();
        assert!(due_after.is_empty());

        // delete escalation state when incident is resolved.
        s.delete_escalation_state(incident_id).await.unwrap();
        assert!(s.get_escalation_state(incident_id).await.unwrap().is_none());
        // acked state for incident2 still around until explicitly deleted.
        assert!(s.get_escalation_state(incident2).await.unwrap().is_some());
    }

    // ── Postmortems ─────────────────────────────────────────────────────

    fn make_action_items() -> Vec<ActionItem> {
        vec![
            ActionItem {
                text: "patch the cache invalidator".into(),
                owner_user_id: Some(UserId(Uuid::from_u128(7))),
                done: false,
            },
            ActionItem { text: "add a regression test".into(), owner_user_id: None, done: true },
        ]
    }

    fn make_postmortem_upsert() -> PostmortemUpsert {
        PostmortemUpsert {
            summary: Some("cache stampede took down the API".into()),
            root_cause: Some("missing TTL jitter".into()),
            impact: Some("5xx for 12 minutes".into()),
            action_items: make_action_items(),
        }
    }

    #[tokio::test]
    async fn postmortem_crud_roundtrip() {
        let s = MemoryStorage::new();
        let incident_id = Uuid::now_v7();
        let author = Uuid::from_u128(42);

        // initially absent
        assert!(s.get_postmortem(incident_id).await.unwrap().is_none());

        // upsert (create)
        let body = make_postmortem_upsert();
        let pm = s.upsert_postmortem(incident_id, Some(author), &body).await.unwrap();
        assert_eq!(pm.incident_id, incident_id);
        assert_eq!(pm.summary.as_deref(), Some("cache stampede took down the API"));
        assert_eq!(pm.root_cause.as_deref(), Some("missing TTL jitter"));
        assert_eq!(pm.impact.as_deref(), Some("5xx for 12 minutes"));
        assert_eq!(pm.action_items.len(), 2);
        assert_eq!(pm.action_items[0].text, "patch the cache invalidator");
        assert!(pm.action_items[1].done);
        assert_eq!(pm.author_id.map(|u| u.0), Some(author));
        assert!(pm.published_at.is_none());

        // get
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert_eq!(got.summary, pm.summary);
        assert_eq!(got.action_items.len(), 2);
        assert!(got.published_at.is_none());

        // publish
        let published = s.publish_postmortem(incident_id).await.unwrap();
        assert!(published.published_at.is_some());
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert!(got.published_at.is_some());

        // unpublish
        let unpublished = s.unpublish_postmortem(incident_id).await.unwrap();
        assert!(unpublished.published_at.is_none());
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert!(got.published_at.is_none());

        // publish on missing → NotFound
        let err = s.publish_postmortem(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));
        // unpublish on missing → NotFound
        let err = s.unpublish_postmortem(Uuid::now_v7()).await.unwrap_err();
        assert!(format!("{err:?}").contains("NotFound"));

        // delete + absent again
        s.delete_postmortem(incident_id).await.unwrap();
        assert!(s.get_postmortem(incident_id).await.unwrap().is_none());
        // delete is idempotent
        s.delete_postmortem(incident_id).await.unwrap();
    }

    #[tokio::test]
    async fn postmortem_upsert_preserves_published_at() {
        let s = MemoryStorage::new();
        let incident_id = Uuid::now_v7();

        // create + publish
        let body = make_postmortem_upsert();
        s.upsert_postmortem(incident_id, None, &body).await.unwrap();
        let published = s.publish_postmortem(incident_id).await.unwrap();
        let original_published_at = published.published_at.expect("published_at set");
        let original_created_at = published.created_at;

        // re-upsert (edit) — published_at must be preserved, created_at too
        let mut body2 = body.clone();
        body2.summary = Some("edited summary".into());
        let edited = s.upsert_postmortem(incident_id, None, &body2).await.unwrap();
        assert_eq!(edited.summary.as_deref(), Some("edited summary"));
        assert_eq!(edited.published_at, Some(original_published_at));
        assert_eq!(edited.created_at, original_created_at);

        // get reflects the preserved published_at
        let got = s.get_postmortem(incident_id).await.unwrap().unwrap();
        assert_eq!(got.published_at, Some(original_published_at));
        assert_eq!(got.created_at, original_created_at);
        assert_eq!(got.summary.as_deref(), Some("edited summary"));
    }

    #[tokio::test]
    async fn monitor_share_crud_roundtrip() {
        let s = MemoryStorage::new();
        let target_id = Uuid::now_v7();

        // Create a share — the raw token is returned once.
        let created = s.create_monitor_share(target_id, Some("on-call rota"), None).await.unwrap();
        assert!(!created.token.is_empty(), "raw token must be non-empty");
        assert_eq!(created.share.target_id, target_id);
        assert_eq!(created.share.label.as_deref(), Some("on-call rota"));
        assert_eq!(created.share.view_count, 0);
        assert!(created.share.last_viewed_at.is_none());
        // The raw token is never stored on the persisted view.
        assert!(created.share.token.is_none());

        // List — newest-first, one entry.
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.share.id);
        assert_eq!(listed[0].view_count, 0);
        // Listed shares never carry the raw token.
        assert!(listed[0].token.is_none());

        // Resolve via the raw token (hashed). View count increments.
        let hash = hash_cookie_value(&created.token);
        let resolved = s.resolve_monitor_share(&hash).await.unwrap().unwrap();
        assert_eq!(resolved.target_id, target_id);
        assert_eq!(resolved.share_id, created.share.id);

        // View count + last_viewed_at updated.
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed[0].view_count, 1);
        assert!(listed[0].last_viewed_at.is_some());

        // A second resolve bumps the count again.
        let _ = s.resolve_monitor_share(&hash).await.unwrap().unwrap();
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed[0].view_count, 2);

        // Delete — idempotent.
        s.delete_monitor_share(created.share.id.0).await.unwrap();
        s.delete_monitor_share(created.share.id.0).await.unwrap();
        assert!(s.list_monitor_shares(target_id).await.unwrap().is_empty());

        // After delete, resolve returns None.
        let after = s.resolve_monitor_share(&hash).await.unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn monitor_share_expires() {
        let s = MemoryStorage::new();
        let target_id = Uuid::now_v7();
        // Mint a share that already expired.
        let past = Utc::now() - chrono::Duration::seconds(60);
        let created = s.create_monitor_share(target_id, None, Some(past)).await.unwrap();

        // Resolve must return None — expired tokens never match.
        let hash = hash_cookie_value(&created.token);
        let resolved = s.resolve_monitor_share(&hash).await.unwrap();
        assert!(resolved.is_none());

        // The row still exists (expired ≠ deleted) so it shows in the list.
        let listed = s.list_monitor_shares(target_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].view_count, 0, "expired resolve must not bump view_count");
    }
}
