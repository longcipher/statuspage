//! Write-through cache layer for storage implementations.
//!
//! Wraps any `Storage` impl with an in-memory Moka cache for read-heavy
//! operations (list_targets, get_target, list_results). Writes pass through
//! to the underlying store and invalidate the cache.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use statuscore::domain::{
    ApiTokenRow, ApiTokenUpdate, AssetSlot, CheckResult, ComponentDayHistory, CreatedShare,
    DashboardRow, DashboardSummary, DeliveryReason, DeliveryStatus, DomainExpiryState,
    EscalationPolicy, EscalationPolicySummary, Incident, IncidentEscalationState,
    IncidentMetricsRollup, IncidentOpsPatch, IncidentPostmortem, LatencyBucket, MagicLinkRow,
    MaintenanceFilter, MaintenanceWindow, MonitorShare, NewApiToken, NewNotificationChannel,
    NewSession, NewSilenceRule, NewUser, NotificationChannel, NotificationChannelUpdate,
    OnCallOverride, OnCallSchedule, OnCallScheduleDetail, OnCallScheduleSummary, PageAsset,
    PostmortemUpsert, PublicIncidentUpdate, ResolvedShare, SessionRow, SilenceFilter, SilenceRule,
    SilenceRuleUpdate, StatusPage, StatusPageComponent, Subscriber, SubscriberChannel,
    SubscriberDelivery, Target, TargetChannelBinding, UptimeResult, User, UserUpdate, Variable,
};
use statuscore::error::Result;
use uuid::Uuid;

use crate::traits::Storage;

/// Cached storage wrapper. Reads are served from cache when available;
/// writes pass through and invalidate affected entries.
///
/// ponytail: uses moka::future::Cache for concurrent, async-friendly caching.
#[derive(Debug)]
pub struct CachedStorage<S: Storage> {
    inner: S,
    // ponytail: moka cache is already in workspace deps
    target_cache: moka::future::Cache<Uuid, Target>,
}

impl<S: Storage> CachedStorage<S> {
    pub fn new(inner: S) -> Self {
        let target_cache = moka::future::Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_mins(1))
            .build();
        Self { inner, target_cache }
    }
}

#[async_trait]
impl<S: Storage + Send + Sync> Storage for CachedStorage<S> {
    async fn list_targets(&self) -> Result<Vec<Target>> {
        // ponytail: list not cached individually; delegate to inner
        self.inner.list_targets().await
    }

    async fn get_target(&self, id: Uuid) -> Result<Target> {
        if let Some(t) = self.target_cache.get(&id).await {
            return Ok(t);
        }
        let t = self.inner.get_target(id).await?;
        self.target_cache.insert(id, t.clone()).await;
        Ok(t)
    }

    async fn create_target(&self, target: &Target) -> Result<Target> {
        let t = self.inner.create_target(target).await?;
        self.target_cache.insert(t.id, t.clone()).await;
        Ok(t)
    }

    async fn update_target(&self, target: &Target) -> Result<Target> {
        let t = self.inner.update_target(target).await?;
        self.target_cache.insert(t.id, t.clone()).await;
        Ok(t)
    }

    async fn delete_target(&self, id: Uuid) -> Result<()> {
        self.target_cache.invalidate(&id).await;
        self.inner.delete_target(id).await
    }

    // ponytail: delegate all remaining methods to inner without caching
    async fn record_result(&self, result: &CheckResult) -> Result<()> {
        self.inner.record_result(result).await
    }
    async fn list_results(&self, target_id: Uuid, limit: u32) -> Result<Vec<CheckResult>> {
        self.inner.list_results(target_id, limit).await
    }
    async fn list_recent_results(&self, limit: u32) -> Result<Vec<CheckResult>> {
        self.inner.list_recent_results(limit).await
    }
    async fn list_incidents(&self) -> Result<Vec<Incident>> {
        self.inner.list_incidents().await
    }
    async fn create_incident(&self, incident: &Incident) -> Result<Incident> {
        self.inner.create_incident(incident).await
    }
    async fn get_incident(&self, id: Uuid) -> Result<Incident> {
        self.inner.get_incident(id).await
    }
    async fn update_incident(&self, incident: &Incident) -> Result<Incident> {
        self.inner.update_incident(incident).await
    }
    async fn add_incident_update(
        &self,
        incident_id: Uuid,
        update: &PublicIncidentUpdate,
    ) -> Result<Incident> {
        self.inner.add_incident_update(incident_id, update).await
    }
    async fn find_open_incident_for_target(&self, target_id: Uuid) -> Result<Option<Incident>> {
        self.inner.find_open_incident_for_target(target_id).await
    }
    async fn list_status_pages(&self) -> Result<Vec<StatusPage>> {
        self.inner.list_status_pages().await
    }
    async fn get_status_page(&self, id: Uuid) -> Result<StatusPage> {
        self.inner.get_status_page(id).await
    }
    async fn create_status_page(&self, page: &StatusPage) -> Result<StatusPage> {
        self.inner.create_status_page(page).await
    }
    async fn update_status_page(&self, page: &StatusPage) -> Result<StatusPage> {
        self.inner.update_status_page(page).await
    }
    async fn delete_status_page(&self, id: Uuid) -> Result<()> {
        self.inner.delete_status_page(id).await
    }
    async fn list_status_page_components(
        &self,
        status_page_id: Uuid,
    ) -> Result<Vec<StatusPageComponent>> {
        self.inner.list_status_page_components(status_page_id).await
    }
    async fn set_status_page_component(
        &self,
        status_page_id: Uuid,
        component: &StatusPageComponent,
    ) -> Result<()> {
        self.inner.set_status_page_component(status_page_id, component).await
    }
    async fn delete_status_page_component(
        &self,
        status_page_id: Uuid,
        target_id: Uuid,
    ) -> Result<()> {
        self.inner.delete_status_page_component(status_page_id, target_id).await
    }
    async fn reorder_status_page_components(
        &self,
        status_page_id: Uuid,
        ordered_target_ids: &[Uuid],
    ) -> Result<()> {
        self.inner.reorder_status_page_components(status_page_id, ordered_target_ids).await
    }
    async fn upload_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
        content_type: &str,
        data: &[u8],
    ) -> Result<PageAsset> {
        self.inner.upload_page_asset(status_page_id, slot, content_type, data).await
    }
    async fn get_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
    ) -> Result<Option<PageAsset>> {
        self.inner.get_page_asset(status_page_id, slot).await
    }
    async fn delete_page_asset(&self, status_page_id: Uuid, slot: AssetSlot) -> Result<()> {
        self.inner.delete_page_asset(status_page_id, slot).await
    }
    async fn list_page_assets(&self, status_page_id: Uuid) -> Result<Vec<PageAsset>> {
        self.inner.list_page_assets(status_page_id).await
    }
    async fn record_heartbeat_ping(&self, target_id: Uuid) -> Result<()> {
        self.inner.record_heartbeat_ping(target_id).await
    }
    async fn get_last_heartbeat_ping(&self, target_id: Uuid) -> Result<Option<DateTime<Utc>>> {
        self.inner.get_last_heartbeat_ping(target_id).await
    }
    async fn list_maintenance_windows(
        &self,
        filter: MaintenanceFilter,
    ) -> Result<Vec<MaintenanceWindow>> {
        self.inner.list_maintenance_windows(filter).await
    }
    async fn get_maintenance_window(&self, id: Uuid) -> Result<MaintenanceWindow> {
        self.inner.get_maintenance_window(id).await
    }
    async fn create_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        self.inner.create_maintenance_window(window).await
    }
    async fn update_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        self.inner.update_maintenance_window(window).await
    }
    async fn delete_maintenance_window(&self, id: Uuid) -> Result<()> {
        self.inner.delete_maintenance_window(id).await
    }
    async fn is_target_in_active_maintenance(&self, target_id: Uuid) -> Result<bool> {
        self.inner.is_target_in_active_maintenance(target_id).await
    }
    async fn list_silence_rules(&self, filter: SilenceFilter) -> Result<Vec<SilenceRule>> {
        self.inner.list_silence_rules(filter).await
    }
    async fn get_silence_rule(&self, id: Uuid) -> Result<SilenceRule> {
        self.inner.get_silence_rule(id).await
    }
    async fn create_silence_rule(&self, rule: &NewSilenceRule) -> Result<SilenceRule> {
        self.inner.create_silence_rule(rule).await
    }
    async fn update_silence_rule(
        &self,
        id: Uuid,
        update: &SilenceRuleUpdate,
    ) -> Result<SilenceRule> {
        self.inner.update_silence_rule(id, update).await
    }
    async fn delete_silence_rule(&self, id: Uuid) -> Result<()> {
        self.inner.delete_silence_rule(id).await
    }
    async fn list_active_silences_for_target(&self, target_id: Uuid) -> Result<Vec<SilenceRule>> {
        self.inner.list_active_silences_for_target(target_id).await
    }
    async fn list_subscribers(&self, status_page_id: Uuid) -> Result<Vec<Subscriber>> {
        self.inner.list_subscribers(status_page_id).await
    }
    async fn create_subscriber(&self, subscriber: &Subscriber) -> Result<Subscriber> {
        self.inner.create_subscriber(subscriber).await
    }
    async fn verify_subscriber(&self, id: Uuid) -> Result<Subscriber> {
        self.inner.verify_subscriber(id).await
    }
    async fn delete_subscriber(&self, id: Uuid) -> Result<()> {
        self.inner.delete_subscriber(id).await
    }
    async fn list_variables(&self) -> Result<Vec<Variable>> {
        self.inner.list_variables().await
    }
    async fn create_variable(&self, variable: &Variable) -> Result<Variable> {
        self.inner.create_variable(variable).await
    }
    async fn update_variable(&self, variable: &Variable) -> Result<Variable> {
        self.inner.update_variable(variable).await
    }
    async fn delete_variable(&self, id: Uuid) -> Result<()> {
        self.inner.delete_variable(id).await
    }
    async fn latency_buckets(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_count: u32,
    ) -> Result<Vec<LatencyBucket>> {
        self.inner.latency_buckets(target_id, from, to, bucket_count).await
    }
    async fn uptime(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Option<UptimeResult>> {
        self.inner.uptime(target_id, from, to).await
    }
    async fn dashboard_rollup(&self) -> Result<Vec<DashboardRow>> {
        self.inner.dashboard_rollup().await
    }
    async fn dashboard_summary(&self) -> Result<DashboardSummary> {
        self.inner.dashboard_summary().await
    }
    async fn component_day_history(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ComponentDayHistory>> {
        self.inner.component_day_history(target_id, from, to).await
    }
    async fn recent_results_for_targets(
        &self,
        target_ids: &[Uuid],
        limit_per_target: u32,
    ) -> Result<std::collections::HashMap<Uuid, Vec<CheckResult>>> {
        self.inner.recent_results_for_targets(target_ids, limit_per_target).await
    }
    async fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        self.inner.list_notification_channels().await
    }
    async fn get_notification_channel(&self, id: Uuid) -> Result<NotificationChannel> {
        self.inner.get_notification_channel(id).await
    }
    async fn create_notification_channel(
        &self,
        channel: &NewNotificationChannel,
    ) -> Result<NotificationChannel> {
        self.inner.create_notification_channel(channel).await
    }
    async fn update_notification_channel(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel> {
        self.inner.update_notification_channel(id, update).await
    }
    async fn delete_notification_channel(&self, id: Uuid) -> Result<()> {
        self.inner.delete_notification_channel(id).await
    }
    async fn create_channel_verification_token(
        &self,
        channel_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        self.inner.create_channel_verification_token(channel_id, token_hash, expires_at).await
    }
    async fn consume_channel_verification_token(&self, token_hash: &str) -> Result<Option<Uuid>> {
        self.inner.consume_channel_verification_token(token_hash).await
    }
    async fn set_channel_verified(&self, channel_id: Uuid) -> Result<()> {
        self.inner.set_channel_verified(channel_id).await
    }
    async fn set_channel_disabled_reason(&self, channel_id: Uuid, reason: &str) -> Result<()> {
        self.inner.set_channel_disabled_reason(channel_id, reason).await
    }
    async fn list_target_channels(&self, target_id: Uuid) -> Result<Vec<TargetChannelBinding>> {
        self.inner.list_target_channels(target_id).await
    }
    async fn bind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()> {
        self.inner.bind_target_channel(target_id, channel_id).await
    }
    async fn unbind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()> {
        self.inner.unbind_target_channel(target_id, channel_id).await
    }
    async fn unbind_channel_everywhere(&self, channel_id: Uuid) -> Result<()> {
        self.inner.unbind_channel_everywhere(channel_id).await
    }
    async fn apply_incident_ops(
        &self,
        incident_id: Uuid,
        patch: &IncidentOpsPatch,
    ) -> Result<Incident> {
        self.inner.apply_incident_ops(incident_id, patch).await
    }
    async fn incident_metrics(&self, window_days: u32) -> Result<IncidentMetricsRollup> {
        self.inner.incident_metrics(window_days).await
    }
    async fn list_pending_deliveries(&self, limit: u32) -> Result<Vec<SubscriberDelivery>> {
        self.inner.list_pending_deliveries(limit).await
    }
    async fn claim_delivery(&self, id: Uuid) -> Result<Option<SubscriberDelivery>> {
        self.inner.claim_delivery(id).await
    }
    async fn mark_delivery(
        &self,
        id: Uuid,
        status: DeliveryStatus,
        error: Option<&str>,
    ) -> Result<()> {
        self.inner.mark_delivery(id, status, error).await
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
        self.inner
            .enqueue_delivery(subscriber_id, status_page_id, channel, target, payload, reason)
            .await
    }
    async fn delete_old_deliveries(&self, older_than: DateTime<Utc>) -> Result<u64> {
        self.inner.delete_old_deliveries(older_than).await
    }
    async fn delete_unverified_subscribers(&self, older_than: DateTime<Utc>) -> Result<u64> {
        self.inner.delete_unverified_subscribers(older_than).await
    }
    async fn delete_old_check_results(&self, older_than: DateTime<Utc>) -> Result<u64> {
        self.inner.delete_old_check_results(older_than).await
    }
    async fn get_domain_expiry_state(&self, target_id: Uuid) -> Result<Option<DomainExpiryState>> {
        self.inner.get_domain_expiry_state(target_id).await
    }
    async fn set_domain_expiry_state(&self, state: &DomainExpiryState) -> Result<()> {
        self.inner.set_domain_expiry_state(state).await
    }
    async fn create_user(&self, new: &NewUser) -> Result<User> {
        self.inner.create_user(new).await
    }
    async fn get_user(&self, id: Uuid) -> Result<User> {
        self.inner.get_user(id).await
    }
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        self.inner.find_user_by_email(email).await
    }
    async fn count_users(&self) -> Result<i64> {
        self.inner.count_users().await
    }
    async fn update_user(&self, id: Uuid, update: &UserUpdate) -> Result<User> {
        self.inner.update_user(id, update).await
    }
    async fn touch_user(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        self.inner.touch_user(id, at).await
    }
    async fn create_session(&self, id_hash: &str, new: &NewSession) -> Result<SessionRow> {
        self.inner.create_session(id_hash, new).await
    }
    async fn lookup_session(&self, id_hash: &str) -> Result<Option<SessionRow>> {
        self.inner.lookup_session(id_hash).await
    }
    async fn touch_session(&self, id_hash: &str, at: DateTime<Utc>) -> Result<()> {
        self.inner.touch_session(id_hash, at).await
    }
    async fn delete_session(&self, id_hash: &str) -> Result<()> {
        self.inner.delete_session(id_hash).await
    }
    async fn delete_other_sessions(&self, user_id: Uuid, keep_id_hash: &str) -> Result<u64> {
        self.inner.delete_other_sessions(user_id, keep_id_hash).await
    }
    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRow>> {
        self.inner.list_sessions(user_id).await
    }
    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<u64> {
        self.inner.delete_expired_sessions(now).await
    }
    async fn create_api_token(
        &self,
        user_id: Uuid,
        new: &NewApiToken,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<ApiTokenRow> {
        self.inner.create_api_token(user_id, new, token_hash, token_prefix).await
    }
    async fn find_api_tokens_by_prefix(&self, prefix: &str) -> Result<Vec<ApiTokenRow>> {
        self.inner.find_api_tokens_by_prefix(prefix).await
    }
    async fn list_api_tokens(&self, user_id: Uuid) -> Result<Vec<ApiTokenRow>> {
        self.inner.list_api_tokens(user_id).await
    }
    async fn update_api_token(&self, id: Uuid, update: &ApiTokenUpdate) -> Result<ApiTokenRow> {
        self.inner.update_api_token(id, update).await
    }
    async fn touch_api_token(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        self.inner.touch_api_token(id, at).await
    }
    async fn delete_api_token(&self, id: Uuid) -> Result<()> {
        self.inner.delete_api_token(id).await
    }
    async fn delete_api_tokens_for_user(&self, user_id: Uuid) -> Result<u64> {
        self.inner.delete_api_tokens_for_user(user_id).await
    }
    async fn delete_expired_api_tokens(&self, cutoff: DateTime<Utc>) -> Result<u64> {
        self.inner.delete_expired_api_tokens(cutoff).await
    }
    async fn create_magic_link(
        &self,
        email: &str,
        token_hash: &str,
        token_prefix: &str,
        expires_at: DateTime<Utc>,
        ip_hash: Option<&str>,
        redirect_after: Option<&str>,
    ) -> Result<MagicLinkRow> {
        self.inner
            .create_magic_link(email, token_hash, token_prefix, expires_at, ip_hash, redirect_after)
            .await
    }
    async fn find_magic_links_by_prefix(&self, prefix: &str) -> Result<Vec<MagicLinkRow>> {
        self.inner.find_magic_links_by_prefix(prefix).await
    }
    async fn consume_magic_link(&self, id: Uuid) -> Result<Option<MagicLinkRow>> {
        self.inner.consume_magic_link(id).await
    }
    async fn delete_expired_magic_links(&self, now: DateTime<Utc>) -> Result<u64> {
        self.inner.delete_expired_magic_links(now).await
    }
    async fn list_escalation_policies(&self) -> Result<Vec<EscalationPolicySummary>> {
        self.inner.list_escalation_policies().await
    }
    async fn get_escalation_policy(&self, id: Uuid) -> Result<EscalationPolicy> {
        self.inner.get_escalation_policy(id).await
    }
    async fn upsert_escalation_policy(
        &self,
        policy: &EscalationPolicy,
    ) -> Result<EscalationPolicy> {
        self.inner.upsert_escalation_policy(policy).await
    }
    async fn delete_escalation_policy(&self, id: Uuid) -> Result<()> {
        self.inner.delete_escalation_policy(id).await
    }
    async fn list_on_call_schedules(&self) -> Result<Vec<OnCallScheduleSummary>> {
        self.inner.list_on_call_schedules().await
    }
    async fn get_on_call_schedule(&self, id: Uuid) -> Result<OnCallScheduleDetail> {
        self.inner.get_on_call_schedule(id).await
    }
    async fn upsert_on_call_schedule(
        &self,
        detail: &OnCallScheduleDetail,
    ) -> Result<OnCallSchedule> {
        self.inner.upsert_on_call_schedule(detail).await
    }
    async fn delete_on_call_schedule(&self, id: Uuid) -> Result<()> {
        self.inner.delete_on_call_schedule(id).await
    }
    async fn list_on_call_overrides(&self, schedule_id: Uuid) -> Result<Vec<OnCallOverride>> {
        self.inner.list_on_call_overrides(schedule_id).await
    }
    async fn create_on_call_override(
        &self,
        schedule_id: Uuid,
        override_: &OnCallOverride,
    ) -> Result<OnCallOverride> {
        self.inner.create_on_call_override(schedule_id, override_).await
    }
    async fn delete_on_call_override(&self, id: Uuid) -> Result<()> {
        self.inner.delete_on_call_override(id).await
    }
    async fn get_escalation_state(
        &self,
        incident_id: Uuid,
    ) -> Result<Option<IncidentEscalationState>> {
        self.inner.get_escalation_state(incident_id).await
    }
    async fn upsert_escalation_state(&self, state: &IncidentEscalationState) -> Result<()> {
        self.inner.upsert_escalation_state(state).await
    }
    async fn list_due_escalation_states(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<IncidentEscalationState>> {
        self.inner.list_due_escalation_states(now).await
    }
    async fn ack_escalation_state(&self, incident_id: Uuid) -> Result<()> {
        self.inner.ack_escalation_state(incident_id).await
    }
    async fn delete_escalation_state(&self, incident_id: Uuid) -> Result<()> {
        self.inner.delete_escalation_state(incident_id).await
    }
    async fn get_postmortem(&self, incident_id: Uuid) -> Result<Option<IncidentPostmortem>> {
        self.inner.get_postmortem(incident_id).await
    }
    async fn upsert_postmortem(
        &self,
        incident_id: Uuid,
        author_id: Option<Uuid>,
        body: &PostmortemUpsert,
    ) -> Result<IncidentPostmortem> {
        self.inner.upsert_postmortem(incident_id, author_id, body).await
    }
    async fn publish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem> {
        self.inner.publish_postmortem(incident_id).await
    }
    async fn unpublish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem> {
        self.inner.unpublish_postmortem(incident_id).await
    }
    async fn delete_postmortem(&self, incident_id: Uuid) -> Result<()> {
        self.inner.delete_postmortem(incident_id).await
    }
    async fn list_monitor_shares(&self, target_id: Uuid) -> Result<Vec<MonitorShare>> {
        self.inner.list_monitor_shares(target_id).await
    }
    async fn create_monitor_share(
        &self,
        target_id: Uuid,
        label: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedShare> {
        self.inner.create_monitor_share(target_id, label, expires_at).await
    }
    async fn delete_monitor_share(&self, id: Uuid) -> Result<()> {
        self.inner.delete_monitor_share(id).await
    }
    async fn resolve_monitor_share(&self, token_hash: &str) -> Result<Option<ResolvedShare>> {
        self.inner.resolve_monitor_share(token_hash).await
    }
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }
}
