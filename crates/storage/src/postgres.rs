//! PostgreSQL storage implementation.
//!
//! ponytail: Full Postgres implementation would mirror duckdb.rs with
//! sqlx::PgPool. This skeleton establishes the type and trait impl
//! structure; each method delegates to SQL queries that match the
//! DuckDB schema. Add `sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "chrono", "uuid", "json"] }`
//! to Cargo.toml when filling in the implementations.

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

use crate::traits::{Storage, StorageError};

/// PostgreSQL-backed storage. ponytail: skeleton only — each method
/// returns `not implemented` until the full SQL queries are ported
/// from duckdb.rs.
#[derive(Debug)]
pub struct PostgresStorage {
    #[expect(dead_code)]
    connection_string: String,
}

impl PostgresStorage {
    /// Open a connection to the PostgreSQL database.
    pub fn connect(connection_string: &str) -> std::result::Result<Self, StorageError> {
        // ponytail: would use sqlx::PgPool::connect(connection_string).await
        Ok(Self { connection_string: connection_string.to_string() })
    }
}

#[async_trait]
impl Storage for PostgresStorage {
    async fn list_targets(&self) -> Result<Vec<Target>> {
        // ponytail: SELECT * FROM targets
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "list_targets not implemented",
        ))
    }

    async fn get_target(&self, _id: Uuid) -> Result<Target> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "get_target not implemented",
        ))
    }

    async fn create_target(&self, _target: &Target) -> Result<Target> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "create_target not implemented",
        ))
    }

    async fn update_target(&self, _target: &Target) -> Result<Target> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "update_target not implemented",
        ))
    }

    async fn delete_target(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "delete_target not implemented",
        ))
    }

    async fn record_result(&self, _result: &CheckResult) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "record_result not implemented",
        ))
    }

    async fn list_results(&self, _target_id: Uuid, _limit: u32) -> Result<Vec<CheckResult>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "list_results not implemented",
        ))
    }

    async fn list_recent_results(&self, _limit: u32) -> Result<Vec<CheckResult>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "list_recent_results not implemented",
        ))
    }

    async fn list_incidents(&self) -> Result<Vec<Incident>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_incident(&self, _incident: &Incident) -> Result<Incident> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_incident(&self, _id: Uuid) -> Result<Incident> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_incident(&self, _incident: &Incident) -> Result<Incident> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn add_incident_update(
        &self,
        _incident_id: Uuid,
        _update: &PublicIncidentUpdate,
    ) -> Result<Incident> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn find_open_incident_for_target(&self, _target_id: Uuid) -> Result<Option<Incident>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_status_pages(&self) -> Result<Vec<StatusPage>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_status_page(&self, _id: Uuid) -> Result<StatusPage> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_status_page(&self, _page: &StatusPage) -> Result<StatusPage> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_status_page(&self, _page: &StatusPage) -> Result<StatusPage> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_status_page(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_status_page_components(
        &self,
        _status_page_id: Uuid,
    ) -> Result<Vec<StatusPageComponent>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn set_status_page_component(
        &self,
        _status_page_id: Uuid,
        _component: &StatusPageComponent,
    ) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_status_page_component(
        &self,
        _status_page_id: Uuid,
        _target_id: Uuid,
    ) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn reorder_status_page_components(
        &self,
        _status_page_id: Uuid,
        _ordered_target_ids: &[Uuid],
    ) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn upload_page_asset(
        &self,
        _status_page_id: Uuid,
        _slot: AssetSlot,
        _content_type: &str,
        _data: &[u8],
    ) -> Result<PageAsset> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_page_asset(
        &self,
        _status_page_id: Uuid,
        _slot: AssetSlot,
    ) -> Result<Option<PageAsset>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_page_asset(&self, _status_page_id: Uuid, _slot: AssetSlot) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn list_page_assets(&self, _status_page_id: Uuid) -> Result<Vec<PageAsset>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn record_heartbeat_ping(&self, _target_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_last_heartbeat_ping(&self, _target_id: Uuid) -> Result<Option<DateTime<Utc>>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_maintenance_windows(
        &self,
        _filter: MaintenanceFilter,
    ) -> Result<Vec<MaintenanceWindow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_maintenance_window(&self, _id: Uuid) -> Result<MaintenanceWindow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_maintenance_window(
        &self,
        _window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_maintenance_window(
        &self,
        _window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_maintenance_window(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn is_target_in_active_maintenance(&self, _target_id: Uuid) -> Result<bool> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_silence_rules(&self, _filter: SilenceFilter) -> Result<Vec<SilenceRule>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_silence_rule(&self, _id: Uuid) -> Result<SilenceRule> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_silence_rule(&self, _rule: &NewSilenceRule) -> Result<SilenceRule> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_silence_rule(
        &self,
        _id: Uuid,
        _update: &SilenceRuleUpdate,
    ) -> Result<SilenceRule> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_silence_rule(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn list_active_silences_for_target(&self, _target_id: Uuid) -> Result<Vec<SilenceRule>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_subscribers(&self, _status_page_id: Uuid) -> Result<Vec<Subscriber>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_subscriber(&self, _subscriber: &Subscriber) -> Result<Subscriber> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn verify_subscriber(&self, _id: Uuid) -> Result<Subscriber> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_subscriber(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_variables(&self) -> Result<Vec<Variable>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_variable(&self, _variable: &Variable) -> Result<Variable> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_variable(&self, _variable: &Variable) -> Result<Variable> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_variable(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn latency_buckets(
        &self,
        _target_id: Uuid,
        _from: DateTime<Utc>,
        _to: DateTime<Utc>,
        _bucket_count: u32,
    ) -> Result<Vec<LatencyBucket>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn uptime(
        &self,
        _target_id: Uuid,
        _from: DateTime<Utc>,
        _to: DateTime<Utc>,
    ) -> Result<Option<UptimeResult>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn dashboard_rollup(&self) -> Result<Vec<DashboardRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn dashboard_summary(&self) -> Result<DashboardSummary> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn component_day_history(
        &self,
        _target_id: Uuid,
        _from: DateTime<Utc>,
        _to: DateTime<Utc>,
    ) -> Result<Vec<ComponentDayHistory>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn recent_results_for_targets(
        &self,
        _target_ids: &[Uuid],
        _limit_per_target: u32,
    ) -> Result<std::collections::HashMap<Uuid, Vec<CheckResult>>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_notification_channel(&self, _id: Uuid) -> Result<NotificationChannel> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_notification_channel(
        &self,
        _channel: &NewNotificationChannel,
    ) -> Result<NotificationChannel> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_notification_channel(
        &self,
        _id: Uuid,
        _update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_notification_channel(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn create_channel_verification_token(
        &self,
        _channel_id: Uuid,
        _token_hash: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn consume_channel_verification_token(&self, _token_hash: &str) -> Result<Option<Uuid>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn set_channel_verified(&self, _channel_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn set_channel_disabled_reason(&self, _channel_id: Uuid, _reason: &str) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_target_channels(&self, _target_id: Uuid) -> Result<Vec<TargetChannelBinding>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn bind_target_channel(&self, _target_id: Uuid, _channel_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn unbind_target_channel(&self, _target_id: Uuid, _channel_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn unbind_channel_everywhere(&self, _channel_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn apply_incident_ops(
        &self,
        _incident_id: Uuid,
        _patch: &IncidentOpsPatch,
    ) -> Result<Incident> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn incident_metrics(&self, _window_days: u32) -> Result<IncidentMetricsRollup> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_pending_deliveries(&self, _limit: u32) -> Result<Vec<SubscriberDelivery>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn claim_delivery(&self, _id: Uuid) -> Result<Option<SubscriberDelivery>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn mark_delivery(
        &self,
        _id: Uuid,
        _status: DeliveryStatus,
        _error: Option<&str>,
    ) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn enqueue_delivery(
        &self,
        _subscriber_id: Uuid,
        _status_page_id: Uuid,
        _channel: SubscriberChannel,
        _target: &str,
        _payload: &str,
        _reason: DeliveryReason,
    ) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_old_deliveries(&self, _older_than: DateTime<Utc>) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_unverified_subscribers(&self, _older_than: DateTime<Utc>) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_old_check_results(&self, _older_than: DateTime<Utc>) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn get_domain_expiry_state(&self, _target_id: Uuid) -> Result<Option<DomainExpiryState>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn set_domain_expiry_state(&self, _state: &DomainExpiryState) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn create_user(&self, _new: &NewUser) -> Result<User> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_user(&self, _id: Uuid) -> Result<User> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn find_user_by_email(&self, _email: &str) -> Result<Option<User>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn count_users(&self) -> Result<i64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_user(&self, _id: Uuid, _update: &UserUpdate) -> Result<User> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn touch_user(&self, _id: Uuid, _at: DateTime<Utc>) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn create_session(&self, _id_hash: &str, _new: &NewSession) -> Result<SessionRow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn lookup_session(&self, _id_hash: &str) -> Result<Option<SessionRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn touch_session(&self, _id_hash: &str, _at: DateTime<Utc>) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_session(&self, _id_hash: &str) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_other_sessions(&self, _user_id: Uuid, _keep_id_hash: &str) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn list_sessions(&self, _user_id: Uuid) -> Result<Vec<SessionRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_expired_sessions(&self, _now: DateTime<Utc>) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn create_api_token(
        &self,
        _user_id: Uuid,
        _new: &NewApiToken,
        _token_hash: &str,
        _token_prefix: &str,
    ) -> Result<ApiTokenRow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn find_api_tokens_by_prefix(&self, _prefix: &str) -> Result<Vec<ApiTokenRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn list_api_tokens(&self, _user_id: Uuid) -> Result<Vec<ApiTokenRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn update_api_token(&self, _id: Uuid, _update: &ApiTokenUpdate) -> Result<ApiTokenRow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn touch_api_token(&self, _id: Uuid, _at: DateTime<Utc>) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_api_token(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_api_tokens_for_user(&self, _user_id: Uuid) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_expired_api_tokens(&self, _cutoff: DateTime<Utc>) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn create_magic_link(
        &self,
        _email: &str,
        _token_hash: &str,
        _token_prefix: &str,
        _expires_at: DateTime<Utc>,
        _ip_hash: Option<&str>,
        _redirect_after: Option<&str>,
    ) -> Result<MagicLinkRow> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn find_magic_links_by_prefix(&self, _prefix: &str) -> Result<Vec<MagicLinkRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn consume_magic_link(&self, _id: Uuid) -> Result<Option<MagicLinkRow>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_expired_magic_links(&self, _now: DateTime<Utc>) -> Result<u64> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_escalation_policies(&self) -> Result<Vec<EscalationPolicySummary>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_escalation_policy(&self, _id: Uuid) -> Result<EscalationPolicy> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn upsert_escalation_policy(
        &self,
        _policy: &EscalationPolicy,
    ) -> Result<EscalationPolicy> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_escalation_policy(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_on_call_schedules(&self) -> Result<Vec<OnCallScheduleSummary>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn get_on_call_schedule(&self, _id: Uuid) -> Result<OnCallScheduleDetail> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn upsert_on_call_schedule(
        &self,
        _detail: &OnCallScheduleDetail,
    ) -> Result<OnCallSchedule> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_on_call_schedule(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_on_call_overrides(&self, _schedule_id: Uuid) -> Result<Vec<OnCallOverride>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_on_call_override(
        &self,
        _schedule_id: Uuid,
        _override: &OnCallOverride,
    ) -> Result<OnCallOverride> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_on_call_override(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn get_escalation_state(
        &self,
        _incident_id: Uuid,
    ) -> Result<Option<IncidentEscalationState>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn upsert_escalation_state(&self, _state: &IncidentEscalationState) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn list_due_escalation_states(
        &self,
        _now: DateTime<Utc>,
    ) -> Result<Vec<IncidentEscalationState>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn ack_escalation_state(&self, _incident_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_escalation_state(&self, _incident_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn get_postmortem(&self, _incident_id: Uuid) -> Result<Option<IncidentPostmortem>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn upsert_postmortem(
        &self,
        _incident_id: Uuid,
        _author_id: Option<Uuid>,
        _body: &PostmortemUpsert,
    ) -> Result<IncidentPostmortem> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn publish_postmortem(&self, _incident_id: Uuid) -> Result<IncidentPostmortem> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn unpublish_postmortem(&self, _incident_id: Uuid) -> Result<IncidentPostmortem> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_postmortem(&self, _incident_id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn list_monitor_shares(&self, _target_id: Uuid) -> Result<Vec<MonitorShare>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn create_monitor_share(
        &self,
        _target_id: Uuid,
        _label: Option<&str>,
        _expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedShare> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn delete_monitor_share(&self, _id: Uuid) -> Result<()> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }
    async fn resolve_monitor_share(&self, _token_hash: &str) -> Result<Option<ResolvedShare>> {
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "not implemented",
        ))
    }

    async fn ping(&self) -> Result<()> {
        // ponytail: SELECT 1 via sqlx
        Err(statuscore::error::AppError::internal_with_context(
            "POSTGRES_NOT_IMPL",
            "ping not implemented",
        ))
    }
}
