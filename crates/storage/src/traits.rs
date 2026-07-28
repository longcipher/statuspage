//! Storage contract for the StatusPage persistence layer.
//!
//! DuckDB serves as both the configuration store and the time-series
//! results store, so a single trait covers both halves.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use statuscore::domain::{
    ApiTokenRow, ApiTokenUpdate, AssetSlot, CheckResult, ComponentDayHistory, CreatedShare,
    DashboardRow, DashboardSummary, DeliveryReason, DeliveryStatus, DomainExpiryState,
    EscalationPolicy, EscalationPolicySummary, Incident, IncidentEscalationState,
    IncidentMetricsRollup, IncidentOpsPatch, IncidentPostmortem, LatencyBucket, MagicLinkRow,
    MaintenanceFilter, MaintenanceWindow, MonitorShare, NewApiToken, NewNotificationChannel,
    NewSilenceRule, NewUser, NotificationChannel, NotificationChannelUpdate, OnCallOverride,
    OnCallSchedule, OnCallScheduleDetail, OnCallScheduleSummary, PageAsset, PostmortemUpsert,
    PublicIncidentUpdate, ResolvedShare, SessionRow, SilenceFilter, SilenceRule, SilenceRuleUpdate,
    StatusPage, StatusPageComponent, Subscriber, SubscriberDelivery, Target, TargetChannelBinding,
    UptimeResult, User, UserUpdate, Variable,
};
use statuscore::error::Result;
use uuid::Uuid;

/// Storage-layer errors. [`StorageError::NotFound`] signals a missing row so
/// callers can map it to a 404; [`StorageError::Conflict`] a duplicate /
/// uniqueness violation; [`StorageError::InvalidInput`] a caller-supplied
/// validation failure (maps to 400); [`StorageError::Duckdb`] wraps any
/// driver-level failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("duckdb error: {0}")]
    Duckdb(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// Map storage failures to the AppError variants that surface with the right
// HTTP status: NotFound -> 404, Conflict -> 409, InvalidInput -> 400,
// everything else -> 500.
impl From<StorageError> for statuscore::error::AppError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::NotFound(msg) => Self::not_found("STORAGE_NOT_FOUND", msg),
            StorageError::Conflict(msg) => Self::conflict("STORAGE_CONFLICT", msg),
            StorageError::InvalidInput(msg) => Self::bad_request("STORAGE_INVALID_INPUT", msg),
            StorageError::Duckdb(msg) => Self::internal_with_context("STORAGE_ERROR", msg),
        }
    }
}

/// Unified storage contract. DuckDB serves as both the configuration store
/// and the time-series results store, so one trait covers both halves.
#[async_trait]
pub trait Storage: Send + Sync {
    // ── Target operations ───────────────────────────────────────────────
    async fn list_targets(&self) -> Result<Vec<Target>>;
    async fn get_target(&self, id: Uuid) -> Result<Target>;
    async fn create_target(&self, target: &Target) -> Result<Target>;
    async fn update_target(&self, target: &Target) -> Result<Target>;
    async fn delete_target(&self, id: Uuid) -> Result<()>;

    // ── Check result operations (time-series storage) ──────────────────
    async fn record_result(&self, result: &CheckResult) -> Result<()>;
    async fn list_results(&self, target_id: Uuid, limit: u32) -> Result<Vec<CheckResult>>;
    /// Newest-first results across ALL targets (no target filter), capped at
    /// `limit`. Used by status-page history aggregation until the
    /// status_page → targets association is modelled.
    async fn list_recent_results(&self, limit: u32) -> Result<Vec<CheckResult>>;

    // ── Incident operations ─────────────────────────────────────────────
    async fn list_incidents(&self) -> Result<Vec<Incident>>;
    async fn create_incident(&self, incident: &Incident) -> Result<Incident>;
    async fn get_incident(&self, id: Uuid) -> Result<Incident>;
    async fn update_incident(&self, incident: &Incident) -> Result<Incident>;
    /// Append `update` to the incident's `updates` vec and persist the
    /// updated incident. Returns the resulting incident.
    async fn add_incident_update(
        &self,
        incident_id: Uuid,
        update: &PublicIncidentUpdate,
    ) -> Result<Incident>;
    /// Return the most recent incident for `target_id` with `ended_at IS
    /// NULL`, or `None` if no incident is currently open. Used by the
    /// incident writer to decide between insert-open and close.
    async fn find_open_incident_for_target(&self, target_id: Uuid) -> Result<Option<Incident>>;

    // ── Status page operations ──────────────────────────────────────────
    async fn list_status_pages(&self) -> Result<Vec<StatusPage>>;
    async fn get_status_page(&self, id: Uuid) -> Result<StatusPage>;
    async fn create_status_page(&self, page: &StatusPage) -> Result<StatusPage>;
    async fn update_status_page(&self, page: &StatusPage) -> Result<StatusPage>;
    async fn delete_status_page(&self, id: Uuid) -> Result<()>;

    // ── Status page components (target ↔ page binding) ──────────────────
    /// Components bound to a status page, ordered by `sort_order` then
    /// `monitor_name`. The component list drives the public status page
    /// rendering and the history aggregation query.
    async fn list_status_page_components(
        &self,
        status_page_id: Uuid,
    ) -> Result<Vec<StatusPageComponent>>;
    /// Upsert a single component binding for a status page. If a binding
    /// for `(status_page_id, target_id)` already exists, it is replaced.
    async fn set_status_page_component(
        &self,
        status_page_id: Uuid,
        component: &StatusPageComponent,
    ) -> Result<()>;
    /// Remove the `(status_page_id, target_id)` binding. No-op (returns
    /// `Ok(())`) if the binding does not exist, so the caller can delete
    /// idempotently.
    async fn delete_status_page_component(
        &self,
        status_page_id: Uuid,
        target_id: Uuid,
    ) -> Result<()>;
    /// Bulk-reorder the components on a page. `ordered_target_ids` is the
    /// desired full ordering (ascending); each component's `sort_order` is
    /// rewritten to its index in this list. Ids in the list that have no
    /// existing binding are skipped silently. The caller should pass the
    /// complete set of bound target ids in display order — anything omitted
    /// keeps its old `sort_order`, which may collide with the new sequence;
    /// callers that want a clean reorder should include every component.
    async fn reorder_status_page_components(
        &self,
        status_page_id: Uuid,
        ordered_target_ids: &[Uuid],
    ) -> Result<()>;

    // ── Page assets (logo upload etc.) ─────────────────────────────────
    /// Upsert a per-slot asset (e.g. `AssetSlot::Logo`). The storage layer
    /// computes `hash = sha256_hex(data)` so the caller never has to. The
    /// `content_type` is the caller-supplied MIME (validated against
    /// [`AssetSlot::policy`] by the handler before this call). Returns the
    /// stored row. Replacing an existing slot reuses its `created_at` and
    /// bumps `updated_at` so logo URL cache-busters track changes.
    async fn upload_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
        content_type: &str,
        data: &[u8],
    ) -> Result<PageAsset>;
    /// Read a slot's asset. `None` if no asset is stored for that slot.
    async fn get_page_asset(
        &self,
        status_page_id: Uuid,
        slot: AssetSlot,
    ) -> Result<Option<PageAsset>>;
    /// Delete a slot's asset. Idempotent — returns `Ok(())` if the row is
    /// already gone.
    async fn delete_page_asset(&self, status_page_id: Uuid, slot: AssetSlot) -> Result<()>;
    /// List all assets attached to a page (every populated slot). Used to
    /// hydrate `PublicOrgBranding.logo_hash` for the public page response.
    async fn list_page_assets(&self, status_page_id: Uuid) -> Result<Vec<PageAsset>>;

    // ── Heartbeat pings (passive dead-man's switch) ─────────────────────
    /// Record an inbound heartbeat ping for `target_id`, stamping
    /// `last_ping_at = now()`. Used by the `POST /heartbeat/{target_id}`
    /// endpoint. The scheduler's heartbeat evaluator reads this timestamp
    /// to decide up/down.
    async fn record_heartbeat_ping(&self, target_id: Uuid) -> Result<()>;
    /// Read the most recent heartbeat ping timestamp for `target_id`, or
    /// `None` if no ping has ever been recorded.
    async fn get_last_heartbeat_ping(&self, target_id: Uuid) -> Result<Option<DateTime<Utc>>>;

    // ── Maintenance windows ─────────────────────────────────────────────
    async fn list_maintenance_windows(
        &self,
        filter: MaintenanceFilter,
    ) -> Result<Vec<MaintenanceWindow>>;
    async fn get_maintenance_window(&self, id: Uuid) -> Result<MaintenanceWindow>;
    async fn create_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow>;
    async fn update_maintenance_window(
        &self,
        window: &MaintenanceWindow,
    ) -> Result<MaintenanceWindow>;
    async fn delete_maintenance_window(&self, id: Uuid) -> Result<()>;
    /// True if `target_id` is currently inside an active maintenance window
    /// (one whose `starts_at <= now < ends_at` and whose `component_ids`
    /// contains `target_id`). Used by the scheduler / incident writer to
    /// suppress alerting during planned maintenance.
    async fn is_target_in_active_maintenance(&self, target_id: Uuid) -> Result<bool>;

    // ── Silence rules (notification suppression windows) ───────────────
    async fn list_silence_rules(&self, filter: SilenceFilter) -> Result<Vec<SilenceRule>>;
    async fn get_silence_rule(&self, id: Uuid) -> Result<SilenceRule>;
    async fn create_silence_rule(&self, rule: &NewSilenceRule) -> Result<SilenceRule>;
    async fn update_silence_rule(
        &self,
        id: Uuid,
        update: &SilenceRuleUpdate,
    ) -> Result<SilenceRule>;
    async fn delete_silence_rule(&self, id: Uuid) -> Result<()>;
    /// Every active silence rule that could match `target_id` (rules whose
    /// `target_id` is `None` or equals `target_id`, and whose time window
    /// covers `now`). The dispatch path fetches these once per incident and
    /// filters per-channel / per-reason in-memory — one query instead of
    /// one per channel.
    async fn list_active_silences_for_target(&self, target_id: Uuid) -> Result<Vec<SilenceRule>>;

    // ── Subscribers (public status page opt-in notifications) ───────────
    async fn list_subscribers(&self, status_page_id: Uuid) -> Result<Vec<Subscriber>>;
    async fn create_subscriber(&self, subscriber: &Subscriber) -> Result<Subscriber>;
    /// Mark a subscriber as verified (double opt-in). Sets `verified_at =
    /// now()`. Returns the updated subscriber. NotFound if `id` does not
    /// exist.
    async fn verify_subscriber(&self, id: Uuid) -> Result<Subscriber>;
    async fn delete_subscriber(&self, id: Uuid) -> Result<()>;

    // ── Variables (org-scoped reusable values for interpolation) ────────
    async fn list_variables(&self) -> Result<Vec<Variable>>;
    async fn create_variable(&self, variable: &Variable) -> Result<Variable>;
    async fn update_variable(&self, variable: &Variable) -> Result<Variable>;
    async fn delete_variable(&self, id: Uuid) -> Result<()>;

    // ── Results aggregations (dashboard + detail page) ─────────────────
    /// Latency time-series for a target over `[from, to]`, bucketed into
    /// `bucket_count` equal-width intervals. Each bucket carries p50/p95/p99
    /// and the number of checks that fell into it. Buckets with zero checks
    /// have `None` percentiles but `count = 0`.
    async fn latency_buckets(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        bucket_count: u32,
    ) -> Result<Vec<LatencyBucket>>;

    /// Uptime percentage for a target over `[from, to]`. Returns `None` when
    /// the target has zero checks in the window (no data).
    async fn uptime(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Option<UptimeResult>>;

    /// Fleet-wide dashboard rollup: one row per target with current status,
    /// trailing 24h uptime, p95 latency, and 90-day day-strip history.
    async fn dashboard_rollup(&self) -> Result<Vec<DashboardRow>>;

    /// Fleet-wide status summary: counts by status (up/down/degraded/error)
    /// plus total and disabled counts.
    async fn dashboard_summary(&self) -> Result<DashboardSummary>;

    /// Per-day component history for the 90-day day strip. Returns one entry
    /// per (target, day) pair within `[from, to]`, with the worst `DayState`
    /// observed that day. Days with no data are returned as `DayState::NoData`.
    async fn component_day_history(
        &self,
        target_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<ComponentDayHistory>>;

    /// Results for multiple targets in one call (batch read). Used by the
    /// incident writer to avoid N+1 queries when evaluating many targets.
    async fn recent_results_for_targets(
        &self,
        target_ids: &[Uuid],
        limit_per_target: u32,
    ) -> Result<std::collections::HashMap<Uuid, Vec<CheckResult>>>;

    // ── Notification channels (operator alerting) ──────────────────────
    async fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>>;
    async fn get_notification_channel(&self, id: Uuid) -> Result<NotificationChannel>;
    async fn create_notification_channel(
        &self,
        channel: &NewNotificationChannel,
    ) -> Result<NotificationChannel>;
    async fn update_notification_channel(
        &self,
        id: Uuid,
        update: &NotificationChannelUpdate,
    ) -> Result<NotificationChannel>;
    async fn delete_notification_channel(&self, id: Uuid) -> Result<()>;

    // ── Channel verification tokens ───────────────────────────────────
    /// Insert a new verification token for a channel. `token_hash` is
    /// `sha256_hex(raw_token)`; the raw token goes in the email link and is
    /// never stored. Returns after the row is persisted.
    async fn create_channel_verification_token(
        &self,
        channel_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()>;
    /// Atomically consume a verification token: marks `used_at = now()` on
    /// the first unused, non-expired row matching `token_hash`. Returns the
    /// `channel_id` on success, `None` if the token is missing, expired, or
    /// already used.
    async fn consume_channel_verification_token(&self, token_hash: &str) -> Result<Option<Uuid>>;
    /// Mark a channel as verified (`verified_at = now()`). Called by the
    /// verify endpoint after a successful token consumption.
    async fn set_channel_verified(&self, channel_id: Uuid) -> Result<()>;
    /// Set a channel's `disabled_reason` and persist it. Used by the decline
    /// endpoint and by platform-side disables (bounces, abuse). Pass an empty
    /// string (or use [`Self::set_channel_verified`]'s sibling update) to
    /// clear.
    async fn set_channel_disabled_reason(&self, channel_id: Uuid, reason: &str) -> Result<()>;

    // ── Target ↔ notification channel bindings ─────────────────────────
    async fn list_target_channels(&self, target_id: Uuid) -> Result<Vec<TargetChannelBinding>>;
    async fn bind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()>;
    async fn unbind_target_channel(&self, target_id: Uuid, channel_id: Uuid) -> Result<()>;
    /// Remove all bindings for a channel — used when a channel is deleted.
    async fn unbind_channel_everywhere(&self, channel_id: Uuid) -> Result<()>;

    // ── Incident ops (acknowledge / resolve / reopen / assign / note) ──
    /// Apply an operational patch to an incident. Handles state transitions
    /// (acknowledge/resolve/reopen), assignment, visibility toggle, severity
    /// change, and note append. Returns the updated incident.
    async fn apply_incident_ops(
        &self,
        incident_id: Uuid,
        patch: &IncidentOpsPatch,
    ) -> Result<Incident>;

    /// Incident metrics rollup over a trailing window (days). Counts by
    /// state, MTTR, etc.
    async fn incident_metrics(&self, window_days: u32) -> Result<IncidentMetricsRollup>;

    // ── Subscriber deliveries (dispatch log) ───────────────────────────
    /// List pending deliveries (status = Pending), capped at `limit`. The
    /// dispatcher claims these, attempts delivery, and marks them.
    async fn list_pending_deliveries(&self, limit: u32) -> Result<Vec<SubscriberDelivery>>;
    /// Atomically claim a delivery: set status = Claimed and return the
    /// updated row. Returns `None` if the delivery was already claimed by
    /// another worker.
    async fn claim_delivery(&self, id: Uuid) -> Result<Option<SubscriberDelivery>>;
    /// Mark a delivery as sent or failed / dead-lettered. Bumps `attempts`,
    /// sets `last_error`, and schedules `next_attempt_at` for retries.
    async fn mark_delivery(
        &self,
        id: Uuid,
        status: DeliveryStatus,
        error: Option<&str>,
    ) -> Result<()>;
    /// Enqueue a new delivery for a subscriber. Called by the incident
    /// writer / maintenance trigger when an event happens.
    async fn enqueue_delivery(
        &self,
        subscriber_id: Uuid,
        status_page_id: Uuid,
        channel: statuscore::domain::SubscriberChannel,
        target: &str,
        payload: &str,
        reason: DeliveryReason,
    ) -> Result<()>;

    /// Delete deliveries in a terminal state (`Sent` or `DeadLetter`) older
    /// than `older_than`. Returns the number of rows deleted. Used by the
    /// cleanup worker to keep the `subscriber_deliveries` table bounded.
    async fn delete_old_deliveries(&self, older_than: chrono::DateTime<Utc>) -> Result<u64>;

    /// Delete subscribers that have never verified (`verified_at IS NULL`)
    /// and were created before `older_than`. Returns the number of rows
    /// deleted. Prevents unverified sign-ups from accumulating forever.
    async fn delete_unverified_subscribers(&self, older_than: chrono::DateTime<Utc>)
    -> Result<u64>;

    /// Delete `check_results` rows whose `timestamp` is older than
    /// `older_than`. Returns the number of rows deleted. The time-series
    /// table grows unbounded without a purge; the 90-day day-strip is
    /// derived from incidents + the latest result, not raw results, so
    /// purging old rows does not affect the public page.
    async fn delete_old_check_results(&self, older_than: chrono::DateTime<Utc>) -> Result<u64>;

    // ── Domain expiry state (sticky last-good for RDAP) ────────────────
    async fn get_domain_expiry_state(&self, target_id: Uuid) -> Result<Option<DomainExpiryState>>;
    async fn set_domain_expiry_state(&self, state: &DomainExpiryState) -> Result<()>;

    // ── Auth: users ───────────────────────────────────────────────────
    /// Create a new user. Email is normalized (trim + lowercase) before
    /// insert; a duplicate email surfaces as `StorageError::Conflict`.
    async fn create_user(&self, new: &NewUser) -> Result<User>;
    /// Look up a user by id. Returns `NotFound` if the row is missing or
    /// soft-deleted.
    async fn get_user(&self, id: Uuid) -> Result<User>;
    /// Look up a user by normalized email. Returns `None` if no row matches
    /// (including soft-deleted rows).
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>>;
    /// Count total non-deleted users. Used by the bootstrap check: if zero,
    /// the first-run setup endpoint is enabled without auth.
    async fn count_users(&self) -> Result<i64>;
    /// Apply a partial update to a user. `NotFound` if the row is missing.
    async fn update_user(&self, id: Uuid, update: &UserUpdate) -> Result<User>;
    /// Stamp `last_seen_at = now()` on a user. Called from the session
    /// middleware on a debounced (60s) basis to avoid a write per request.
    async fn touch_user(&self, id: Uuid, at: DateTime<Utc>) -> Result<()>;

    // ── Auth: sessions (cookie-based browser auth) ───────────────────
    /// Insert a new session row. `id_hash` is `sha256_hex(cookie_value)` —
    /// the caller (AuthService) generates the raw cookie, hashes it, and
    /// passes both the hash and the rest of the session fields here.
    async fn create_session(
        &self,
        id_hash: &str,
        new: &statuscore::domain::NewSession,
    ) -> Result<SessionRow>;
    /// Look up a session by its `id_hash`. Returns `None` if no row matches.
    /// Does not enforce timeouts — the caller checks `expires_at` and
    /// `last_used_at` against the configured idle/absolute limits.
    async fn lookup_session(&self, id_hash: &str) -> Result<Option<SessionRow>>;
    /// Stamp `last_used_at = now()` on a session. Called from the session
    /// middleware on a debounced basis.
    async fn touch_session(&self, id_hash: &str, at: DateTime<Utc>) -> Result<()>;
    /// Delete a session by `id_hash`. No-op (returns `Ok(())`) if the row
    /// is already gone — logout is idempotent.
    async fn delete_session(&self, id_hash: &str) -> Result<()>;
    /// Delete all sessions for a user except the one with `keep_id_hash`.
    /// Used by "revoke other sessions" on the account page.
    async fn delete_other_sessions(&self, user_id: Uuid, keep_id_hash: &str) -> Result<u64>;
    /// List all sessions for a user, newest-first. Used by the "active
    /// sessions" account page.
    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRow>>;
    /// Delete sessions whose `expires_at` is in the past. Returns the number
    /// of rows deleted. Called by the cleanup worker.
    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<u64>;

    // ── Auth: API tokens (Bearer auth for CLI/automation) ────────────
    /// Insert a new API token row. The `token_hash` is an argon2id PHC string;
    /// `token_prefix` is the non-unique lookup index.
    async fn create_api_token(
        &self,
        user_id: Uuid,
        new: &NewApiToken,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<ApiTokenRow>;
    /// Look up candidate token rows by prefix. The caller verifies each
    /// candidate's hash against the raw token. Returns rows newest-first.
    async fn find_api_tokens_by_prefix(&self, prefix: &str) -> Result<Vec<ApiTokenRow>>;
    /// List all tokens for a user (no hash). Used by the account page.
    async fn list_api_tokens(&self, user_id: Uuid) -> Result<Vec<ApiTokenRow>>;
    /// Rename a token. `NotFound` if the row is missing.
    async fn update_api_token(&self, id: Uuid, update: &ApiTokenUpdate) -> Result<ApiTokenRow>;
    /// Stamp `last_used_at = now()` on a token. Called from the auth
    /// middleware on a debounced basis.
    async fn touch_api_token(&self, id: Uuid, at: DateTime<Utc>) -> Result<()>;
    /// Delete a token. No-op if missing.
    async fn delete_api_token(&self, id: Uuid) -> Result<()>;
    /// Delete all tokens for a user. Used by account deletion.
    async fn delete_api_tokens_for_user(&self, user_id: Uuid) -> Result<u64>;
    /// Hard-delete tokens whose `expires_at` is older than `cutoff` (i.e.
    /// expired at least `api_tokens_post_expiry_days` ago). Returns the
    /// number of rows deleted. Bounds table growth and shrinks the
    /// rotation-pattern leak from a compromised user reading their own
    /// `token_prefix` / `name` history.
    async fn delete_expired_api_tokens(&self, cutoff: DateTime<Utc>) -> Result<u64>;

    // ── Auth: magic links (passwordless email login) ─────────────────
    /// Insert a new magic-link row. The `token_hash` is argon2id; `token_prefix`
    /// is the lookup index.
    async fn create_magic_link(
        &self,
        email: &str,
        token_hash: &str,
        token_prefix: &str,
        expires_at: DateTime<Utc>,
        ip_hash: Option<&str>,
        redirect_after: Option<&str>,
    ) -> Result<MagicLinkRow>;
    /// Look up candidate magic-link rows by prefix. The caller verifies each
    /// candidate's hash against the raw token.
    async fn find_magic_links_by_prefix(&self, prefix: &str) -> Result<Vec<MagicLinkRow>>;
    /// Atomically mark a magic-link row as consumed: `UPDATE ... SET used_at
    /// = now() WHERE id = ? AND used_at IS NULL`. Returns the updated row on
    /// success, `None` if already used / not found.
    async fn consume_magic_link(&self, id: Uuid) -> Result<Option<MagicLinkRow>>;
    /// Delete magic-link rows whose `expires_at` is in the past. Returns the
    /// number of rows deleted. Called by the cleanup worker.
    async fn delete_expired_magic_links(&self, now: DateTime<Utc>) -> Result<u64>;

    // ── Escalation policies ───────────────────────────────────────────
    /// List all escalation policies (lightweight summaries — no steps loaded).
    async fn list_escalation_policies(&self) -> Result<Vec<EscalationPolicySummary>>;
    /// Get the full escalation policy (steps + targets) by id.
    async fn get_escalation_policy(&self, id: Uuid) -> Result<EscalationPolicy>;
    /// Create or fully replace a policy. The caller provides the full
    /// aggregate (steps + targets); storage replaces the whole step list.
    async fn upsert_escalation_policy(&self, policy: &EscalationPolicy)
    -> Result<EscalationPolicy>;
    /// Delete a policy by id. `NotFound` if missing.
    async fn delete_escalation_policy(&self, id: Uuid) -> Result<()>;

    // ── On-call schedules ─────────────────────────────────────────────
    /// List all on-call schedules (lightweight summaries — no layers loaded).
    async fn list_on_call_schedules(&self) -> Result<Vec<OnCallScheduleSummary>>;
    /// Get the full schedule detail (layers + overrides) by id.
    async fn get_on_call_schedule(&self, id: Uuid) -> Result<OnCallScheduleDetail>;
    /// Create or fully replace a schedule's metadata + layer stack in one
    /// call. Overrides are managed separately. Returns the schedule
    /// metadata portion (no layers).
    async fn upsert_on_call_schedule(
        &self,
        detail: &OnCallScheduleDetail,
    ) -> Result<OnCallSchedule>;
    /// Delete a schedule by id. `NotFound` if missing.
    async fn delete_on_call_schedule(&self, id: Uuid) -> Result<()>;

    // ── On-call overrides ─────────────────────────────────────────────
    /// List all overrides for a schedule, ordered by `starts_at` descending.
    async fn list_on_call_overrides(&self, schedule_id: Uuid) -> Result<Vec<OnCallOverride>>;
    /// Create a new override attached to `schedule_id`. `Conflict` if the
    /// override `id` already exists. (`OnCallOverride` does not carry its
    /// schedule link inline, so the caller supplies it here.)
    async fn create_on_call_override(
        &self,
        schedule_id: Uuid,
        r#override: &OnCallOverride,
    ) -> Result<OnCallOverride>;
    /// Delete an override by id. `NotFound` if missing.
    async fn delete_on_call_override(&self, id: Uuid) -> Result<()>;

    // ── Incident escalation state ─────────────────────────────────────
    /// Get the escalation state for an incident. Returns `None` if no
    /// escalation is in progress.
    async fn get_escalation_state(
        &self,
        incident_id: Uuid,
    ) -> Result<Option<IncidentEscalationState>>;
    /// Upsert escalation state for an incident. Called by the engine on
    /// every page + ack.
    async fn upsert_escalation_state(&self, state: &IncidentEscalationState) -> Result<()>;
    /// List escalation states due for a check (`next_check_at <= now` AND
    /// NOT acked). Used by the engine's tick.
    async fn list_due_escalation_states(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<IncidentEscalationState>>;
    /// Mark an incident's escalation as acknowledged (stop paging).
    async fn ack_escalation_state(&self, incident_id: Uuid) -> Result<()>;
    /// Delete escalation state when an incident is resolved/closed.
    async fn delete_escalation_state(&self, incident_id: Uuid) -> Result<()>;

    // ── Postmortems ───────────────────────────────────────────────────
    /// Get the postmortem for an incident. Returns `None` if no postmortem exists.
    async fn get_postmortem(&self, incident_id: Uuid) -> Result<Option<IncidentPostmortem>>;
    /// Upsert (create or update) a postmortem. `published_at` stays `None`
    /// until `publish_postmortem` is called.
    async fn upsert_postmortem(
        &self,
        incident_id: Uuid,
        author_id: Option<Uuid>,
        body: &PostmortemUpsert,
    ) -> Result<IncidentPostmortem>;
    /// Publish a postmortem (sets `published_at = now()`). Returns the updated
    /// postmortem. `NotFound` if no postmortem exists.
    async fn publish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem>;
    /// Unpublish a postmortem (sets `published_at = None`). Returns the updated
    /// postmortem. `NotFound` if no postmortem exists.
    async fn unpublish_postmortem(&self, incident_id: Uuid) -> Result<IncidentPostmortem>;
    /// Delete a postmortem entirely.
    async fn delete_postmortem(&self, incident_id: Uuid) -> Result<()>;

    // ── Monitor share links ───────────────────────────────────────────
    /// List all share links for a target. Newest-first. The raw token is
    /// never included (it is not persisted); `MonitorShare::token` is always
    /// `None` on this path.
    async fn list_monitor_shares(&self, target_id: Uuid) -> Result<Vec<MonitorShare>>;
    /// Create a new share link. The storage layer generates the raw token
    /// (32 random bytes, base64url), hashes it with `sha256_hex`, stores
    /// only the hash, and returns the [`CreatedShare`] carrying the
    /// one-time plaintext token. The raw token is never persisted.
    async fn create_monitor_share(
        &self,
        target_id: Uuid,
        label: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<CreatedShare>;
    /// Delete a share link by id. No-op (returns `Ok(())`) if the row is
    /// already gone — revoke is idempotent.
    async fn delete_monitor_share(&self, id: Uuid) -> Result<()>;
    /// Resolve a share token to its target. Atomically increments
    /// `view_count` and updates `last_viewed_at`. Returns `None` if the
    /// token is unknown, expired, or the share was deleted.
    async fn resolve_monitor_share(&self, token_hash: &str) -> Result<Option<ResolvedShare>>;

    // ── Health check ───────────────────────────────────────────────────
    /// Ping the storage backend (e.g. `SELECT 1`). Used by `/readyz` to
    /// verify the storage is reachable and responsive.
    async fn ping(&self) -> Result<()>;
}
