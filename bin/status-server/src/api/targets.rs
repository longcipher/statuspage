//! Target CRUD + check-now + test handlers.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Deserialize;
use statuscore::domain::{CheckStatus, NewTarget, Target, TargetUpdate, WriteSource};
use uuid::Uuid;

use super::{ApiError, ApiResult};
use crate::app::AppState;

/// Query params for `GET /targets`. All filters are optional and combine
/// with AND semantics: a target must match every supplied filter to appear
/// in the result. The `status` filter matches the target's latest check
/// result; targets with no recorded checks are treated as `unknown` and
/// excluded when a concrete status is requested.
#[derive(Debug, Default, Deserialize)]
pub(super) struct TargetsQuery {
    /// Case-insensitive substring match against `tags` (a target passes if
    /// any of its tags contains the substring).
    #[serde(default)]
    tag: Option<String>,
    /// Exact match against `group_name` (case-sensitive). Pass `null` /
    /// omit to ignore. To find targets with no group, use `group=`.
    #[serde(default)]
    group: Option<String>,
    /// Filter by `enabled` flag.
    #[serde(default)]
    enabled: Option<bool>,
    /// Filter by latest `CheckStatus` (`up` / `down` / `degraded` / `error`).
    /// Targets without a recorded check are excluded when this is set.
    #[serde(default)]
    status: Option<String>,
}

pub(super) async fn list_targets(
    State(state): State<AppState>,
    Query(query): Query<TargetsQuery>,
) -> ApiResult<impl IntoResponse> {
    let mut targets = state.storage.list_targets().await?;

    // Tag filter: case-insensitive substring against any tag.
    if let Some(tag) = &query.tag {
        let needle = tag.to_lowercase();
        targets.retain(|t| t.tags.iter().any(|tag| tag.to_lowercase().contains(&needle)));
    }

    // Group filter: exact match. An empty string means "no group"
    // (`group_name` is `None`), so callers can find ungrouped targets.
    if let Some(group) = &query.group {
        targets.retain(|t| match group.as_str() {
            "" => t.group_name.is_none(),
            g => t.group_name.as_deref() == Some(g),
        });
    }

    if let Some(enabled) = query.enabled {
        targets.retain(|t| t.enabled == enabled);
    }

    // Status filter: needs the latest check result per target. The
    // dashboard rollup already carries `current_status`, so reuse it
    // rather than N+1 per-target `list_results(1)` reads.
    if let Some(status_str) = &query.status {
        let want = match status_str.to_lowercase().as_str() {
            "up" => CheckStatus::Up,
            "down" => CheckStatus::Down,
            "degraded" => CheckStatus::Degraded,
            "error" => CheckStatus::Error,
            _ => {
                return Err(ApiError(statuscore::error::AppError::bad_request(
                    "INVALID_STATUS",
                    format!(
                        "unknown status `{status_str}`; expected one of: up, down, degraded, error"
                    ),
                )));
            }
        };
        let rollup = state.storage.dashboard_rollup().await?;
        let mut by_id: std::collections::HashMap<Uuid, CheckStatus> =
            rollup.iter().map(|r| (r.target_id, r.current_status)).collect();
        targets.retain(|t| by_id.remove(&t.id) == Some(want));
    }

    Ok(Json(targets))
}

pub(super) async fn create_target(
    State(state): State<AppState>,
    Json(new_target): Json<NewTarget>,
) -> ApiResult<impl IntoResponse> {
    let now = Utc::now();
    let target = Target {
        id: Uuid::now_v7(),
        name: new_target.name,
        check: new_target.check,
        interval: new_target.interval,
        enabled: new_target.enabled,
        tags: new_target.tags,
        alerts: new_target.alerts,
        alert_confirmations: new_target.alert_confirmations,
        notify_recovery: new_target.notify_recovery,
        renotify_interval_secs: new_target.renotify_interval_secs,
        region_policy: new_target.region_policy.unwrap_or_default(),
        group_name: new_target.group_name,
        owner_user_id: new_target.owner_user_id,
        escalation_policy_id: new_target.escalation_policy_id,
        created_at: now,
        updated_at: now,
        write_source: WriteSource::default(),
    };
    let created = state.storage.create_target(&target).await?;
    state.public_cache.invalidate_all();
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_target(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let target = state.storage.get_target(id).await?;
    Ok(Json(target))
}

pub(super) async fn update_target(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(update): Json<TargetUpdate>,
) -> ApiResult<impl IntoResponse> {
    let mut target = state.storage.get_target(id).await?;
    update.apply_to(&mut target);
    target.updated_at = Utc::now();
    let updated = state.storage.update_target(&target).await?;
    state.public_cache.invalidate_all();
    Ok(Json(updated))
}

pub(super) async fn delete_target(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_target(id).await?;
    state.public_cache.invalidate_all();
    Ok(StatusCode::NO_CONTENT)
}

/// Query params for `GET /targets/{id}/results`.
#[derive(Debug, Deserialize)]
pub(super) struct ResultsQuery {
    limit: Option<u32>,
}

/// Recent check results for a single target, newest-first.
pub(super) async fn list_target_results(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ResultsQuery>,
) -> ApiResult<impl IntoResponse> {
    let limit = query.limit.unwrap_or(100).min(1000);
    let results = state.storage.list_results(id, limit).await?;
    Ok(Json(results))
}

/// `POST /targets/{id}/check-now` — probe a target immediately, record the
/// result, and return it.
pub(super) async fn check_target_now(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let target = state.storage.get_target(id).await?;
    if !target.enabled {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "TARGET_DISABLED",
            "target is disabled; enable it before triggering a check",
        )));
    }

    let result = crate::scheduler::probe_target(state.storage.as_ref(), &target).await;
    if let Err(e) = state.storage.record_result(&result).await {
        tracing::error!(target_id = %id, error = %e, "check-now: record_result failed");
        return Err(ApiError(statuscore::error::AppError::internal_with_context(
            "RECORD_RESULT",
            format!("failed to record check result: {e}"),
        )));
    }

    let dispatch_ctx = crate::incident_writer::ChannelDispatchCtx::new(
        state.email_sender.clone(),
        state.from_address.clone(),
        state.public_base_url.clone(),
        state.notifier_http.clone(),
    );
    crate::incident_writer::evaluate_target(state.storage.as_ref(), id, Some(&dispatch_ctx)).await;

    state.public_cache.invalidate_all();
    Ok(Json(result))
}

/// Request body for `POST /targets/test`.
#[derive(Debug, Deserialize)]
pub(super) struct TestTargetBody {
    check: statuscore::domain::CheckSpec,
}

/// `POST /targets/test` — dry-run a `CheckSpec` against the network
/// without persisting a target.
pub(super) async fn test_target_spec(
    State(state): State<AppState>,
    Json(body): Json<TestTargetBody>,
) -> ApiResult<impl IntoResponse> {
    use statuscore::domain::CheckSpec;

    match &body.check {
        CheckSpec::Heartbeat(_) | CheckSpec::DomainExpiry(_) => {
            return Err(ApiError(statuscore::error::AppError::bad_request(
                "NOT_TESTABLE",
                "heartbeat and domain_expiry checks require a persisted target; \
                 create the target and use POST /targets/{id}/check-now instead",
            )));
        }
        _ => {}
    }

    let ephemeral = Target {
        id: Uuid::nil(),
        name: "__test__".to_string(),
        check: body.check,
        interval: std::time::Duration::from_mins(1),
        enabled: true,
        tags: Vec::new(),
        alerts: Default::default(),
        alert_confirmations: 1,
        notify_recovery: false,
        renotify_interval_secs: 0,
        region_policy: Default::default(),
        group_name: None,
        owner_user_id: None,
        escalation_policy_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        write_source: WriteSource::default(),
    };

    let result = crate::scheduler::probe_target(state.storage.as_ref(), &ephemeral).await;
    Ok(Json(result))
}
