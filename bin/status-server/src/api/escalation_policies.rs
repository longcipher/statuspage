//! Escalation policy CRUD.
//!
//! - `GET /escalation-policies` — list policies (summaries, no steps loaded).
//! - `POST /escalation-policies` — create a policy from [`NewEscalationPolicy`].
//! - `GET /escalation-policies/{id}` — get the full policy (steps + targets).
//! - `PATCH /escalation-policies/{id}` — full-replace a policy (same body as
//!   POST). PATCH rewrites the whole step list in one round-trip so the
//!   builder UI can edit levels/targets without nested CRUD.
//! - `DELETE /escalation-policies/{id}` — delete a policy.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use statuscore::domain::{
    EscalationPolicy, EscalationStep, EscalationTarget, EscalationTargetType, NewEscalationPolicy,
};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

/// Route tree mounted by [`crate::api::routes`].
pub fn routes() -> Router<AppState> {
    Router::new().route("/escalation-policies", get(list_policies).post(create_policy)).route(
        "/escalation-policies/{id}",
        get(get_policy).patch(update_policy).delete(delete_policy),
    )
}

/// `GET /escalation-policies` — lightweight summary rows (no steps loaded).
async fn list_policies(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let policies = state.storage.list_escalation_policies().await?;
    Ok(Json(policies))
}

/// `POST /escalation-policies` — create a policy. Mint v7 ids for the policy,
/// every step, and every target, stamp `created_at`/`updated_at`, and upsert.
/// Returns 201 with the stored policy.
async fn create_policy(
    State(state): State<AppState>,
    Json(new_policy): Json<NewEscalationPolicy>,
) -> ApiResult<impl IntoResponse> {
    validate_new_policy(&new_policy)?;
    let policy = build_policy(Uuid::now_v7(), &new_policy);
    let created = state.storage.upsert_escalation_policy(&policy).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// `GET /escalation-policies/{id}` — full policy with steps + targets.
async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let policy = state.storage.get_escalation_policy(id).await?;
    Ok(Json(policy))
}

/// `PATCH /escalation-policies/{id}` — full-replace a policy's metadata +
/// step list (overrides the whole step set; overrides are not modelled here).
/// Returns 200 with the stored policy.
async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(new_policy): Json<NewEscalationPolicy>,
) -> ApiResult<impl IntoResponse> {
    validate_new_policy(&new_policy)?;
    let policy = build_policy(id, &new_policy);
    let updated = state.storage.upsert_escalation_policy(&policy).await?;
    Ok((StatusCode::OK, Json(updated)))
}

/// `DELETE /escalation-policies/{id}` — delete a policy. 204 on success.
async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_escalation_policy(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Validate a create/replace payload. Rejects empty names, non-positive step
/// levels, and targets whose set id field does not match `target_type`.
fn validate_new_policy(new: &NewEscalationPolicy) -> ApiResult<()> {
    if new.name.trim().is_empty() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_POLICY_NAME",
            "name is required",
        )));
    }
    for (i, step) in new.steps.iter().enumerate() {
        if step.level <= 0 {
            return Err(ApiError(statuscore::error::AppError::bad_request(
                "INVALID_STEP_LEVEL",
                format!("step at index {i} has non-positive level {}", step.level),
            )));
        }
        for (j, target) in step.targets.iter().enumerate() {
            if let Err(reason) = validate_target(target) {
                return Err(ApiError(statuscore::error::AppError::bad_request(
                    "INVALID_ESCALATION_TARGET",
                    format!("step {i} target {j}: {reason}"),
                )));
            }
        }
    }
    Ok(())
}

/// Exactly one id field is set, and it matches `target_type`.
fn validate_target(target: &statuscore::domain::NewEscalationTarget) -> Result<(), String> {
    let set_count =
        [target.user_id.is_some(), target.schedule_id.is_some(), target.channel_id.is_some()]
            .iter()
            .filter(|&&b| b)
            .count();
    if set_count != 1 {
        return Err(format!(
            "expected exactly one of user_id/schedule_id/channel_id set, got {set_count}"
        ));
    }
    let matches = match target.target_type {
        EscalationTargetType::User => target.user_id.is_some(),
        EscalationTargetType::Schedule => target.schedule_id.is_some(),
        EscalationTargetType::Channel => target.channel_id.is_some(),
        // `EscalationTargetType` is #[non_exhaustive]; unknown types fail
        // validation defensively (the set-id check above already rejected
        // them, but never silently pass an unknown shape).
        _ => false,
    };
    if !matches {
        return Err(format!("set id does not match target_type {:?}", target.target_type));
    }
    Ok(())
}

/// Build a fully-stamped [`EscalationPolicy`] from a create/replace payload,
/// minting v7 ids for the policy, every step, and every target.
fn build_policy(id: Uuid, new: &NewEscalationPolicy) -> EscalationPolicy {
    let now = Utc::now();
    let steps = new
        .steps
        .iter()
        .map(|s| EscalationStep {
            id: Uuid::now_v7(),
            level: s.level,
            delay_secs: s.delay_secs,
            targets: s
                .targets
                .iter()
                .map(|t| EscalationTarget {
                    id: Uuid::now_v7(),
                    target_type: t.target_type,
                    user_id: t.user_id,
                    schedule_id: t.schedule_id,
                    channel_id: t.channel_id,
                })
                .collect(),
        })
        .collect();
    EscalationPolicy {
        id,
        name: new.name.clone(),
        description: new.description.clone(),
        repeat_count: new.repeat_count,
        steps,
        created_at: now,
        updated_at: now,
    }
}
