//! On-call schedule CRUD + override management.
//!
//! - `GET /on-call-schedules` — list schedules (summaries, no layers loaded).
//! - `POST /on-call-schedules` — create a schedule from [`NewOnCallSchedule`].
//! - `GET /on-call-schedules/{id}` — full schedule detail (layers + overrides).
//! - `PATCH /on-call-schedules/{id}` — full-replace a schedule's metadata +
//!   layer stack. Overrides are NOT replaced on PATCH (manage them via the
//!   override routes below).
//! - `DELETE /on-call-schedules/{id}` — delete a schedule.
//! - `GET /on-call-schedules/{id}/overrides` — list overrides for a schedule.
//! - `POST /on-call-schedules/{id}/overrides` — create an override from
//!   [`NewOnCallOverride`].
//! - `DELETE /on-call-schedules/{id}/overrides/{override_id}` — delete an
//!   override.

use std::str::FromStr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use chrono_tz::Tz;
use serde::Deserialize;
use statuscore::domain::{
    NewOnCallOverride, NewOnCallSchedule, OnCallLayer, OnCallOverride, OnCallParticipant,
    OnCallSchedule, OnCallScheduleDetail,
};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

/// Route tree mounted by [`crate::api::routes`].
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/on-call-schedules", get(list_schedules).post(create_schedule))
        .route(
            "/on-call-schedules/{id}",
            get(get_schedule).patch(update_schedule).delete(delete_schedule),
        )
        .route("/on-call-schedules/{id}/overrides", get(list_overrides).post(create_override))
        .route(
            "/on-call-schedules/{id}/overrides/{override_id}",
            axum::routing::delete(delete_override),
        )
}

/// `GET /on-call-schedules` — lightweight summary rows (no layers loaded).
async fn list_schedules(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let schedules = state.storage.list_on_call_schedules().await?;
    Ok(Json(schedules))
}

/// `POST /on-call-schedules` — create a schedule. Mint v7 ids for the
/// schedule, every layer, and every participant, stamp `created_at`/
/// `updated_at`, and upsert. Returns 201 with the schedule metadata.
async fn create_schedule(
    State(state): State<AppState>,
    Json(new_schedule): Json<NewOnCallSchedule>,
) -> ApiResult<impl IntoResponse> {
    validate_new_schedule(&new_schedule)?;
    let detail = build_schedule_detail(Uuid::now_v7(), &new_schedule);
    let created = state.storage.upsert_on_call_schedule(&detail).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// `GET /on-call-schedules/{id}` — full schedule detail (layers + overrides).
async fn get_schedule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let detail = state.storage.get_on_call_schedule(id).await?;
    Ok(Json(detail))
}

/// `PATCH /on-call-schedules/{id}` — full-replace a schedule's metadata +
/// layer stack. Overrides are managed separately and are NOT touched here
/// (the upsert only persists metadata + layers). Returns 200 with the
/// schedule metadata.
async fn update_schedule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(new_schedule): Json<NewOnCallSchedule>,
) -> ApiResult<impl IntoResponse> {
    validate_new_schedule(&new_schedule)?;
    let detail = build_schedule_detail(id, &new_schedule);
    let updated = state.storage.upsert_on_call_schedule(&detail).await?;
    Ok((StatusCode::OK, Json(updated)))
}

/// `DELETE /on-call-schedules/{id}` — delete a schedule. 204 on success.
async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_on_call_schedule(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /on-call-schedules/{id}/overrides` — list overrides for a schedule,
/// newest-first (per the storage contract).
async fn list_overrides(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // Surface a 404 if the schedule itself is missing before listing overrides.
    let _ = state.storage.get_on_call_schedule(id).await?;
    let overrides = state.storage.list_on_call_overrides(id).await?;
    Ok(Json(overrides))
}

/// `POST /on-call-schedules/{id}/overrides` — create a one-off coverage
/// override. Returns 201 with the stored override.
async fn create_override(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(new_override): Json<NewOnCallOverride>,
) -> ApiResult<impl IntoResponse> {
    // Surface a 404 if the schedule itself is missing before creating.
    let _ = state.storage.get_on_call_schedule(id).await?;
    if new_override.ends_at <= new_override.starts_at {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_OVERRIDE_WINDOW",
            "ends_at must be strictly after starts_at",
        )));
    }
    let r#override = OnCallOverride {
        id: Uuid::now_v7(),
        user_id: new_override.user_id,
        starts_at: new_override.starts_at,
        ends_at: new_override.ends_at,
        created_by: None,
        created_at: Utc::now(),
    };
    let created = state.storage.create_on_call_override(id, &r#override).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// Path params for override delete: `{schedule_id}/overrides/{override_id}`.
#[derive(Debug, Deserialize)]
struct OverridePath {
    /// Schedule id (validated implicitly by storage on the override lookup).
    #[expect(dead_code)]
    id: Uuid,
    override_id: Uuid,
}

/// `DELETE /on-call-schedules/{id}/overrides/{override_id}` — delete an
/// override. 204 on success.
async fn delete_override(
    State(state): State<AppState>,
    Path(path): Path<OverridePath>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_on_call_override(path.override_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Validate a create/replace payload. Rejects empty names, unparsable IANA
/// timezones, layers with non-positive `rotation_length_secs`, and layers
/// with no participants.
fn validate_new_schedule(new: &NewOnCallSchedule) -> ApiResult<()> {
    if new.name.trim().is_empty() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_SCHEDULE_NAME",
            "name is required",
        )));
    }
    // `chrono_tz::Tz::from_str` rejects unknown zone names; fall back to 400
    // rather than the resolver's silent UTC default so a typo surfaces now.
    if Tz::from_str(&new.timezone).is_err() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_TIMEZONE",
            format!("timezone {:?} is not a valid IANA zone", new.timezone),
        )));
    }
    for (i, layer) in new.layers.iter().enumerate() {
        if layer.rotation_length_secs <= 0 {
            return Err(ApiError(statuscore::error::AppError::bad_request(
                "INVALID_ROTATION_LENGTH",
                format!(
                    "layer at index {i} has non-positive rotation_length_secs {}",
                    layer.rotation_length_secs
                ),
            )));
        }
        if layer.participants.is_empty() {
            return Err(ApiError(statuscore::error::AppError::bad_request(
                "EMPTY_PARTICIPANTS",
                format!("layer at index {i} must have at least one participant"),
            )));
        }
    }
    Ok(())
}

/// Build a fully-stamped [`OnCallScheduleDetail`] from a create/replace
/// payload, minting v7 ids for the schedule, every layer, and every
/// participant. Overrides are empty — they are managed via the override
/// routes and ignored by the upsert.
fn build_schedule_detail(id: Uuid, new: &NewOnCallSchedule) -> OnCallScheduleDetail {
    let now = Utc::now();
    let schedule = OnCallSchedule {
        id,
        name: new.name.clone(),
        timezone: new.timezone.clone(),
        created_at: now,
        updated_at: now,
    };
    let layers = new
        .layers
        .iter()
        .map(|l| OnCallLayer {
            id: Uuid::now_v7(),
            name: l.name.clone(),
            rotation_type: l.rotation_type,
            rotation_length_secs: l.rotation_length_secs,
            handoff_at: l.handoff_at,
            layer_order: l.layer_order,
            created_at: now,
            participants: l
                .participants
                .iter()
                .enumerate()
                .map(|(pos, p)| OnCallParticipant {
                    id: Uuid::now_v7(),
                    user_id: p.user_id,
                    position: pos as i32,
                })
                .collect(),
        })
        .collect();
    OnCallScheduleDetail { schedule, layers, overrides: Vec::new() }
}
