//! Silence rules CRUD.
//!
//! `GET/POST /silence-rules` and `GET/PATCH/DELETE /silence-rules/{id}`. A
//! silence rule suppresses notification delivery (operator channels bound to
//! a target) for matching `(target_id, channel_id, reason)` triples during
//! `[starts_at, ends_at)`. Probing and incident state are unaffected —
//! only the dispatch path is filtered.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use statuscore::domain::{NewSilenceRule, SilenceFilter, SilenceRuleUpdate};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;
use crate::auth::RequireAuth;

pub fn routes() -> Router<AppState> {
    Router::new().route("/silence-rules", get(list_silence_rules).post(create_silence_rule)).route(
        "/silence-rules/{id}",
        get(get_silence_rule).patch(update_silence_rule).delete(delete_silence_rule),
    )
}

#[derive(Debug, Deserialize, Default)]
struct SilenceQuery {
    #[serde(default)]
    filter: SilenceFilter,
}

async fn list_silence_rules(
    State(state): State<AppState>,
    Query(query): Query<SilenceQuery>,
) -> ApiResult<impl IntoResponse> {
    let rules = state.storage.list_silence_rules(query.filter).await?;
    Ok(Json(rules))
}

async fn create_silence_rule(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Json(new_rule): Json<NewSilenceRule>,
) -> ApiResult<impl IntoResponse> {
    if new_rule.ends_at <= new_rule.starts_at {
        return Err(ApiError(statuscore::error::AppError::BadRequest {
            code: "INVALID_WINDOW",
            message: "ends_at must be after starts_at".to_string(),
            field: None,
        }));
    }

    // Global silence rules (no `target_id`) suppress dispatch for every
    // target — an operator-only action. This is single-tenant self-hosted
    // (no role/scope model), so the closest analog of "admin scope" is to
    // require a browser session: the session is the operator surface, while
    // API tokens are automation. A token-scoped admin role plugs in here
    // when multi-tenancy is introduced.
    if new_rule.target_id.is_none() && !identity.is_session() {
        return Err(ApiError(statuscore::error::AppError::forbidden_code(
            "GLOBAL_SILENCE_REQUIRES_SESSION",
            "global silence rules require a browser session (API tokens are not permitted)",
        )));
    }

    let created = state.storage.create_silence_rule(&new_rule).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_silence_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let rule = state.storage.get_silence_rule(id).await?;
    Ok(Json(rule))
}

async fn update_silence_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(update): Json<SilenceRuleUpdate>,
) -> ApiResult<impl IntoResponse> {
    let updated = state.storage.update_silence_rule(id, &update).await?;
    Ok(Json(updated))
}

async fn delete_silence_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_silence_rule(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
