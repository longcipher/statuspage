//! Incident postmortem endpoints.
//!
//! `GET /incidents/{id}/postmortem` — fetch the postmortem (operator view,
//! includes `author_id`). Returns 404 if no postmortem exists yet.
//! `PUT /incidents/{id}/postmortem` — create or replace the postmortem from
//! a [`PostmortemUpsert`] body. `published_at` is preserved across updates
//! so editing a published postmortem does not un-publish it.
//! `POST /incidents/{id}/postmortem/publish` — stamp `published_at = now()`.
//! `DELETE /incidents/{id}/postmortem/publish` — clear `published_at`.
//! `DELETE /incidents/{id}/postmortem` — remove the postmortem entirely.
//!
//! All endpoints require authentication. The authenticated user becomes the
//! `author_id` on `PUT`. CSRF is enforced on browser mutations via
//! `X-Requested-With` (API tokens are exempt).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use statuscore::domain::{IncidentPostmortem, PostmortemUpsert};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;
use crate::auth::middleware::{RequireAuth, csrf_guard};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/incidents/{id}/postmortem",
            get(get_postmortem).put(upsert_postmortem).delete(delete_postmortem),
        )
        .route(
            "/incidents/{id}/postmortem/publish",
            post(publish_postmortem).delete(unpublish_postmortem),
        )
}

/// `GET /incidents/{id}/postmortem` — operator view of the postmortem,
/// including the internal `author_id`. Returns 404 if no postmortem exists.
async fn get_postmortem(
    State(state): State<AppState>,
    RequireAuth(_identity): RequireAuth,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    match state.storage.get_postmortem(id).await? {
        Some(pm) => Ok(Json(pm).into_response()),
        None => Err(ApiError(statuscore::error::AppError::NotFound {
            code: "POSTMORTEM_NOT_FOUND",
            message: format!("no postmortem for incident {id}"),
        })),
    }
}

/// `PUT /incidents/{id}/postmortem` — create or replace the postmortem.
/// The authenticated user becomes the `author_id`. `published_at` is
/// preserved across replaces.
async fn upsert_postmortem(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
    Json(body): Json<PostmortemUpsert>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let author_id = identity.user_id().map(|u| u.0);
    let pm: IncidentPostmortem = state.storage.upsert_postmortem(id, author_id, &body).await?;
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(pm)))
}

/// `POST /incidents/{id}/postmortem/publish` — publish the postmortem.
/// Sets `published_at = now()`. 404 if no postmortem exists.
async fn publish_postmortem(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let pm = state.storage.publish_postmortem(id).await?;
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(pm)))
}

/// `DELETE /incidents/{id}/postmortem/publish` — unpublish the postmortem.
/// Sets `published_at = NULL`. 404 if no postmortem exists.
async fn unpublish_postmortem(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let pm = state.storage.unpublish_postmortem(id).await?;
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(pm)))
}

/// `DELETE /incidents/{id}/postmortem` — remove the postmortem entirely.
/// Idempotent (returns 204 even if no row existed).
async fn delete_postmortem(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    state.storage.delete_postmortem(id).await?;
    invalidate_public_cache(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Invalidate the public status cache after any postmortem mutation. See
/// `incident_ops::invalidate_public_cache` for the rationale on full
/// invalidation vs. targeted.
async fn invalidate_public_cache(state: &AppState) {
    state.public_cache.invalidate_all();
}
