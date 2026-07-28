//! Monitor share-link CRUD.
//!
//! - `GET /targets/{target_id}/shares` — list share links for a target.
//!   The raw token is never included (only its hash is persisted); each
//!   returned `MonitorShare.token` is `None`.
//! - `POST /targets/{target_id}/shares` — mint a new share link from a
//!   [`NewMonitorShare`] body. Returns `201` with [`CreatedShare`], which
//!   carries the one-time plaintext token. The caller must persist it
//!   client-side — it cannot be recovered.
//! - `DELETE /targets/{target_id}/shares/{share_id}` — revoke a share link.
//!   Idempotent (returns `204` whether or not the row existed).
//!
//! All endpoints require authentication. CSRF is enforced on browser
//! mutations via `X-Requested-With` (API tokens are exempt).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use statuscore::domain::{CreatedShare, MonitorShare, NewMonitorShare};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;
use crate::auth::middleware::{RequireAuth, csrf_guard};

/// Serialisable projection of [`CreatedShare`] for the `POST` response. The
/// domain `CreatedShare` is `Debug + Clone` only (it isn't a wire type by
/// design); this wrapper mirrors its shape `{ share, token }` so the API
/// response is stable and the raw token is shown exactly once.
#[derive(Debug, Serialize)]
struct CreatedShareResponse {
    share: MonitorShare,
    /// Raw capability URL token — embedded in `/shared/{token}` once, never
    /// persisted. The caller must copy it now; it cannot be recovered.
    token: String,
}

impl From<CreatedShare> for CreatedShareResponse {
    fn from(c: CreatedShare) -> Self {
        Self { share: c.share, token: c.token }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/targets/{target_id}/shares", get(list_shares).post(create_share))
        .route("/targets/{target_id}/shares/{share_id}", delete(delete_share))
}

/// `GET /targets/{target_id}/shares` — list share links for a target,
/// newest-first. Surfaces a 404 if the target itself doesn't exist so a
/// stale client link doesn't read as an empty 200.
async fn list_shares(
    State(state): State<AppState>,
    RequireAuth(_identity): RequireAuth,
    Path(target_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // Surface 404 if the target doesn't exist.
    let _ = state.storage.get_target(target_id).await?;
    let shares: Vec<MonitorShare> = state.storage.list_monitor_shares(target_id).await?;
    Ok(Json(shares))
}

/// `POST /targets/{target_id}/shares` — mint a new share link. The storage
/// layer generates the raw capability token (32 random bytes, base64url),
/// hashes it with `sha256_hex`, persists only the hash, and returns the
/// [`CreatedShare`] carrying the one-time plaintext token.
///
/// Returns:
/// - `404 TARGET_NOT_FOUND` if the target doesn't exist.
/// - `201` with [`CreatedShare`] on success.
async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(target_id): Path<Uuid>,
    Json(body): Json<NewMonitorShare>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    // Verify the target exists — a 404 here is more useful than a 201 with
    // a share pointing at a phantom target.
    let _ = state.storage.get_target(target_id).await?;
    let created: CreatedShare = state
        .storage
        .create_monitor_share(target_id, body.label.as_deref(), body.expires_at)
        .await?;
    Ok((StatusCode::CREATED, Json(CreatedShareResponse::from(created))))
}

/// Path params for `DELETE /targets/{target_id}/shares/{share_id}`.
#[derive(Debug, Deserialize)]
struct SharePath {
    #[expect(dead_code)]
    target_id: Uuid,
    share_id: Uuid,
}

/// `DELETE /targets/{target_id}/shares/{share_id}` — revoke a share link.
/// Idempotent: returns `204` whether or not the row existed.
async fn delete_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(path): Path<SharePath>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    state.storage.delete_monitor_share(path.share_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
