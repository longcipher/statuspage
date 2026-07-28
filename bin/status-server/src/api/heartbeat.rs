//! Heartbeat ping endpoint.
//!
//! `POST /api/v1/heartbeat/{target_id}` records a heartbeat ping for the
//! given target. The scheduler's heartbeat probe reads `last_ping_at` and
//! marks the target `Down` when `now - last_ping > period + grace`.
//!
//! # Security model
//!
//! This endpoint is unauthenticated by design — heartbeat pings originate
//! from cron jobs / CI runners that cannot hold a session cookie. The
//! `target_id` (UUIDv4, 122 bits of entropy) is the shared secret:
//! operators treat the ping URL as a capability token. The endpoint is
//! rate-limited per-IP (`[rate_limits.per_ip].heartbeat_per_ip_per_min`)
//! to prevent a single source from exhausting the DuckDB mutex throughput
//! and starving legitimate API traffic. CSRF is not a relevant threat
//! model (no session cookie), so the route is mounted outside the CSRF
//! guard middleware.
//!
//! # Operational note
//!
//! An operator who needs to rotate a compromised ping URL deletes the
//! target and recreates it — the new target gets a fresh UUID. The old
//! URL stops accepting pings immediately (target no longer exists).

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use uuid::Uuid;

use crate::api::error::ApiResult;
use crate::app::AppState;

/// Router for the heartbeat endpoint. Mounted as a separate nest under
/// `/api/v1/heartbeat` (see `router::build_router`) so it can carry its
/// own rate-limit layer without affecting the authenticated management
/// API. The route is `/{target_id}` (relative) — the `/api/v1/heartbeat`
/// prefix is added by the nest.
pub fn routes() -> Router<AppState> {
    Router::new().route("/{target_id}", post(record_heartbeat_ping))
}

/// Record a heartbeat ping for the given target. The target must exist and
/// have a `Heartbeat` check spec; a non-heartbeat target returns 400 so a
/// misconfigured ping URL doesn't silently succeed.
pub(crate) async fn record_heartbeat_ping(
    State(state): State<AppState>,
    Path(target_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // Verify the target exists and is a heartbeat target.
    let target = state.storage.get_target(target_id).await?;
    if !matches!(target.check, statuscore::domain::CheckSpec::Heartbeat(_)) {
        return Err(crate::api::error::ApiError(statuscore::error::AppError::BadRequest {
            code: "NOT_HEARTBEAT_TARGET",
            message: "target check kind is not heartbeat".to_string(),
            field: None,
        }));
    }

    state.storage.record_heartbeat_ping(target_id).await?;
    Ok((StatusCode::OK, "ok"))
}
