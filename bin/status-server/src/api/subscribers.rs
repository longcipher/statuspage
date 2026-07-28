//! Subscribers CRUD + double opt-in.
//!
//! `GET/POST /status-pages/{id}/subscribers`,
//! `DELETE /status-pages/{id}/subscribers/{subscriber_id}`,
//! `POST /status-pages/{id}/subscribers/{subscriber_id}/verify`.
//!
//! Subscribers are public status-page opt-ins for incident/maintenance
//! notifications. Every subscription starts unverified; the verify endpoint
//! flips `verified_at` to `now` (double opt-in).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use statuscore::domain::{Subscriber, SubscriberChannel};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status-pages/{id}/subscribers", get(list_subscribers).post(create_subscriber))
        .route(
            "/status-pages/{id}/subscribers/{subscriber_id}",
            axum::routing::delete(delete_subscriber),
        )
        .route("/status-pages/{id}/subscribers/{subscriber_id}/verify", post(verify_subscriber))
}

async fn list_subscribers(
    State(state): State<AppState>,
    Path(page_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _ = state.storage.get_status_page(page_id).await?;
    let subscribers = state.storage.list_subscribers(page_id).await?;
    Ok(Json(subscribers))
}

#[derive(Debug, Deserialize)]
struct NewSubscriberBody {
    channel: SubscriberChannel,
    target: String,
    #[serde(default)]
    config: Value,
}

async fn create_subscriber(
    State(state): State<AppState>,
    Path(page_id): Path<Uuid>,
    Json(body): Json<NewSubscriberBody>,
) -> ApiResult<impl IntoResponse> {
    let page = state.storage.get_status_page(page_id).await?;
    let now = Utc::now();
    let subscriber = Subscriber {
        id: Uuid::now_v7(),
        status_page_id: page.id.0,
        org_id: page.org_id,
        channel: body.channel,
        target: body.target,
        config: body.config,
        verified_at: None,
        created_at: now,
        updated_at: now,
    };
    let created = state.storage.create_subscriber(&subscriber).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize)]
struct SubscriberPath {
    id: Uuid,
    subscriber_id: Uuid,
}

async fn delete_subscriber(
    State(state): State<AppState>,
    Path(path): Path<SubscriberPath>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_subscriber(path.subscriber_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Double opt-in: flip `verified_at` to `now`. Idempotent — verifying an
/// already-verified subscriber is a no-op (returns 200, not 409).
async fn verify_subscriber(
    State(state): State<AppState>,
    Path(path): Path<SubscriberPath>,
) -> ApiResult<impl IntoResponse> {
    // Load the subscriber list for the page and find the one to verify.
    let subscribers = state.storage.list_subscribers(path.id).await?;
    let sub = subscribers.into_iter().find(|s| s.id == path.subscriber_id).ok_or_else(|| {
        ApiError(statuscore::error::AppError::NotFound {
            code: "SUBSCRIBER_NOT_FOUND",
            message: format!("subscriber {} not found on page {}", path.subscriber_id, path.id),
        })
    })?;

    if sub.is_verified() {
        return Ok((StatusCode::OK, Json(sub)));
    }

    let verified = state.storage.verify_subscriber(path.subscriber_id).await?;
    Ok((StatusCode::OK, Json(verified)))
}
