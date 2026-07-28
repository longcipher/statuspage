//! Bulk target operations + idempotency helpers.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use statuscore::domain::{NewTarget, Target, WriteSource};
use uuid::Uuid;

use super::{ApiError, ApiResult};
use crate::app::AppState;

/// Body for `POST /targets/bulk`.
#[derive(Debug, Deserialize)]
struct BulkCreateTargetsBody {
    targets: Vec<NewTarget>,
}

/// One per-item error in a bulk-create response.
#[derive(Debug, Serialize)]
struct BulkCreateError {
    index: usize,
    code: String,
    message: String,
}

/// Response for `POST /targets/bulk`.
#[derive(Debug, Serialize)]
struct BulkCreateResult {
    created: Vec<Target>,
    errors: Vec<BulkCreateError>,
}

/// `POST /targets/bulk` — create multiple targets at once.
pub(super) async fn bulk_create_targets(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    if let Some(cached) = state.idempotency.lookup(&headers, &body).await {
        return Ok(idempotent_response(cached));
    }

    let _in_flight = state.idempotency.acquire_in_flight(&headers, &body).await;

    if let Some(cached) = state.idempotency.lookup(&headers, &body).await {
        return Ok(idempotent_response(cached));
    }

    let parsed: BulkCreateTargetsBody = serde_json::from_slice(&body).map_err(|e| {
        ApiError(statuscore::error::AppError::bad_request(
            "INVALID_JSON",
            format!("failed to parse bulk create body: {e}"),
        ))
    })?;

    let response = bulk_create_targets_impl(&state, parsed).await?;
    let (status, bytes) = response_to_parts(&response);
    state.idempotency.store(&headers, &body, status, "application/json", bytes.clone()).await;
    Ok((status, [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))], bytes))
}

async fn bulk_create_targets_impl(
    state: &AppState,
    body: BulkCreateTargetsBody,
) -> ApiResult<(StatusCode, BulkCreateResult)> {
    if body.targets.is_empty() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "EMPTY_BATCH",
            "bulk create requires at least one target spec",
        )));
    }
    if body.targets.len() > 200 {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "BATCH_TOO_LARGE",
            "bulk create accepts at most 200 targets per request",
        )));
    }

    let mut created: Vec<Target> = Vec::with_capacity(body.targets.len());
    let mut errors: Vec<BulkCreateError> = Vec::new();

    for (i, spec) in body.targets.into_iter().enumerate() {
        let now = Utc::now();
        let target = Target {
            id: Uuid::now_v7(),
            name: spec.name,
            check: spec.check,
            interval: spec.interval,
            enabled: spec.enabled,
            tags: spec.tags,
            alerts: spec.alerts,
            alert_confirmations: spec.alert_confirmations,
            notify_recovery: spec.notify_recovery,
            renotify_interval_secs: spec.renotify_interval_secs,
            region_policy: spec.region_policy.unwrap_or_default(),
            group_name: spec.group_name,
            owner_user_id: spec.owner_user_id,
            escalation_policy_id: spec.escalation_policy_id,
            created_at: now,
            updated_at: now,
            write_source: WriteSource::default(),
        };
        match state.storage.create_target(&target).await {
            Ok(t) => created.push(t),
            Err(statuscore::error::AppError::Conflict { code, message }) => {
                errors.push(BulkCreateError { index: i, code: code.to_string(), message });
            }
            Err(statuscore::error::AppError::BadRequest { code, message, .. }) => {
                errors.push(BulkCreateError { index: i, code: code.to_string(), message });
            }
            Err(statuscore::error::AppError::Unprocessable { code, message }) => {
                errors.push(BulkCreateError { index: i, code: code.to_string(), message });
            }
            Err(e) => {
                errors.push(BulkCreateError {
                    index: i,
                    code: "STORAGE_ERROR".to_string(),
                    message: e.to_string(),
                });
            }
        }
    }

    if !created.is_empty() {
        state.public_cache.invalidate_all();
    }
    Ok((StatusCode::OK, BulkCreateResult { created, errors }))
}

/// Action kind for `POST /targets/bulk/action`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BulkActionKind {
    Enable,
    Disable,
    Delete,
}

/// Body for `POST /targets/bulk/action`.
#[derive(Debug, Deserialize)]
struct BulkActionBody {
    ids: Vec<Uuid>,
    action: BulkActionKind,
}

/// One per-id result in a bulk-action response.
#[derive(Debug, Serialize)]
struct BulkActionResult {
    id: Uuid,
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
}

/// `POST /targets/bulk/action` — apply an action to a set of targets.
pub(super) async fn bulk_action_targets(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    if let Some(cached) = state.idempotency.lookup(&headers, &body).await {
        return Ok(idempotent_response(cached));
    }

    let _in_flight = state.idempotency.acquire_in_flight(&headers, &body).await;

    if let Some(cached) = state.idempotency.lookup(&headers, &body).await {
        return Ok(idempotent_response(cached));
    }

    let parsed: BulkActionBody = serde_json::from_slice(&body).map_err(|e| {
        ApiError(statuscore::error::AppError::bad_request(
            "INVALID_JSON",
            format!("failed to parse bulk action body: {e}"),
        ))
    })?;

    let response = bulk_action_targets_impl(&state, parsed).await?;
    let (status, bytes) = response_to_parts(&response);
    state.idempotency.store(&headers, &body, status, "application/json", bytes.clone()).await;
    Ok((status, [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))], bytes))
}

async fn bulk_action_targets_impl(
    state: &AppState,
    body: BulkActionBody,
) -> ApiResult<(StatusCode, Vec<BulkActionResult>)> {
    if body.ids.is_empty() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "EMPTY_BATCH",
            "bulk action requires at least one target id",
        )));
    }
    if body.ids.len() > 500 {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "BATCH_TOO_LARGE",
            "bulk action accepts at most 500 target ids per request",
        )));
    }

    let mut seen = std::collections::HashSet::new();
    let ids: Vec<Uuid> = body.ids.into_iter().filter(|id| seen.insert(*id)).collect();

    let mut results: Vec<BulkActionResult> = Vec::with_capacity(ids.len());
    let mut any_mutation = false;

    for id in &ids {
        let (status, message) = match body.action {
            BulkActionKind::Enable | BulkActionKind::Disable => {
                let enable = matches!(body.action, BulkActionKind::Enable);
                match state.storage.get_target(*id).await {
                    Ok(mut t) => {
                        if t.enabled == enable {
                            ("ok".to_string(), String::new())
                        } else {
                            t.enabled = enable;
                            t.updated_at = Utc::now();
                            match state.storage.update_target(&t).await {
                                Ok(_) => {
                                    any_mutation = true;
                                    ("ok".to_string(), String::new())
                                }
                                Err(e) => ("storage_error".to_string(), e.to_string()),
                            }
                        }
                    }
                    Err(statuscore::error::AppError::NotFound { .. }) => {
                        ("not_found".to_string(), "target not found".to_string())
                    }
                    Err(e) => ("storage_error".to_string(), e.to_string()),
                }
            }
            BulkActionKind::Delete => match state.storage.delete_target(*id).await {
                Ok(()) => {
                    any_mutation = true;
                    ("ok".to_string(), String::new())
                }
                Err(statuscore::error::AppError::NotFound { .. }) => {
                    ("not_found".to_string(), "target not found".to_string())
                }
                Err(e) => ("storage_error".to_string(), e.to_string()),
            },
        };
        results.push(BulkActionResult { id: *id, status, message });
    }

    if any_mutation {
        state.public_cache.invalidate_all();
    }
    Ok((StatusCode::OK, results))
}

// ── Idempotency helpers ───────────────────────────────────────────────────

pub(super) fn idempotent_response(
    cached: crate::idempotency::CachedResponse,
) -> (StatusCode, [(header::HeaderName, HeaderValue); 1], Bytes) {
    let ct = HeaderValue::from_str(&cached.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/json"));
    (cached.status, [(header::CONTENT_TYPE, ct)], (*cached.body).clone())
}

pub(super) fn response_to_parts<T: Serialize>(response: &(StatusCode, T)) -> (StatusCode, Bytes) {
    let (status, body) = response;
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"null".to_vec());
    (*status, Bytes::from(bytes))
}
