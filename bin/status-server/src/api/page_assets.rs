//! Status page asset upload / download / delete.
//!
//! `POST /status-pages/{id}/assets/{slot}` — upload raw bytes (the request
//! body is the file content; the `Content-Type` header supplies the MIME).
//! `GET  /status-pages/{id}/assets/{slot}` — download the raw bytes with the
//! stored `Content-Type` (used by the curation UI's preview, and by the
//! public logo URL when proxied).
//! `DELETE /status-pages/{id}/assets/{slot}` — remove the slot's asset.
//! `GET /status-pages/{id}/assets` — list populated slots with metadata
//! (no `data` blob), so the curation UI can show what's uploaded without
//! pulling every byte.
//!
//! The body is raw bytes (not base64-wrapped JSON) so a browser `fetch`
//! can `body: file` directly — no encoding overhead on a 1 MiB logo upload.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use statuscore::domain::AssetSlot;
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/status-pages/{id}/assets", get(list_assets)).route(
        "/status-pages/{id}/assets/{slot}",
        post(upload_asset).get(get_asset).delete(delete_asset),
    )
}

#[derive(Debug, Deserialize)]
struct AssetPath {
    id: Uuid,
    slot: String,
}

/// Resolve the `{slot}` path segment to an `AssetSlot`, mapping an unknown
/// slug to a 400 (not a 404 — the page exists, the request was malformed).
fn parse_slot(slot: &str) -> ApiResult<AssetSlot> {
    AssetSlot::parse(slot).ok_or_else(|| {
        ApiError(statuscore::error::AppError::bad_request(
            "UNKNOWN_ASSET_SLOT",
            format!("unknown asset slot `{slot}`; supported slots: logo"),
        ))
    })
}

/// Pull the MIME type from the `Content-Type` header. An absent header is a
/// client error (the browser always sends one for file uploads), not a 500.
/// Only the media type is kept (parameters like `; charset=utf-8` are
/// stripped) so the slot-policy check compares against the bare MIME.
fn content_type_from_headers(headers: &HeaderMap) -> ApiResult<String> {
    let raw = headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| {
            ApiError(statuscore::error::AppError::bad_request(
                "MISSING_CONTENT_TYPE",
                "asset upload requires a Content-Type header",
            ))
        })?
        .to_str()
        .map_err(|_| {
            ApiError(statuscore::error::AppError::bad_request(
                "INVALID_CONTENT_TYPE",
                "Content-Type header is not valid UTF-8",
            ))
        })?;
    // Strip parameters (`; charset=...`) — the slot policy matches on the
    // bare media type (e.g. `image/png`), not the full header value.
    let mime = raw.split(';').next().unwrap_or(raw).trim();
    if mime.is_empty() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_CONTENT_TYPE",
            "Content-Type header is empty",
        )));
    }
    Ok(mime.to_string())
}

async fn upload_asset(
    State(state): State<AppState>,
    Path(path): Path<AssetPath>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let slot = parse_slot(&path.slot)?;
    let page = state.storage.get_status_page(path.id).await?;
    let ct = content_type_from_headers(&headers)?;

    // Validate the MIME + size against the slot's policy before the bytes
    // touch the store — reject a 1 MiB PDF uploaded to the logo slot
    // without round-tripping it through DuckDB.
    let policy = slot.policy();
    if !policy.allowed_content_types.contains(&ct.as_str()) {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "UNSUPPORTED_ASSET_MIME",
            format!(
                "slot `{}` does not accept `{ct}`; allowed: {}",
                slot.as_str(),
                policy.allowed_content_types.join(", ")
            ),
        )));
    }
    if body.len() as u64 > policy.max_byte_size {
        return Err(ApiError(statuscore::error::AppError::payload_too_large(
            "ASSET_TOO_LARGE",
            format!(
                "slot `{}` accepts at most {} bytes; got {}",
                slot.as_str(),
                policy.max_byte_size,
                body.len()
            ),
        )));
    }

    let asset = state.storage.upload_page_asset(page.id.0, slot, &ct, &body).await?;
    state.public_cache.invalidate_page(page.id.0).await;
    Ok((StatusCode::CREATED, Json(AssetMeta::from(asset))))
}

async fn get_asset(
    State(state): State<AppState>,
    Path(path): Path<AssetPath>,
) -> ApiResult<impl IntoResponse> {
    let slot = parse_slot(&path.slot)?;
    // Surface 404 if the page itself doesn't exist before looking up the
    // asset — a missing page should not look like a missing asset.
    let _ = state.storage.get_status_page(path.id).await?;
    let asset = state.storage.get_page_asset(path.id, slot).await?.ok_or_else(|| {
        ApiError(statuscore::error::AppError::not_found(
            "ASSET_NOT_FOUND",
            format!("no asset in slot `{}` for page {}", path.slot, path.id),
        ))
    })?;
    // Return raw bytes with the stored Content-Type so the browser can
    // render the logo directly (no base64 decode on the client).
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, asset.content_type.clone())], asset.data))
}

async fn delete_asset(
    State(state): State<AppState>,
    Path(path): Path<AssetPath>,
) -> ApiResult<impl IntoResponse> {
    let slot = parse_slot(&path.slot)?;
    let _ = state.storage.get_status_page(path.id).await?;
    state.storage.delete_page_asset(path.id, slot).await?;
    state.public_cache.invalidate_page(path.id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct AssetMeta {
    slot: String,
    content_type: String,
    hash: String,
    /// Base64-encoded raw bytes. Only included on the single-asset upload
    /// response so the caller can immediately preview without a second
    /// round-trip. The list endpoint omits this.
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<statuscore::domain::PageAsset> for AssetMeta {
    fn from(asset: statuscore::domain::PageAsset) -> Self {
        Self {
            slot: asset.slot.as_str().to_string(),
            content_type: asset.content_type,
            hash: asset.hash,
            data: Some(B64.encode(&asset.data)),
            created_at: asset.created_at,
            updated_at: asset.updated_at,
        }
    }
}

async fn list_assets(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _ = state.storage.get_status_page(id).await?;
    let assets = state.storage.list_page_assets(id).await?;
    // Metadata-only view (no `data` blob) — the curation UI only needs to
    // know which slots are populated, not their bytes.
    let metas: Vec<AssetMeta> =
        assets.into_iter().map(|a| AssetMeta { data: None, ..AssetMeta::from(a) }).collect();
    Ok(Json(metas))
}
