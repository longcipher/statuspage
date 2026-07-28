//! Status page CRUD + history handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use statuscore::domain::{
    NewStatusPage, OrgId, PublicOrgBranding, StatusPage, StatusPageId, StatusPageUpdate,
    WriteSource,
};
use uuid::Uuid;

use super::ApiResult;
use crate::app::AppState;

pub(super) async fn list_status_pages(
    State(state): State<AppState>,
) -> ApiResult<impl IntoResponse> {
    let pages = state.storage.list_status_pages().await?;
    Ok(Json(pages))
}

pub(super) async fn create_status_page(
    State(state): State<AppState>,
    Json(new_page): Json<NewStatusPage>,
) -> ApiResult<impl IntoResponse> {
    let now = Utc::now();
    let page = StatusPage {
        id: StatusPageId(Uuid::now_v7()),
        org_id: OrgId(Uuid::nil()),
        slug: new_page.slug,
        name: new_page.name,
        enabled: new_page.enabled,
        branding: PublicOrgBranding::default(),
        write_source: WriteSource::default(),
        created_at: now,
        updated_at: now,
    };
    let created = state.storage.create_status_page(&page).await?;
    state.public_cache.invalidate_page(page.id.0).await;
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_status_page(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let page = state.storage.get_status_page(id).await?;
    Ok(Json(page))
}

pub(super) async fn update_status_page(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(update): Json<StatusPageUpdate>,
) -> ApiResult<impl IntoResponse> {
    let mut page = state.storage.get_status_page(id).await?;
    update.apply_to(&mut page);
    page.updated_at = Utc::now();
    let updated = state.storage.update_status_page(&page).await?;
    state.public_cache.invalidate_page(id).await;
    Ok(Json(updated))
}

pub(super) async fn delete_status_page(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_status_page(id).await?;
    state.public_cache.invalidate_page(id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `(timestamp_label, duration_ms)` for the chart.
pub(super) async fn get_status_page_history(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _ = state.storage.get_status_page(id).await?;
    let results = state.storage.list_recent_results(100).await?;
    let mut points: Vec<(String, f64)> =
        results.into_iter().map(|r| (r.timestamp.to_rfc3339(), f64::from(r.duration_ms))).collect();
    points.reverse();
    Ok(Json(points))
}
