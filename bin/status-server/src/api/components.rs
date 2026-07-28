//! Status page components CRUD.
//!
//! `GET/POST /status-pages/{id}/components` and
//! `PATCH/DELETE /status-pages/{id}/components/{target_id}`. A component
//! binds a target to a status page with per-page curation overrides
//! (public name, description, group, sort order).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use statuscore::domain::{NewStatusPageComponent, StatusPageComponent, StatusPageComponentUpdate};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status-pages/{id}/components", get(list_components).post(add_component))
        .route(
            "/status-pages/{id}/components/{target_id}",
            patch(update_component).delete(remove_component),
        )
        // Bulk-reorder components on a page. Body: `{ "target_ids": [...] }`
        // in the desired display order. Each id's `sort_order` is rewritten
        // to its index in the list. Ids with no existing binding are
        // skipped silently; the caller should pass the full set of bound
        // component target ids for a clean reorder.
        .route("/status-pages/{id}/components/reorder", post(reorder_components))
}

async fn list_components(
    State(state): State<AppState>,
    Path(page_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // Surface 404 if the page doesn't exist.
    let _ = state.storage.get_status_page(page_id).await?;
    let components = state.storage.list_status_page_components(page_id).await?;
    Ok(Json(components))
}

async fn add_component(
    State(state): State<AppState>,
    Path(page_id): Path<Uuid>,
    Json(new_component): Json<NewStatusPageComponent>,
) -> ApiResult<impl IntoResponse> {
    // Verify the page exists.
    let page = state.storage.get_status_page(page_id).await?;
    // Verify the target exists and derive monitor_name from it.
    let target = state.storage.get_target(new_component.target_id).await?;
    let component = StatusPageComponent {
        target_id: new_component.target_id,
        monitor_name: target.name,
        public_name: new_component.public_name,
        public_description: new_component.public_description,
        public_group: new_component.public_group,
        sort_order: new_component.sort_order,
    };
    state.storage.set_status_page_component(page.id.0, &component).await?;
    state.public_cache.invalidate_all();
    Ok((StatusCode::CREATED, Json(component)))
}

#[derive(Deserialize)]
struct ComponentPath {
    id: Uuid,
    target_id: Uuid,
}

async fn update_component(
    State(state): State<AppState>,
    Path(path): Path<ComponentPath>,
    Json(update): Json<StatusPageComponentUpdate>,
) -> ApiResult<impl IntoResponse> {
    let page_id = path.id;
    let target_id = path.target_id;
    // Load existing component.
    let components = state.storage.list_status_page_components(page_id).await?;
    let mut component =
        components.into_iter().find(|c| c.target_id == target_id).ok_or_else(|| {
            crate::api::error::ApiError(statuscore::error::AppError::NotFound {
                code: "COMPONENT_NOT_FOUND",
                message: format!("component {target_id} not found on page {page_id}"),
            })
        })?;
    if let Some(public_name) = update.public_name {
        component.public_name = public_name;
    }
    if let Some(public_description) = update.public_description {
        component.public_description = public_description;
    }
    if let Some(public_group) = update.public_group {
        component.public_group = public_group;
    }
    if let Some(sort_order) = update.sort_order {
        component.sort_order = sort_order;
    }
    state.storage.set_status_page_component(page_id, &component).await?;
    state.public_cache.invalidate_all();
    Ok(Json(component))
}

async fn remove_component(
    State(state): State<AppState>,
    Path(path): Path<ComponentPath>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_status_page_component(path.id, path.target_id).await?;
    state.public_cache.invalidate_all();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct ReorderBody {
    /// Target ids in the desired display order (ascending). Each id's
    /// `sort_order` is rewritten to its index in this list.
    target_ids: Vec<Uuid>,
}

async fn reorder_components(
    State(state): State<AppState>,
    Path(page_id): Path<Uuid>,
    Json(body): Json<ReorderBody>,
) -> ApiResult<impl IntoResponse> {
    if body.target_ids.is_empty() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "EMPTY_REORDER",
            "reorder requires at least one target id",
        )));
    }
    if body.target_ids.len() > 500 {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "REORDER_TOO_LARGE",
            "reorder accepts at most 500 target ids per request",
        )));
    }
    // Surface 404 if the page doesn't exist before rewriting sort orders.
    let _ = state.storage.get_status_page(page_id).await?;
    state.storage.reorder_status_page_components(page_id, &body.target_ids).await?;
    state.public_cache.invalidate_all();
    // Return the resulting ordered list so the caller can confirm the new
    // ordering without a second round-trip.
    let components = state.storage.list_status_page_components(page_id).await?;
    Ok(Json(components))
}
