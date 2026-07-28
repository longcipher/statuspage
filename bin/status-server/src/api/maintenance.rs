//! Maintenance windows CRUD.
//!
//! `GET/POST /maintenance` and `GET/PATCH/DELETE /maintenance/{id}`. A
//! maintenance window suppresses incident creation for its `component_ids`
//! (target IDs) during `[starts_at, ends_at)`. Results are still recorded
//! so history is complete; only alerting is suppressed.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use statuscore::domain::{
    MaintenanceFilter, MaintenanceWindow, MaintenanceWindowUpdate, NewMaintenanceWindow,
    WriteSource,
};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/maintenance", get(list_maintenance_windows).post(create_maintenance_window))
        .route(
            "/maintenance/{id}",
            get(get_maintenance_window)
                .patch(update_maintenance_window)
                .delete(delete_maintenance_window),
        )
}

#[derive(Debug, Deserialize, Default)]
struct MaintenanceQuery {
    #[serde(default)]
    filter: MaintenanceFilter,
}

async fn list_maintenance_windows(
    State(state): State<AppState>,
    Query(query): Query<MaintenanceQuery>,
) -> ApiResult<impl IntoResponse> {
    let windows = state.storage.list_maintenance_windows(query.filter).await?;
    Ok(Json(windows))
}

async fn create_maintenance_window(
    State(state): State<AppState>,
    Json(new_window): Json<NewMaintenanceWindow>,
) -> ApiResult<impl IntoResponse> {
    if new_window.ends_at <= new_window.starts_at {
        return Err(ApiError(statuscore::error::AppError::BadRequest {
            code: "INVALID_WINDOW",
            message: "ends_at must be after starts_at".to_string(),
            field: None,
        }));
    }
    let now = Utc::now();
    let window = MaintenanceWindow {
        id: Uuid::now_v7(),
        title: new_window.title,
        description: new_window.description,
        starts_at: new_window.starts_at,
        ends_at: new_window.ends_at,
        component_ids: new_window.component_ids,
        created_at: now,
        updated_at: now,
        write_source: WriteSource::default(),
    };
    let created = state.storage.create_maintenance_window(&window).await?;
    state.public_cache.invalidate_all();
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_maintenance_window(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let window = state.storage.get_maintenance_window(id).await?;
    Ok(Json(window))
}

async fn update_maintenance_window(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(update): Json<MaintenanceWindowUpdate>,
) -> ApiResult<impl IntoResponse> {
    let mut window = state.storage.get_maintenance_window(id).await?;
    if let Some(title) = update.title {
        window.title = title;
    }
    if let Some(description) = update.description {
        window.description = Some(description);
    }
    if let Some(starts_at) = update.starts_at {
        window.starts_at = starts_at;
    }
    if let Some(ends_at) = update.ends_at {
        window.ends_at = ends_at;
    }
    if let Some(component_ids) = update.component_ids {
        window.component_ids = component_ids;
    }
    // Re-validate temporal ordering after partial update.
    if window.ends_at <= window.starts_at {
        return Err(ApiError(statuscore::error::AppError::BadRequest {
            code: "INVALID_WINDOW",
            message: "ends_at must be after starts_at".to_string(),
            field: None,
        }));
    }
    window.updated_at = Utc::now();
    let updated = state.storage.update_maintenance_window(&window).await?;
    state.public_cache.invalidate_all();
    Ok(Json(updated))
}

async fn delete_maintenance_window(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_maintenance_window(id).await?;
    state.public_cache.invalidate_all();
    Ok(StatusCode::NO_CONTENT)
}
