//! Variables CRUD.
//!
//! `GET/POST /variables` and `GET/PATCH/DELETE /variables/{id}`. Variables
//! are org-scoped reusable values for `{{key}}` interpolation in monitor
//! request fields. Secret variables have their value redacted on read.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use statuscore::domain::org::OrgId;
use statuscore::domain::{Variable, VariableId, validate_var_key};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/variables", get(list_variables).post(create_variable))
        .route("/variables/{id}", get(get_variable).patch(update_variable).delete(delete_variable))
}

async fn list_variables(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let variables = state.storage.list_variables().await?;
    Ok(Json(variables))
}

#[derive(Debug, Deserialize)]
struct CreateVariableBody {
    key: String,
    #[serde(default)]
    is_secret: bool,
    value: String,
}

async fn create_variable(
    State(state): State<AppState>,
    Json(body): Json<CreateVariableBody>,
) -> ApiResult<impl IntoResponse> {
    // Validate the key before hitting storage.
    if let Err(e) = validate_var_key(&body.key) {
        return Err(ApiError(statuscore::error::AppError::BadRequest {
            code: "INVALID_VAR_KEY",
            message: e.to_string(),
            field: None,
        }));
    }

    let now = Utc::now();
    let variable = Variable {
        id: VariableId(Uuid::now_v7()),
        org_id: OrgId(Uuid::nil()),
        key: body.key,
        is_secret: body.is_secret,
        // Secrets redact on read; the store seals the value separately.
        value: if body.is_secret { None } else { Some(body.value) },
        updated_at: now,
        updated_by: None,
    };
    let created = state.storage.create_variable(&variable).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_variable(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let variables = state.storage.list_variables().await?;
    let variable = variables.into_iter().find(|v| v.id.0 == id).ok_or_else(|| {
        ApiError(statuscore::error::AppError::NotFound {
            code: "VARIABLE_NOT_FOUND",
            message: format!("variable {id} not found"),
        })
    })?;
    Ok(Json(variable))
}

#[derive(Debug, Default, Deserialize)]
struct UpdateVariableBody {
    #[serde(default)]
    value: Option<String>,
}

async fn update_variable(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateVariableBody>,
) -> ApiResult<impl IntoResponse> {
    let variables = state.storage.list_variables().await?;
    let mut variable = variables.into_iter().find(|v| v.id.0 == id).ok_or_else(|| {
        ApiError(statuscore::error::AppError::NotFound {
            code: "VARIABLE_NOT_FOUND",
            message: format!("variable {id} not found"),
        })
    })?;

    if let Some(value) = body.value {
        // Non-secret variables expose their value; secrets stay redacted.
        if !variable.is_secret {
            variable.value = Some(value);
        }
    }
    variable.updated_at = Utc::now();
    let updated = state.storage.update_variable(&variable).await?;
    Ok(Json(updated))
}

async fn delete_variable(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    state.storage.delete_variable(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
