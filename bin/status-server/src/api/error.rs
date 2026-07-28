//! HTTP error adapter: wraps [`statuscore::error::AppError`] (which cannot
//! directly `impl IntoResponse` because of the orphan rule) and maps each
//! variant to the appropriate HTTP status + a structured JSON body of the
//! shape `{"error":{"code","message"}}`.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use statuscore::error::AppError;
use tracing::error;

/// Wrapper that lets handlers return `ApiResult<T>` and propagate `AppError`
/// (or `StorageError`) via `?` while still being a valid axum response.
pub struct ApiError(pub AppError);

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}

impl From<storage::StorageError> for ApiError {
    fn from(e: storage::StorageError) -> Self {
        // `StorageError → AppError` is already implemented in `storage::traits`.
        Self(e.into())
    }
}

impl From<(axum::http::StatusCode, String)> for ApiError {
    /// CSRF guard + middleware rejections return `(StatusCode, String)`.
    /// Map to the closest `AppError` variant so the response shape stays
    /// consistent with the rest of the API.
    fn from((status, message): (axum::http::StatusCode, String)) -> Self {
        match status {
            axum::http::StatusCode::UNAUTHORIZED => Self(AppError::Unauthorized),
            axum::http::StatusCode::FORBIDDEN => {
                Self(AppError::forbidden_code("FORBIDDEN", message))
            }
            _ => Self(AppError::internal_with_context(
                "HTTP_MIDDLEWARE",
                format!("{}: {message}", status.as_u16()),
            )),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self.0 {
            AppError::NotFound { code, message } => (StatusCode::NOT_FOUND, *code, message.clone()),
            AppError::Conflict { code, message } => (StatusCode::CONFLICT, *code, message.clone()),
            AppError::BadRequest { code, message, .. } => {
                (StatusCode::BAD_REQUEST, *code, message.clone())
            }
            AppError::PayloadTooLarge { code, message } => {
                (StatusCode::PAYLOAD_TOO_LARGE, *code, message.clone())
            }
            AppError::Unprocessable { code, message } => {
                (StatusCode::UNPROCESSABLE_ENTITY, *code, message.clone())
            }
            AppError::UnprocessableDetails { code, message, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, *code, message.to_string())
            }
            AppError::Gone { code, message } => (StatusCode::GONE, *code, message.clone()),
            AppError::ServiceUnavailable { code, message } => {
                (StatusCode::SERVICE_UNAVAILABLE, *code, message.clone())
            }
            AppError::QuotaExceeded { code, message, .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, *code, message.to_string())
            }
            AppError::RateLimited { scope, retry_after_secs } => {
                let body = json!({
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": format!("rate limited on {scope}"),
                        "details": {
                            "scope": scope,
                            "retry_after_secs": retry_after_secs,
                        },
                    }
                });
                return (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
            }
            AppError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "authentication required".to_owned())
            }
            AppError::SessionRequired => (
                StatusCode::UNAUTHORIZED,
                "SESSION_REQUIRED",
                "browser session required".to_owned(),
            ),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN", "access denied".to_owned()),
            AppError::ForbiddenCoded { code, message } => {
                (StatusCode::FORBIDDEN, *code, message.clone())
            }
            AppError::Internal { code, log } => {
                // The `log` field is private by contract — write it to the
                // error log only, never into the response body.
                error!(code = *code, log = %log, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, *code, "internal error".to_owned())
            }
            AppError::Other(e) => {
                error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "internal error".to_owned())
            }
            // Config / Io / BindAddr all surface as 500 — explicitly listed
            // (no `_` wildcard) so adding a future AppError variant is a
            // compile error here rather than a silent 500 fallthrough.
            // Internal details (config paths, io errors, bind addresses) are
            // logged via `tracing::error!` and never serialised into the
            // response body — they may contain PII / secrets / file paths.
            AppError::Config(e) => {
                error!(error = %e, "config error");
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "internal error".to_owned())
            }
            AppError::Io(e) => {
                error!(error = %e, "io error");
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "internal error".to_owned())
            }
            AppError::BindAddr { addr, source } => {
                error!(error = %source, addr = %addr, "bind address error");
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", "internal error".to_owned())
            }
        };
        let body = json!({ "error": { "code": code, "message": message } });
        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
