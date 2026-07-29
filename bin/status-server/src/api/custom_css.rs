//! Custom CSS endpoint for status page theming.
//!
//! `GET /css/custom.css` serves user-defined CSS stored in the config.

use axum::extract::State;
use axum::response::IntoResponse;

use crate::app::AppState;

/// `GET /css/custom.css` — serves custom CSS. Returns empty CSS when none configured.
pub async fn custom_css_handler(State(state): State<AppState>) -> impl IntoResponse {
    let css = state.config.public_status.custom_css.as_deref().unwrap_or("");
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/css; charset=utf-8"), ("cache-control", "public, max-age=3600")],
        css.to_string(),
    )
}
