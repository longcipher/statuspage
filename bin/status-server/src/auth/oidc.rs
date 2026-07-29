//! OIDC authentication routes.
//!
//! Implements the Authorization Code flow:
//! - `GET /api/v1/auth/oidc/login` — redirect to OIDC provider
//! - `GET /api/v1/auth/oidc/callback` — handle callback, create session

use axum::extract::State;
use axum::response::IntoResponse;

use crate::app::AppState;

/// `GET /api/v1/auth/oidc/login` — redirect to the OIDC provider's
/// authorization endpoint. Returns 501 when OIDC is not configured.
pub async fn oidc_login(State(state): State<AppState>) -> impl IntoResponse {
    let oidc = &state.config.auth.oidc;
    if !oidc.enabled {
        return (
            axum::http::StatusCode::NOT_IMPLEMENTED,
            axum::Json(serde_json::json!({"error": "OIDC not configured"})),
        )
            .into_response();
    }
    // Build authorization URL
    let auth_url = format!(
        "{}/protocol/openid-connect/auth?client_id={}&redirect_uri={}&scope={}&response_type=code&state=random",
        oidc.issuer_url.trim_end_matches('/'),
        url::form_urlencoded::byte_serialize(oidc.client_id.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(oidc.redirect_url.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(oidc.scopes.as_bytes()).collect::<String>(),
    );
    axum::response::Redirect::temporary(&auth_url).into_response()
}

/// `GET /api/v1/auth/oidc/callback` — handle the OIDC callback with
/// the authorization code. Exchanges the code for tokens, creates a session.
pub async fn oidc_callback(State(_state): State<AppState>) -> impl IntoResponse {
    // ponytail: full OIDC token exchange would use reqwest to POST to the
    // token endpoint, validate the ID token, and create a session.
    // This is the skeleton; full implementation needs openidconnect crate.
    (
        axum::http::StatusCode::NOT_IMPLEMENTED,
        axum::Json(serde_json::json!({"error": "OIDC callback not yet implemented"})),
    )
}
