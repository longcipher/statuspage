//! Auth HTTP routes: bootstrap, magic-link, sessions, API tokens, prefs.
//!
//! All routes are mounted under `/api/v1/auth`. The bootstrap + magic-link
//! request + magic-link verify endpoints are unauthenticated; everything
//! else requires a session (browser) or API token (CLI). Mutations from
//! browser sessions must carry the `X-Requested-With` header (CSRF guard).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use statuscore::domain::{
    ApiTokenInfo, CreatedApiToken, NewApiToken, SessionInfo, TimeFormat, UserUpdate,
};

use crate::api::{ApiError, ApiResult};
use crate::app::AppState;
use crate::auth::middleware::{AuthIdentity, RequireAuth, RequireSession, csrf_guard};

pub fn routes() -> Router<AppState> {
    Router::new()
        // ── Bootstrap (only available when zero users exist) ──
        .route("/bootstrap", get(bootstrap_status).post(bootstrap_create))
        // ── Magic-link login ──
        .route("/magic-link/request", post(magic_link_request))
        .route("/magic-link/verify", post(magic_link_verify))
        // ── OIDC login ──
        .route("/oidc/login", get(crate::auth::oidc::oidc_login))
        .route("/oidc/callback", get(crate::auth::oidc::oidc_callback))
        // ── Session (browser) ──
        .route("/session", get(get_session).delete(destroy_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id_hash}", delete(revoke_session))
        // ── API tokens ──
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{id}", get(get_token).patch(rename_token).delete(delete_token))
        // ── User profile / prefs ──
        .route("/me", get(get_me).patch(update_me))
}

// ── Bootstrap ─────────────────────────────────────────────────────────────

/// `GET /bootstrap` — whether the bootstrap endpoint is still available.
/// Returns `{ "bootstrap_needed": bool }`. The frontend uses this to decide
/// whether to show the first-user setup screen.
async fn bootstrap_status(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let needed = state.auth.bootstrap_needed().await?;
    Ok(Json(serde_json::json!({ "bootstrap_needed": needed })))
}

#[derive(Debug, Deserialize)]
struct BootstrapBody {
    email: String,
    #[serde(default)]
    display_name: Option<String>,
}

/// `POST /bootstrap` — create the first admin user and open a session for
/// them. Returns 409 once any user exists. The new session cookie is set on
/// the response so the operator is logged in immediately.
async fn bootstrap_create(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(body): Json<BootstrapBody>,
) -> ApiResult<impl IntoResponse> {
    let user = state.auth.create_first_user(&body.email, body.display_name.as_deref()).await?;
    let created = state.auth.create_session_for(user.id).await?;
    let cookie = build_session_cookie(&state, &created.cookie_value);
    Ok((
        StatusCode::CREATED,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "user": public_user_view(&user),
            "session": session_view(&created.row, true),
        })),
    )
        .into_response())
}

// ── Magic link ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MagicLinkRequestBody {
    email: String,
    #[serde(default)]
    redirect_after: Option<String>,
}

/// `POST /magic-link/request` — request a magic-link login email. Always
/// returns 202 (anti-enum): unknown emails get a row but no email.
async fn magic_link_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MagicLinkRequestBody>,
) -> ApiResult<impl IntoResponse> {
    let ip_hint = client_ip(&headers);
    state
        .auth
        .request_magic_link(&body.email, ip_hint.as_deref(), body.redirect_after.as_deref())
        .await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Deserialize)]
struct MagicLinkVerifyBody {
    token: String,
}

/// `POST /magic-link/verify` — consume a magic-link token and open a session.
/// Returns 200 + sets the session cookie on success; 401 on invalid /
/// expired / already-used tokens.
async fn magic_link_verify(
    State(state): State<AppState>,
    Json(body): Json<MagicLinkVerifyBody>,
) -> ApiResult<impl IntoResponse> {
    let created = state.auth.verify_magic_link(&body.token).await?;
    match created {
        Some(created) => {
            let user = state.auth.get_user(created.row.user_id).await?;
            let cookie = build_session_cookie(&state, &created.cookie_value);
            Ok((
                StatusCode::OK,
                [(axum::http::header::SET_COOKIE, cookie)],
                Json(serde_json::json!({
                    "user": public_user_view(&user),
                    "session": session_view(&created.row, true),
                })),
            )
                .into_response())
        }
        None => Err(ApiError(statuscore::error::AppError::bad_request(
            "MAGIC_LINK_INVALID",
            "magic-link token is invalid, expired, or already used",
        ))),
    }
}

// ── Session ───────────────────────────────────────────────────────────────

/// `GET /session` — the current session's user + session info. Requires
/// authentication (session or API token). API tokens get a minimal
/// `{ "user": ... }` response with no session row.
async fn get_session(
    State(_state): State<AppState>,
    RequireAuth(identity): RequireAuth,
) -> ApiResult<impl IntoResponse> {
    let user = identity.require_user()?;
    let is_session = identity.is_session();
    let session_view = match &identity {
        AuthIdentity::Session { .. } => {
            // We don't have the SessionRow here (middleware resolved it);
            // surface a minimal marker so the frontend can distinguish.
            Some(serde_json::json!({ "is_current": true }))
        }
        _ => None,
    };
    let _ = is_session;
    Ok(Json(serde_json::json!({
        "user": public_user_view(user),
        "session": session_view,
    })))
}

/// `DELETE /session` — log out the current browser session. Requires a
/// session (API tokens can't log out a browser). Clears the cookie.
async fn destroy_session(
    State(state): State<AppState>,
    RequireSession(_user, cookie_value): RequireSession,
) -> ApiResult<impl IntoResponse> {
    if let Err(e) = state.auth.destroy_session(&cookie_value).await {
        tracing::warn!(error = %e, "destroy_session failed");
    }
    let cookie = clear_session_cookie(&state);
    Ok((StatusCode::NO_CONTENT, [(axum::http::header::SET_COOKIE, cookie)]))
}

/// `GET /sessions` — list the current user's active sessions. Requires a
/// browser session (API tokens can't enumerate sessions).
async fn list_sessions(
    State(state): State<AppState>,
    RequireSession(user, cookie_value): RequireSession,
) -> ApiResult<impl IntoResponse> {
    let sessions = state.auth.list_sessions(user.id, Some(&cookie_value)).await?;
    let views: Vec<_> = sessions.into_iter().map(session_info_view).collect();
    Ok(Json(views))
}

/// `DELETE /sessions/{id_hash}` — revoke another session by its id_hash.
/// Requires a browser session. The current session cannot revoke itself
/// (use `DELETE /session` to log out).
async fn revoke_session(
    State(state): State<AppState>,
    RequireSession(user, _cookie_value): RequireSession,
    Path(id_hash): Path<String>,
) -> ApiResult<impl IntoResponse> {
    // Verify the session belongs to the current user before deleting.
    let sessions = state.auth.list_sessions(user.id, None).await?;
    if !sessions.iter().any(|s| s.id_hash == id_hash) {
        return Err(ApiError(statuscore::error::AppError::not_found(
            "SESSION_NOT_FOUND",
            "no active session with that id_hash for the current user",
        )));
    }
    state.auth.revoke_session(&id_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── API tokens ────────────────────────────────────────────────────────────

/// `GET /tokens` — list the current user's API tokens (safe info only).
async fn list_tokens(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
) -> ApiResult<impl IntoResponse> {
    let user_id = identity.require_user_id()?;
    let tokens = state.auth.list_api_tokens(user_id).await?;
    Ok(Json(tokens))
}

/// `POST /tokens` — create a new API token. The raw token is returned once
/// (in the response body); it's unrecoverable after that.
async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Json(new): Json<NewApiToken>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let user_id = identity.require_user_id()?;
    let created: CreatedApiToken = state.auth.create_api_token(user_id, new).await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "raw_token": created.raw_token,
            "info": created.info,
        })),
    ))
}

/// `GET /tokens/{id}` — get a single token's safe info.
async fn get_token(
    State(state): State<AppState>,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let user_id = identity.require_user_id()?;
    let tokens = state.auth.list_api_tokens(user_id).await?;
    let token = tokens.into_iter().find(|t| t.id == id).ok_or_else(|| {
        ApiError(statuscore::error::AppError::not_found(
            "TOKEN_NOT_FOUND",
            "no API token with that id for the current user",
        ))
    })?;
    Ok(Json(token))
}

#[derive(Debug, Deserialize)]
struct RenameTokenBody {
    name: String,
}

/// `PATCH /tokens/{id}` — rename an API token. Scopes and expiry are
/// immutable; rotate by delete + create.
async fn rename_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
    Json(body): Json<RenameTokenBody>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let user_id = identity.require_user_id()?;
    let info: ApiTokenInfo = state.auth.rename_api_token(user_id, id, body.name).await?;
    Ok(Json(info))
}

/// `DELETE /tokens/{id}` — delete an API token. Idempotent.
async fn delete_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let user_id = identity.require_user_id()?;
    state.auth.delete_api_token(user_id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── User profile / prefs ──────────────────────────────────────────────────

/// `GET /me` — the current user's profile + preferences.
async fn get_me(
    State(_state): State<AppState>,
    RequireAuth(identity): RequireAuth,
) -> ApiResult<impl IntoResponse> {
    let user = identity.require_user()?;
    Ok(Json(public_user_view(user)))
}

/// `PATCH /me` — update the current user's profile / preferences. Only
/// `display_name`, `theme`, and `time_format` are mutable; email and id
/// are immutable.
async fn update_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAuth(identity): RequireAuth,
    Json(update): Json<UserUpdate>,
) -> ApiResult<impl IntoResponse> {
    csrf_guard(&identity, &headers).map_err(ApiError::from)?;
    let user_id = identity.require_user_id()?;
    let updated = state.auth.update_user(user_id, update).await?;
    Ok(Json(public_user_view(&updated)))
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Build the `Set-Cookie` value for a session cookie.
fn build_session_cookie(state: &AppState, cookie_value: &str) -> String {
    let name = state.auth.session_cookie_name();
    let secure = state.auth.session_cookie_secure();
    let domain = state.auth.session_cookie_domain();
    let mut cookie =
        format!("{name}={cookie_value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=7776000"); // 90 days
    if secure {
        cookie.push_str("; Secure");
    }
    if !domain.is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

/// Build the `Set-Cookie` value that clears the session cookie.
fn clear_session_cookie(state: &AppState) -> String {
    let name = state.auth.session_cookie_name();
    let secure = state.auth.session_cookie_secure();
    let domain = state.auth.session_cookie_domain();
    let mut cookie = format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    if !domain.is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

/// Extract the client IP from `X-Forwarded-For` or `X-Real-IP`. Used only
/// as a hint in magic-link emails; not for security decisions.
fn client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(s) = xff.to_str()
        && let Some(first) = s.split(',').next()
    {
        return Some(first.trim().to_string());
    }
    headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string())
}

/// Public-facing user view (no internal fields). What the frontend gets
/// on login / session / me endpoints.
fn public_user_view(user: &statuscore::domain::User) -> serde_json::Value {
    serde_json::json!({
        "id": user.id.0,
        "email": user.email,
        "display_name": user.display_name,
        "email_verified_at": user.email_verified_at,
        "last_seen_at": user.last_seen_at,
        "theme": user.theme.as_str(),
        "time_format": time_format_str(user.time_format),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    })
}

/// Render a `SessionRow` as the frontend-facing JSON.
fn session_view(row: &statuscore::domain::SessionRow, is_current: bool) -> serde_json::Value {
    serde_json::json!({
        "id_hash": row.id_hash,
        "created_at": row.created_at,
        "last_used_at": row.last_used_at,
        "expires_at": row.expires_at,
        "is_current": is_current,
    })
}

/// Render a `SessionInfo` as the frontend-facing JSON.
fn session_info_view(s: SessionInfo) -> serde_json::Value {
    serde_json::json!({
        "id_hash": s.id_hash,
        "created_at": s.created_at,
        "last_used_at": s.last_used_at,
        "expires_at": s.expires_at,
        "is_current": s.is_current,
    })
}

/// Stringify a `TimeFormat` for the wire.
const fn time_format_str(tf: TimeFormat) -> &'static str {
    tf.as_str()
}
