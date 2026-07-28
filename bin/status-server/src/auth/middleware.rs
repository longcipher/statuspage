//! Auth middleware: extract user from session cookie or Bearer token.
//!
//! Two extractors:
//! - `AuthIdentity` — optional auth; resolves to `User`, `ApiToken`, or `None`.
//! - `RequireAuth` — required auth; returns 401 if not authenticated.
//! - `RequireSession` — required session-based auth; blocks API tokens from
//!   browser-session-only endpoints (e.g. session management).
//!
//! CSRF: browser mutations (POST/PATCH/DELETE) must carry a custom header
//! (`X-Requested-With`). API tokens (Bearer) are exempt — they're already
//! CSRF-safe (not sent automatically by browsers).

use axum::extract::{FromRef, FromRequestParts, Request, State};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use statuscore::domain::{ApiTokenRow, User, UserId};

use crate::app::AppState;

/// The resolved auth identity for a request.
#[derive(Debug, Clone)]
pub enum AuthIdentity {
    /// Anonymous — no cookie, no Bearer token.
    Anonymous,
    /// Session-cookie auth (browser). Carries the raw cookie value so the
    /// handler can set/clear it on logout.
    Session { user: User, cookie_value: String },
    /// Bearer-token auth (CLI/automation).
    ApiToken {
        // Carried for future auth-z checks; not read by current middleware.
        #[expect(dead_code)]
        token: ApiTokenRow,
        user: User,
    },
}

impl AuthIdentity {
    pub const fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    pub const fn is_session(&self) -> bool {
        matches!(self, Self::Session { .. })
    }

    pub const fn is_api_token(&self) -> bool {
        matches!(self, Self::ApiToken { .. })
    }

    pub const fn user(&self) -> Option<&User> {
        match self {
            Self::Session { user, .. } | Self::ApiToken { user, .. } => Some(user),
            Self::Anonymous => None,
        }
    }

    pub fn user_id(&self) -> Option<UserId> {
        self.user().map(|u| u.id)
    }

    /// The authenticated user, or an `AppError::Internal` (500). Used by
    /// `RequireAuth`-protected handlers where the extractor has already
    /// guaranteed `is_authenticated()` — the `Anonymous` arm is unreachable
    /// but the type system can't see it, so we surface a 500 instead of
    /// panicking.
    pub fn require_user(&self) -> Result<&User, statuscore::error::AppError> {
        self.user().ok_or_else(|| {
            statuscore::error::AppError::internal_with_context(
                "AUTH_INVARIANT",
                "RequireAuth resolved without an authenticated user",
            )
        })
    }

    /// The authenticated user's id. See [`Self::require_user`].
    pub fn require_user_id(&self) -> Result<UserId, statuscore::error::AppError> {
        Ok(self.require_user()?.id)
    }
}

/// Extractor: resolve the auth identity. Does NOT reject unauthenticated
/// requests — use `RequireAuth` for that.
#[expect(dead_code)]
#[derive(Debug, Clone)]
pub struct AuthIdentityExt(pub AuthIdentity);

impl<S> FromRequestParts<S> for AuthIdentityExt
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let auth = &app_state.auth;
        let identity = resolve_identity(&parts.headers, &parts.uri, auth).await;
        Ok(Self(identity))
    }
}

/// Extractor: require authentication. Returns 401 if not authenticated.
#[derive(Debug, Clone)]
pub struct RequireAuth(pub AuthIdentity);

impl<S> FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let auth = &app_state.auth;
        let identity = resolve_identity(&parts.headers, &parts.uri, auth).await;
        if identity.is_authenticated() {
            Ok(Self(identity))
        } else {
            Err((StatusCode::UNAUTHORIZED, "authentication required".to_string()))
        }
    }
}

/// Extractor: require session-based auth (blocks API tokens). Used by
/// endpoints that manage the browser session itself (logout, session list,
/// session revoke) — a Bearer token can't log out a browser session.
#[derive(Debug, Clone)]
pub struct RequireSession(pub User, pub String);

impl<S> FromRequestParts<S> for RequireSession
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let auth = &app_state.auth;
        let identity = resolve_identity(&parts.headers, &parts.uri, auth).await;
        match identity {
            AuthIdentity::Session { user, cookie_value } => Ok(Self(user, cookie_value)),
            AuthIdentity::ApiToken { .. } => Err((
                StatusCode::UNAUTHORIZED,
                "browser session required; API tokens are not accepted here".to_string(),
            )),
            AuthIdentity::Anonymous => {
                Err((StatusCode::UNAUTHORIZED, "authentication required".to_string()))
            }
        }
    }
}

/// Resolve the auth identity from headers. Tries session cookie first,
/// then Bearer token. Returns `Anonymous` if neither is present or valid.
async fn resolve_identity(
    headers: &HeaderMap,
    _uri: &axum::http::Uri,
    auth: &crate::auth::AuthService,
) -> AuthIdentity {
    // Try session cookie first.
    if let Some(cookie_value) = extract_session_cookie(headers, auth.session_cookie_name()) {
        match auth.lookup_session(&cookie_value).await {
            Ok(statuscore::domain::SessionLookupOutcome::Active(row)) => {
                // Load the user.
                match auth.get_user(row.user_id).await {
                    Ok(user) => {
                        // Fire-and-forget touches (debounced inside the service).
                        // Combined into a single spawn to halve the per-request
                        // task overhead on the session path.
                        let auth_clone = auth.clone();
                        let row_clone = row.clone();
                        let user_clone = user.clone();
                        tokio::spawn(async move {
                            if let Err(e) = auth_clone.touch_session(&row_clone).await {
                                tracing::warn!(error = %e, "touch_session failed");
                            }
                            if let Err(e) = auth_clone.touch_user(&user_clone).await {
                                tracing::warn!(error = %e, "touch_user failed");
                            }
                        });
                        return AuthIdentity::Session { user, cookie_value };
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "session cookie valid but user lookup failed");
                    }
                }
            }
            Ok(statuscore::domain::SessionLookupOutcome::Expired) => {
                // Session expired — destroy it so the row doesn't linger.
                let auth_clone = auth.clone();
                let cookie_clone = cookie_value.clone();
                tokio::spawn(async move {
                    if let Err(e) = auth_clone.destroy_session(&cookie_clone).await {
                        tracing::warn!(error = %e, "destroy expired session failed");
                    }
                });
            }
            Ok(statuscore::domain::SessionLookupOutcome::Missing) => {}
            // `SessionLookupOutcome` is #[non_exhaustive]; unknown Ok
            // variants fall through to anonymous (treat as not authed).
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "session lookup failed");
            }
        }
    }

    // Try Bearer token.
    if let Some(raw_token) = extract_bearer_token(headers) {
        match auth.lookup_api_token(&raw_token).await {
            Ok(statuscore::domain::ApiTokenLookupOutcome::Active(row)) => {
                match auth.get_user(row.user_id).await {
                    Ok(user) => {
                        // Fire-and-forget touch (debounced inside the service).
                        let auth_clone = auth.clone();
                        let row_clone = row.clone();
                        tokio::spawn(async move {
                            if let Err(e) = auth_clone.touch_api_token(&row_clone).await {
                                tracing::warn!(error = %e, "touch_api_token failed");
                            }
                        });
                        return AuthIdentity::ApiToken { token: row, user };
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "api token valid but user lookup failed");
                    }
                }
            }
            Ok(statuscore::domain::ApiTokenLookupOutcome::Invalid) => {}
            // `ApiTokenLookupOutcome` is #[non_exhaustive]; unknown Ok
            // variants fall through to anonymous (treat as not authed).
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "api token lookup failed");
            }
        }
    }

    AuthIdentity::Anonymous
}

/// Extract the session cookie value from the `Cookie` header.
fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    // Parse `name=value; name2=value2` — simple split, no full cookie parser.
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == cookie_name
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Extract the Bearer token from the `Authorization` header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = auth_header.strip_prefix("Bearer ")?;
    let trimmed = token.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

/// CSRF check for browser mutations. Returns 403 if the request is a
/// browser mutation (no Bearer token) and lacks the `X-Requested-With`
/// header. API tokens (Bearer) are exempt.
///
/// Call this at the top of any POST/PATCH/DELETE handler that accepts
/// browser auth.
pub fn csrf_guard(
    identity: &AuthIdentity,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, String)> {
    // API tokens are CSRF-safe (not auto-sent by browsers). Anonymous is
    // irrelevant here — the surrounding handler will have already rejected
    // unauthenticated requests via `RequireAuth`.
    if identity.is_api_token() || !identity.is_authenticated() {
        return Ok(());
    }
    // Browser session — require the custom header.
    if headers.contains_key("x-requested-with") {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "CSRF check failed: missing X-Requested-With header".to_string(),
        ))
    }
}

/// Auth enforcement middleware for `/api/v1`. Rejects any request that
/// isn't authenticated (session cookie or Bearer API token) with 401.
///
/// Every path under `/api/v1` requires auth, including GETs: the
/// management API exposes full account configuration (targets, channels,
/// escalation policies, etc.) that must not leak to anonymous callers.
///
/// The heartbeat endpoint (`POST /api/v1/heartbeat/{target_id}`) is
/// intentionally unauthenticated and is mounted as a separate nest
/// outside this middleware — see `router::build_router`.
///
/// Applied as a router-level layer on the `/api/v1` nest in
/// [`crate::router::build_router`]. Defence-in-depth on top of the
/// per-handler `RequireAuth` extractor used by `silence_rules`,
/// `share_links`, and `postmortems`.
pub async fn require_auth_middleware(
    State(app_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let identity = resolve_identity(request.headers(), request.uri(), &app_state.auth).await;
    if identity.is_authenticated() {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "authentication required").into_response()
    }
}

/// CSRF guard middleware: rejects state-changing requests
/// (POST/PATCH/DELETE/PUT) that don't carry either an `X-Requested-With`
/// header (set by the SPA's fetch layer) or an `Authorization` header
/// (Bearer API token — CSRF-safe because browsers don't auto-send it).
///
/// Applied at the router level on `/api/v1` so every management mutation
/// is protected without each handler needing to call [`csrf_guard`]. GET /
/// HEAD / OPTIONS pass through unchecked. This is defence-in-depth on top
/// of the per-handler [`csrf_guard`] — the middleware runs before auth
/// resolution, so it can short-circuit a forged browser POST before any DB
/// read.
pub async fn csrf_guard_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    // Only check state-changing methods.
    if !matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
            | axum::http::Method::PUT
    ) {
        return next.run(request).await;
    }
    // Pass through if the request carries either:
    // 1. `X-Requested-With` — a custom header browsers won't send without JS
    //    (the frontend sets it on every fetch).
    // 2. `Authorization` — a Bearer API token; not subject to CSRF because
    //    browsers don't auto-send it the way they do cookies.
    let headers = request.headers();
    let has_x_requested_with = headers.contains_key("x-requested-with");
    let has_authorization = headers.contains_key("authorization");
    if has_x_requested_with || has_authorization {
        return next.run(request).await;
    }
    // Likely a CSRF attempt — reject.
    tracing::warn!(
        method = %method,
        path = %request.uri().path(),
        "CSRF guard: rejected state-changing request without X-Requested-With or Authorization header"
    );
    (StatusCode::FORBIDDEN, "CSRF check failed").into_response()
}
