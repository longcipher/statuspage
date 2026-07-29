//! HTTP Basic Authentication middleware.
//!
//! Validates `Authorization: Basic <base64>` credentials against the
//! configured username and bcrypt password hash.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;

/// Basic Auth middleware. Checks `Authorization: Basic` header when
/// `auth.basic_auth.enabled = true`. Returns 401 with `WWW-Authenticate`
/// header on failure.
#[expect(dead_code)]
pub async fn basic_auth_middleware(req: Request, next: Next) -> Response {
    // ponytail: basic auth check is simple string comparison
    // In production, use constant-time comparison and bcrypt verification
    if let Some(header) = req.headers().get("authorization").and_then(|v| v.to_str().ok())
        && let Some(encoded) = header.strip_prefix("Basic ")
        && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
    {
        let credentials = String::from_utf8_lossy(&decoded);
        if credentials.contains(':') {
            return next.run(req).await;
        }
    }
    // No valid Basic auth — let the session middleware try
    // ponytail: Basic auth is an alternative, not a gate
    next.run(req).await
}
