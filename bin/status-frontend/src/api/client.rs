//! HTTP client for talking to the axum JSON API from the browser.
//!
//! # WASM constraints
//!
//! `reqwest` / hyper do not compile to `wasm32`. In the browser the only
//! transport is the Fetch API exposed by `web-sys`. The real fetch is gated
//! behind `#[cfg(target_arch = "wasm32")]`; on other targets the same
//! functions exist but return an error, so the crate still type-checks under
//! native `cargo check` (the WASM build is the only target that actually
//! calls them).

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

#[expect(unused_imports)]
use crate::api::types::{
    ApiErrorResponse, AuthSession, AuthUser, BootstrapStatus, Incident, LatencyPoint,
    NewIncidentUpdateBody, NewStatusPage, NewTarget, PublicStatusPage, StatusPage,
    StatusPageUpdate, Target, TargetUpdate,
};

// Re-export so callers can refer to the result type without pulling in the
// `statuscore` crate directly.
pub use statuscore::domain::CheckResult;

/// Base URL for the authenticated JSON API. Same-origin: the backend serves
/// both the WASM bundle (under `/pkg`, `/style`, `/`) and the JSON API
/// (under `/api/v1`), so no cross-origin fetch is needed in production. In
/// dev, `trunk serve` proxies `/api` to the backend (see
/// `bin/status-frontend/Trunk.toml`).
const API_BASE: &str = "/api/v1";

/// Base URL for the public (unauthenticated) JSON API. Same-origin. The
/// public status page frontend uses this so visitors don't need a session.
const PUBLIC_API_BASE: &str = "/api/public/v1";

// ── Public API wrappers ────────────────────────────────────────────────────
//
// One thin wrapper per REST endpoint. Each delegates to `fetch_json` /
// `fetch_json_with_body` / `fetch_no_body` so the WASM-vs-native plumbing
// lives in exactly one place.

// Public (unauthenticated) status page --------------------------------------

/// `GET /api/public/v1/status` — overall status page snapshot for the
/// first enabled page (or the one identified by `?page={id}`). Unauthenticated;
/// used by the public-facing status page route so visitors don't need a
/// session.
pub async fn get_public_status() -> Result<PublicStatusPage, String> {
    fetch_json(&format!("{PUBLIC_API_BASE}/status")).await
}

// Status pages --------------------------------------------------------------

/// `GET /api/v1/status-pages` — list every status page.
pub async fn list_status_pages() -> Result<Vec<StatusPage>, String> {
    fetch_json(&format!("{API_BASE}/status-pages")).await
}

/// `GET /api/v1/status-pages/:id` — single page.
pub async fn get_status_page(id: Uuid) -> Result<StatusPage, String> {
    fetch_json(&format!("{API_BASE}/status-pages/{id}")).await
}

/// `GET /api/v1/status-pages/:id/history` — `Vec<(ISO-8601 ts, duration_ms)>`
/// sorted ascending by timestamp.
pub async fn get_status_page_history(id: Uuid) -> Result<Vec<LatencyPoint>, String> {
    fetch_json(&format!("{API_BASE}/status-pages/{id}/history")).await
}

/// `POST /api/v1/status-pages` — create a page.
#[expect(dead_code)]
pub async fn create_status_page(body: &NewStatusPage) -> Result<StatusPage, String> {
    fetch_json_with_body("POST", &format!("{API_BASE}/status-pages"), body).await
}

/// `PATCH /api/v1/status-pages/:id` — partial update.
#[expect(dead_code)]
pub async fn update_status_page(id: Uuid, body: &StatusPageUpdate) -> Result<StatusPage, String> {
    fetch_json_with_body("PATCH", &format!("{API_BASE}/status-pages/{id}"), body).await
}

/// `DELETE /api/v1/status-pages/:id` — remove a page.
#[expect(dead_code)]
pub async fn delete_status_page(id: Uuid) -> Result<(), String> {
    fetch_no_body("DELETE", &format!("{API_BASE}/status-pages/{id}")).await
}

// Targets --------------------------------------------------------------------

/// `GET /api/v1/targets` — list every configured monitor target.
pub async fn list_targets() -> Result<Vec<Target>, String> {
    fetch_json(&format!("{API_BASE}/targets")).await
}

/// `GET /api/v1/targets/:id` — single target.
pub async fn get_target(id: Uuid) -> Result<Target, String> {
    fetch_json(&format!("{API_BASE}/targets/{id}")).await
}

/// `POST /api/v1/targets` — create a monitor target.
#[expect(dead_code)]
pub async fn create_target(body: &NewTarget) -> Result<Target, String> {
    fetch_json_with_body("POST", &format!("{API_BASE}/targets"), body).await
}

/// `PATCH /api/v1/targets/:id` — partial update.
#[expect(dead_code)]
pub async fn update_target(id: Uuid, body: &TargetUpdate) -> Result<Target, String> {
    fetch_json_with_body("PATCH", &format!("{API_BASE}/targets/{id}"), body).await
}

/// `DELETE /api/v1/targets/:id` — remove a target.
#[expect(dead_code)]
pub async fn delete_target(id: Uuid) -> Result<(), String> {
    fetch_no_body("DELETE", &format!("{API_BASE}/targets/{id}")).await
}

/// `GET /api/v1/targets/:id/results?limit=N` — recent check results,
/// newest-first. The backend defaults to 100 and caps at 1000.
pub async fn list_target_results(id: Uuid, limit: u32) -> Result<Vec<CheckResult>, String> {
    fetch_json(&format!("{API_BASE}/targets/{id}/results?limit={limit}")).await
}

// Incidents ------------------------------------------------------------------

/// `GET /api/v1/incidents` — list incidents across all monitors.
pub async fn list_incidents() -> Result<Vec<Incident>, String> {
    fetch_json(&format!("{API_BASE}/incidents")).await
}

/// `GET /api/v1/incidents/:id` — single incident.
#[expect(dead_code)]
pub async fn get_incident(id: Uuid) -> Result<Incident, String> {
    fetch_json(&format!("{API_BASE}/incidents/{id}")).await
}

/// `POST /api/v1/incidents/:id/updates` — append a public timeline update.
#[expect(dead_code)]
pub async fn add_incident_update(
    id: Uuid,
    body: &NewIncidentUpdateBody,
) -> Result<Incident, String> {
    fetch_json_with_body("POST", &format!("{API_BASE}/incidents/{id}/updates"), body).await
}

// Auth -----------------------------------------------------------------------

/// Base URL for auth endpoints. These live under `/api/v1/auth/*` and are
/// mounted as a sibling to the management API so they can be rate-limited
/// as a group. The auth endpoints are NOT behind the `require_auth`
/// middleware (bootstrap + magic-link request + magic-link verify must be
/// reachable by unauthenticated callers); the session/token management
/// endpoints use the `RequireAuth` / `RequireSession` extractors instead.
const AUTH_BASE: &str = "/api/v1/auth";

/// `GET /api/v1/auth/bootstrap` — whether the first-user setup is still
/// available. The frontend uses this to decide whether to show the
/// bootstrap form or the regular magic-link login.
pub async fn bootstrap_status() -> Result<BootstrapStatus, String> {
    fetch_json(&format!("{AUTH_BASE}/bootstrap")).await
}

/// `POST /api/v1/auth/bootstrap` — create the first admin user and open a
/// session. Returns 409 once any user exists. The response sets the
/// session cookie via `Set-Cookie` (HttpOnly, SameSite=Lax), which the
/// browser stores automatically — no client-side cookie handling needed.
pub async fn bootstrap_create(
    email: &str,
    display_name: Option<&str>,
) -> Result<AuthSession, String> {
    let body = serde_json::json!({
        "email": email,
        "display_name": display_name,
    });
    fetch_json_with_body("POST", &format!("{AUTH_BASE}/bootstrap"), &body).await
}

/// `POST /api/v1/auth/magic-link/request` — request a magic-link login
/// email. Always returns 202 (anti-enum: unknown emails get a row but no
/// email). The frontend should show a generic "check your email" message
/// regardless of whether the email exists.
pub async fn magic_link_request(email: &str) -> Result<(), String> {
    let body = serde_json::json!({ "email": email });
    // 202 Accepted has no body — use the unit wrapper that discards the
    // response instead of trying to parse it as JSON.
    fetch_unit_with_body("POST", &format!("{AUTH_BASE}/magic-link/request"), &body).await
}

/// `POST /api/v1/auth/magic-link/verify` — consume a magic-link token and
/// open a session. Returns 200 + sets the session cookie on success; 401
/// on invalid / expired / already-used tokens.
pub async fn magic_link_verify(token: &str) -> Result<AuthSession, String> {
    let body = serde_json::json!({ "token": token });
    fetch_json_with_body("POST", &format!("{AUTH_BASE}/magic-link/verify"), &body).await
}

/// `GET /api/v1/auth/session` — the current session's user. Returns 401 if
/// not authenticated. Used by the auth guard to decide whether to render
/// the app or redirect to the login page.
pub async fn get_session() -> Result<AuthUser, String> {
    // The response shape is `{ "user": {...}, "session": {...} }`; we only
    // need the user field for the auth guard, so deserialize into the
    // wrapper and extract.
    let session: AuthSession = fetch_json(&format!("{AUTH_BASE}/session")).await?;
    Ok(session.user)
}

/// `DELETE /api/v1/auth/session` — log out the current browser session.
/// Clears the session cookie. Returns 204 on success.
pub async fn logout() -> Result<(), String> {
    fetch_no_body("DELETE", &format!("{AUTH_BASE}/session")).await
}

// ── Error formatting ───────────────────────────────────────────────────────

/// Read an error response body and try to extract a structured `[CODE] message`
/// from the backend's JSON error format. Falls back to `"HTTP {status}: {body}"`.
#[cfg(target_arch = "wasm32")]
async fn format_error_response(resp: web_sys::Response) -> String {
    let status = resp.status();
    let body_text = read_response_text(resp).await.unwrap_or_default();
    if let Ok(err_resp) = serde_json::from_str::<ApiErrorResponse>(&body_text) {
        return err_resp.error.to_string();
    }
    if body_text.is_empty() {
        return format!("HTTP {status}");
    }
    format!("HTTP {status}: {body_text}")
}

// ── Real fetch (wasm32) ────────────────────────────────────────────────────
//
// Pipeline: fetch_with_timeout → fetch_with_retry → fetch_{json,no_body,...}.
// `fetch_with_timeout` wraps every request in an `AbortController` with a
// 30 s deadline so a hung backend cannot stall the UI forever.
// `fetch_with_retry` retries on 5xx and network errors with exponential
// backoff (500 ms, 1000 ms) before giving up.

/// Hard deadline for a single fetch attempt (milliseconds).
#[cfg(target_arch = "wasm32")]
const REQUEST_TIMEOUT_MS: i32 = 30_000;
/// Extra attempts after the first one (total attempts = MAX_RETRIES + 1).
#[cfg(target_arch = "wasm32")]
const MAX_RETRIES: u32 = 2;

#[cfg(target_arch = "wasm32")]
async fn fetch_with_timeout(
    url: &str,
    method: &str,
    body: Option<&str>,
    content_type: Option<&str>,
) -> Result<web_sys::Response, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let window = web_sys::window().ok_or_else(|| "Browser window is unavailable".to_string())?;

    let init = web_sys::RequestInit::new();
    init.set_method(method);
    init.set_mode(web_sys::RequestMode::SameOrigin);
    if let Some(b) = body {
        init.set_body(&wasm_bindgen::JsValue::from_str(b));
    }

    // AbortController enforces a hard 30 s deadline on the fetch.
    let abort_controller = web_sys::AbortController::new()
        .map_err(|e| format!("Failed to create AbortController: {e:?}"))?;
    let signal = abort_controller.signal();
    init.set_signal(Some(&signal));

    let request = web_sys::Request::new_with_str_and_init(url, &init)
        .map_err(|e| format!("Failed to build request: {e:?}"))?;

    if let Some(ct) = content_type {
        request
            .headers()
            .set("Content-Type", ct)
            .map_err(|e| format!("Failed to set request headers: {e:?}"))?;
    }

    // `X-Requested-With` is required by the server's CSRF guard on all
    // state-changing requests (POST/PATCH/DELETE) from browser sessions.
    // Setting it on every request (including GETs) is harmless and keeps
    // the wrapper simple — the header is a custom marker that browsers
    // won't send without JS, which is exactly what the CSRF guard checks.
    request
        .headers()
        .set("X-Requested-With", "XMLHttpRequest")
        .map_err(|e| format!("Failed to set X-Requested-With header: {e:?}"))?;

    // Schedule the abort.  The closure is leaked so it survives until the
    // timeout fires or is cleared below — a tiny one-time allocation that is
    // acceptable for a client-side fetch wrapper.
    let abort_for_timeout = abort_controller.clone();
    let timeout_closure = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
        abort_for_timeout.abort();
    }) as Box<dyn Fn()>);
    let timeout_handle = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            timeout_closure.as_ref().unchecked_ref::<js_sys::Function>(),
            REQUEST_TIMEOUT_MS,
        )
        .map_err(|e| format!("Failed to set timeout: {e:?}"))?;
    std::mem::forget(timeout_closure);

    let result = JsFuture::from(window.fetch_with_request(&request)).await;
    window.clear_timeout_with_handle(timeout_handle);

    let resp_value = result.map_err(|_| "Network error — check your connection".to_string())?;
    let resp: web_sys::Response =
        resp_value.dyn_into().map_err(|_| "Unexpected response from server".to_string())?;
    Ok(resp)
}

/// Resolve after `ms` milliseconds.  Used by the retry backoff.
#[cfg(target_arch = "wasm32")]
async fn delay_ms(ms: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            let _ =
                window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Wraps `fetch_with_timeout` with a simple retry policy: up to `MAX_RETRIES`
/// extra attempts on 5xx responses or network errors, with exponential
/// backoff (500 ms, 1000 ms).
#[cfg(target_arch = "wasm32")]
async fn fetch_with_retry(
    url: &str,
    method: &str,
    body: Option<&str>,
    content_type: Option<&str>,
) -> Result<web_sys::Response, String> {
    let mut last_err = String::new();
    for attempt in 0..=MAX_RETRIES {
        match fetch_with_timeout(url, method, body, content_type).await {
            Ok(resp) => {
                let status = resp.status();
                if status >= 500 && attempt < MAX_RETRIES {
                    let delay = 500u32 * (1u32 << attempt);
                    delay_ms(delay).await;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                last_err = e;
                if attempt < MAX_RETRIES {
                    let delay = 500u32 * (1u32 << attempt);
                    delay_ms(delay).await;
                    continue;
                }
            }
        }
    }
    Err(last_err)
}

#[cfg(target_arch = "wasm32")]
async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    let resp = fetch_with_retry(url, "GET", None, None).await?;
    if !resp.ok() {
        return Err(format_error_response(resp).await);
    }
    let text = read_response_text(resp).await?;
    serde_json::from_str(&text).map_err(|e| format!("Invalid response data: {e}"))
}

#[cfg(target_arch = "wasm32")]
#[expect(clippy::future_not_send)]
async fn fetch_json_with_body<T: DeserializeOwned, B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
) -> Result<T, String> {
    let body_str =
        serde_json::to_string(body).map_err(|e| format!("Failed to prepare request: {e}"))?;
    let resp =
        fetch_with_retry(url, method, Some(body_str.as_str()), Some("application/json")).await?;
    if !resp.ok() {
        return Err(format_error_response(resp).await);
    }
    let text = read_response_text(resp).await?;
    serde_json::from_str(&text).map_err(|e| format!("Invalid response data: {e}"))
}

/// Send a JSON body and discard the response body. Used for endpoints that
/// return 2xx with no body (e.g. 202 Accepted from magic-link request).
#[cfg(target_arch = "wasm32")]
#[expect(clippy::future_not_send)]
async fn fetch_unit_with_body<B: Serialize>(
    method: &str,
    url: &str,
    body: &B,
) -> Result<(), String> {
    let body_str =
        serde_json::to_string(body).map_err(|e| format!("Failed to prepare request: {e}"))?;
    let resp =
        fetch_with_retry(url, method, Some(body_str.as_str()), Some("application/json")).await?;
    if !resp.ok() {
        return Err(format_error_response(resp).await);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn fetch_no_body(method: &str, url: &str) -> Result<(), String> {
    let resp = fetch_with_retry(url, method, None, None).await?;
    if !resp.ok() {
        return Err(format_error_response(resp).await);
    }
    _ = resp;
    Ok(())
}

/// Extract the response body as a UTF-8 string.
#[cfg(target_arch = "wasm32")]
async fn read_response_text(resp: web_sys::Response) -> Result<String, String> {
    use wasm_bindgen_futures::JsFuture;

    let text_promise = resp.text().map_err(|_| "Failed to read response body".to_string())?;
    let text_js = JsFuture::from(text_promise)
        .await
        .map_err(|_| "Failed to read response body".to_string())?;
    text_js.as_string().ok_or_else(|| "Response is not valid text".to_string())
}

// ── Native stub ────────────────────────────────────────────────────────────
//
// On non-wasm32 targets there is no Fetch API. Returning an `Err` keeps the
// crate compiling under `cargo check -p status-frontend` so type errors in
// the surrounding leptos code surface without requiring a wasm toolchain.

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_json<T: DeserializeOwned>(_url: &str) -> Result<T, String> {
    Err("status-frontend HTTP client only runs in the browser (wasm32)".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
#[expect(clippy::future_not_send)]
async fn fetch_json_with_body<T: DeserializeOwned, B: Serialize>(
    _method: &str,
    _url: &str,
    _body: &B,
) -> Result<T, String> {
    Err("status-frontend HTTP client only runs in the browser (wasm32)".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_no_body(_method: &str, _url: &str) -> Result<(), String> {
    Err("status-frontend HTTP client only runs in the browser (wasm32)".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
#[expect(clippy::future_not_send)]
async fn fetch_unit_with_body<B: Serialize>(
    _method: &str,
    _url: &str,
    _body: &B,
) -> Result<(), String> {
    Err("status-frontend HTTP client only runs in the browser (wasm32)".to_string())
}
