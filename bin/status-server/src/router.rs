//! HTTP router assembly.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use statuscore::config::CorsConfig;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::app::AppState;
use crate::assets::spa_fallback;

/// Maximum request body size for JSON API endpoints (8 MiB). Large enough
/// for bulk target operations and incident updates, small enough to prevent
/// memory exhaustion from malicious oversized payloads.
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

pub fn build_router(state: AppState) -> Router {
    let cors_layer =
        state.config.api.cors.enabled.then(|| build_cors_layer(&state.config.api.cors));

    // Serve the frontend bundle from `target/site/` (pkg/*.js, pkg/*.wasm,
    // style/main.css, index.html) produced by `just fe-build`. Unknown paths
    // fall back to the SPA index so client-side routing works.
    //
    // `fallback` (not `not_found_service`) is intentional: `not_found_service`
    // wraps the fallback with `SetStatus(NOT_FOUND)`, overriding whatever
    // status the fallback sets. Using `fallback` lets `spa_fallback` return
    // 200 OK so search engines, link previews, and the SPA itself treat
    // client-side routes (`/p`, `/status-pages`, `/targets`, ...) as real
    // pages rather than broken links.
    let serve_dir = ServeDir::new("target/site").fallback(tower::service_fn(spa_fallback));

    // Management API (targets, channels, incidents, auth, etc.).
    // Disabled when api.management_api_enabled = false — all /api/v1/*
    // routes return 404. Public routes and heartbeat remain accessible.
    let management_routes = if state.config.api.management_api_enabled {
        crate::api::routes()
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::middleware::require_auth_middleware,
            ))
            .layer(axum::middleware::from_fn(crate::auth::middleware::csrf_guard_middleware))
    } else {
        Router::new()
            .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "management API disabled") })
    };

    let mut router = Router::new()
        // Liveness: always returns 200 "ok" as long as the process is up.
        .route("/healthz", get(|| async { "ok" }))
        // Readiness: pings the storage backend; 200 "ready" on success, 503
        // "not ready" with the underlying error on failure. Load balancers
        // should only route traffic when this returns 200.
        .route("/readyz", get(readyz))
        // Prometheus metrics — public, no auth.
        .route("/metrics", get(crate::api::metrics_endpoint::metrics_handler))
        // Custom CSS — public, no auth.
        .route("/css/custom.css", get(crate::api::custom_css::custom_css_handler))
        // SVG badges — public, no auth.
        .route("/api/v1/endpoints/{id}/health/badge.svg", get(crate::api::badges::health_badge))
        .route(
            "/api/v1/endpoints/{id}/health/badge.shields",
            get(crate::api::badges::health_badge_shields),
        )
        .route(
            "/api/v1/endpoints/{id}/uptimes/{duration}/badge.svg",
            get(crate::api::badges::uptime_badge),
        )
        .route(
            "/api/v1/endpoints/{id}/response-times/{duration}/badge.svg",
            get(crate::api::badges::response_time_badge),
        )
        .nest(
            "/api/v1",
            management_routes.layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES)),
        )
        // Heartbeat endpoint — mounted as a separate nest so it can carry
        // its own per-IP rate-limit layer without the auth/CSRF middleware
        // that wraps the rest of `/api/v1`. Heartbeat pings originate from
        // cron jobs / CI runners that cannot hold a session cookie or send
        // custom headers; the `target_id` UUID (122 bits of entropy) is the
        // shared secret. The rate limiter prevents a single source from
        // exhausting the DuckDB mutex throughput.
        .nest(
            "/api/v1/heartbeat",
            crate::api::heartbeat::routes()
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::rate_limit::heartbeat_guard,
                ))
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES)),
        )
        // Auth API (bootstrap, magic-link, sessions, tokens, prefs). Mounted
        // as a sibling to /api/v1 so auth endpoints live under
        // `/api/v1/auth/*` and can be protected / rate-limited as a group.
        // The rate-limit middleware wraps the whole subtree so every auth
        // endpoint shares the per-IP bucket — a brute-force on /verify
        // also consumes the budget for /magic-link/request.
        .nest(
            "/api/v1/auth",
            crate::auth::routes()
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::rate_limit::guard,
                ))
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES)),
        )
        // Public API (unauthenticated, read-only). Rate-limited per-IP to
        // prevent abuse when the reverse proxy (Caddy) is bypassed or
        // misconfigured. The limiter uses `public_per_ip_rate_limit_per_min`
        // from config (default 60/min). A body limit is applied defensively
        // even though the public API is currently GET-only — a future POST
        // addition (e.g. subscriber signup) would otherwise be unprotected.
        .nest(
            "/api/public/v1",
            crate::api::public_routes()
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::rate_limit::public_guard,
                ))
                .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES)),
        )
        // MCP server (JSON-RPC 2.0 over HTTP). Mounted unconditionally;
        // `mcp::routes()` returns an empty router when `[mcp].enabled = false`,
        // so the merge is a no-op in the default config. Auth reuses the
        // existing session cookie / Bearer API token via `RequireAuth`. Body
        // limit guards against oversized JSON-RPC batches.
        .merge(crate::mcp::routes(&state).layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES)))
        // Frontend (WASM bundle + SPA fallback)
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http())
        // Per-route HTTP metrics middleware: records request counters,
        // latency histograms, and the in-flight gauge. Skips `/healthz`
        // and `/readyz` so Caddy / systemd healthcheck pollers don't
        // dominate every SLO ratio. Route label is `MatchedPath` (the
        // pattern, not the concrete URL) so cardinality is bounded by
        // the router's static route table.
        .layer(axum::middleware::from_fn(common::observability::http_metrics::middleware));

    if let Some(cors) = cors_layer {
        router = router.layer(cors);
    }

    router.with_state(state)
}

/// `GET /readyz` — real readiness check. Calls [`storage::Storage::ping`]
/// (typically `SELECT 1`) and returns 200 with `"ready"` on success, or 503
/// with `"not ready: <error>"` on failure. A 503 here tells the load
/// balancer / orchestrator to stop routing traffic without killing the
/// process — a transient storage blip should self-heal on the next ping.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.storage.ping().await {
        Ok(()) => (StatusCode::OK, "ready".to_string()),
        Err(e) => {
            tracing::warn!(error = %e, "readyz: storage ping failed");
            (StatusCode::SERVICE_UNAVAILABLE, format!("not ready: {e}"))
        }
    }
}

/// Build a CORS layer from `[api.cors]` config. When `allow_any_origin` is
/// true, emits `Access-Control-Allow-Origin: *`; otherwise reflects the
/// configured origins. Methods come from `allowed_methods`; headers are
/// restricted to the explicit allowlist the frontend actually uses —
/// `Content-Type`, `Authorization`, `X-Requested-With`, `Idempotency-Key`.
/// Reflecting any header (`allow_headers(Any)`) weakens the policy by
/// letting browser JS attach arbitrary headers (e.g., custom auth headers
/// from third-party scripts).
fn build_cors_layer(cfg: &CorsConfig) -> CorsLayer {
    let cors = if cfg.allow_any_origin {
        CorsLayer::new().allow_origin(Any)
    } else {
        let origins: Vec<HeaderValue> =
            cfg.allowed_origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new().allow_origin(origins)
    };
    let methods: Vec<Method> = cfg.allowed_methods.iter().filter_map(|m| m.parse().ok()).collect();
    // Restrict to headers the frontend actually sends. `X-Requested-With`
    // is the CSRF marker checked by `csrf_guard_middleware`; the others
    // are standard JSON API headers.
    cors.allow_methods(methods).allow_headers([
        HeaderName::from_static("content-type"),
        HeaderName::from_static("authorization"),
        HeaderName::from_static("x-requested-with"),
        HeaderName::from_static("idempotency-key"),
    ])
}
