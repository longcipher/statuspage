//! Frontend SPA serving.

use axum::body::Body;
use axum::http::{Request, header};
use axum::response::Response;
use std::convert::Infallible;

/// Serve the frontend index.html (SPA fallback).
///
/// `just fe-build` (cargo + wasm-bindgen) builds the CSR bundle to
/// `target/site/` (workspace-relative). We probe a few candidate paths so the
/// server finds the bundle whether it was launched from the workspace root,
/// from `bin/status-server/`, or via an absolute `CARGO_MANIFEST_DIR`-anchored
/// path. If none match, fall back to a placeholder telling the operator to
/// build the frontend.
pub async fn serve_index() -> Response {
    const FRONTEND_INDEX_PATHS: &[&str] = &[
        // `cargo run -p status-server` from the workspace root.
        "target/site/index.html",
        // `cargo run` from `bin/status-server/`.
        "../target/site/index.html",
        // Anchored to this crate's manifest dir at compile time — works no
        // matter what CWD the binary was launched from.
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/site/index.html",),
    ];
    for path in FRONTEND_INDEX_PATHS {
        match std::fs::read_to_string(path) {
            Ok(html) => {
                tracing::debug!(path, "served frontend index.html");
                return build_html_response(html);
            }
            Err(e) => {
                tracing::debug!(
                    path,
                    error = %e,
                    "frontend index.html not found at candidate path"
                );
            }
        }
    }
    tracing::warn!(
        "frontend index.html not found at any candidate path; serving placeholder. \
         Run: just fe-build"
    );
    // Fallback: placeholder with build instructions.
    build_html_response(
        "<!DOCTYPE html><html><head><title>StatusPage</title></head><body>\
         <h1>StatusPage</h1>\
         <p>Frontend not built. Run: <code>just fe-build</code></p>\
         </body></html>",
    )
}

/// Build a `text/html` response. The header value is statically valid, so
/// `Response::builder().body()` is infallible in practice — on the impossible
/// driver error we fall back to a header-less `Response::new` rather than
/// panic.
fn build_html_response(html: impl Into<Body>) -> Response {
    let body = html.into();
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::from("frontend unavailable".to_string())))
}

/// `ServeDir::not_found_service` adapter: serves `index.html` for unknown
/// paths so the SPA router can take over (e.g. `/dashboard`, `/incidents`).
///
/// The response status is explicitly set to 200 — `ServeDir` delegates to
/// this service when no static file matches, and without overriding the
/// status the browser would receive a 404 even though the body is valid
/// HTML. A 200 ensures search engines, link previews, and the SPA itself
/// treat the route as a real page.
pub async fn spa_fallback(_req: Request<Body>) -> Result<Response, Infallible> {
    let mut resp = serve_index().await;
    *resp.status_mut() = axum::http::StatusCode::OK;
    Ok(resp)
}
