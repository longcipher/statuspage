//! SVG badge generation for health, uptime, and response time.
//!
//! Generates shields.io-compatible SVG badges at:
//! - `GET /api/v1/endpoints/:id/health/badge.svg`
//! - `GET /api/v1/endpoints/:id/uptimes/:duration/badge.svg`
//! - `GET /api/v1/endpoints/:key/response-times/:duration/badge.svg`
//! - `GET /api/v1/endpoints/:key/health/badge.shields` (JSON for shields.io endpoint)

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::app::AppState;

/// Badge color thresholds for uptime percentage.
fn uptime_color(pct: f64) -> &'static str {
    if pct >= 99.5 {
        "brightgreen"
    } else if pct >= 97.5 {
        "green"
    } else if pct >= 95.0 {
        "yellowgreen"
    } else if pct >= 90.0 {
        "yellow"
    } else if pct >= 80.0 {
        "orange"
    } else {
        "red"
    }
}

fn svg_badge(label: &str, value: &str, color: &str) -> String {
    // ponytail: inline SVG template — no external crate needed
    let label_width = (6.4f64.mul_add(label.len() as f64, 10.0)) as usize;
    let value_width = (6.4f64.mul_add(value.len() as f64, 10.0)) as usize;
    let total = label_width + value_width;
    let lx = label_width / 2;
    let vx = label_width + value_width / 2;
    let mut svg = String::with_capacity(1024);
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{total}\" height=\"20\">\n"
    ));
    svg.push_str("  <linearGradient id=\"b\" x2=\"0\" y2=\"100%\">\n");
    svg.push_str("    <stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>\n");
    svg.push_str("    <stop offset=\"1\" stop-opacity=\".1\"/>\n");
    svg.push_str("  </linearGradient>\n");
    svg.push_str(&format!("  <mask id=\"a\">\n    <rect width=\"{total}\" height=\"20\" rx=\"3\" fill=\"#fff\"/>\n  </mask>\n"));
    svg.push_str("  <g mask=\"url(#a)\">\n");
    svg.push_str(&format!("    <rect width=\"{label_width}\" height=\"20\" fill=\"#555\"/>\n"));
    svg.push_str(&format!(
        "    <rect x=\"{label_width}\" width=\"{value_width}\" height=\"20\" fill=\"{color}\"/>\n"
    ));
    svg.push_str(&format!("    <rect width=\"{total}\" height=\"20\" fill=\"url(#b)\"/>\n"));
    svg.push_str("  </g>\n");
    svg.push_str("  <g fill=\"#fff\" text-anchor=\"middle\" font-family=\"DejaVu Sans,Verdana,Geneva,sans-serif\" font-size=\"11\">\n");
    svg.push_str(&format!(
        "    <text x=\"{lx}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{label}</text>\n"
    ));
    svg.push_str(&format!("    <text x=\"{lx}\" y=\"14\">{label}</text>\n"));
    svg.push_str(&format!(
        "    <text x=\"{vx}\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">{value}</text>\n"
    ));
    svg.push_str(&format!("    <text x=\"{vx}\" y=\"14\">{value}</text>\n"));
    svg.push_str("  </g>\n</svg>");
    svg
}

/// `GET /api/v1/endpoints/:id/health/badge.svg`
pub async fn health_badge(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let target = match state.storage.get_target(id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                axum::http::StatusCode::OK,
                [("content-type", "image/svg+xml")],
                svg_badge("status", "unknown", "lightgrey"),
            );
        }
    };
    let results = state.storage.list_results(id, 1).await.unwrap_or_default();
    let (value, color) = if let Some(r) = results.first() {
        match r.status {
            statuscore::domain::CheckStatus::Up => ("up", "brightgreen"),
            statuscore::domain::CheckStatus::Degraded => ("degraded", "yellow"),
            statuscore::domain::CheckStatus::Down => ("down", "red"),
            statuscore::domain::CheckStatus::Error => ("error", "lightgrey"),
            _ => ("unknown", "lightgrey"),
        }
    } else {
        ("no data", "lightgrey")
    };
    (
        axum::http::StatusCode::OK,
        [("content-type", "image/svg+xml")],
        svg_badge(&target.name, value, color),
    )
}

/// `GET /api/v1/endpoints/:id/health/badge.shields`
pub async fn health_badge_shields(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let results = state.storage.list_results(id, 1).await.unwrap_or_default();
    let (value, color) = if let Some(r) = results.first() {
        match r.status {
            statuscore::domain::CheckStatus::Up => ("up", "brightgreen"),
            statuscore::domain::CheckStatus::Degraded => ("degraded", "yellow"),
            statuscore::domain::CheckStatus::Down => ("down", "red"),
            statuscore::domain::CheckStatus::Error => ("unknown", "lightgrey"),
            _ => ("unknown", "lightgrey"),
        }
    } else {
        ("no data", "lightgrey")
    };
    let json = serde_json::json!({
        "schemaVersion": 1,
        "label": "status",
        "message": value,
        "color": color,
    });
    (axum::http::StatusCode::OK, axum::Json(json))
}

/// `GET /api/v1/endpoints/:id/uptimes/:duration/badge.svg`
pub async fn uptime_badge(
    State(state): State<AppState>,
    Path((id, _duration)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let target = match state.storage.get_target(id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                axum::http::StatusCode::OK,
                [("content-type", "image/svg+xml")],
                svg_badge("uptime", "N/A", "lightgrey"),
            );
        }
    };
    let results = state.storage.list_results(id, 100).await.unwrap_or_default();
    let total = results.len() as f64;
    let up =
        results.iter().filter(|r| matches!(r.status, statuscore::domain::CheckStatus::Up)).count()
            as f64;
    let pct = if total > 0.0 { (up / total) * 100.0 } else { 0.0 };
    let value = format!("{pct:.1}%");
    let color = uptime_color(pct);
    (
        axum::http::StatusCode::OK,
        [("content-type", "image/svg+xml")],
        svg_badge(&target.name, &value, color),
    )
}

/// `GET /api/v1/endpoints/:id/response-times/:duration/badge.svg`
pub async fn response_time_badge(
    State(state): State<AppState>,
    Path((id, _duration)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let results = state.storage.list_results(id, 100).await.unwrap_or_default();
    let avg_ms = if results.is_empty() {
        0
    } else {
        results.iter().map(|r| r.duration_ms as u64).sum::<u64>() / results.len() as u64
    };
    let (value, color) = if avg_ms == 0 {
        ("N/A".to_string(), "lightgrey")
    } else {
        let c = if avg_ms < 200 {
            "brightgreen"
        } else if avg_ms < 500 {
            "green"
        } else if avg_ms < 1000 {
            "yellowgreen"
        } else if avg_ms < 2000 {
            "yellow"
        } else if avg_ms < 5000 {
            "orange"
        } else {
            "red"
        };
        (format!("{avg_ms}ms"), c)
    };
    (
        axum::http::StatusCode::OK,
        [("content-type", "image/svg+xml")],
        svg_badge("response time", &value, color),
    )
}
