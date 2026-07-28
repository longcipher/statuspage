//! Fleet dashboard API.
//!
//! - `GET /dashboard` — fleet rollup: one row per target with current
//!   status, 24h uptime, p95 latency, and 90-day day-strip history.
//! - `GET /dashboard/summary` — status summary counts (up/down/degraded/
//!   error + total + disabled).
//! - `GET /targets/{id}/latency?from=&to=&buckets=60` — latency time-series
//!   bucketed into `buckets` equal-width intervals over `[from, to]`.
//! - `GET /targets/{id}/uptime?from=&to=` — uptime percentage over a window.

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use statuscore::domain::{DashboardRow, DashboardSummary, LatencyBucket, UptimeResult};
use uuid::Uuid;

use crate::api::error::ApiResult;
use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(get_dashboard))
        .route("/dashboard/summary", get(get_dashboard_summary))
        .route("/targets/{id}/latency", get(get_target_latency))
        .route("/targets/{id}/uptime", get(get_target_uptime))
}

async fn get_dashboard(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let rows: Vec<DashboardRow> = state.storage.dashboard_rollup().await?;
    Ok(Json(rows))
}

async fn get_dashboard_summary(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let summary: DashboardSummary = state.storage.dashboard_summary().await?;
    Ok(Json(summary))
}

/// Query params for `GET /targets/{id}/latency`. `buckets` defaults to 60,
/// capped at 1000 to bound the response.
#[derive(Debug, Deserialize)]
struct LatencyQuery {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    #[serde(default = "default_buckets")]
    buckets: u32,
}

const fn default_buckets() -> u32 {
    60
}

async fn get_target_latency(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<LatencyQuery>,
) -> ApiResult<impl IntoResponse> {
    // Verify the target exists so we return a 404 instead of an empty series
    // for an unknown id.
    let _ = state.storage.get_target(id).await?;
    let buckets = query.buckets.min(1000);
    let result: Vec<LatencyBucket> =
        state.storage.latency_buckets(id, query.from, query.to, buckets).await?;
    Ok(Json(result))
}

/// Query params for `GET /targets/{id}/uptime`. Returns the uptime
/// percentage over `[from, to]`.
#[derive(Debug, Deserialize)]
struct UptimeQuery {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}

async fn get_target_uptime(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<UptimeQuery>,
) -> ApiResult<impl IntoResponse> {
    let _ = state.storage.get_target(id).await?;
    let result: Option<UptimeResult> = state.storage.uptime(id, query.from, query.to).await?;
    Ok(Json(result))
}
