//! Same-port Prometheus metrics endpoint.

use crate::app::AppState;
use axum::extract::State;
use axum::response::IntoResponse;

/// `GET /metrics` — same-port Prometheus exposition.
pub(super) async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let target_count = state.storage.list_targets().await.map_or(0, |t| t.len());
    let incident_count = state.storage.list_incidents().await.map_or(0, |i| i.len());

    let body = format!(
        "# HELP statuspage_targets_total Total number of configured targets.\n\
         # TYPE statuspage_targets_total gauge\n\
         statuspage_targets_total {target_count}\n\
         # HELP statuspage_incidents_total Total number of incidents.\n\
         # TYPE statuspage_incidents_total gauge\n\
         statuspage_incidents_total {incident_count}\n"
    );

    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], body)
}
