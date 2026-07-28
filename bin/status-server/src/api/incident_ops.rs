//! Incident lifecycle operations.
//!
//! `POST /incidents/{id}/acknowledge` — acknowledge an open incident.
//! `POST /incidents/{id}/resolve` — resolve an incident (manual).
//! `POST /incidents/{id}/reopen` — reopen a resolved incident.
//! `PATCH /incidents/{id}/ops` — apply an [`IncidentOpsPatch`] (assign,
//! publish, severity change, note, or any of the transitions above).
//! `GET /incidents/metrics?days=30` — incident metrics rollup over a
//! trailing window.
//!
//! Acknowledge / resolve / reopen are convenience shortcuts for the
//! `transition` field of [`IncidentOpsPatch`]; each constructs a patch with
//! only the `transition` field set and delegates to
//! [`storage::Storage::apply_incident_ops`].

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use statuscore::domain::{Incident, IncidentMetricsRollup, IncidentOpsPatch};
use tracing::warn;
use uuid::Uuid;

use crate::api::error::ApiResult;
use crate::app::AppState;

/// The set of lifecycle transitions the incident ops endpoints accept.
/// Centralising the string literals here means a typo at a call site is a
/// compile error rather than a silently-ignored transition. The wire form
/// is `snake_case` to match the existing `IncidentOpsPatch.transition`
/// contract (which stays `Option<String>` so the storage layer remains the
/// source of truth for accepted values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Acknowledge,
    Resolve,
    Reopen,
}

impl Transition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledge => "acknowledge",
            Self::Resolve => "resolve",
            Self::Reopen => "reopen",
        }
    }

    /// Build an `IncidentOpsPatch` carrying only this transition. The
    /// convenience endpoints (`/acknowledge`, `/resolve`, `/reopen`) each
    /// delegate to `apply_incident_ops` with one of these.
    fn to_patch(self) -> IncidentOpsPatch {
        IncidentOpsPatch { transition: Some(self.as_str().to_string()), ..Default::default() }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/incidents/{id}/acknowledge", post(acknowledge_incident))
        .route("/incidents/{id}/resolve", post(resolve_incident))
        .route("/incidents/{id}/reopen", post(reopen_incident))
        .route("/incidents/{id}/ops", patch(apply_incident_ops))
        .route("/incidents/metrics", get(incident_metrics))
}

async fn acknowledge_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let patch = Transition::Acknowledge.to_patch();
    let incident = state.storage.apply_incident_ops(id, &patch).await?;
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(incident)))
}

async fn resolve_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let patch = Transition::Resolve.to_patch();
    let incident = state.storage.apply_incident_ops(id, &patch).await?;
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(incident)))
}

async fn reopen_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let patch = Transition::Reopen.to_patch();
    let incident = state.storage.apply_incident_ops(id, &patch).await?;
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(incident)))
}

/// `PATCH /incidents/{id}/ops` — apply an arbitrary [`IncidentOpsPatch`].
/// The body is the patch itself; any subset of fields may be set.
async fn apply_incident_ops(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(patch): Json<IncidentOpsPatch>,
) -> ApiResult<impl IntoResponse> {
    let incident: Incident = state.storage.apply_incident_ops(id, &patch).await?;
    // Mirror the transition into the escalation engine's bookkeeping so the
    // engine stops paging on acknowledge and cleans up on resolve. Both
    // calls are idempotent and silently no-op when no escalation state
    // exists (target had no policy). Errors are logged — the ops call itself
    // already succeeded, so a bookkeeping failure must not turn the response
    // red.
    //
    // The match keys on `Transition::as_str()` so a rename here is a
    // single-site edit rather than a string-hunt across the file.
    match patch.transition.as_deref() {
        Some(t) if t == Transition::Acknowledge.as_str() => {
            if let Err(e) = state.storage.ack_escalation_state(id).await {
                warn!(incident_id = %id, error = %e, "incident_ops: ack_escalation_state failed");
            }
        }
        Some(t) if t == Transition::Resolve.as_str() => {
            if let Err(e) = state.storage.delete_escalation_state(id).await {
                warn!(incident_id = %id, error = %e, "incident_ops: delete_escalation_state failed");
            }
        }
        _ => {}
    }
    invalidate_public_cache(&state).await;
    Ok((StatusCode::OK, Json(incident)))
}

/// `GET /incidents/metrics?days=30` — incident metrics rollup. `days`
/// defaults to 30; capped at 365 to bound the query.
#[derive(Debug, Deserialize)]
struct MetricsQuery {
    #[serde(default = "default_metrics_days")]
    days: u32,
}

const fn default_metrics_days() -> u32 {
    30
}

async fn incident_metrics(
    State(state): State<AppState>,
    Query(query): Query<MetricsQuery>,
) -> ApiResult<impl IntoResponse> {
    let days = query.days.min(365);
    let rollup: IncidentMetricsRollup = state.storage.incident_metrics(days).await?;
    Ok(Json(rollup))
}

/// Invalidate the public status cache after any incident mutation. A
/// targeted invalidation per page would be more efficient, but the
/// single-tenant v1 rarely has more than a handful of pages, and
/// `invalidate_all` is cheap (one moka call + one HashMap clear).
async fn invalidate_public_cache(state: &AppState) {
    state.public_cache.invalidate_all();
}
