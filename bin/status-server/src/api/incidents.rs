//! Incident CRUD + update handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Deserialize;
use statuscore::domain::{
    CheckStatus, Incident, IncidentSeverity, IncidentStatusPhase, PublicIncidentUpdate,
};
use uuid::Uuid;

use super::ApiResult;
use crate::app::AppState;

pub(super) async fn list_incidents(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let incidents = state.storage.list_incidents().await?;
    Ok(Json(incidents))
}

/// Body for `POST /incidents`.
#[derive(Debug, Deserialize)]
pub(super) struct NewIncidentBody {
    #[serde(default)]
    target_id: Option<Uuid>,
    #[serde(default)]
    severity: IncidentSeverity,
    #[serde(default)]
    public_title: Option<String>,
    #[serde(default)]
    public_description: Option<String>,
}

pub(super) async fn create_incident(
    State(state): State<AppState>,
    Json(body): Json<NewIncidentBody>,
) -> ApiResult<impl IntoResponse> {
    let now = Utc::now();
    let incident = Incident {
        id: Uuid::now_v7(),
        target_id: body.target_id.unwrap_or(Uuid::nil()),
        started_at: now,
        ended_at: None,
        status: CheckStatus::Down,
        duration_secs: None,
        check_count: 0,
        error_sample: None,
        severity: body.severity,
        public_title: body.public_title,
        public_description: body.public_description,
        created_at: Some(now),
        updated_at: Some(now),
        updates: Vec::new(),
        regions_down: Vec::new(),
        regions_up: Vec::new(),
    };
    let created = state.storage.create_incident(&incident).await?;

    let notifier = state.notifier.clone();
    let incident_clone = created.clone();
    tokio::spawn(async move {
        let message = format!(
            "incident {} opened: severity={} target={} title={}",
            incident_clone.id,
            incident_clone.severity.as_db_str(),
            incident_clone.target_id,
            incident_clone.public_title.as_deref().unwrap_or("(none)"),
        );
        if let Err(e) = notifier.send(&message).await {
            tracing::warn!(error = %e, "notifier: failed to notify incident");
        }
    });

    state.public_cache.invalidate_all();
    Ok((StatusCode::CREATED, Json(created)))
}

pub(super) async fn get_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let incident = state.storage.get_incident(id).await?;
    Ok(Json(incident))
}

/// Partial update for `PATCH /incidents/{id}`.
#[derive(Debug, Deserialize)]
pub(super) struct IncidentUpdateBody {
    #[serde(default)]
    severity: Option<IncidentSeverity>,
    #[serde(default)]
    status: Option<CheckStatus>,
    #[serde(default)]
    ended_at: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    public_title: Option<String>,
    #[serde(default)]
    public_description: Option<String>,
}

impl IncidentUpdateBody {
    pub(super) fn apply_to(self, incident: &mut Incident) {
        if let Some(v) = self.severity {
            incident.severity = v;
        }
        if let Some(v) = self.status {
            incident.status = v;
        }
        if let Some(v) = self.ended_at {
            incident.ended_at = Some(v);
        }
        if let Some(v) = self.public_title {
            incident.public_title = Some(v);
        }
        if let Some(v) = self.public_description {
            incident.public_description = Some(v);
        }
    }
}

pub(super) async fn update_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<IncidentUpdateBody>,
) -> ApiResult<impl IntoResponse> {
    let mut incident = state.storage.get_incident(id).await?;
    body.apply_to(&mut incident);
    incident.updated_at = Some(Utc::now());
    let updated = state.storage.update_incident(&incident).await?;
    state.public_cache.invalidate_all();
    Ok(Json(updated))
}

/// Body for `POST /incidents/{id}/updates`.
#[derive(Debug, Deserialize)]
pub(super) struct NewIncidentUpdateBody {
    phase: IncidentStatusPhase,
    message: String,
    #[serde(default)]
    posted_at: Option<chrono::DateTime<Utc>>,
}

pub(super) async fn add_incident_update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<NewIncidentUpdateBody>,
) -> ApiResult<impl IntoResponse> {
    let update = PublicIncidentUpdate {
        posted_at: body.posted_at.unwrap_or_else(Utc::now),
        phase: body.phase,
        message: body.message,
    };
    let incident = state.storage.add_incident_update(id, &update).await?;
    state.public_cache.invalidate_all();
    Ok((StatusCode::OK, Json(incident)))
}
