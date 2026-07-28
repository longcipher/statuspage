//! Account data export for backup / migration.

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Serialize;
use statuscore::domain::{
    Incident, MaintenanceFilter, MaintenanceWindow, NotificationChannel, SilenceFilter,
    SilenceRule, StatusPage, StatusPageComponent, Target,
};

use crate::app::AppState;

/// Full account configuration dump for backup / migration.
#[derive(Debug, Serialize)]
struct AccountExport {
    exported_at: chrono::DateTime<Utc>,
    version: u32,
    targets: Vec<Target>,
    status_pages: Vec<StatusPage>,
    components: Vec<StatusPageComponent>,
    incidents: Vec<Incident>,
    maintenance_windows: Vec<MaintenanceWindow>,
    notification_channels: Vec<NotificationChannel>,
    silence_rules: Vec<SilenceRule>,
}

/// `GET /export/account` — dump every configuration row as a single JSON document.
pub(super) async fn export_account(State(state): State<AppState>) -> impl IntoResponse {
    let exported_at = Utc::now();

    let targets = match state.storage.list_targets().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "export: list_targets failed");
            vec![]
        }
    };
    let status_pages = match state.storage.list_status_pages().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "export: list_status_pages failed");
            vec![]
        }
    };

    let mut components: Vec<StatusPageComponent> = Vec::new();
    for page in &status_pages {
        match state.storage.list_status_page_components(page.id.0).await {
            Ok(comps) => components.extend(comps),
            Err(e) => {
                tracing::error!(error = %e, page_id = %page.id.0, "export: list_status_page_components failed");
            }
        }
    }

    let incidents = match state.storage.list_incidents().await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(error = %e, "export: list_incidents failed");
            vec![]
        }
    };
    let maintenance_windows =
        match state.storage.list_maintenance_windows(MaintenanceFilter::All).await {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(error = %e, "export: list_maintenance_windows failed");
                vec![]
            }
        };
    let notification_channels = match state.storage.list_notification_channels().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "export: list_notification_channels failed");
            vec![]
        }
    };
    let silence_rules = match state.storage.list_silence_rules(SilenceFilter::All).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "export: list_silence_rules failed");
            vec![]
        }
    };

    let export = AccountExport {
        exported_at,
        version: 1,
        targets,
        status_pages,
        components,
        incidents,
        maintenance_windows,
        notification_channels,
        silence_rules,
    };

    Json(export)
}
