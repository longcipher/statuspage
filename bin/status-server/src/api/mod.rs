//! API v1 routes — real handlers backed by `storage::Storage`.

pub(crate) mod badges;
mod bulk;
mod components;
pub(crate) mod custom_css;
mod dashboard;
mod error;
mod escalation_policies;
mod exports;
pub(crate) mod heartbeat;
mod incident_ops;
mod incidents;
mod maintenance;
mod metrics;
pub(crate) mod metrics_endpoint;
mod notification_channels;
mod on_call_schedules;
mod page_assets;
mod postmortems;
mod public_api;
mod share_links;
mod silence_rules;
mod status_pages;
mod subscribers;
mod targets;
mod variables;

pub(crate) use error::{ApiError, ApiResult};

use axum::Router;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use utoipa::OpenApi;

use statuscore::domain::{
    CheckResult, Incident, MaintenanceWindow, NewStatusPage, NewTarget, NotificationChannel,
    SilenceRule, StatusPage, StatusPageComponent, StatusPageUpdate, Target, TargetUpdate,
};

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/openapi.json", get(openapi_json))
        .route("/targets", get(targets::list_targets).post(targets::create_target))
        .route(
            "/targets/{id}",
            get(targets::get_target).patch(targets::update_target).delete(targets::delete_target),
        )
        .route("/targets/{id}/results", get(targets::list_target_results))
        .route("/targets/{id}/check-now", post(targets::check_target_now))
        .route("/targets/test", post(targets::test_target_spec))
        .route("/targets/bulk", post(bulk::bulk_create_targets))
        .route("/targets/bulk/action", post(bulk::bulk_action_targets))
        .route("/export/account", get(exports::export_account))
        .route(
            "/status-pages",
            get(status_pages::list_status_pages).post(status_pages::create_status_page),
        )
        .route(
            "/status-pages/{id}",
            get(status_pages::get_status_page)
                .patch(status_pages::update_status_page)
                .delete(status_pages::delete_status_page),
        )
        .route("/status-pages/{id}/history", get(status_pages::get_status_page_history))
        .route("/incidents", get(incidents::list_incidents).post(incidents::create_incident))
        .route("/incidents/{id}", get(incidents::get_incident).patch(incidents::update_incident))
        .route("/incidents/{id}/updates", post(incidents::add_incident_update))
        .route("/metrics", get(metrics::metrics))
        // ── Feature modules (each owns its own route tree) ──
        .merge(maintenance::routes())
        .merge(components::routes())
        .merge(subscribers::routes())
        .merge(variables::routes())
        .merge(dashboard::routes())
        .merge(incident_ops::routes())
        .merge(notification_channels::routes())
        .merge(escalation_policies::routes())
        .merge(on_call_schedules::routes())
        .merge(postmortems::routes())
        .merge(share_links::routes())
        .merge(silence_rules::routes())
        .merge(page_assets::routes())
}

/// Public (unauthenticated) API routes mounted at `/api/public/v1`.
pub fn public_routes() -> Router<AppState> {
    public_api::routes()
}

// ── OpenAPI document ──────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    info(
        title = "StatusPage API",
        version = "0.1.0",
        description = "Self-hosted uptime monitoring and status page management API.",
        license(name = "Apache-2.0"),
    ),
    components(schemas(
        Target,
        NewTarget,
        TargetUpdate,
        CheckResult,
        Incident,
        StatusPage,
        NewStatusPage,
        StatusPageUpdate,
        StatusPageComponent,
        MaintenanceWindow,
        NotificationChannel,
        SilenceRule,
    ))
)]
pub struct ApiDoc;

/// Serve the OpenAPI JSON document.
pub async fn openapi_json() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        )],
        ApiDoc::openapi().to_pretty_json().unwrap_or_else(|_| "{}".to_string()),
    )
}
