//! Public status page API.
//!
//! Unauthenticated read-only endpoints that power the public status page
//! frontend. All routes are mounted under `/api/public/v1`.
//!
//! - `GET /status` — overall status + component breakdown for a status page,
//!   aggregated from incidents, maintenance windows, and the latest check
//!   result per component. Includes a 90-day day-strip per component.
//! - `GET /incidents` — recent public incidents.
//! - `GET /incidents/{id}` — single public incident.
//! - `GET /incidents.rss` — RSS 2.0 feed of recent public incidents.
//! - `GET /components/{id}/history` — 90-day day-strip history for a single
//!   component (target). Mirrors the per-component slice embedded in
//!   `/status` so a single-monitor widget can render without pulling the
//!   full page snapshot.
//! - `GET /maintenance` — active + upcoming maintenance windows.
//! - `GET /badge.svg` — a shields.io-style SVG badge with accessibility
//!   markup and a configurable `?type=status|uptime` shape.
//! - `GET /notification-channels/verify?token=…` — confirm an email
//!   notification channel's address. Linked from the verification email;
//!   the token is a single-use bearer, hashed at rest. Returns a small
//!   HTML ack so a mail client's link preview shows the outcome.
//! - `GET /notification-channels/decline?token=…` — refuse an email
//!   notification channel. Disables the channel and marks the token used.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use statuscore::domain::{
    CheckResult, CheckStatus, DayState, Incident, IncidentPostmortem, IncidentSeverity,
    IncidentStatusPhase, MaintenanceFilter, MaintenanceWindow, OverallState, OverallStatus,
    PublicComponent, PublicComponentGroup, PublicComponentStatus, PublicIncident,
    PublicMaintenance, PublicMaintenanceList, PublicPostmortem, PublicStatusPage,
};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;
use crate::public_status_cache::CacheLookup;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(get_status))
        .route("/incidents", get(list_public_incidents))
        .route("/incidents/{id}", get(get_public_incident))
        // RSS 2.0 feed of recent public incidents. The `.rss` suffix is a
        // distinct single-segment path from `/incidents` and `/incidents/{id}`,
        // so there is no axum routing conflict. Returns `application/rss+xml`
        // so feed readers render it natively rather than as plain text.
        .route("/incidents.rss", get(get_incidents_rss))
        // 90-day day-strip history for a single component (target). Useful
        // for embedding a single-monitor widget without pulling the whole
        // page snapshot. `{id}` is the target id (the same identifier used
        // by `StatusPageComponent.target_id`).
        .route("/components/{id}/history", get(get_component_history))
        .route("/maintenance", get(list_public_maintenance))
        .route("/badge.svg", get(get_badge))
        // One-click unsubscribe for public status-page subscribers. Linked
        // from every subscriber email; the subscriber id (UUIDv7, ~122 bits
        // of entropy) serves as the unguessable token. Returns 204 on
        // success and 404 if the subscriber doesn't exist (already
        // unsubscribed). The endpoint is POST so mail-gateway auto-actuators
        // (RFC 8058 List-Unsubscribe-Post) work without a confirmation page.
        .route("/subscribers/{subscriber_id}/unsubscribe", post(unsubscribe_subscriber))
        // Channel verification — the links are embedded in the verification
        // email sent by `POST /notification-channels/{id}/request-verification`.
        // Both are GET so a mail client's link preview (and a one-click RFC
        // 8058 List-Unsubscribe-Post header for the decline URL) works
        // without a form submit. The token is the unguessable bearer; the
        // hashed form is the only thing stored.
        .route("/notification-channels/verify", get(verify_channel))
        .route("/notification-channels/decline", get(decline_channel))
        // Shared single-monitor view. The `{token}` segment is the raw
        // capability URL token (32 random bytes, base64url). It is hashed
        // with `sha256_hex` and looked up against the stored hash; the raw
        // token is never persisted. Returns 404 if the token is unknown,
        // expired, or revoked.
        .route("/shared/{token}", get(get_shared_monitor))
        // Public page asset (logo). Unauthenticated so the public status
        // page can `<img src="/api/public/v1/pages/{id}/assets/logo">`
        // directly. Returns 404 if the page or the slot has no asset.
        .route("/pages/{id}/assets/{slot}", get(get_public_asset))
}

/// Query params for `GET /status`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(style = Form, parameter_in = Query)]
struct StatusQuery {
    /// Status page id. When omitted, the first enabled page is used.
    page: Option<Uuid>,
}

/// `GET /pages/{id}/assets/{slot}` — public, unauthenticated page asset
/// (logo) download. Returns the raw bytes with the stored `Content-Type` so
/// the public status page can `<img src="...">` directly. Returns 404 if the
/// page is disabled/missing or the slot has no asset.
async fn get_public_asset(
    State(state): State<AppState>,
    Path(path): Path<PublicAssetPath>,
) -> ApiResult<impl IntoResponse> {
    let page = state.storage.get_status_page(path.id).await?;
    // A disabled page 404s on its public surface — mirror the public status
    // endpoint's behaviour so a hidden page's logo isn't reachable either.
    if !page.enabled {
        return Err(ApiError(statuscore::error::AppError::not_found(
            "PAGE_DISABLED",
            "status page is not published",
        )));
    }
    let slot = statuscore::domain::AssetSlot::parse(&path.slot).ok_or_else(|| {
        ApiError(statuscore::error::AppError::bad_request(
            "UNKNOWN_ASSET_SLOT",
            format!("unknown asset slot `{}`; supported slots: logo", path.slot),
        ))
    })?;
    let asset = state.storage.get_page_asset(page.id.0, slot).await?.ok_or_else(|| {
        ApiError(statuscore::error::AppError::not_found(
            "ASSET_NOT_FOUND",
            format!("no asset in slot `{}` for page {}", path.slot, path.id),
        ))
    })?;
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, asset.content_type.clone())], asset.data))
}

#[derive(Debug, Deserialize)]
struct PublicAssetPath {
    id: Uuid,
    slot: String,
}

/// `GET /status` — overall status page snapshot. Computed from:
///
/// 1. Active maintenance windows covering each component → `Maintenance`
///    (suppresses incidents during planned maintenance).
/// 2. Open incidents on each component → `MajorOutage` (Critical/Major) or
///    `PartialOutage` (Minor) based on severity.
/// 3. Latest check result → `Operational` / `Degraded` / `MajorOutage` /
///    `PartialOutage`.
///
/// The 90-day day-strip per component is read from
/// `storage.component_day_history()`. The whole snapshot is served through
/// [`crate::public_status_cache::PublicStatusCache`] so concurrent public
/// reads share one compute and a transient storage failure falls back to
/// the last-good snapshot.
#[utoipa::path(
    get,
    path = "/api/public/v1/status",
    params(StatusQuery),
    responses(
        (status = 200, description = "Status page snapshot", body = PublicStatusPage),
        (status = 404, description = "No status page found")
    ),
    tag = "Public"
)]
async fn get_status(
    State(state): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> ApiResult<impl IntoResponse> {
    let page_id = resolve_page_id(&state, query.page).await?;
    let state_clone = state.clone();
    // `Box::pin` the async closure so the resulting future is heap-allocated
    // instead of being inlined into the caller's frame — clippy's
    // `large_futures` lint fires because the captured state + compute body
    // would otherwise blow the 16 KB on-stack-future threshold. The
    // `get_or_compute` signature accepts any `Fut: Future` (and
    // `Pin<Box<dyn Future + Send>>` implements `Future`), so no signature
    // change is needed.
    let lookup = state
        .public_cache
        .get_or_compute(page_id, |id| {
            Box::pin(async move { compute_status_snapshot(&state_clone, id).await })
        })
        .await
        .map_err(ApiError::from)?;

    // Stale-while-revalidate: log when we serve the stale snapshot so an
    // operator can correlate a public-page freeze with a storage blip.
    if let CacheLookup::Stale(_) = &lookup {
        tracing::warn!(page_id = %page_id, "public status: serving stale snapshot");
    }

    let snapshot = lookup.into_inner();
    Ok(Json(snapshot.as_ref().clone()))
}

impl CacheLookup {
    fn into_inner(self) -> Arc<PublicStatusPage> {
        match self {
            Self::Fresh(arc) | Self::Stale(arc) => arc,
        }
    }
}

/// Resolve the page id from the query or fall back to the first enabled
/// page. Returns 404 (`NO_STATUS_PAGE`) when none is enabled.
async fn resolve_page_id(state: &AppState, page: Option<Uuid>) -> ApiResult<Uuid> {
    Ok(if let Some(id) = page {
        id
    } else {
        let pages = state.storage.list_status_pages().await?;
        pages.into_iter().find(|p| p.enabled).map(|p| p.id.0).ok_or_else(|| {
            ApiError(statuscore::error::AppError::NotFound {
                code: "NO_STATUS_PAGE",
                message: "no enabled status page found".to_string(),
            })
        })?
    })
}

/// Build the full `PublicStatusPage` snapshot for `page_id`. Reads:
///
/// - the page itself (404 if missing / disabled),
/// - bound components,
/// - active maintenance windows (component_ids → set),
/// - all incidents (filtered to open + per-component),
/// - per-component day-strip history (90 days ending today).
///
/// The worst per-component state wins the overall status. Incidents
/// targeting a component that is currently in an active maintenance window
/// are suppressed (the component shows `Maintenance`, not `MajorOutage`).
async fn compute_status_snapshot(
    state: &AppState,
    page_id: Uuid,
) -> statuscore::error::Result<PublicStatusPage> {
    let page = state.storage.get_status_page(page_id).await?;
    let components = state.storage.list_status_page_components(page.id.0).await?;

    // Active maintenance windows → set of target_ids under maintenance.
    let active_mw = state.storage.list_maintenance_windows(MaintenanceFilter::Active).await?;
    let maintenance_targets: std::collections::HashSet<Uuid> =
        active_mw.iter().flat_map(|w| w.component_ids.iter().copied()).collect();

    // All incidents — filter to open + per-component below. A single read
    // keeps this N+1-free for the common case.
    let all_incidents = state.storage.list_incidents().await?;

    // 90-day window ending now (UTC today inclusive). `to` is exclusive on
    // the lower bound, inclusive on the upper — `component_day_history`
    // returns one row per (target, day) within `[from, to]`.
    let to = Utc::now();
    let from = to - ChronoDuration::days(90);

    let mut groups: Vec<PublicComponentGroup> = Vec::new();
    let mut worst = OverallState::Operational;

    for comp in &components {
        let target_id = comp.target_id;

        // Active maintenance on this component wins over everything else.
        let in_maintenance = maintenance_targets.contains(&target_id);

        // Open incidents on this target (suppressed during maintenance).
        let open_incidents: Vec<&Incident> = if in_maintenance {
            Vec::new()
        } else {
            all_incidents
                .iter()
                .filter(|i| i.target_id == target_id && i.ended_at.is_none())
                .collect()
        };

        let status = if in_maintenance {
            PublicComponentStatus::Maintenance
        } else if let Some(worst_incident) = worst_incident_status(&open_incidents) {
            worst_incident
        } else {
            // Fall back to the latest check result.
            let results = state.storage.list_results(target_id, 1).await?;
            results.first().map_or(PublicComponentStatus::Operational, |r| {
                component_status_from_result(r.status)
            })
        };

        let overall = overall_from_component(status);
        if overall_severity_rank(overall) > overall_severity_rank(worst) {
            worst = overall;
        }

        // 90-day day-strip, oldest first. The storage layer returns one
        // entry per day; missing days come back as `DayState::NoData`.
        let history = state
            .storage
            .component_day_history(target_id, from, to)
            .await?
            .into_iter()
            .map(|h| h.state)
            .collect();

        let public_comp = PublicComponent {
            id: target_id,
            name: comp.public_name.clone().unwrap_or_else(|| comp.monitor_name.clone()),
            description: comp.public_description.clone(),
            current_status: status,
            history,
        };

        push_into_group(&mut groups, public_comp, comp.public_group.as_deref());
    }

    // Active incidents surfaced on the page (suppressed components excluded).
    let mut active_incidents: Vec<PublicIncident> = Vec::new();
    for inc in all_incidents.iter().filter(|i| {
        i.ended_at.is_none()
            && !maintenance_targets.contains(&i.target_id)
            && components.iter().any(|c| c.target_id == i.target_id)
    }) {
        // Best-effort postmortem load — open incidents rarely have a published
        // postmortem, but the call is cheap and keeps the projection honest.
        let pm = match state.storage.get_postmortem(inc.id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(incident_id = %inc.id, error = %e, "public_api: postmortem load failed (active)");
                None
            }
        };
        if let Some(p) = to_public_incident(inc, pm.as_ref()) {
            active_incidents.push(p);
        }
    }

    // Recent incidents (last 90 days, closed) — cap at 25 to keep the payload
    // bounded. `has_more` is set when more incidents exist past the cap.
    let recent_cutoff = to - ChronoDuration::days(90);
    let mut recent_incidents: Vec<PublicIncident> = Vec::new();
    for inc in all_incidents.iter().filter(|i| {
        i.ended_at.is_some()
            && i.started_at >= recent_cutoff
            && components.iter().any(|c| c.target_id == i.target_id)
    }) {
        let pm = match state.storage.get_postmortem(inc.id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(incident_id = %inc.id, error = %e, "public_api: postmortem load failed (recent)");
                None
            }
        };
        if let Some(p) = to_public_incident(inc, pm.as_ref()) {
            recent_incidents.push(p);
        }
    }
    // Sort newest-first by started_at.
    recent_incidents.sort_by_key(|b| std::cmp::Reverse(b.started_at));
    let recent_incidents_has_more = recent_incidents.len() > 25;
    recent_incidents.truncate(25);

    // Maintenance (active + upcoming) resolved to public projection with
    // component names. We reuse the storage's existing maintenance list.
    let active_mw_list = state.storage.list_maintenance_windows(MaintenanceFilter::Active).await?;
    let upcoming_mw_list =
        state.storage.list_maintenance_windows(MaintenanceFilter::Upcoming).await?;
    let active_maintenance =
        to_public_maintenance_list(&active_mw_list, state.storage.as_ref()).await;
    let upcoming_maintenance =
        to_public_maintenance_list(&upcoming_mw_list, state.storage.as_ref()).await;

    let overall = OverallStatus { state: worst, label: overall_label(worst).to_string() };

    // Best-effort logo hash for cache-busting. A missing asset (`None`) is
    // not an error — it just means no logo was uploaded. The snapshot is
    // cached, so this reads the asset row at most once per TTL window.
    let logo_hash = state
        .storage
        .get_page_asset(page.id.0, statuscore::domain::AssetSlot::Logo)
        .await?
        .map(|a| a.hash);

    Ok(PublicStatusPage {
        overall,
        generated_at: Utc::now(),
        site_name: page.name.clone(),
        groups,
        active_incidents,
        recent_incidents,
        recent_incidents_has_more,
        active_maintenance,
        upcoming_maintenance,
        logo_hash,
    })
}

/// Group a [`PublicComponent`] into the right group bucket, creating the
/// bucket lazily. Components without a `public_group` go into an ungrouped
/// (name = `None`) bucket — but always a fresh bucket per component so the
/// render order matches the storage's `sort_order`.
fn push_into_group(
    groups: &mut Vec<PublicComponentGroup>,
    public_comp: PublicComponent,
    public_group: Option<&str>,
) {
    if let Some(group_name) = public_group {
        if let Some(existing) = groups.iter_mut().find(|g| g.name.as_deref() == Some(group_name)) {
            existing.components.push(public_comp);
        } else {
            groups.push(PublicComponentGroup {
                name: Some(group_name.to_string()),
                components: vec![public_comp],
            });
        }
    } else {
        groups.push(PublicComponentGroup { name: None, components: vec![public_comp] });
    }
}

/// Pick the worst [`PublicComponentStatus`] from a slice of open incidents
/// on the same target. `None` when there are no open incidents. Severity
/// ordering: Critical/Major → `MajorOutage`; Minor → `PartialOutage`.
fn worst_incident_status(incidents: &[&Incident]) -> Option<PublicComponentStatus> {
    let mut worst: Option<PublicComponentStatus> = None;
    for inc in incidents {
        let s = match inc.severity {
            IncidentSeverity::Critical | IncidentSeverity::Major => {
                PublicComponentStatus::MajorOutage
            }
            IncidentSeverity::Minor => PublicComponentStatus::PartialOutage,
            // `IncidentSeverity` is `#[non_exhaustive]`; unknown severities
            // are treated as partial outages rather than ignored.
            _ => PublicComponentStatus::PartialOutage,
        };
        if worst.is_none_or(|w| component_severity_rank(s) > component_severity_rank(w)) {
            worst = Some(s);
        }
    }
    worst
}

const fn component_status_from_result(status: CheckStatus) -> PublicComponentStatus {
    match status {
        CheckStatus::Up => PublicComponentStatus::Operational,
        CheckStatus::Degraded => PublicComponentStatus::Degraded,
        CheckStatus::Down => PublicComponentStatus::MajorOutage,
        CheckStatus::Error => PublicComponentStatus::PartialOutage,
        // `CheckStatus` is `#[non_exhaustive]`; map unknown states to a
        // partial outage so they are surfaced rather than hidden.
        _ => PublicComponentStatus::PartialOutage,
    }
}

const fn component_severity_rank(s: PublicComponentStatus) -> u8 {
    match s {
        PublicComponentStatus::Operational => 0,
        PublicComponentStatus::Maintenance => 1,
        PublicComponentStatus::Degraded => 2,
        PublicComponentStatus::PartialOutage => 3,
        PublicComponentStatus::MajorOutage => 4,
        // `PublicComponentStatus` is `#[non_exhaustive]`; rank unknown states
        // as least severe so they never inflate the worst-case computation.
        _ => 0,
    }
}

const fn overall_from_component(s: PublicComponentStatus) -> OverallState {
    match s {
        PublicComponentStatus::Operational => OverallState::Operational,
        PublicComponentStatus::Degraded | PublicComponentStatus::PartialOutage => {
            OverallState::PartialOutage
        }
        PublicComponentStatus::MajorOutage => OverallState::MajorOutage,
        PublicComponentStatus::Maintenance => OverallState::Maintenance,
        // `PublicComponentStatus` is `#[non_exhaustive]`; unknown component
        // states surface as a partial outage on the overall page state.
        _ => OverallState::PartialOutage,
    }
}

const fn overall_severity_rank(state: OverallState) -> u8 {
    match state {
        OverallState::Operational => 0,
        OverallState::Maintenance => 1,
        OverallState::MinorDisruption => 2,
        OverallState::PartialOutage => 3,
        OverallState::MajorOutage => 4,
        // `OverallState` is `#[non_exhaustive]`; rank unknown states as least
        // severe so they never inflate the worst-case computation.
        _ => 0,
    }
}

const fn overall_label(state: OverallState) -> &'static str {
    match state {
        OverallState::Operational => "All Systems Operational",
        OverallState::Maintenance => "Under Maintenance",
        OverallState::MinorDisruption => "Minor Disruption",
        OverallState::PartialOutage => "Partial Outage",
        OverallState::MajorOutage => "Major Outage",
        // `OverallState` is `#[non_exhaustive]`; unknown states get a neutral
        // label rather than panicking.
        _ => "Unknown",
    }
}

/// Map an internal incident to its public view. Only incidents with a
/// public title or description are surfaced; internal-only incidents
/// return `None`. The optional `postmortem` is included only when it has
/// been published (`published_at` is `Some`); the internal `author_id`
/// and action-item `owner_user_id` fields are stripped from the public
/// projection.
fn to_public_incident(
    incident: &statuscore::domain::Incident,
    postmortem: Option<&IncidentPostmortem>,
) -> Option<PublicIncident> {
    let title = incident.public_title.clone()?;
    let postmortem = postmortem.and_then(|pm| {
        let published_at = pm.published_at?;
        Some(PublicPostmortem {
            summary: pm.summary.clone(),
            root_cause: pm.root_cause.clone(),
            impact: pm.impact.clone(),
            action_items: pm
                .action_items
                .iter()
                .map(|a| statuscore::domain::PublicActionItem {
                    text: a.text.clone(),
                    done: a.done,
                })
                .collect(),
            published_at,
        })
    });
    Some(PublicIncident {
        id: incident.id,
        component_id: incident.target_id,
        component_name: String::new(),
        title,
        started_at: incident.started_at,
        ended_at: incident.ended_at,
        severity: incident.severity,
        status_phase: incident
            .updates
            .last()
            .map_or(IncidentStatusPhase::Investigating, |u| u.phase),
        updates: incident.updates.clone(),
        postmortem,
    })
}

/// Resolve component_ids → target names for the public maintenance list.
/// A miss (deleted target) is silently skipped.
async fn to_public_maintenance_list(
    windows: &[MaintenanceWindow],
    storage: &dyn storage::Storage,
) -> Vec<PublicMaintenance> {
    let mut out = Vec::with_capacity(windows.len());
    for w in windows {
        let mut names = Vec::new();
        for cid in &w.component_ids {
            if let Ok(t) = storage.get_target(*cid).await {
                names.push(t.name);
            }
        }
        out.push(PublicMaintenance {
            id: w.id,
            title: w.title.clone(),
            description: w.description.clone(),
            starts_at: w.starts_at,
            ends_at: w.ends_at,
            affected_component_names: names,
        });
    }
    out
}

#[utoipa::path(
    get,
    path = "/api/public/v1/incidents",
    responses(
        (status = 200, description = "List of public incidents", body = Vec<PublicIncident>)
    ),
    tag = "Public"
)]
async fn list_public_incidents(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let incidents = state.storage.list_incidents().await?;
    let mut public: Vec<PublicIncident> = Vec::with_capacity(incidents.len());
    for inc in &incidents {
        // Best-effort postmortem load: a storage failure here degrades to
        // `postmortem: None` rather than failing the whole list — the
        // incident listing is the primary payload.
        let pm = match state.storage.get_postmortem(inc.id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(incident_id = %inc.id, error = %e, "public_api: postmortem load failed");
                None
            }
        };
        if let Some(p) = to_public_incident(inc, pm.as_ref()) {
            public.push(p);
        }
    }
    Ok(Json(public))
}

#[utoipa::path(
    get,
    path = "/api/public/v1/incidents/{id}",
    params(
        ("id" = Uuid, Path, description = "Incident id")
    ),
    responses(
        (status = 200, description = "Public incident detail", body = PublicIncident),
        (status = 404, description = "Incident not found or not public")
    ),
    tag = "Public"
)]
async fn get_public_incident(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let incident = state.storage.get_incident(id).await?;
    let pm = state.storage.get_postmortem(id).await?;
    let public = to_public_incident(&incident, pm.as_ref()).ok_or_else(|| {
        ApiError(statuscore::error::AppError::NotFound {
            code: "INCIDENT_NOT_PUBLIC",
            message: "incident has no public title".to_string(),
        })
    })?;
    Ok(Json(public))
}

// ── RSS feed ───────────────────────────────────────────────────────────────

/// Query params for `GET /incidents.rss`. `page` selects which status page's
/// title lands in the channel `<title>`; omitted falls back to the first
/// enabled page (mirrors [`get_status`]).
#[derive(Debug, Deserialize)]
struct RssQuery {
    #[serde(default)]
    page: Option<Uuid>,
}

/// `GET /incidents.rss` — RSS 2.0 feed of recent public incidents.
///
/// The feed lists the last 50 public incidents (newest-first by
/// `started_at`). Each `<item>` carries:
/// - `<title>` — the incident's public title.
/// - `<link>` / `<guid isPermaLink="true">` — the public base URL joined
///   with `/incidents/{id}` (the SPA route). Feed readers that follow
///   `<link>` land on the incident detail page.
/// - `<pubDate>` — `started_at` formatted as RFC 822 (`to_rfc2822`), the
///   date format RSS 2.0 requires.
/// - `<description>` — a one-line summary of severity + current phase, plus
///   the latest update message if any. XML-escaped.
///
/// The channel `<title>` is `"{site_name} — Incident History"`; `<link>` is
/// the public base URL. When no status page is enabled, the channel title
/// falls back to `"Status Page — Incident History"` and the feed still
/// renders (with whatever public incidents exist) so a misconfigured
/// deployment serves a usable feed rather than a 5xx.
///
/// Storage errors propagate as 5xx (the public status cache's stale
/// fallback doesn't apply here — RSS readers retry on failure and a stale
/// feed would mislead subscribers about open incidents).
async fn get_incidents_rss(
    State(state): State<AppState>,
    Query(query): Query<RssQuery>,
) -> ApiResult<impl IntoResponse> {
    // Channel title: prefer the (first) enabled page's name. Fall back to
    // a generic label so the feed still renders when no page is configured.
    let site_name = match resolve_page_id(&state, query.page).await {
        Ok(page_id) => state.storage.get_status_page(page_id).await.ok().map(|p| p.name),
        Err(_) => None,
    }
    .unwrap_or_else(|| "Status Page".to_string());

    let base = &state.public_base_url;
    let channel_title = format!("{site_name} — Incident History");
    let channel_link = base.clone();
    let channel_desc = "Recent incidents and outages affecting this status page.";

    let incidents = state.storage.list_incidents().await?;
    // Newest-first by started_at, capped at 50 to keep the feed bounded.
    let mut public: Vec<PublicIncident> = Vec::new();
    for inc in &incidents {
        let pm = match state.storage.get_postmortem(inc.id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(incident_id = %inc.id, error = %e, "rss: postmortem load failed");
                None
            }
        };
        if let Some(p) = to_public_incident(inc, pm.as_ref()) {
            public.push(p);
        }
    }
    public.sort_by_key(|b| std::cmp::Reverse(b.started_at));
    public.truncate(50);

    let last_build = Utc::now().to_rfc2822();

    let xml =
        render_rss_xml(&channel_title, &channel_link, channel_desc, &last_build, base, &public);

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "application/rss+xml; charset=utf-8")], xml))
}

/// Render an RSS 2.0 feed document. Pure function (no I/O) so it can be
/// unit-tested independently of the storage layer. The `<item>` list is
/// built from `incidents` in the order given (newest-first); the caller is
/// responsible for sorting and truncating.
///
/// `base` is the public base URL used to build per-item `<link>`s; it is
/// XML-escaped along with every other interpolated field.
fn render_rss_xml(
    channel_title: &str,
    channel_link: &str,
    channel_desc: &str,
    last_build_date: &str,
    base: &str,
    incidents: &[PublicIncident],
) -> String {
    let mut items_xml = String::with_capacity(8 * 1024);
    for inc in incidents {
        let link = format!("{base}/incidents/{}", inc.id);
        let pub_date = inc.started_at.to_rfc2822();
        let phase = inc.status_phase.as_db_str();
        let severity = inc.severity.as_db_str();
        let mut desc = format!("Severity: {severity} — Phase: {phase}");
        if let Some(last_update) = inc.updates.last() {
            desc.push_str(" — ");
            desc.push_str(&last_update.message);
        }
        let title = xml_escape(&inc.title);
        let desc = xml_escape(&desc);
        let link_esc = xml_escape(&link);
        items_xml.push_str(&format!(
            "    <item>\n      <title>{title}</title>\n      <link>{link_esc}</link>\n      \
             <guid isPermaLink=\"true\">{link_esc}</guid>\n      <pubDate>{pub_date}</pubDate>\n      \
             <description>{desc}</description>\n    </item>\n"
        ));
    }

    let channel_title = xml_escape(channel_title);
    let channel_link = xml_escape(channel_link);
    let channel_desc = xml_escape(channel_desc);

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <rss version=\"2.0\">\n  <channel>\n    \
         <title>{channel_title}</title>\n    <link>{channel_link}</link>\n    \
         <description>{channel_desc}</description>\n    \
         <lastBuildDate>{last_build_date}</lastBuildDate>\n    \
         <generator>statuspage</generator>\n\
         {items_xml}  </channel>\n</rss>\n"
    )
}

// ── Component history ──────────────────────────────────────────────────────

/// Response body for `GET /components/{id}/history`. Mirrors the per-component
/// slice of [`PublicComponent`] so a single-monitor widget can render without
/// pulling the full page snapshot. `from` / `to` are the bounds actually
/// queried so the caller can validate the range it received.
#[derive(Debug, Serialize)]
struct ComponentHistoryResponse {
    /// The target id the history was fetched for.
    target_id: Uuid,
    /// Inclusive lower bound of the range (UTC, 90 days before `to`).
    from: chrono::DateTime<Utc>,
    /// Exclusive upper bound of the range (UTC, "now").
    to: chrono::DateTime<Utc>,
    /// 90-day day-strip, oldest first. Days with no recorded checks come back
    /// as `DayState::NoData`.
    history: Vec<DayState>,
}

/// `GET /components/{id}/history` — 90-day day-strip history for a single
/// component (target). Returns the same per-day `DayState` sequence that
/// `PublicComponent.history` carries in `/status`, scoped to one target so
/// a single-monitor widget (e.g. an embedded tile) doesn't pull the whole
/// page snapshot.
///
/// The target is fetched first so a missing target surfaces as 404
/// (`TARGET_NOT_FOUND`) rather than an empty history. A target that exists
/// but has no recorded checks returns 200 with an all-`NoData` history —
/// that's a legitimate state, not an error.
async fn get_component_history(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // Verify the target exists so a stale / wrong id surfaces as 404 rather
    // than an all-NoData history that looks like "no data yet".
    let target = state.storage.get_target(id).await?;

    let to = Utc::now();
    let from = to - ChronoDuration::days(90);
    let history = state
        .storage
        .component_day_history(target.id, from, to)
        .await?
        .into_iter()
        .map(|h| h.state)
        .collect();

    Ok(Json(ComponentHistoryResponse { target_id: target.id, from, to, history }))
}

async fn list_public_maintenance(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let active = state.storage.list_maintenance_windows(MaintenanceFilter::Active).await?;
    let upcoming = state.storage.list_maintenance_windows(MaintenanceFilter::Upcoming).await?;
    let active_pub = to_public_maintenance_list(&active, state.storage.as_ref()).await;
    let upcoming_pub = to_public_maintenance_list(&upcoming, state.storage.as_ref()).await;
    Ok(Json(PublicMaintenanceList { active: active_pub, upcoming: upcoming_pub }))
}

// ── Badge ──────────────────────────────────────────────────────────────────

/// Badge query params. `type=uptime` produces a "99.x% uptime" badge;
/// `type=status` (default) produces the operational-state label.
#[derive(Debug, Deserialize)]
struct BadgeQuery {
    #[serde(default)]
    page: Option<Uuid>,
    #[serde(default)]
    #[serde(rename = "type")]
    badge_type: Option<String>,
}

/// `GET /badge.svg` — shields.io-style SVG badge. Always returns 200 (even
/// on error) so an `<img>` embed never breaks. Errors produce a "no data"
/// badge rather than a 5xx.
async fn get_badge(
    State(state): State<AppState>,
    Query(query): Query<BadgeQuery>,
) -> impl IntoResponse {
    let page_id = resolve_page_id(&state, query.page).await.ok();
    let (label_text, value_text, color) = match page_id {
        Some(id) => match render_badge_payload(&state, id, query.badge_type.as_deref()).await {
            Ok(payload) => payload,
            Err(_) => ("status".to_string(), "no data".to_string(), "#9CA3AF".to_string()),
        },
        None => ("status".to_string(), "no data".to_string(), "#9CA3AF".to_string()),
    };

    let svg = render_badge_svg(&label_text, &value_text, &color);
    (StatusCode::OK, [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")], svg)
}

/// Resolve the (label, value, color) triple for a badge. `badge_type`:
/// - `status` (default): "All Systems Operational" / "Major Outage" / …
/// - `uptime`: "99.97% uptime" — computed from the day-strip history.
async fn render_badge_payload(
    state: &AppState,
    page_id: Uuid,
    badge_type: Option<&str>,
) -> ApiResult<(String, String, String)> {
    let page = state.storage.get_status_page(page_id).await?;
    let components = state.storage.list_status_page_components(page.id.0).await?;

    match badge_type {
        Some(t) if t.eq_ignore_ascii_case("uptime") => {
            let to = Utc::now();
            let from = to - ChronoDuration::days(90);
            // Compute the simple uptime average across components using the
            // day-strip history (operational+degraded days count as up).
            let mut total_days = 0u64;
            let mut up_days = 0u64;
            for comp in &components {
                let hist = state.storage.component_day_history(comp.target_id, from, to).await?;
                for h in hist {
                    total_days += 1;
                    match h.state {
                        DayState::Operational | DayState::Degraded => up_days += 1,
                        _ => {}
                    }
                }
            }
            let pct =
                if total_days == 0 { 100.0 } else { (up_days as f64 / total_days as f64) * 100.0 };
            let color = if pct >= 99.5 {
                "#22C55E"
            } else if pct >= 95.0 {
                "#F59E0B"
            } else {
                "#EF4444"
            }
            .to_string();
            Ok(("uptime".to_string(), format!("{:.2}% uptime", pct), color))
        }
        _ => {
            // Default: status badge — worst overall state.
            let mut worst = OverallState::Operational;
            let active_mw =
                state.storage.list_maintenance_windows(MaintenanceFilter::Active).await?;
            let mw_targets: std::collections::HashSet<Uuid> =
                active_mw.iter().flat_map(|w| w.component_ids.iter().copied()).collect();
            let incidents = state.storage.list_incidents().await?;
            for comp in &components {
                let target_id = comp.target_id;
                if mw_targets.contains(&target_id) {
                    if overall_severity_rank(OverallState::Maintenance)
                        > overall_severity_rank(worst)
                    {
                        worst = OverallState::Maintenance;
                    }
                    continue;
                }
                let open_incidents: Vec<&Incident> = incidents
                    .iter()
                    .filter(|i| i.target_id == target_id && i.ended_at.is_none())
                    .collect();
                if let Some(s) = worst_incident_status(&open_incidents) {
                    let overall = overall_from_component(s);
                    if overall_severity_rank(overall) > overall_severity_rank(worst) {
                        worst = overall;
                    }
                    continue;
                }
                let results = state.storage.list_results(target_id, 1).await?;
                if let Some(latest) = results.first() {
                    let s = component_status_from_result(latest.status);
                    let overall = overall_from_component(s);
                    if overall_severity_rank(overall) > overall_severity_rank(worst) {
                        worst = overall;
                    }
                }
            }
            Ok((
                "status".to_string(),
                overall_label(worst).to_string(),
                badge_color(worst).to_string(),
            ))
        }
    }
}

/// Render the SVG markup for a badge with the given label/value/color.
/// Includes `<title>` and `<desc>` for accessibility, XML-escapes the label
/// and value text, and computes the width based on the text lengths
/// (approximate: 6.5 px per character at font-size 11).
fn render_badge_svg(label_text: &str, value_text: &str, color: &str) -> String {
    let esc_label = xml_escape(label_text);
    let esc_value = xml_escape(value_text);
    // Approximate character widths for Verdana 11px. The label is usually
    // short ("status", "uptime"); the value is the variable-length part.
    let label_width = (esc_label.chars().count() as f64 * 6.5).max(40.0) as u32;
    let value_width = (esc_value.chars().count() as f64 * 6.5).max(60.0) as u32;
    let total_width = label_width + value_width;
    let value_x = label_width + value_width / 2;
    let label_x = label_width / 2;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{esc_label}: {esc_value}">
  <title>{esc_label}: {esc_value}</title>
  <desc>Status badge — {esc_label}: {esc_value}</desc>
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect width="{total_width}" height="20" fill="#555"/>
  <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
  <rect width="{total_width}" height="20" fill="url(#b)"/>
  <text x="{label_x}" y="14" fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">{esc_label}</text>
  <text x="{value_x}" y="14" fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">{esc_value}</text>
</svg>"##
    )
}

/// XML-escape the four characters that must be escaped in element text and
/// attribute values (`& < > "`). Apostrophes are intentionally not escaped
/// (we always use double quotes for attributes).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

const fn badge_color(state: OverallState) -> &'static str {
    match state {
        OverallState::Operational => "#22C55E",
        OverallState::Maintenance => "#F59E0B",
        OverallState::MinorDisruption => "#F59E0B",
        OverallState::PartialOutage => "#F97316",
        OverallState::MajorOutage => "#EF4444",
        // `OverallState` is `#[non_exhaustive]`; unknown states render as a
        // neutral gray badge.
        _ => "#6B7280",
    }
}

/// `POST /api/public/v1/subscribers/{subscriber_id}/unsubscribe` — one-click
/// opt-out for public status-page subscribers. The subscriber id is the
/// unguessable token (UUIDv7, ~122 bits of entropy); no separate secret is
/// needed for a self-hosted single-tenant deployment. Idempotent: deleting an
/// already-deleted subscriber returns 404 (the caller sees success either way).
async fn unsubscribe_subscriber(
    State(state): State<AppState>,
    Path(subscriber_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // delete_subscriber returns NotFound if the subscriber doesn't exist.
    // For unsubscribe, that's a success state (already unsubscribed) — return
    // 204 so the mail client doesn't surface an error.
    match state.storage.delete_subscriber(subscriber_id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(statuscore::error::AppError::NotFound { .. }) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(ApiError(e)),
    }
}

// ── Channel verification ──────────────────────────────────────────────────

/// Query params for the verify / decline endpoints. The token is the raw
/// bearer from the email link; `hash_cookie_value(token)` is the storage
/// lookup key.
#[derive(Debug, Deserialize)]
struct VerifyQuery {
    token: String,
}

/// `GET /api/public/v1/notification-channels/verify?token=…` — confirm an
/// email notification channel's address.
///
/// Flow:
/// 1. Hash the bearer token and call `consume_channel_verification_token`
///    (atomic: marks the row used and returns the channel_id, or `None`
///    if missing / expired / already used).
/// 2. On success, mark the channel as verified (`verified_at = now()`).
/// 3. Return a small HTML ack so a mail client's link preview shows the
///    outcome without a separate API call.
///
/// The endpoint is idempotent in the sense that a second click on the same
/// link consumes nothing (the token is already used) and returns the
/// "already used" page — no error surface for the operator.
///
/// Returns:
/// - `200` with an HTML ack on success.
/// - `200` with an HTML "already used / expired" page if the token is
///   invalid (we deliberately don't 4xx so the link preview still works).
/// - `500` HTML page if storage fails mid-flow.
async fn verify_channel(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> impl IntoResponse {
    let token = query.token.trim().to_string();
    if token.is_empty() {
        return verification_response(VerificationOutcome::Invalid);
    }

    let token_hash = statuscore::domain::hash_cookie_value(&token);
    let channel_id = match state.storage.consume_channel_verification_token(&token_hash).await {
        Ok(Some(id)) => id,
        Ok(None) => return verification_response(VerificationOutcome::Invalid),
        Err(e) => {
            tracing::warn!(error = %e, "verify_channel: consume token failed");
            return verification_response(VerificationOutcome::ServerError);
        }
    };

    // Mark the channel verified. If the channel was deleted between token
    // issue and consume, surface a soft "invalid" page rather than a 404 —
    // the operator either re-creates the channel or ignores the stale link.
    if let Err(e) = state.storage.set_channel_verified(channel_id).await {
        tracing::warn!(channel_id = %channel_id, error = %e, "verify_channel: set_channel_verified failed");
        return verification_response(VerificationOutcome::ServerError);
    }

    tracing::info!(channel_id = %channel_id, "verify_channel: channel verified");
    verification_response(VerificationOutcome::Verified)
}

/// `GET /api/public/v1/notification-channels/decline?token=…` — refuse an
/// email notification channel. The channel is marked disabled with a
/// `disabled_reason` of "recipient declined verification"; future dispatch
/// skips it. The token is consumed so the link can't be replayed.
///
/// Same idempotency / preview rules as [`verify_channel`]: an invalid or
/// already-used token returns a soft "invalid" page, never a 4xx.
async fn decline_channel(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> impl IntoResponse {
    let token = query.token.trim().to_string();
    if token.is_empty() {
        return verification_response(VerificationOutcome::Invalid);
    }

    let token_hash = statuscore::domain::hash_cookie_value(&token);
    let channel_id = match state.storage.consume_channel_verification_token(&token_hash).await {
        Ok(Some(id)) => id,
        Ok(None) => return verification_response(VerificationOutcome::Invalid),
        Err(e) => {
            tracing::warn!(error = %e, "decline_channel: consume token failed");
            return verification_response(VerificationOutcome::ServerError);
        }
    };

    // Disable the channel with a clear reason. An empty reason would clear
    // the field; the storage contract treats "" as "no reason".
    const DECLINE_REASON: &str = "recipient declined verification";
    if let Err(e) = state.storage.set_channel_disabled_reason(channel_id, DECLINE_REASON).await {
        tracing::warn!(channel_id = %channel_id, error = %e, "decline_channel: set_channel_disabled_reason failed");
        return verification_response(VerificationOutcome::ServerError);
    }

    tracing::info!(channel_id = %channel_id, "decline_channel: channel declined");
    verification_response(VerificationOutcome::Declined)
}

/// Outcome of a verify / decline flow, used to pick the rendered HTML page.
enum VerificationOutcome {
    Verified,
    Declined,
    /// Token missing, expired, already used, or empty.
    Invalid,
    /// Storage failure mid-flow — the operator should retry.
    ServerError,
}

/// Render a minimal HTML ack page for a verification outcome. The page is
/// self-contained (no external CSS / JS) so it renders in any mail client's
/// link preview and on any browser without the SPA bundle. The text is
/// plain English so an operator pasting the URL into a chat gets a readable
/// result.
fn verification_response(
    outcome: VerificationOutcome,
) -> (StatusCode, [(axum::http::header::HeaderName, &'static str); 1], String) {
    let (title, body) = match outcome {
        VerificationOutcome::Verified => (
            "Channel verified",
            "Your notification channel is now verified. You will receive incident alerts at this address.",
        ),
        VerificationOutcome::Declined => (
            "Channel declined",
            "The notification channel has been disabled. You will not receive alerts at this address.",
        ),
        VerificationOutcome::Invalid => (
            "Link invalid or expired",
            "This verification link is invalid, expired, or already used. Request a new link from your status page settings.",
        ),
        VerificationOutcome::ServerError => (
            "Verification failed",
            "We couldn't complete your request right now. Please try again later, or contact your administrator.",
        ),
    };
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f8fafc; color: #0f172a; margin: 0; padding: 2rem; }}
  .card {{ max-width: 32rem; margin: 2rem auto; background: #fff; border-radius: 12px;
          padding: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  h1 {{ font-size: 1.25rem; margin: 0 0 1rem; }}
  p {{ margin: 0; line-height: 1.5; color: #475569; }}
</style>
</head>
<body>
  <main class="card" role="alert">
    <h1>{title}</h1>
    <p>{body}</p>
  </main>
</body>
</html>"#
    );
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

// ── Shared single-monitor view ────────────────────────────────────────────

/// Minimal read-only snapshot for the shared-monitor capability URL
/// (`/shared/{token}`). Mirrors the per-component slice of
/// [`PublicStatusPage`] for a single target, without the page-oriented
/// framing (groups, site name, maintenance, incidents) — a shared monitor
/// is a single monitor's lens, not a status page.
#[derive(Debug, Clone, Serialize)]
struct SharedMonitorView {
    /// The target's operator-facing name, used as the public display name.
    /// A dedicated `public_display_name` override isn't modelled for
    /// standalone shares — the monitor name is the headline.
    pub public_display_name: String,
    /// Current status derived from the latest check result. Falls back to
    /// `Operational` when the target has no recorded checks.
    pub current_status: PublicComponentStatus,
    /// Last 100 check results, newest-first, for the latency chart.
    pub recent_results: Vec<CheckResult>,
    /// 90-day day-strip history, oldest-first (matches `PublicComponent`).
    pub history: Vec<DayState>,
}

/// `GET /shared/{token}` — resolve a share token and return the target's
/// current status snapshot. The token is the raw capability URL segment;
/// it is hashed with `sha256_hex` and looked up against the stored hash.
///
/// Returns:
/// - `404 SHARE_NOT_FOUND` if the token is unknown, expired, or revoked.
/// - `404 TARGET_NOT_FOUND` if the share resolves but its target was
///   deleted after the share was minted (treat as not found rather than
///   a 500 — the link is effectively dead).
/// - `200` with [`SharedMonitorView`] on success.
///
/// Each resolve atomically increments the share's `view_count` and stamps
/// `last_viewed_at`, so the operator can see how often a link was opened.
async fn get_shared_monitor(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError(statuscore::error::AppError::NotFound {
            code: "SHARE_NOT_FOUND",
            message: "share token is invalid or expired".to_string(),
        }));
    }
    // Hash the raw token and resolve. The raw token is never stored; only
    // its sha256_hex is persisted, so the lookup is by hash.
    let token_hash = statuscore::domain::hash_cookie_value(token);
    let resolved = state.storage.resolve_monitor_share(&token_hash).await?.ok_or_else(|| {
        ApiError(statuscore::error::AppError::NotFound {
            code: "SHARE_NOT_FOUND",
            message: "share token is invalid or expired".to_string(),
        })
    })?;

    // Load the target. A deleted target means the share is effectively
    // dead — surface 404 rather than a 500.
    let target = state.storage.get_target(resolved.target_id).await?;

    // Current status from the latest check result.
    let latest = state.storage.list_results(target.id, 1).await?;
    let current_status = latest
        .first()
        .map_or(PublicComponentStatus::Operational, |r| component_status_from_result(r.status));

    // Last 100 results for the latency chart (newest-first, matching the
    // storage contract).
    let recent_results = state.storage.list_results(target.id, 100).await?;

    // 90-day day-strip history, oldest-first (matches `PublicComponent`).
    let to = Utc::now();
    let from = to - ChronoDuration::days(90);
    let history = state
        .storage
        .component_day_history(target.id, from, to)
        .await?
        .into_iter()
        .map(|h| h.state)
        .collect();

    Ok(Json(SharedMonitorView {
        public_display_name: target.name,
        current_status,
        recent_results,
        history,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use statuscore::domain::{
        IncidentSeverity, IncidentStatusPhase, PublicIncident, PublicIncidentUpdate,
    };

    fn make_incident(
        id: Uuid,
        title: &str,
        started_at: chrono::DateTime<Utc>,
        severity: IncidentSeverity,
        phase: IncidentStatusPhase,
    ) -> PublicIncident {
        PublicIncident {
            id,
            component_id: Uuid::nil(),
            component_name: String::new(),
            title: title.to_string(),
            started_at,
            ended_at: None,
            severity,
            status_phase: phase,
            updates: Vec::new(),
            postmortem: None,
        }
    }

    #[test]
    fn render_rss_xml_empty_items_is_valid_skeleton() {
        let xml = render_rss_xml(
            "My Page — Incident History",
            "https://status.example.com",
            "desc",
            "Sat, 26 Jul 2026 12:00:00 +0000",
            "https://status.example.com",
            &[],
        );
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<rss version=\"2.0\">"));
        assert!(xml.contains("<title>My Page — Incident History</title>"));
        assert!(xml.contains("<generator>statuspage</generator>"));
        // No <item> elements when the input is empty.
        assert!(!xml.contains("<item>"));
        assert!(xml.contains("</channel>\n</rss>"));
    }

    #[test]
    fn render_rss_xml_renders_items_with_link_and_pubdate() {
        let id = Uuid::nil();
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let inc = make_incident(
            id,
            "API outage",
            started_at,
            IncidentSeverity::Major,
            IncidentStatusPhase::Investigating,
        );
        let xml = render_rss_xml(
            "Page",
            "https://status.example.com",
            "desc",
            "Sat, 26 Jul 2026 12:00:00 +0000",
            "https://status.example.com",
            &[inc],
        );
        let expected_pub_date = started_at.to_rfc2822();
        assert!(xml.contains("<title>API outage</title>"));
        assert!(xml.contains(
            "<link>https://status.example.com/incidents/00000000-0000-0000-0000-000000000000</link>"
        ));
        assert!(xml.contains("<guid isPermaLink=\"true\">https://status.example.com/incidents/"));
        assert!(xml.contains(&format!("<pubDate>{expected_pub_date}</pubDate>")));
        assert!(xml.contains("Severity: major — Phase: investigating"));
    }

    #[test]
    fn render_rss_xml_escapes_special_characters() {
        let inc = make_incident(
            Uuid::nil(),
            "Alert: <script>\"xss\"</script> & more",
            Utc::now(),
            IncidentSeverity::Minor,
            IncidentStatusPhase::Resolved,
        );
        let xml = render_rss_xml(
            "Page",
            "https://status.example.com",
            "desc",
            "Sat, 26 Jul 2026 12:00:00 +0000",
            "https://status.example.com",
            &[inc],
        );
        // `xml_escape` escapes `& < > "` (apostrophes are intentionally not
        // escaped; we always use double quotes for attributes).
        assert!(xml.contains("&lt;script&gt;"));
        assert!(xml.contains("&quot;xss&quot;"));
        assert!(xml.contains("&amp; more"));
        // The raw unescaped form must not appear.
        assert!(!xml.contains("<script>"));
    }

    #[test]
    fn render_rss_xml_includes_latest_update_in_description() {
        let now = Utc::now();
        let mut inc = make_incident(
            Uuid::nil(),
            "DB outage",
            now,
            IncidentSeverity::Critical,
            IncidentStatusPhase::Monitoring,
        );
        inc.updates.push(PublicIncidentUpdate {
            posted_at: now,
            phase: IncidentStatusPhase::Monitoring,
            message: "We are watching recovery.".to_string(),
        });
        let xml = render_rss_xml(
            "Page",
            "https://status.example.com",
            "desc",
            "Sat, 26 Jul 2026 12:00:00 +0000",
            "https://status.example.com",
            &[inc],
        );
        assert!(xml.contains("We are watching recovery."));
        assert!(xml.contains("Phase: monitoring"));
    }
}
