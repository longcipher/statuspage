//! Public status page — modern, production-grade status dashboard.
//!
//! Renders the public status page snapshot from `GET /api/public/v1/status`.
//! Unauthenticated; mounted at `/p` outside the auth guard so anyone with the
//! URL can see the current status.
//!
//! Layout:
//!   1. **Header** — logo placeholder, site name, "Last updated" timestamp,
//!      subscribe button, timezone indicator, theme toggle.
//!   2. **Hero status banner** — pulsing status dot + large status text.
//!   3. **Component groups** — collapsible groups, each with a 90-day uptime
//!      grid. Hovering any day bar shows a rich tooltip (date, status, uptime).
//!   4. **Active incidents** — ongoing incidents with timeline updates.
//!   5. **Past incidents** — resolved incidents grouped by month.

use chrono::{DateTime, Datelike, Duration as ChronoDuration, Utc};
use leptos::either::Either;
use leptos::prelude::*;
use statuscore::domain::public::{
    DayState, OverallState, PublicComponent, PublicComponentGroup, PublicComponentStatus,
    PublicIncident, PublicIncidentUpdate, PublicStatusPage,
};

use crate::api::client;
use crate::components::error_state::{EmptyState, ErrorCallout, SkeletonDetail};
use crate::components::theme_toggle::ThemeToggle;

/// WASM-safe `Utc::now()`. `chrono::Utc::now()` panics on `wasm32` unless the
/// `wasmbind` feature is wired through the entire dependency graph; calling
/// `js_sys::Date::new_0()` directly avoids the `std::time::SystemTime` path.
fn now_utc() -> DateTime<Utc> {
    #[cfg(target_arch = "wasm32")]
    {
        DateTime::<Utc>::from(js_sys::Date::new_0())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Utc::now()
    }
}

/// Format a UTC timestamp as a human-readable "X minutes ago" string.
fn relative_time(ts: DateTime<Utc>) -> String {
    let now = now_utc();
    let delta = now.signed_duration_since(ts);
    let mins = delta.num_minutes();
    if mins < 1 {
        "just now".to_string()
    } else if mins < 60 {
        format!("{mins} min ago")
    } else if mins < 1440 {
        format!("{}h ago", mins / 60)
    } else {
        format!("{}d ago", mins / 1440)
    }
}

#[component]
pub fn PublicStatusPage() -> impl IntoView {
    let snapshot = LocalResource::new(|| async { client::get_public_status().await });

    view! {
      <div class="sp-public">
        <Suspense fallback=|| {
          view! { <SkeletonDetail label="Loading status page..." /> }
        }>
          {move || {
            snapshot
              .get()
              .map(|res| match res {
                Err(e) => {
                  Either::Left(
                    view! {
                      <ErrorCallout
                        title="Failed to load status page"
                        errors=vec![e]
                        on_retry=Box::new(move || snapshot.refetch())
                      />
                    },
                  )
                }
                Ok(page) => Either::Right(view! { <PublicStatusPageBody page=page /> }),
              })
          }}
        </Suspense>
      </div>
    }
}

#[component]
fn PublicStatusPageBody(page: PublicStatusPage) -> impl IntoView {
    let generated_at = page.generated_at;
    let last_updated = relative_time(generated_at);
    let overall_state = page.overall.state;
    let overall_label = page.overall.label.clone();
    let groups = page.groups.clone();
    let active_incidents = page.active_incidents.clone();
    let recent_incidents = page.recent_incidents.clone();

    view! {
      <PublicHeader site_name=page.site_name last_updated=last_updated />
      <main class="sp-main">
        <HeroStatusBanner state=overall_state label=overall_label />
        <ComponentGroups groups=groups generated_at=generated_at />
        <ActiveIncidentsSection incidents=active_incidents />
        <PastIncidentsSection incidents=recent_incidents />
        <PublicFooter />
      </main>
    }
}

// ── Header ────────────────────────────────────────────────────────────────

#[component]
fn PublicHeader(site_name: String, last_updated: String) -> impl IntoView {
    view! {
      <header class="sp-header">
        <div class="sp-header-inner">
          <div class="sp-header-brand">
            <div class="sp-logo" aria-hidden="true">
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2.5"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <path d="M12 2L2 7l10 5 10-5-10-5z" />
                <path d="M2 17l10 5 10-5" />
                <path d="M2 12l10 5 10-5" />
              </svg>
            </div>
            <div class="sp-header-titles">
              <h1 class="sp-site-name">{site_name}</h1>
              <p class="sp-last-updated">
                <svg
                  class="sp-icon-sm"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="10" />
                  <polyline points="12 6 12 12 16 14" />
                </svg>
                {format!("Updated {last_updated}")}
              </p>
            </div>
          </div>
          <div class="sp-header-actions">
            <span class="sp-tz" title="Timezone">
              <svg
                class="sp-icon-sm"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <circle cx="12" cy="12" r="10" />
                <line x1="2" y1="12" x2="22" y2="12" />
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
              </svg>
              "UTC"
            </span>
            <button class="sp-btn sp-btn-subscribe" type="button" aria-label="Subscribe to updates">
              <svg
                class="sp-icon-sm"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              <span class="sp-btn-label">Subscribe</span>
            </button>
            <ThemeToggle />
          </div>
        </div>
      </header>
    }
}

// ── Hero status banner ───────────────────────────────────────────────────

#[component]
fn HeroStatusBanner(state: OverallState, label: String) -> impl IntoView {
    let (dot_cls, sub) = match state {
        OverallState::Operational => {
            ("sp-hero-dot sp-hero-dot--ok", "All services are running normally.")
        }
        OverallState::Maintenance => {
            ("sp-hero-dot sp-hero-dot--maint", "Scheduled maintenance is in progress.")
        }
        OverallState::MinorDisruption => {
            ("sp-hero-dot sp-hero-dot--warn", "Some services are experiencing minor issues.")
        }
        OverallState::PartialOutage => {
            ("sp-hero-dot sp-hero-dot--warn", "Some services are partially degraded.")
        }
        OverallState::MajorOutage => {
            ("sp-hero-dot sp-hero-dot--bad", "Major service disruption is ongoing.")
        }
        _ => ("sp-hero-dot sp-hero-dot--unknown", "System status is being determined."),
    };

    let icon_svg = match state {
        OverallState::Operational => Either::Left(view! {
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        }),
        OverallState::Maintenance => Either::Right(Either::Left(view! {
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
          </svg>
        })),
        OverallState::MinorDisruption | OverallState::PartialOutage | OverallState::MajorOutage => {
            Either::Right(Either::Right(Either::Left(view! {
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2.5"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
            })))
        }
        _ => Either::Right(Either::Right(Either::Right(view! {
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        }))),
    };

    view! {
      <section class="sp-hero" class:sp-hero--ok={state == OverallState::Operational}
               class:sp-hero--warn={matches!(state, OverallState::MinorDisruption | OverallState::PartialOutage)}
               class:sp-hero--bad={state == OverallState::MajorOutage}
               class:sp-hero--maint={state == OverallState::Maintenance}
               role="status" aria-live="polite">
        <div class="sp-hero-inner">
          <span class={dot_cls} aria-hidden="true">
            <span class="sp-hero-pulse"></span>
          </span>
          <div class="sp-hero-text">
            <div class="sp-hero-icon" aria-hidden="true">{icon_svg}</div>
            <h2 class="sp-hero-title">{label}</h2>
            <p class="sp-hero-sub">{sub}</p>
          </div>
        </div>
      </section>
    }
}

// ── Component groups ─────────────────────────────────────────────────────

#[component]
fn ComponentGroups(
    groups: Vec<PublicComponentGroup>,
    generated_at: DateTime<Utc>,
) -> impl IntoView {
    if groups.is_empty() {
        return Either::Left(view! {
          <EmptyState
            title="No components published"
            message="This status page has no components yet."
          />
        });
    }
    Either::Right(
        groups
            .into_iter()
            .map(|g| view! { <ComponentGroup group=g generated_at=generated_at /> })
            .collect::<Vec<_>>(),
    )
}

#[component]
fn ComponentGroup(group: PublicComponentGroup, generated_at: DateTime<Utc>) -> impl IntoView {
    let group_name = group.name.clone().unwrap_or_else(|| "Components".to_string());
    let components = group.components;
    let component_count = components.len();
    let all_op = components.iter().all(|c| c.current_status == PublicComponentStatus::Operational);
    let summary = if all_op { "All operational" } else { "Issues detected" };

    view! {
      <section class="sp-group">
        <div class="sp-group-header">
          <div class="sp-group-titles">
            <h3 class="sp-group-name">{group_name}</h3>
            <span class="sp-group-summary" class:sp-group-summary--ok={all_op}>
              {summary}
              <span class="sp-group-count">{format!("{} {}", component_count, if component_count == 1 { "service" } else { "services" })}</span>
            </span>
          </div>
        </div>
        <div class="sp-group-body">
          {components
            .into_iter()
            .map(|c| view! { <ComponentRow component=c generated_at=generated_at /> })
            .collect::<Vec<_>>()}
        </div>
      </section>
    }
}

#[component]
fn ComponentRow(component: PublicComponent, generated_at: DateTime<Utc>) -> impl IntoView {
    let PublicComponent { name, current_status, history, .. } = component;
    let status_label = component_status_label(current_status);
    let status_cls = component_status_class(current_status);

    // Fix uptime: exclude NoData days from the denominator. A monitor that
    // was just created should not show "1.1% uptime" just because 89 of 90
    // days have no data. Days with data are counted; NoData is transparent.
    let days_with_data = history.iter().filter(|d| !matches!(d, DayState::NoData)).count();
    let up_days = history.iter().filter(|d| matches!(d, DayState::Operational)).count();
    let uptime_pct = if days_with_data == 0 {
        None // Show "—" when no data at all
    } else {
        Some((up_days as f64 / days_with_data as f64) * 100.0)
    };
    let uptime_label = match uptime_pct {
        None => "—".to_string(),
        Some(p) if p >= 99.99 => "100%".to_string(),
        Some(p) => format!("{p:.2}%"),
    };

    view! {
      <div class="sp-comp">
        <div class="sp-comp-head">
          <div class="sp-comp-id">
            <span class=format!("sp-comp-dot sp-comp-dot--{status_cls}") aria-hidden="true"></span>
            <span class="sp-comp-name">{name}</span>
            <span class=format!("sp-comp-badge sp-comp-badge--{status_cls}")>{status_label}</span>
          </div>
          <div class="sp-comp-meta">
            <span class="sp-comp-uptime" title="Uptime over the last 90 days">
              {uptime_label}
              <span class="sp-comp-uptime-label">uptime</span>
            </span>
          </div>
        </div>
        <UptimeGrid history=history generated_at=generated_at />
      </div>
    }
}

// ── Uptime grid with tooltips ────────────────────────────────────────────

#[component]
fn UptimeGrid(history: Vec<DayState>, generated_at: DateTime<Utc>) -> impl IntoView {
    let total = history.len();
    // The history is oldest-first, 90 days. The last entry corresponds to
    // `generated_at` (today). Day[i] = generated_at - (total - 1 - i) days.
    let start_date =
        generated_at.date_naive() - ChronoDuration::days((total.saturating_sub(1)) as i64);

    view! {
      <div class="sp-uptime" role="group" aria-label="90-day uptime history">
        <div class="sp-uptime-grid">
          {history
            .iter()
            .enumerate()
            .map(|(i, day)| {
              let date = start_date + ChronoDuration::days(i as i64);
              let cls = day_cell_class(*day);
              let tooltip = format!("{} • {}", date.format("%B %-d, %Y"), day_label(*day));
              view! {
                <span
                  class=format!("sp-uptime-bar {cls}")
                  data-tooltip=tooltip.clone()
                  role="img"
                  aria-label=tooltip
                ></span>
              }
            })
            .collect::<Vec<_>>()}
        </div>
        <div class="sp-uptime-axis">
          <span>{start_date.format("%b %-d").to_string()}</span>
          <span>{(start_date + ChronoDuration::days(30)).format("%b %-d").to_string()}</span>
          <span>{(start_date + ChronoDuration::days(60)).format("%b %-d").to_string()}</span>
          <span>{generated_at.format("%b %-d").to_string()}</span>
        </div>
      </div>
    }
}

// ── Active incidents ─────────────────────────────────────────────────────

#[component]
fn ActiveIncidentsSection(incidents: Vec<PublicIncident>) -> impl IntoView {
    if incidents.is_empty() {
        return Either::Left(view! {
          <section class="sp-section">
            <div class="sp-section-head">
              <h3 class="sp-section-title">"Active Incidents"</h3>
            </div>
            <div class="sp-empty-card">
              <svg
                class="sp-empty-icon"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
              <p>"No active incidents reported"</p>
            </div>
          </section>
        });
    }
    Either::Right(view! {
      <section class="sp-section">
        <div class="sp-section-head">
          <h3 class="sp-section-title">"Active Incidents"</h3>
          <span class="sp-section-count">{format!("{} ongoing", incidents.len())}</span>
        </div>
        <div class="sp-incident-list">
          {incidents.into_iter().map(|i| view! { <IncidentCard incident=i /> }).collect::<Vec<_>>()}
        </div>
      </section>
    })
}

// ── Past incidents grouped by month ──────────────────────────────────────

#[component]
fn PastIncidentsSection(incidents: Vec<PublicIncident>) -> impl IntoView {
    if incidents.is_empty() {
        return Either::Left(view! {
          <section class="sp-section">
            <div class="sp-section-head">
              <h3 class="sp-section-title">"Past Incidents"</h3>
            </div>
            <div class="sp-empty-card">
              <p class="sp-empty-text">"No past incidents to show."</p>
            </div>
          </section>
        });
    }

    // Group incidents by (year, month) of started_at.
    let mut groups: Vec<(i32, u32, Vec<PublicIncident>)> = Vec::new();
    for inc in incidents {
        let y = inc.started_at.year();
        let m = inc.started_at.month();
        if let Some(g) = groups.iter_mut().find(|(gy, gm, _)| *gy == y && *gm == m) {
            g.2.push(inc);
        } else {
            groups.push((y, m, vec![inc]));
        }
    }
    // Sort newest month first (descending by (year, month)).
    groups.sort_by_key(|(y, m, _)| std::cmp::Reverse((*y, *m)));

    Either::Right(view! {
      <section class="sp-section">
        <div class="sp-section-head">
          <h3 class="sp-section-title">"Past Incidents"</h3>
        </div>
        {groups
          .into_iter()
          .map(|(y, m, incs)| {
            let month_label = month_name(y, m);
            view! {
              <div class="sp-month-group">
                <h4 class="sp-month-label">{month_label}</h4>
                <div class="sp-incident-list">
                  {incs
                    .into_iter()
                    .map(|i| view! { <IncidentCard incident=i /> })
                    .collect::<Vec<_>>()}
                </div>
              </div>
            }
          })
          .collect::<Vec<_>>()}
      </section>
    })
}

// ── Incident card with timeline ──────────────────────────────────────────

#[component]
fn IncidentCard(incident: PublicIncident) -> impl IntoView {
    let severity_cls = match incident.severity {
        statuscore::domain::public::IncidentSeverity::Critical => "crit",
        statuscore::domain::public::IncidentSeverity::Major => "maj",
        statuscore::domain::public::IncidentSeverity::Minor => "min",
        _ => "unknown",
    };
    let updates = incident.updates.clone();

    view! {
      <article class=format!("sp-incident sp-incident--{severity_cls}")>
        <div class="sp-incident-head">
          <div class="sp-incident-titles">
            <span class=format!(
              "sp-severity sp-severity--{severity_cls}",
            )>{severity_label(incident.severity)}</span>
            <h4 class="sp-incident-title">{incident.title}</h4>
          </div>
          <time class="sp-incident-date">
            {incident.started_at.format("%b %-d, %Y").to_string()}
          </time>
        </div>
        {if updates.is_empty() {
          Either::Left(())
        } else {
          Either::Right(
            view! {
              <ol class="sp-timeline">
                {updates
                  .into_iter()
                  .map(|u| view! { <TimelineEntry update=u /> })
                  .collect::<Vec<_>>()}
              </ol>
            },
          )
        }}
      </article>
    }
}

#[component]
fn TimelineEntry(update: PublicIncidentUpdate) -> impl IntoView {
    let (phase_cls, phase_icon) = phase_visual(update.phase);
    view! {
      <li class="sp-timeline-item">
        <div class=format!("sp-timeline-marker {phase_cls}") aria-hidden="true">
          {phase_icon}
        </div>
        <div class="sp-timeline-body">
          <div class="sp-timeline-meta">
            <span class=format!("sp-phase sp-phase--{phase_cls}")>{phase_label(update.phase)}</span>
            <time class="sp-timeline-time">
              {update.posted_at.format("%b %-d, %H:%M UTC").to_string()}
            </time>
          </div>
          <p class="sp-timeline-msg">{update.message}</p>
        </div>
      </li>
    }
}

// ── Footer ───────────────────────────────────────────────────────────────

#[component]
fn PublicFooter() -> impl IntoView {
    view! {
      <footer class="sp-footer">
        <div class="sp-footer-inner">
          <span class="sp-footer-text">
            <svg
              class="sp-icon-sm"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            "Powered by StatusPage"
          </span>
          <button
            class="sp-btn sp-btn-ghost"
            type="button"
            on:click=move |_| {
              let _ = window().location().reload();
            }
          >
            <svg
              class="sp-icon-sm"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            "Refresh"
          </button>
        </div>
      </footer>
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

const fn day_cell_class(state: DayState) -> &'static str {
    match state {
        DayState::Operational => "sp-bar--op",
        DayState::Degraded => "sp-bar--deg",
        DayState::PartialOutage => "sp-bar--part",
        DayState::MajorOutage => "sp-bar--maj",
        DayState::Maintenance => "sp-bar--maint",
        DayState::NoData => "sp-bar--none",
        _ => "sp-bar--none",
    }
}

const fn day_label(state: DayState) -> &'static str {
    match state {
        DayState::Operational => "Operational",
        DayState::Degraded => "Degraded performance",
        DayState::PartialOutage => "Partial outage",
        DayState::MajorOutage => "Major outage",
        DayState::Maintenance => "Maintenance",
        DayState::NoData => "No data",
        _ => "Unknown",
    }
}

const fn component_status_label(s: PublicComponentStatus) -> &'static str {
    match s {
        PublicComponentStatus::Operational => "Operational",
        PublicComponentStatus::Degraded => "Degraded",
        PublicComponentStatus::PartialOutage => "Partial Outage",
        PublicComponentStatus::MajorOutage => "Major Outage",
        PublicComponentStatus::Maintenance => "Maintenance",
        _ => "Unknown",
    }
}

const fn component_status_class(s: PublicComponentStatus) -> &'static str {
    match s {
        PublicComponentStatus::Operational => "op",
        PublicComponentStatus::Degraded => "deg",
        PublicComponentStatus::PartialOutage => "part",
        PublicComponentStatus::MajorOutage => "maj",
        PublicComponentStatus::Maintenance => "maint",
        _ => "unknown",
    }
}

const fn severity_label(s: statuscore::domain::public::IncidentSeverity) -> &'static str {
    match s {
        statuscore::domain::public::IncidentSeverity::Critical => "Critical",
        statuscore::domain::public::IncidentSeverity::Major => "Major",
        statuscore::domain::public::IncidentSeverity::Minor => "Minor",
        _ => "Unknown",
    }
}

const fn phase_label(p: statuscore::domain::public::IncidentStatusPhase) -> &'static str {
    match p {
        statuscore::domain::public::IncidentStatusPhase::Investigating => "Investigating",
        statuscore::domain::public::IncidentStatusPhase::Identified => "Identified",
        statuscore::domain::public::IncidentStatusPhase::Monitoring => "Monitoring",
        statuscore::domain::public::IncidentStatusPhase::Resolved => "Resolved",
        statuscore::domain::public::IncidentStatusPhase::Postmortem => "Postmortem",
        _ => "Unknown",
    }
}

const fn phase_visual(
    p: statuscore::domain::public::IncidentStatusPhase,
) -> (&'static str, &'static str) {
    match p {
        statuscore::domain::public::IncidentStatusPhase::Investigating => ("invest", "🔍"),
        statuscore::domain::public::IncidentStatusPhase::Identified => ("ident", "🎯"),
        statuscore::domain::public::IncidentStatusPhase::Monitoring => ("mon", "👁"),
        statuscore::domain::public::IncidentStatusPhase::Resolved => ("resolved", "✓"),
        statuscore::domain::public::IncidentStatusPhase::Postmortem => ("pm", "📋"),
        _ => ("unknown", "?"),
    }
}

fn month_name(y: i32, m: u32) -> String {
    let names = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let idx = (m as usize).saturating_sub(1).min(11);
    format!("{} {}", names[idx], y)
}
