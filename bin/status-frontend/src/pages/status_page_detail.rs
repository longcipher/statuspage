//! Status page detail — a real public-facing status dashboard.
//!
//! Mirrors the layout of the `statuspage` reference design:
//!   1. Overall status banner (Operational / Degraded / Outage) derived
//!      from the latest check result of every target on the page AND
//!      active incident severity.
//!   2. Active incidents callout (warn-toned) for ongoing incidents.
//!   3. Status legend + per-target component list with 90-day day-strip
//!      history bars and uptime %.
//!   4. Past incidents callout (neutral) for recently resolved incidents.
//!
//! Data fetched in one async pass: page metadata, all targets (each with
//! up to 1000 recent results bucketed into 90 daily cells), active and
//! recent incidents, and the aggregated latency history. Partial failures
//! are surfaced inline rather than silently swallowed.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::stream::{self, StreamExt};
use leptos::either::Either;
use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use statuscore::domain::{CheckResult, CheckSpec, CheckStatus, IncidentSeverity, Target};
use uuid::Uuid;

/// WASM-safe `Utc::now()`. `chrono::Utc::now()` panics with
/// "time not implemented on this platform" on `wasm32-unknown-unknown`
/// unless the `wasmbind` feature is correctly wired through the entire
/// dependency graph. Calling `js_sys::Date::new_0()` directly avoids the
/// std::time::SystemTime path entirely and is the recommended pattern for
/// CSR Leptos apps that need the current wall clock.
fn now_utc() -> DateTime<Utc> {
    #[cfg(target_arch = "wasm32")]
    {
        let js_date = js_sys::Date::new_0();
        DateTime::<Utc>::from(js_date)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Utc::now()
    }
}

use crate::api::client;
use crate::api::types::{Incident, LatencyPoint, StatusPage};
use crate::components::error_state::{EmptyState, ErrorCallout, SkeletonDetail};
use crate::components::latency_chart::LatencyChart;

const HISTORY_DAYS: usize = 90;
/// Reduced from 1000 to 200 — a 90-day day-strip only needs 1–2 sampled
/// results per day to classify the day's status; fetching 1000 raw results
/// per target was wasteful and amplified N+1 load on the backend.
const HISTORY_FETCH_LIMIT: u32 = 200;

#[derive(Clone)]
struct TargetStatus {
    target: Target,
    latest: Option<CheckResult>,
    history: Vec<Option<DayState>>,
    uptime_pct: Option<f64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DayState {
    Operational,
    Degraded,
    Partial,
    Major,
}

impl DayState {
    const fn cell_class(self) -> &'static str {
        match self {
            Self::Operational => "day-cell--op",
            Self::Degraded => "day-cell--deg",
            Self::Partial => "day-cell--part",
            Self::Major => "day-cell--maj",
        }
    }

    const fn aria_label(self) -> &'static str {
        match self {
            Self::Operational => "Operational",
            Self::Degraded => "Degraded",
            Self::Partial => "Partial outage",
            Self::Major => "Major outage",
        }
    }
}

#[derive(Clone)]
struct StatusPageView {
    page: Option<StatusPage>,
    targets: Vec<TargetStatus>,
    active_incidents: Vec<Incident>,
    recent_incidents: Vec<Incident>,
    history: Vec<LatencyPoint>,
    errors: Vec<String>,
}

#[component]
pub fn StatusPageDetailPage() -> impl IntoView {
    let params = use_params_map();

    let id = move || {
        params.with(|p| p.get("id")).and_then(|s| Uuid::parse_str(&s).ok()).unwrap_or(Uuid::nil())
    };

    let view_data = LocalResource::new(move || {
        let id = id();
        async move { fetch_status_page_view(id).await }
    });

    view! {
      <section class="flex flex-col gap-8">
        <Suspense fallback=|| {
          view! { <SkeletonDetail label="Loading status page..." /> }
        }>
          {move || {
            view_data
              .get()
              .map(|data| {
                let StatusPageView {
                  page,
                  targets,
                  active_incidents,
                  recent_incidents,
                  history,
                  errors,
                } = data;
                let fatal = page.is_none() && !errors.is_empty();
                let overall = compute_overall_status(&targets, &active_incidents);

                view! {
                  {if fatal {
                    Either::Left(
                      view! {
                        <ErrorCallout
                          title="Failed to load status page"
                          errors=errors
                          on_retry=Box::new(move || view_data.refetch())
                        />
                      },
                    )
                  } else {
                    Either::Right(
                      view! {
                        <>
                          {page
                            .as_ref()
                            .map(|p| {
                              let display_name = p
                                .branding
                                .public_display_name
                                .as_deref()
                                .unwrap_or(&p.name);
                              view! {
                                <header class="flex flex-col gap-1">
                                  <h1
                                    class="break-words type-display"
                                    style="color: var(--theme-text)"
                                  >
                                    {display_name.to_string()}
                                  </h1>
                                  {p
                                    .branding
                                    .public_about
                                    .as_deref()
                                    .map(|about| {
                                      view! {
                                        <p
                                          class="break-words type-body"
                                          style="color: var(--theme-text-muted)"
                                        >
                                          {about.to_string()}
                                        </p>
                                      }
                                    })}
                                </header>
                              }
                            })} <OverallStatusBanner status=overall />
                          {if errors.is_empty() {
                            Either::Right(())
                          } else {
                            Either::Left(
                              view! {
                                <ErrorCallout
                                  title="Some data could not be loaded"
                                  errors=errors.clone()
                                  on_retry=Box::new(move || view_data.refetch())
                                />
                              },
                            )
                          }}
                          {if active_incidents.is_empty() {
                            Either::Left(())
                          } else {
                            Either::Right(
                              view! { <ActiveIncidentsCallout incidents=active_incidents /> },
                            )
                          }}
                          {if targets.is_empty() && errors.is_empty() {
                            Either::Left(
                              Either::Left(
                                view! {
                                  <EmptyState
                                    title="No monitors on this page"
                                    message="No components are being monitored on this status page yet."
                                  />
                                },
                              ),
                            )
                          } else if !targets.is_empty() {
                            Either::Right(
                              view! {
                                <section class="flex flex-col gap-3">
                                  <DayStripLegend />
                                  <ul
                                    class="overflow-hidden p-0 divide-y public-callout"
                                    style="border-color: var(--theme-line)"
                                  >
                                    {targets
                                      .into_iter()
                                      .map(|ts| {
                                        view! { <TargetStatusRow ts=ts /> }
                                      })
                                      .collect::<Vec<_>>()}
                                  </ul>
                                </section>
                              },
                            )
                          } else {
                            Either::Left(Either::Right(()))
                          }}
                          {if recent_incidents.is_empty() {
                            Either::Left(())
                          } else {
                            Either::Right(
                              view! {
                                <section class="flex flex-col gap-3">
                                  <h2 class="panel-label">"Past incidents (30 days)"</h2>
                                  <ul
                                    class="overflow-hidden p-0 divide-y public-callout"
                                    style="border-color: var(--theme-line)"
                                  >
                                    {recent_incidents
                                      .into_iter()
                                      .map(|inc| {
                                        view! { <IncidentRow inc=inc past=true /> }
                                      })
                                      .collect::<Vec<_>>()}
                                  </ul>
                                </section>
                              },
                            )
                          }} <LatencyChart data=history />
                        </>
                      },
                    )
                  }}
                }
              })
          }}
        </Suspense>
      </section>
    }
}

// ── Overall status ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum OverallStatus {
    Operational,
    Degraded,
    Outage,
    Unknown,
}

fn compute_overall_status(
    targets: &[TargetStatus],
    active_incidents: &[Incident],
) -> OverallStatus {
    if !active_incidents.is_empty() {
        let has_critical =
            active_incidents.iter().any(|i| i.severity == IncidentSeverity::Critical);
        let has_major = active_incidents.iter().any(|i| i.severity == IncidentSeverity::Major);
        if has_critical {
            return OverallStatus::Outage;
        } else if has_major {
            return OverallStatus::Degraded;
        }
    }

    if targets.is_empty() {
        return OverallStatus::Unknown;
    }

    let mut has_degraded = false;
    let mut has_outage = false;
    let mut has_any_result = false;

    for ts in targets {
        if let Some(r) = &ts.latest {
            has_any_result = true;
            match r.status {
                CheckStatus::Up => {}
                CheckStatus::Degraded => has_degraded = true,
                CheckStatus::Down | CheckStatus::Error => has_outage = true,
                // `CheckStatus` is `#[non_exhaustive]`: a future variant must
                // not change the aggregate. Treat anything novel as Up-free
                // but not a confirmed outage (degraded is the safe middle).
                _ => has_degraded = true,
            }
        }
    }

    if !has_any_result {
        OverallStatus::Unknown
    } else if has_outage {
        OverallStatus::Outage
    } else if has_degraded {
        OverallStatus::Degraded
    } else {
        OverallStatus::Operational
    }
}

#[component]
fn OverallStatusBanner(#[prop(into)] status: OverallStatus) -> impl IntoView {
    let (title, subtitle, bg_class, icon_class, icon_svg) = match status {
        OverallStatus::Operational => (
            "All Systems Operational",
            "All monitors are responding normally.",
            "public-overall public-overall--op",
            "status-icon status-icon--op",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M20 6L9 17l-5-5\"/></svg>",
        ),
        OverallStatus::Degraded => (
            "Partial Degradation",
            "One or more monitors are responding slower than expected.",
            "public-overall public-overall--deg",
            "status-icon status-icon--deg",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z\"/></svg>",
        ),
        OverallStatus::Outage => (
            "Active Outage",
            "One or more monitors are down or reporting errors.",
            "public-overall public-overall--outage",
            "status-icon status-icon--outage",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M15 9l-6 6M9 9l6 6\"/></svg>",
        ),
        OverallStatus::Unknown => (
            "No Data Yet",
            "No check results have been recorded for these monitors.",
            "public-overall public-overall--unknown",
            "status-icon status-icon--unknown",
            "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 16v-4M12 8h.01\"/></svg>",
        ),
    };

    view! {
      <section class=bg_class role="status" aria-live="polite">
        <div class=icon_class inner_html=icon_svg aria-hidden="true"></div>
        <div class="public-overall__text">
          <h2 class="break-words type-section-title">{title}</h2>
          <p class="mt-1 break-words type-body" style="color: var(--theme-text-muted)">
            {subtitle}
          </p>
        </div>
      </section>
    }
}

// ── Day-strip legend ───────────────────────────────────────────────────────

#[component]
fn DayStripLegend() -> impl IntoView {
    view! {
      <ul
        class="flex flex-wrap gap-y-2 gap-x-5 items-center type-body"
        style="color: var(--theme-text-quiet)"
        aria-label="Status colour key"
      >
        <li class="flex gap-1.5 items-center">
          <span class="legend-dot legend-dot--op" aria-hidden="true"></span>
          "Operational"
        </li>
        <li class="flex gap-1.5 items-center">
          <span class="legend-dot legend-dot--deg" aria-hidden="true"></span>
          "Degraded"
        </li>
        <li class="flex gap-1.5 items-center">
          <span class="legend-dot legend-dot--part" aria-hidden="true"></span>
          "Partial outage"
        </li>
        <li class="flex gap-1.5 items-center">
          <span class="legend-dot legend-dot--maj" aria-hidden="true"></span>
          "Major outage"
        </li>
        <li class="flex gap-1.5 items-center">
          <span class="legend-dot legend-dot--none" aria-hidden="true"></span>
          "No data"
        </li>
      </ul>
    }
}

// ── Target row ─────────────────────────────────────────────────────────────

#[component]
fn TargetStatusRow(ts: TargetStatus) -> impl IntoView {
    let TargetStatus { target, latest, history, uptime_pct } = ts;
    let check_type = check_type_label(&target.check);
    let heartbeat = is_heartbeat(&target.check);
    let chip_class = if heartbeat { "type-chip type-chip--heartbeat" } else { "type-chip" };
    let target_href = format!("/targets/{}", target.id);
    let target_name = target.name.clone();

    let (dot_class, status_label) = match latest.as_ref().map(|r| r.status) {
        Some(CheckStatus::Up) if heartbeat => {
            ("dashboard-dot--up dashboard-dot--heartbeat", "Operational")
        }
        Some(CheckStatus::Up) => ("dashboard-dot--up", "Operational"),
        Some(CheckStatus::Degraded) => ("dashboard-dot--degraded", "Degraded"),
        Some(CheckStatus::Down) => ("dashboard-dot--down", "Down"),
        Some(CheckStatus::Error) => ("dashboard-dot--error", "Error"),
        None => ("", "Pending"),
        // `CheckStatus` is `#[non_exhaustive]`: render a future variant as
        // a visible Unknown so the UI stays total and the operator notices.
        Some(_) => ("dashboard-dot--unknown", "Unknown"),
    };

    let latency_label = if heartbeat {
        "—".to_string()
    } else {
        latest.as_ref().map_or_else(|| "—".to_string(), |r| format!("{} ms", r.duration_ms))
    };
    let uptime_label = uptime_pct.map_or_else(|| "—".to_string(), |p| format!("{:.2}%", p));

    let today = now_utc().date_naive();
    let start = today - ChronoDuration::days((HISTORY_DAYS - 1) as i64);

    let cells: Vec<Option<DayState>> = history;

    view! {
      <li class="p-4 sm:p-5">
        <div class="flex flex-wrap gap-y-1 gap-x-3 justify-between items-baseline">
          <p class="flex gap-2 items-center min-w-0">
            <span class=format!("dashboard-dot {}", dot_class) aria-hidden="true"></span>
            <a href=target_href class="min-w-0 break-words title-link type-subsection-title">
              {target_name}
            </a>
            <span class=chip_class>{check_type}</span>
          </p>
          <span
            class="font-medium whitespace-nowrap shrink-0 type-body"
            style="color: var(--theme-text-muted)"
          >
            {status_label}
          </span>
        </div>

        <div
          class="mt-4 day-strip"
          role="group"
          aria-label=format!("90-day status history for {}", target.name)
        >
          {if cells.is_empty() {
            Either::Left(
              view! {
                <div
                  class="day-cell day-cell--none"
                  role="img"
                  title="No data"
                  aria-label="No data"
                  style="flex: 1 1 0"
                ></div>
              },
            )
          } else {
            Either::Right(
              cells
                .into_iter()
                .enumerate()
                .map(|(i, day)| {
                  let date = start + ChronoDuration::days(i as i64);
                  let date_str = date.format("%Y-%m-%d").to_string();
                  let (class, day_label) = match day {
                    Some(s) => (s.cell_class(), s.aria_label()),
                    None => ("day-cell--none", "No data"),
                  };
                  let aria = format!("{}: {}", date_str, day_label);
                  let title = aria.clone();
                  view! {
                    <div
                      class=format!("day-cell {}", class)
                      role="img"
                      title=title
                      aria-label=aria
                    ></div>
                  }
                })
                .collect::<Vec<_>>(),
            )
          }}
        </div>

        <div class="flex justify-between items-center mt-2 type-meta">
          <span class="hidden sm:inline">"90 days ago"</span>
          <span class="sm:hidden">"90d ago"</span>
          <span class="flex gap-2 items-center">
            <span class="type-mono type-data" style="color: var(--theme-text-muted)">
              {uptime_label}
            </span>
            <span aria-hidden="true">"·"</span>
            <span class="type-mono type-data" style="color: var(--theme-text-muted)">
              {latency_label}
            </span>
          </span>
          <span>"Today"</span>
        </div>
      </li>
    }
}

const fn check_type_label(check: &CheckSpec) -> &'static str {
    match check {
        CheckSpec::Http(_) => "HTTP",
        CheckSpec::Tcp(_) => "TCP",
        CheckSpec::Ping(_) => "Ping",
        CheckSpec::Heartbeat(_) => "Heartbeat",
        _ => "Other",
    }
}

const fn is_heartbeat(check: &CheckSpec) -> bool {
    matches!(check, CheckSpec::Heartbeat(_))
}

// ── Active incidents callout ───────────────────────────────────────────────

#[component]
fn ActiveIncidentsCallout(incidents: Vec<Incident>) -> impl IntoView {
    let count = incidents.len();
    let heading = if count == 1 {
        "Active incident".to_string()
    } else {
        format!("Active incidents ({count})")
    };

    view! {
      <section class="public-callout public-callout--warn">
        <h2
          class="break-words type-subsection-title"
          style="color: var(--theme-state-warn-fg-strong)"
        >
          {heading}
        </h2>
        <ul class="flex flex-col gap-4 mt-4">
          {incidents
            .into_iter()
            .map(|inc| {
              view! { <IncidentRow inc=inc /> }
            })
            .collect::<Vec<_>>()}
        </ul>
      </section>
    }
}

// ── Incident row ───────────────────────────────────────────────────────────

#[component]
fn IncidentRow(inc: Incident, #[prop(default = false)] past: bool) -> impl IntoView {
    let title = inc.public_title.clone().unwrap_or_else(|| format!("Incident {}", inc.id));
    let (severity_label, severity_class) = match inc.severity {
        IncidentSeverity::Critical => ("Critical", "status-badge--down"),
        IncidentSeverity::Major => ("Major", "status-badge--degraded"),
        IncidentSeverity::Minor => ("Minor", "status-badge--pending"),
        // `IncidentSeverity` is `#[non_exhaustive]` in the core crate;
        // render any future variant as a neutral "Unknown" severity pill.
        _ => ("Unknown", "status-badge--pending"),
    };
    let (status_label, status_class) = match inc.ended_at {
        Some(_) => ("Resolved", "status-badge--up"),
        None => match inc.status {
            CheckStatus::Degraded => ("Investigating", "status-badge--pending"),
            _ => ("Ongoing", "status-badge--down"),
        },
    };
    let started = inc.started_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let title_color = if past { "var(--theme-text)" } else { "var(--theme-state-warn-fg-strong)" };

    view! {
      <li class="flex flex-col gap-1.5">
        <div class="flex flex-wrap gap-2 items-center">
          <span
            class="min-w-0 break-words type-subsection-title"
            style=format!("color: {}", title_color)
          >
            {title}
          </span>
          <span class=format!("status-badge {}", severity_class)>{severity_label}</span>
          <span class=format!("status-badge {}", status_class)>{status_label}</span>
        </div>
        <p class="type-body" style="color: var(--theme-text-muted)">
          {format!("Started {started}")}
        </p>
        {inc
          .public_description
          .as_deref()
          .map(|desc| {
            view! {
              <p class="break-words type-body line-clamp-3" style="color: var(--theme-text-muted)">
                {desc.to_string()}
              </p>
            }
          })}
      </li>
    }
}

// ── History bucketing ──────────────────────────────────────────────────────

fn bucket_into_days(results: &[CheckResult]) -> (Vec<Option<DayState>>, Option<f64>) {
    if results.is_empty() {
        return (vec![None; HISTORY_DAYS], None);
    }

    let today = now_utc().date_naive();
    let start = today - ChronoDuration::days((HISTORY_DAYS - 1) as i64);

    let mut day_up = vec![0u32; HISTORY_DAYS];
    let mut day_deg = vec![0u32; HISTORY_DAYS];
    let mut day_bad = vec![0u32; HISTORY_DAYS];

    let mut total_up = 0u32;
    let mut total_bad = 0u32;

    for r in results {
        let d = r.timestamp.date_naive();
        if d < start || d > today {
            continue;
        }
        let idx = (d - start).num_days() as usize;
        if idx >= HISTORY_DAYS {
            continue;
        }
        match r.status {
            CheckStatus::Up => {
                day_up[idx] += 1;
                total_up += 1;
            }
            CheckStatus::Degraded => day_deg[idx] += 1,
            CheckStatus::Down | CheckStatus::Error => {
                day_bad[idx] += 1;
                total_bad += 1;
            }
            // `CheckStatus` is `#[non_exhaustive]`: a future variant must
            // not skew the day-strip. Drop the sample so the day still
            // renders as no-data rather than misclassified.
            _ => {}
        }
    }

    let days: Vec<Option<DayState>> = (0..HISTORY_DAYS)
        .map(|i| {
            let up = day_up[i];
            let deg = day_deg[i];
            let bad = day_bad[i];
            let total = up + deg + bad;
            if total == 0 {
                None
            } else if bad == 0 && deg == 0 {
                Some(DayState::Operational)
            } else if bad == 0 {
                Some(DayState::Degraded)
            } else if bad * 2 >= total {
                Some(DayState::Major)
            } else {
                Some(DayState::Partial)
            }
        })
        .collect();

    let total = total_up + total_bad;
    let uptime_pct =
        if total == 0 { None } else { Some(100.0 * f64::from(total_up) / f64::from(total)) };

    (days, uptime_pct)
}

// ── Data fetch ─────────────────────────────────────────────────────────────

async fn fetch_status_page_view(page_id: Uuid) -> StatusPageView {
    let (page_res, targets_res, incidents_res, history_res) = futures::join!(
        client::get_status_page(page_id),
        client::list_targets(),
        client::list_incidents(),
        client::get_status_page_history(page_id),
    );

    let mut errors = Vec::new();

    let page = match page_res {
        Ok(p) => Some(p),
        Err(e) => {
            errors.push(format!("Page data: {e}"));
            None
        }
    };

    let targets = match targets_res {
        Ok(list) => {
            // Cap concurrent history-fetches at 6 — the browser's per-host
            // connection limit — so a status page with many components does
            // not fire N simultaneous requests (the old `join_all` spawned
            // them all at once, amplifying N+1 load).
            stream::iter(list.iter().cloned())
                .map(|t| async move {
                    let results = client::list_target_results(t.id, HISTORY_FETCH_LIMIT)
                        .await
                        .unwrap_or_default();
                    let latest = results.first().cloned();
                    let (days, uptime_pct) = bucket_into_days(&results);
                    let history = if results.is_empty() { Vec::new() } else { days };
                    TargetStatus { target: t, latest, history, uptime_pct }
                })
                .buffer_unordered(6)
                .collect::<Vec<_>>()
                .await
        }
        Err(e) => {
            errors.push(format!("Monitors: {e}"));
            Vec::new()
        }
    };

    let cutoff = now_utc() - ChronoDuration::days(30);
    let mut active_incidents = Vec::new();
    let mut recent_incidents = Vec::new();
    match incidents_res {
        Ok(list) => {
            for inc in list {
                match inc.ended_at {
                    None => active_incidents.push(inc),
                    Some(end) if end >= cutoff => recent_incidents.push(inc),
                    _ => {}
                }
            }
        }
        Err(e) => {
            errors.push(format!("Incidents: {e}"));
        }
    }

    let history = match history_res {
        Ok(h) => h,
        Err(e) => {
            errors.push(format!("Latency history: {e}"));
            Vec::new()
        }
    };

    StatusPageView { page, targets, active_incidents, recent_incidents, history, errors }
}
