//! Targets list — calls `GET /api/v1/targets` and `GET /api/v1/targets/:id/results?limit=1`
//! to render a dashboard-style table with status dots and basic stats.
//!
//! Mirrors the reference design's `.dashboard-table` grid: status dot,
//! monitor name + address, type chip, interval, enabled badge, and the
//! latest check latency. Each row links to the detail view.

use futures::stream::{self, StreamExt};
use leptos::either::Either;
use leptos::prelude::*;

use statuscore::domain::{CheckResult, CheckSpec, CheckStatus, Target};

use crate::api::client;
use crate::components::error_state::{EmptyState, ErrorCallout, SkeletonList};
use crate::components::status_badge::EnabledBadge;

#[derive(Clone)]
struct TargetRow {
    target: Target,
    latest: Option<CheckResult>,
}

#[derive(Clone)]
struct TargetsView {
    rows: Vec<TargetRow>,
    error: Option<String>,
}

#[component]
pub fn TargetsListPage() -> impl IntoView {
    let rows = LocalResource::new(move || async { fetch_target_rows().await });

    view! {
      <section class="flex flex-col gap-5">
        <header class="flex flex-wrap gap-3 justify-between items-end">
          <div class="flex gap-3 items-center">
            <h1 class="type-page-title" style="color: var(--theme-text)">
              "Monitors"
            </h1>
          </div>
        </header>

        <Suspense fallback=|| {
          view! { <SkeletonList count=5 label="Loading monitors..." /> }
        }>
          {move || {
            rows
              .get()
              .map(|data| {
                let TargetsView { rows: table_rows, error } = data;
                let has_fatal_error = error.is_some() && table_rows.is_empty();

                view! {
                  {error
                    .as_ref()
                    .map(|e| {
                      let err = e.clone();
                      if table_rows.is_empty() {
                        view! {
                          <ErrorCallout
                            title="Failed to load monitors"
                            message=err
                            on_retry=Box::new(move || rows.refetch())
                          />
                        }
                      } else {
                        view! {
                          <ErrorCallout
                            title="Some data could not be loaded"
                            message=err
                            on_retry=Box::new(move || rows.refetch())
                          />
                        }
                      }
                    })}

                  {if has_fatal_error {
                    Either::Left(())
                  } else if table_rows.is_empty() {
                    Either::Right(
                      Either::Left(
                        view! {
                          <EmptyState
                            title="No monitors configured"
                            message="Add monitors via the API to start tracking uptime."
                          />
                        },
                      ),
                    )
                  } else {
                    Either::Right(
                      Either::Right(
                        view! {
                          <div class="overflow-hidden sticker-card">
                            <div
                              class="dashboard-table"
                              role="table"
                              aria-label="Monitors with status and latest latency"
                            >
                              <div class="dashboard-table__head" role="row">
                                <span role="columnheader" aria-label="Status"></span>
                                <span role="columnheader">"Monitor"</span>
                                <span role="columnheader">"Type"</span>
                                <span role="columnheader" class="hidden text-right sm:flex">
                                  "Interval"
                                </span>
                                <span role="columnheader" class="hidden text-right sm:flex">
                                  "Latency"
                                </span>
                                <span role="columnheader" class="text-right">
                                  "Enabled"
                                </span>
                              </div>
                              {table_rows
                                .into_iter()
                                .map(|row| {
                                  view! { <TargetListRow row=row /> }
                                })
                                .collect::<Vec<_>>()}
                            </div>
                          </div>
                        },
                      ),
                    )
                  }}
                }
              })
          }}
        </Suspense>
      </section>
    }
}

#[component]
fn TargetListRow(row: TargetRow) -> impl IntoView {
    let TargetRow { target, latest } = row;
    let target_href = format!("/targets/{}", target.id);
    let check_kind = check_kind_label(&target.check);
    let heartbeat = is_heartbeat(&target.check);
    let chip_class = if heartbeat { "type-chip type-chip--heartbeat" } else { "type-chip" };
    let address = check_address(&target.check);
    let interval_secs = target.interval.as_secs();

    let (dot_class, latency_label, status_text) = match latest.as_ref() {
        Some(r) => {
            let dot = match r.status {
                CheckStatus::Up if heartbeat => "dashboard-dot--up dashboard-dot--heartbeat",
                CheckStatus::Up => "dashboard-dot--up",
                CheckStatus::Degraded => "dashboard-dot--degraded",
                CheckStatus::Down => "dashboard-dot--down",
                CheckStatus::Error => "dashboard-dot--error",
                // `CheckStatus` is `#[non_exhaustive]`: a future variant
                // gets a neutral dot so the row still renders.
                _ => "dashboard-dot--unknown",
            };
            let label = if heartbeat { "—".to_string() } else { format!("{} ms", r.duration_ms) };
            let status = match r.status {
                CheckStatus::Up => "Operational",
                CheckStatus::Degraded => "Degraded",
                CheckStatus::Down => "Down",
                CheckStatus::Error => "Error",
                _ => "Unknown",
            };
            (dot, label, status.to_string())
        }
        None => ("", "—".to_string(), "No data yet".to_string()),
    };

    view! {
      <div class="dashboard-table__row" role="row">
        <span role="cell" aria-label=status_text>
          <span class=format!("dashboard-dot {}", dot_class) aria-hidden="true"></span>
        </span>
        <span role="cell" class="dashboard-table__monitor">
          <a href=target_href class="min-w-0 break-words row-link">
            {target.name}
          </a>
          <span class="dashboard-table__host line-clamp-1" title=address>
            {address.clone()}
          </span>
        </span>
        <span role="cell">
          <span class=chip_class>{check_kind}</span>
        </span>
        <span role="cell" class="hidden text-right sm:flex type-mono type-data">
          {format!("{}s", interval_secs)}
        </span>
        <span
          role="cell"
          class="hidden text-right sm:flex type-mono type-data"
          style="color: var(--theme-text-muted)"
        >
          {latency_label}
        </span>
        <span role="cell" class="text-right">
          <EnabledBadge enabled=target.enabled />
        </span>
      </div>
    }
}

const fn check_kind_label(check: &CheckSpec) -> &'static str {
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

fn check_address(check: &CheckSpec) -> String {
    match check {
        CheckSpec::Http(h) => h.url.to_string(),
        CheckSpec::Tcp(t) => format!("{}:{}", t.host, t.port),
        CheckSpec::Ping(p) => p.host.clone(),
        CheckSpec::Heartbeat(_) => "heartbeat".to_string(),
        _ => "-".to_string(),
    }
}

async fn fetch_target_rows() -> TargetsView {
    let targets = match client::list_targets().await {
        Ok(t) => t,
        Err(e) => {
            return TargetsView { rows: Vec::new(), error: Some(e) };
        }
    };

    // Cap concurrent result-fetches at 6 — the browser's per-host connection
    // limit — so a page with many monitors does not fire N simultaneous
    // requests (the old `join_all` spawned them all at once).
    let rows: Vec<TargetRow> = stream::iter(targets.iter().cloned())
        .map(|t| async move {
            let latest = client::list_target_results(t.id, 1).await.ok().and_then(|mut r| r.pop());
            TargetRow { target: t, latest }
        })
        .buffer_unordered(6)
        .collect()
        .await;

    TargetsView { rows, error: None }
}
