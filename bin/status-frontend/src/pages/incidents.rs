//! Incident list — calls `GET /api/v1/incidents`.

use leptos::either::Either;
use leptos::prelude::*;
use statuscore::domain::{CheckStatus, IncidentSeverity};

use crate::api::client;
use crate::components::error_state::{EmptyState, ErrorCallout, SkeletonList};

#[derive(Clone)]
struct IncidentsView {
    incidents: Vec<crate::api::types::Incident>,
    error: Option<String>,
}

#[component]
pub fn IncidentListPage() -> impl IntoView {
    let incidents = LocalResource::new(move || async {
        match client::list_incidents().await {
            Ok(list) => IncidentsView { incidents: list, error: None },
            Err(e) => IncidentsView { incidents: Vec::new(), error: Some(e) },
        }
    });

    view! {
      <section class="flex flex-col gap-5">
        <header class="flex flex-wrap gap-3 justify-between items-end">
          <h1 class="type-page-title" style="color: var(--theme-text)">
            "Incidents"
          </h1>
        </header>

        <Suspense fallback=|| {
          view! { <SkeletonList count=3 label="Loading incidents..." /> }
        }>
          {move || {
            incidents
              .get()
              .map(|data| {
                let IncidentsView { incidents: list, error } = data;
                let has_fatal = error.is_some() && list.is_empty();

                view! {
                  {error
                    .as_ref()
                    .map(|e| {
                      let err = e.clone();
                      if list.is_empty() {
                        view! {
                          <ErrorCallout
                            title="Failed to load incidents"
                            message=err
                            on_retry=Box::new(move || incidents.refetch())
                          />
                        }
                      } else {
                        view! {
                          <ErrorCallout
                            title="Some data could not be loaded"
                            message=err
                            on_retry=Box::new(move || incidents.refetch())
                          />
                        }
                      }
                    })}

                  {if has_fatal {
                    Either::Left(())
                  } else if list.is_empty() {
                    Either::Right(
                      Either::Left(
                        view! {
                          <EmptyState
                            title="All systems operational"
                            message="No incidents have been recorded."
                          />
                        },
                      ),
                    )
                  } else {
                    Either::Right(
                      Either::Right(
                        view! {
                          <ul
                            class="overflow-hidden p-0 divide-y public-callout"
                            style="border-color: var(--theme-line)"
                          >
                            {list
                              .into_iter()
                              .map(|i| {
                                let title = i
                                  .public_title
                                  .clone()
                                  .unwrap_or_else(|| format!("Incident {}", i.id));
                                let (severity_label, severity_class) = match i.severity {
                                  IncidentSeverity::Critical => ("Critical", "status-badge--down"),
                                  IncidentSeverity::Major => ("Major", "status-badge--degraded"),
                                  IncidentSeverity::Minor => ("Minor", "status-badge--pending"),
                                  _ => ("Unknown", "status-badge--pending"),
                                };
                                let (status_label, status_class) = match i.ended_at {
                                  Some(_) => ("Resolved", "status-badge--up"),
                                  None => {
                                    match i.status {
                                      CheckStatus::Degraded => {
                                        ("Investigating", "status-badge--pending")
                                      }
                                      _ => ("Ongoing", "status-badge--down"),
                                    }
                                  }
                                };
                                let started = i.started_at.format("%Y-%m-%d %H:%M UTC").to_string();
                                // `IncidentSeverity` is `#[non_exhaustive]` in the core
                                // crate; render any future variant as a generic
                                // "Unknown" severity pill.
                                view! {
                                  <li class="flex flex-col gap-1.5 p-4 sm:p-5">
                                    <div class="flex flex-wrap gap-2 justify-between items-center">
                                      <span
                                        class="min-w-0 break-words type-subsection-title"
                                        style="color: var(--theme-text)"
                                      >
                                        {title}
                                      </span>
                                      <div class="flex gap-2 items-center shrink-0">
                                        <span class=format!(
                                          "status-badge {}",
                                          severity_class,
                                        )>{severity_label}</span>
                                        <span class=format!(
                                          "status-badge {}",
                                          status_class,
                                        )>{status_label}</span>
                                      </div>
                                    </div>
                                    <p class="type-body" style="color: var(--theme-text-muted)">
                                      {format!("Started {started}")}
                                    </p>
                                    {i
                                      .public_description
                                      .as_deref()
                                      .map(|desc| {
                                        view! {
                                          <p
                                            class="break-words type-body line-clamp-3"
                                            style="color: var(--theme-text-muted)"
                                          >
                                            {desc.to_string()}
                                          </p>
                                        }
                                      })}
                                  </li>
                                }
                              })
                              .collect::<Vec<_>>()}
                          </ul>
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
