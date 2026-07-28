//! Status page list — calls `GET /api/v1/status-pages`.

use leptos::either::Either;
use leptos::prelude::*;

use crate::api::client;
use crate::components::error_state::{EmptyState, ErrorCallout, SkeletonList};
use crate::components::status_badge::EnabledBadge;

#[derive(Clone)]
struct PagesView {
    pages: Vec<crate::api::types::StatusPage>,
    error: Option<String>,
}

#[component]
pub fn StatusPageListPage() -> impl IntoView {
    let pages = LocalResource::new(move || async {
        match client::list_status_pages().await {
            Ok(p) => PagesView { pages: p, error: None },
            Err(e) => PagesView { pages: Vec::new(), error: Some(e) },
        }
    });

    view! {
      <section class="flex flex-col gap-5">
        <header class="flex flex-wrap gap-3 justify-between items-end">
          <h1 class="type-page-title" style="color: var(--theme-text)">
            "Status Pages"
          </h1>
        </header>

        <Suspense fallback=|| {
          view! { <SkeletonList count=3 label="Loading status pages..." /> }
        }>
          {move || {
            pages
              .get()
              .map(|data| {
                let PagesView { pages: page_list, error } = data;
                let has_fatal = error.is_some() && page_list.is_empty();

                view! {
                  {error
                    .as_ref()
                    .map(|e| {
                      let err = e.clone();
                      if page_list.is_empty() {
                        view! {
                          <ErrorCallout
                            title="Failed to load status pages"
                            message=err
                            on_retry=Box::new(move || pages.refetch())
                          />
                        }
                      } else {
                        view! {
                          <ErrorCallout
                            title="Some data could not be loaded"
                            message=err
                            on_retry=Box::new(move || pages.refetch())
                          />
                        }
                      }
                    })}

                  {if has_fatal {
                    Either::Left(())
                  } else if page_list.is_empty() {
                    Either::Right(
                      Either::Left(
                        view! {
                          <EmptyState
                            title="No status pages configured"
                            message="Create a status page via the API to publish a public dashboard."
                          />
                        },
                      ),
                    )
                  } else {
                    Either::Right(
                      Either::Right(
                        view! {
                          <ul class="flex flex-col gap-3">
                            {page_list
                              .into_iter()
                              .map(|page| {
                                let page_href = format!("/status-pages/{}", page.id);
                                let slug_txt = format!("/{}", page.slug);
                                let slug_title = slug_txt.clone();
                                view! {
                                  <li>
                                    <a href=page_href class="block">
                                      <div class="flex flex-wrap gap-2 justify-between items-center p-4 sticker-card">
                                        <div class="min-w-0">
                                          <span
                                            class="block break-words type-section-title"
                                            style="color: var(--theme-text)"
                                          >
                                            {page.name}
                                          </span>
                                          <p
                                            class="mt-0.5 type-mono line-clamp-1"
                                            style="color: var(--theme-text-quiet)"
                                            title=slug_title
                                          >
                                            {slug_txt}
                                          </p>
                                        </div>
                                        <EnabledBadge enabled=page.enabled />
                                      </div>
                                    </a>
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
