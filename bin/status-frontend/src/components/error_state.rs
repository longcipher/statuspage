//! Reusable error-state and loading-state components.

use leptos::either::Either;
use leptos::prelude::*;

#[component]
pub fn ErrorCallout(
    #[prop(into)] title: String,
    #[prop(optional, into)] message: Option<String>,
    #[prop(optional)] errors: Option<Vec<String>>,
    #[prop(optional)] on_retry: Option<Box<dyn Fn() + 'static>>,
) -> impl IntoView {
    let err_list = errors.unwrap_or_default();
    let single_msg = message;

    view! {
      <section
        class="public-callout"
        role="alert"
        style="border-color: var(--theme-state-bad-line); background: var(--theme-state-bad-bg);"
      >
        <h2
          class="break-words type-subsection-title"
          style="color: var(--theme-state-bad-fg-strong)"
        >
          {title}
        </h2>
        {if let Some(msg) = single_msg {
          Either::Left(
            view! {
              <p class="mt-2 break-words type-body" style="color: var(--theme-state-bad-fg)">
                {msg}
              </p>
            },
          )
        } else if err_list.len() == 1 {
          Either::Right(
            Either::Left(
              view! {
                <p class="mt-2 break-words type-body" style="color: var(--theme-state-bad-fg)">
                  {err_list.into_iter().next().unwrap_or_default()}
                </p>
              },
            ),
          )
        } else {
          Either::Right(
            Either::Right(
              view! {
                <ul
                  class="mt-2 list-disc list-inside break-words type-body"
                  style="color: var(--theme-state-bad-fg)"
                >
                  {err_list.into_iter().map(|e| view! { <li>{e}</li> }).collect::<Vec<_>>()}
                </ul>
              },
            ),
          )
        }}
        {on_retry
          .map(|retry| {
            view! {
              <button type="button" class="mt-3 retry-btn" on:click=move |_| retry()>
                "Try again"
              </button>
            }
          })}
      </section>
    }
}

#[component]
pub fn SkeletonList(
    #[prop(default = 3usize)] count: usize,
    #[prop(optional, into)] label: Option<String>,
) -> impl IntoView {
    let loading_text = label.unwrap_or_else(|| "Loading...".to_string());
    view! {
      <div class="flex flex-col gap-3" aria-busy="true" role="status" aria-live="polite">
        <span class="sr-only">{loading_text}</span>
        {(0..count)
          .map(|_| view! { <div class="h-16 rounded animate-pulse sticker-card"></div> })
          .collect::<Vec<_>>()}
      </div>
    }
}

#[component]
pub fn SkeletonDetail(#[prop(optional, into)] label: Option<String>) -> impl IntoView {
    let loading_text = label.unwrap_or_else(|| "Loading...".to_string());
    view! {
      <div class="flex flex-col gap-4" aria-busy="true" role="status" aria-live="polite">
        <span class="sr-only">{loading_text}</span>
        <div
          class="w-3/4 h-10 rounded animate-pulse"
          style="background: var(--theme-surface-sunk)"
        ></div>
        <div class="h-28 rounded animate-pulse sticker-card"></div>
        <div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {(0..4)
            .map(|_| view! { <div class="h-20 rounded animate-pulse sticker-card"></div> })
            .collect::<Vec<_>>()}
        </div>
        <div class="h-64 rounded animate-pulse sticker-card"></div>
      </div>
    }
}

#[component]
pub fn EmptyState(
    #[prop(into)] title: String,
    #[prop(optional, into)] message: Option<String>,
) -> impl IntoView {
    view! {
      <div class="text-center public-callout type-body" style="color: var(--theme-text-quiet)">
        <p class="type-subsection-title" style="color: var(--theme-text-muted)">
          {title}
        </p>
        {message.map(|m| view! { <p class="mt-1 break-words">{m}</p> })}
      </div>
    }
}
