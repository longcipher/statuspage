//! 404 page shown for unmatched routes.

use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
      <section class="flex flex-col gap-4 items-center py-20">
        <h1 class="type-404" style="color: var(--theme-text-quiet)">
          "404"
        </h1>
        <p class="text-center type-body-large" style="color: var(--theme-text-muted)">
          "Page not found."
        </p>
        <A href="/">
          <span class="mt-4 back-link">"← Back to home"</span>
        </A>
      </section>
    }
}
