//! Home / welcome page with navigation cards to the main sections.

use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
      <section class="flex flex-col items-center hero-section">
        <div class="hero-badge">
          <span class="hero-badge__dot" aria-hidden="true"></span>
          "All systems operational"
        </div>
        <h1 class="type-display hero-title">"StatusPage"</h1>
        <p class="mt-4 max-w-lg text-center type-body-large" style="color: var(--theme-text-muted)">
          "Monitor uptime, track incidents, and publish beautiful public status pages."
        </p>

        <div class="grid grid-cols-1 gap-4 mt-12 w-full max-w-3xl sm:grid-cols-3">
          <NavCard
            href="/status-pages"
            icon="📊"
            title="Status Pages"
            description="Public-facing dashboards showing component health and uptime."
          />
          <NavCard
            href="/targets"
            icon="🔍"
            title="Monitors"
            description="View monitor status, latency, and detailed check history."
          />
          <NavCard
            href="/incidents"
            icon="⚠️"
            title="Incidents"
            description="Track active and resolved incidents across all monitors."
          />
        </div>
      </section>
    }
}

#[component]
fn NavCard(
    #[prop(into)] href: String,
    #[prop(into)] icon: String,
    #[prop(into)] title: String,
    #[prop(into)] description: String,
) -> impl IntoView {
    view! {
      <A href=href>
        <div class="flex flex-col p-5 h-full sticker-card">
          <div class="nav-card-icon" aria-hidden="true">
            {icon}
          </div>
          <h2 class="type-section-title" style="color: var(--theme-text)">
            {title}
          </h2>
          <p class="flex-1 mt-1 type-body" style="color: var(--theme-text-muted)">
            {description}
          </p>
          <div class="nav-card-arrow" aria-hidden="true">
            "→"
          </div>
        </div>
      </A>
    }
}
