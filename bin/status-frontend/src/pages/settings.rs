//! Settings / about page — static product info and a short description of
//! the configurable surface. No API calls; everything here is compile-time
//! constant.

use leptos::prelude::*;

/// Static settings / about page.
#[component]
pub fn SettingsPage() -> impl IntoView {
    view! {
      <section class="flex flex-col gap-6">
        <header>
          <h1 class="type-page-title" style="color: var(--theme-text)">
            "Settings"
          </h1>
          <p class="mt-1 type-body" style="color: var(--theme-text-quiet)">
            "StatusPage v0.1.0"
          </p>
        </header>

        <div class="p-5 sticker-card">
          <h2 class="type-section-title" style="color: var(--theme-text)">
            "About"
          </h2>
          <p class="mt-2 type-body" style="color: var(--theme-text-muted)">
            "A self-hosted status page and uptime monitor. Built with a \
             Leptos CSR frontend (WASM), an axum JSON API, and Plotly for \
             latency charts. Monitors are configured via the API or UI \
             and stored in DuckDB."
          </p>
        </div>

        <div class="p-5 sticker-card">
          <h2 class="type-section-title" style="color: var(--theme-text)">
            "Stack"
          </h2>
          <ul class="mt-2 list-disc list-inside type-body" style="color: var(--theme-text-muted)">
            <li>"Frontend: Leptos 0.8 (CSR), Tailwind CSS, Plotly.js"</li>
            <li>"Backend: axum, tokio, reqwest"</li>
            <li>"Storage: DuckDB"</li>
            <li>"Build: wasm-bindgen, trunk (dev)"</li>
          </ul>
        </div>

        <div class="p-5 sticker-card">
          <h2 class="type-section-title" style="color: var(--theme-text)">
            "Configuration"
          </h2>
          <p class="mt-2 type-body" style="color: var(--theme-text-muted)">
            "Runtime configuration is loaded by the backend from \
             environment variables and <code>config/default.toml</code>. \
             The frontend talks to the JSON API at <code>/api/v1</code> \
             and does not read configuration directly. Add monitors, \
             status pages and incidents through their respective REST \
             endpoints or the UI."
          </p>
          <ul class="mt-3 list-disc list-inside type-body" style="color: var(--theme-text-muted)">
            <li>"<code>GET/POST /api/v1/targets</code> — manage monitors"</li>
            <li>"<code>GET/POST /api/v1/status-pages</code> — manage pages"</li>
            <li>"<code>GET/POST /api/v1/incidents</code> — manage incidents"</li>
          </ul>
        </div>
      </section>
    }
}
