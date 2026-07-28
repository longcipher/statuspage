//! Top navigation bar with client-side links and logout button.

use std::sync::Arc;

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::use_location;

use crate::api::client;
use crate::components::theme_toggle::ThemeToggle;

/// Navigation bar. `on_logout` is invoked after the server confirms the
/// session has been destroyed — the parent uses it to flip the auth state
/// and swap back to the login page.
#[component]
pub fn NavBar(on_logout: Arc<dyn Fn() + Send + Sync>) -> impl IntoView {
    let (logging_out, set_logging_out) = signal(false);

    let handle_logout = move || {
        if logging_out.get() {
            return;
        }
        set_logging_out.set(true);
        let cb = on_logout.clone();
        spawn_local(async move {
            // Fire-and-forget: even if the DELETE fails (network error,
            // expired cookie), clear the local state so the UI doesn't
            // stay stuck on an unauthenticated view.
            let _ = client::logout().await;
            set_logging_out.set(false);
            cb();
        });
    };

    view! {
      <nav
        class="flex sticky top-0 z-10 flex-wrap gap-y-2 gap-x-4 items-center py-2 px-4 border-b"
        aria-label="Main navigation"
        style="border-color: var(--theme-line); box-shadow: var(--nav-shadow)"
      >
        <A href="/">
          <span class="nav-brand">"StatusPage"</span>
        </A>
        <div class="flex flex-wrap gap-1 items-center ml-auto sm:gap-2">
          <NavLink href="/status-pages" label="Status Pages" />
          <NavLink href="/targets" label="Monitors" />
          <NavLink href="/incidents" label="Incidents" />
          <NavLink href="/settings" label="Settings" />
          <ThemeToggle />
          <button
            type="button"
            class="nav-link nav-link--logout"
            on:click=move |_| handle_logout()
            disabled=move || logging_out.get()
            aria-label="Sign out"
          >
            {move || if logging_out.get() { "..." } else { "Sign out" }}
          </button>
        </div>
      </nav>
    }
}

#[component]
fn NavLink(#[prop(into)] href: String, #[prop(into)] label: String) -> impl IntoView {
    let loc = use_location();
    let active_href = href.clone();
    let class = move || {
        let path = loc.pathname.get();
        let is_active =
            path == active_href || (active_href != "/" && path.starts_with(&active_href));
        if is_active { "nav-link nav-link--active" } else { "nav-link" }
    };

    view! {
      <A href=href>
        <span class=class>{label}</span>
      </A>
    }
}
