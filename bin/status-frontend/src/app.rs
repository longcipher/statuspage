//! Main application component with client-side routing and auth guard.
//!
//! The app renders one of two top-level route trees:
//!
//! * `/p` — the public status page. Unauthenticated; anyone with the URL
//!   can see the current status snapshot. Rendered by [`PublicStatusPage`].
//! * everything else — the management UI. An auth guard
//!   ([`AuthShell`]) wraps the management routes:
//!   1. On mount it fires `GET /api/v1/auth/session` to check whether the
//!      browser has a valid session cookie. While in flight a centered
//!      "Loading..." is shown.
//!   2. If the session check returns 401 (or errors), [`LoginPage`] is
//!      rendered. On a successful bootstrap or magic-link verify,
//!      `on_logged_in` refetches the session and the shell transitions to
//!      the authenticated state.
//!   3. If authenticated, the [`NavBar`] + nested routes are rendered via
//!      `<Outlet />`. The nav includes a logout button that calls
//!      `DELETE /api/v1/auth/session` and transitions back to
//!      unauthenticated.

use std::sync::Arc;

use leptos::either::EitherOf3;
use leptos::prelude::*;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::{
    components::{Outlet, ParentRoute, Route, Router, Routes},
    path,
};

use crate::api::client;
use crate::components::nav::NavBar;
use crate::pages::{
    HomePage, IncidentListPage, LoginPage, NotFoundPage, PublicStatusPage, SettingsPage,
    StatusPageDetailPage, StatusPageListPage, TargetDetailPage, TargetsListPage,
};

/// Auth state tracked in a signal so the login / logout flows can flip it
/// without a full page reload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthState {
    Checking,
    Authenticated,
    Unauthenticated,
}

#[component]
#[expect(unreachable_pub)]
pub(crate) fn App() -> impl IntoView {
    provide_meta_context();

    view! {
      <Title text="StatusPage" />
      <Router>
        <Routes fallback=|| view! { <NotFoundPage /> }>
          // Public status page — unauthenticated. Mounted at `/p` so it
          // stays outside the auth guard that wraps the management UI.
          <Route path=path!("/p") view=PublicStatusPage />
          // Management UI — auth-gated via `AuthShell`. Nested routes are
          // rendered through `<Outlet />` only when authenticated.
          <ParentRoute path=path!("/") view=AuthShell>
            <Route path=path!("/") view=HomePage />
            <Route path=path!("/status-pages") view=StatusPageListPage />
            <Route path=path!("/status-pages/:id") view=StatusPageDetailPage />
            <Route path=path!("/targets") view=TargetsListPage />
            <Route path=path!("/targets/:id") view=TargetDetailPage />
            <Route path=path!("/incidents") view=IncidentListPage />
            <Route path=path!("/settings") view=SettingsPage />
            <Route path=path!("/*any") view=NotFoundPage />
          </ParentRoute>
        </Routes>
      </Router>
    }
}

/// Auth guard shell for the management UI. Renders [`LoginPage`] when
/// unauthenticated, a loading placeholder while the session check is in
/// flight, and the [`NavBar`] + nested `<Outlet />` once authenticated.
///
/// The session check runs once per shell mount via a [`LocalResource`];
/// `on_logged_in` / `on_logout` flip the signal without a full reload.
#[component]
fn AuthShell() -> impl IntoView {
    let (auth, set_auth) = signal(AuthState::Checking);

    // On mount, check the session. The closure captures `set_auth` so it
    // can flip the state when the fetch resolves. `spawn_local` is safe
    // here — this runs once per shell mount, not per render.
    let session_check = LocalResource::new(move || async move {
        match client::get_session().await {
            Ok(_) => AuthState::Authenticated,
            Err(_) => AuthState::Unauthenticated,
        }
    });

    // Reactively update `auth` when the session check resolves.
    Effect::new(move |_| {
        if let Some(state) = session_check.get() {
            set_auth.set(state);
        }
    });

    let on_logged_in: Arc<dyn Fn() + Send + Sync> =
        Arc::new(move || set_auth.set(AuthState::Authenticated));

    view! {
      {move || {
        match auth.get() {
          AuthState::Checking => {
            EitherOf3::A(
              view! {
                <div class="flex justify-center items-center min-h-screen">
                  <p class="type-body" style="color: var(--theme-text-quiet)">
                    "Loading..."
                  </p>
                </div>
              },
            )
          }
          AuthState::Unauthenticated => {
            EitherOf3::B(view! { <LoginPage on_logged_in=on_logged_in.clone() /> })
          }
          AuthState::Authenticated => {
            EitherOf3::C(
              view! {
                <>
                  <a href="#main-content" class="skip-link">
                    "Skip to main content"
                  </a>
                  <NavBar on_logout=Arc::new(move || set_auth.set(AuthState::Unauthenticated)) />
                  <main id="main-content" tabindex="-1">
                    <Outlet />
                  </main>
                </>
              },
            )
          }
        }
      }}
    }
}
