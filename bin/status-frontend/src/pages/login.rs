//! Login page — bootstrap (first user) or magic-link (existing users).
//!
//! On mount, checks `GET /api/v1/auth/bootstrap` to decide which form to
//! show:
//!
//! * **Bootstrap needed** (no users exist): shows an email + optional
//!   display-name form. `POST /api/v1/auth/bootstrap` creates the first
//!   admin user and opens a session. The response sets the session cookie
//!   via `Set-Cookie` (HttpOnly, SameSite=Lax), which the browser stores
//!   automatically.
//!
//! * **Bootstrap not needed** (users exist): shows the magic-link login
//!   form. Step 1: enter email → `POST /api/v1/auth/magic-link/request`
//!   → server emails a one-time token. Step 2: enter the token →
//!   `POST /api/v1/auth/magic-link/verify` → session cookie set.
//!
//! In dev / local deployments where SMTP is not configured, the magic-link
//! token is logged to the server console (tracing) and can be pasted
//! manually into the token field — this is a dev convenience, not a
//! production path.
//!
//! On success, the page calls `on_logged_in` (passed from the parent) so
//! the parent can re-evaluate the auth guard and render the main app.

use std::sync::Arc;

use leptos::either::{Either, EitherOf3};
use leptos::prelude::*;
use leptos::task::spawn_local;
use web_sys::SubmitEvent;

use crate::api::client;
use crate::api::types::BootstrapStatus;

/// Login page component. `on_logged_in` is a callback invoked after a
/// successful bootstrap or magic-link verify — the parent uses it to
/// re-check the session and swap to the authenticated view.
#[component]
pub fn LoginPage(on_logged_in: Arc<dyn Fn() + Send + Sync>) -> impl IntoView {
    let bootstrap_state = LocalResource::new(move || async move {
        client::bootstrap_status().await.map_or(BootstrapState::Error, BootstrapState::from)
    });

    view! {
      <section class="flex justify-center items-center min-h-[70vh]">
        <div
          class="p-8 w-full max-w-md rounded-lg public-callout login-card"
          style="border-color: var(--theme-line)"
        >
          <h1
            class="mb-2 text-2xl font-bold text-center type-display"
            style="color: var(--theme-text)"
          >
            "StatusPage"
          </h1>
          <p class="mb-6 text-sm text-center type-body" style="color: var(--theme-text-muted)">
            "Sign in to manage your monitors"
          </p>
          <Suspense fallback=move || {
            view! {
              <div class="py-8 text-center type-body" style="color: var(--theme-text-quiet)">
                "Loading..."
              </div>
            }
          }>
            {move || {
              bootstrap_state
                .get()
                .map(|state| match state {
                  BootstrapState::Needed => {
                    EitherOf3::A(view! { <BootstrapForm on_logged_in=on_logged_in.clone() /> })
                  }
                  BootstrapState::NotNeeded => {
                    EitherOf3::B(view! { <MagicLinkForm on_logged_in=on_logged_in.clone() /> })
                  }
                  BootstrapState::Error => {
                    EitherOf3::C(
                      view! {
                        <div class="p-4 rounded error-callout" role="alert">
                          <p class="font-semibold">"Cannot reach server"</p>
                          <p class="mt-1 text-sm">
                            "Check that the backend is running and reload the page."
                          </p>
                        </div>
                      },
                    )
                  }
                })
            }}
          </Suspense>
        </div>
      </section>
    }
}

/// Outcome of the bootstrap-status check.
#[derive(Clone)]
enum BootstrapState {
    Needed,
    NotNeeded,
    Error,
}

impl From<BootstrapStatus> for BootstrapState {
    fn from(s: BootstrapStatus) -> Self {
        if s.bootstrap_needed { Self::Needed } else { Self::NotNeeded }
    }
}

// ── Bootstrap form (first user) ────────────────────────────────────────────

#[component]
fn BootstrapForm(on_logged_in: Arc<dyn Fn() + Send + Sync>) -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (display_name, set_display_name) = signal(String::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let email_val = email.get();
        let name_val = display_name.get();
        if email_val.trim().is_empty() {
            set_error.set(Some("Email is required".to_string()));
            return;
        }
        set_loading.set(true);
        set_error.set(None);
        let on_success = on_logged_in.clone();
        spawn_local(async move {
            let name_opt = if name_val.trim().is_empty() { None } else { Some(name_val.trim()) };
            match client::bootstrap_create(email_val.trim(), name_opt).await {
                Ok(_) => on_success(),
                Err(e) => {
                    set_loading.set(false);
                    set_error.set(Some(e));
                }
            }
        });
    };

    view! {
      <div class="p-3 mb-4 text-sm rounded info-callout" style="border-color: var(--theme-line)">
        <p class="mb-1 font-semibold">"First-time setup"</p>
        <p style="color: var(--theme-text-muted)">
          "No users exist yet. Create the first admin account to get started."
        </p>
      </div>
      <form on:submit=on_submit class="flex flex-col gap-4">
        <FormField label="Email" required=true>
          <input
            type="email"
            required
            prop:value=email
            on:input=move |e| set_email.set(event_target_value(&e))
            class="login-input"
            placeholder="admin@example.com"
            autocomplete="email"
          />
        </FormField>
        <FormField label="Display name (optional)" required=false>
          <input
            type="text"
            prop:value=display_name
            on:input=move |e| set_display_name.set(event_target_value(&e))
            class="login-input"
            placeholder="Admin"
            autocomplete="name"
          />
        </FormField>
        {move || {
          error
            .get()
            .map(|e| {
              view! {
                <p class="text-sm error-text" role="alert">
                  {e}
                </p>
              }
            })
        }}
        <button type="submit" disabled=move || loading.get() class="login-btn">
          {move || if loading.get() { "Creating..." } else { "Create admin account" }}
        </button>
      </form>
    }
}

// ── Magic-link form (existing users) ───────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum MagicLinkStep {
    Request,
    Verify,
}

#[component]
fn MagicLinkForm(on_logged_in: Arc<dyn Fn() + Send + Sync>) -> impl IntoView {
    let (step, set_step) = signal(MagicLinkStep::Request);
    let (email, set_email) = signal(String::new());
    let (token, set_token) = signal(String::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(false);
    let (info, set_info) = signal(None::<String>);

    // Clone the Arc callback into a local that can be captured by the
    // (non-Copy) event handler closures built fresh inside each render of
    // the reactive `move ||` fragment below. Because signals are `Copy`,
    // each render reconstructs the handlers from copied signal handles,
    // avoiding the `FnOnce` error that occurs when a single `on_verify`
    // closure is moved into the first render and then used again.
    let cb = on_logged_in.clone();

    view! {
      {move || {
        let cb = cb.clone();
        match step.get() {
          MagicLinkStep::Request => {
            Either::Left(
              view! {
                <form
                  on:submit=move |ev: SubmitEvent| {
                    ev.prevent_default();
                    let email_val = email.get();
                    if email_val.trim().is_empty() {
                      set_error.set(Some("Email is required".to_string()));
                      return;
                    }
                    set_loading.set(true);
                    set_error.set(None);
                    let email_owned = email_val.trim().to_string();
                    spawn_local(async move {
                      match client::magic_link_request(&email_owned).await {
                        Ok(()) => {
                          set_loading.set(false);
                          set_info
                            .set(
                              Some(
                                format!(
                                  "If an account exists for {}, a sign-in link has been sent. \
                                     Enter the token below to continue.",
                                  email_owned,
                                ),
                              ),
                            );
                          set_step.set(MagicLinkStep::Verify);
                        }
                        Err(e) => {
                          set_loading.set(false);
                          set_error.set(Some(e));
                        }
                      }
                    });
                  }
                  class="flex flex-col gap-4"
                >
                  <FormField label="Email" required=true>
                    <input
                      type="email"
                      required
                      prop:value=email
                      on:input=move |e| set_email.set(event_target_value(&e))
                      class="login-input"
                      placeholder="you@example.com"
                      autocomplete="email"
                    />
                  </FormField>
                  {move || {
                    error
                      .get()
                      .map(|e| {
                        view! {
                          <p class="text-sm error-text" role="alert">
                            {e}
                          </p>
                        }
                      })
                  }}
                  <button type="submit" disabled=move || loading.get() class="login-btn">
                    {move || if loading.get() { "Sending..." } else { "Send sign-in link" }}
                  </button>
                </form>
              },
            )
          }
          MagicLinkStep::Verify => {
            Either::Right(
              view! {
                <form
                  on:submit=move |ev: SubmitEvent| {
                    ev.prevent_default();
                    let token_val = token.get();
                    if token_val.trim().is_empty() {
                      set_error.set(Some("Token is required".to_string()));
                      return;
                    }
                    set_loading.set(true);
                    set_error.set(None);
                    let on_success = cb.clone();
                    spawn_local(async move {
                      match client::magic_link_verify(token_val.trim()).await {
                        Ok(_) => on_success(),
                        Err(e) => {
                          set_loading.set(false);
                          set_error.set(Some(e));
                        }
                      }
                    });
                  }
                  class="flex flex-col gap-4"
                >
                  {move || {
                    info
                      .get()
                      .map(|i| {
                        view! {
                          <div
                            class="p-3 text-sm rounded info-callout"
                            style="border-color: var(--theme-line)"
                          >
                            <p style="color: var(--theme-text-muted)">{i}</p>
                          </div>
                        }
                      })
                  }}
                  <FormField label="Sign-in token" required=true>
                    <input
                      type="text"
                      required
                      prop:value=token
                      on:input=move |e| set_token.set(event_target_value(&e))
                      class="login-input"
                      placeholder="Paste your token here"
                      autocomplete="one-time-code"
                    />
                  </FormField>
                  {move || {
                    error
                      .get()
                      .map(|e| {
                        view! {
                          <p class="text-sm error-text" role="alert">
                            {e}
                          </p>
                        }
                      })
                  }}
                  <button type="submit" disabled=move || loading.get() class="login-btn">
                    {move || if loading.get() { "Verifying..." } else { "Sign in" }}
                  </button>
                  <button
                    type="button"
                    class="text-sm login-link"
                    on:click=move |_| {
                      set_step.set(MagicLinkStep::Request);
                      set_error.set(None);
                      set_info.set(None);
                      set_token.set(String::new());
                    }
                  >
                    "← Use a different email"
                  </button>
                </form>
              },
            )
          }
        }
      }}
    }
}

// ── Shared form field component ────────────────────────────────────────────

#[component]
fn FormField(label: &'static str, required: bool, children: Children) -> impl IntoView {
    view! {
      <label class="flex flex-col gap-1">
        <span class="text-sm font-medium type-body" style="color: var(--theme-text)">
          {label}
          {required.then(|| view! { <span class="error-text">*</span> })}
        </span>
        {children()}
      </label>
    }
}
