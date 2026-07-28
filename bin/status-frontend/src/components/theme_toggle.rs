//! Light/dark theme toggle button.
//!
//! The initial theme is set by an inline script in `index.html` that runs
//! before paint — it reads `localStorage.theme` (or `prefers-color-scheme`)
//! and adds the `.dark` class to `<html>` to avoid a flash of the wrong
//! theme. This component reads that initial state from the DOM, mirrors it
//! into a local signal, and on every toggle updates both the DOM class and
//! `localStorage` so the preference survives reloads.

use leptos::prelude::*;

/// A small button that toggles between light and dark themes by adding or
/// removing the `.dark` class on `<html>`. The current state is read from
/// the DOM at mount (set by the early inline script) and persisted to
/// `localStorage.theme` on every change.
#[component]
pub fn ThemeToggle() -> impl IntoView {
    // Read the initial state from `<html>.classList` — the early inline
    // script in index.html has already applied it before WASM loads, so
    // there's no flash of unstyled (wrong-theme) content.
    let initial_dark =
        document().document_element().is_some_and(|el| el.class_list().contains("dark"));

    let is_dark = RwSignal::new(initial_dark);

    // Whenever the signal changes, sync the DOM class and localStorage.
    // `Effect::new` runs once immediately (no-op for the initial value)
    // and again on every signal change.
    Effect::new(move |_| {
        let dark = is_dark.get();
        if let Some(html) = document().document_element() {
            let class_list = html.class_list();
            if dark {
                let _ = class_list.add_1("dark");
            } else {
                let _ = class_list.remove_1("dark");
            }
        }
        if let Some(storage) = window().local_storage().ok().flatten() {
            let _ = storage.set_item("theme", if dark { "dark" } else { "light" });
        }
    });

    let toggle_label = move || {
        if is_dark.get() { "Switch to light mode" } else { "Switch to dark mode" }
    };

    view! {
      <button
        class="theme-toggle"
        type="button"
        on:click=move |_| is_dark.update(|v| *v = !*v)
        aria-label=toggle_label
        title=toggle_label
      >
        <span aria-hidden="true">{move || if is_dark.get() { "🌙" } else { "☀️" }}</span>
      </button>
    }
}
