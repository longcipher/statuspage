//! Status badge components — render colored pills for state flags.
//!
//! Reads from the semantic state tokens defined in `style/main.css`
//! (`--theme-state-ok-*`, `--theme-state-warn-*`, `--theme-state-bad-*`)
//! so badge colours stay consistent with the overall status banner and
//! day-strip cells.

use leptos::prelude::*;
use statuscore::domain::CheckStatus;

/// Badge for a page's enabled/disabled flag.
#[component]
pub fn EnabledBadge(#[prop(into)] enabled: bool) -> impl IntoView {
    let (label, class) = if enabled {
        ("Enabled", "status-badge status-badge--up")
    } else {
        ("Disabled", "status-badge status-badge--pending")
    };
    view! { <span class=class>{label}</span> }
}

/// Badge for a target's check status (`Up` / `Down` / `Degraded` / `Error`).
#[component]
pub fn CheckStatusBadge(#[prop(into)] status: CheckStatus) -> impl IntoView {
    let (label, class) = match status {
        CheckStatus::Up => ("Operational", "status-badge status-badge--up"),
        CheckStatus::Down => ("Down", "status-badge status-badge--down"),
        CheckStatus::Degraded => ("Degraded", "status-badge status-badge--degraded"),
        CheckStatus::Error => ("Error", "status-badge status-badge--error"),
        // `CheckStatus` is `#[non_exhaustive]` in the core crate, so any
        // variant added there later must not break this render path; fall
        // back to a neutral "Unknown" pill instead of panicking.
        _ => ("Unknown", "status-badge status-badge--unknown"),
    };
    view! { <span class=class>{label}</span> }
}
