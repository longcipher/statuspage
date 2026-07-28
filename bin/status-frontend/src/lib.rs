//! StatusPage — Leptos CSR frontend entry point.
//!
//! Client-side rendered Leptos application compiled to WASM. The release
//! build is produced by `just fe-build` (cargo + wasm-bindgen); the dev
//! server is `just fe-dev` (trunk serve). Talks to the axum JSON API and
//! renders charts via the global Plotly.js runtime.

#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::enum_glob_use)
)]

use leptos::prelude::*;
use wasm_bindgen::prelude::wasm_bindgen;

mod api;
mod app;
mod components;
mod pages;

use app::App;

/// Main entry point for the WASM application.
#[wasm_bindgen(start)]
pub fn main() {
    // Install the panic hook for readable stack traces in the browser console.
    console_error_panic_hook::set_once();
    // Route `log` macros to the browser console.
    _ = console_log::init_with_level(log::Level::Debug);
    mount_to_body(App);
}
