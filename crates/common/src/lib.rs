//! Shared utilities for StatusPage.
//!
//! Independent modules (no storage dependency): networking, HTTP client,
//! observability, email, security, notification.

// Test code legitimately uses `.unwrap()` / `.expect()` / `panic!` for
// assertions and fixture setup. The workspace denies these lints to keep
// production code panic-free; relax them in `#[cfg(test)]` modules only.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::enum_glob_use)
)]

pub mod email;
pub mod http_client;
pub mod net;
pub mod notifier;
pub mod observability;
pub mod security;
