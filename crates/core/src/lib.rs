//! Domain core for the StatusPage project.
//!
//! Holds domain models, error types, and configuration definitions as pure
//! data — no storage or transport layer dependencies. Storage-aware code
//! lives in the `storage` crate; HTTP/API concerns live in the bin crate.

// Test code legitimately uses `.unwrap()` / `.expect()` / `panic!` for
// assertions and fixture setup. The workspace denies these lints to keep
// production code panic-free; relax them in `#[cfg(test)]` modules only.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::enum_glob_use)
)]

pub mod config;
pub mod domain;
pub mod error;

pub use error::{AppError, Result};
