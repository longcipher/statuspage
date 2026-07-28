//! StatusPage storage layer.
//!
//! DuckDB serves as both the configuration store and the time-series
//! results store. The `Storage` trait defines the contract;
//! `DuckdbStorage` is the production implementation; `MemoryStorage` is
//! the in-memory test double.

// Test code legitimately uses `.unwrap()` / `.expect()` / `panic!` for
// assertions and fixture setup. The workspace denies these lints to keep
// production code panic-free; relax them in `#[cfg(test)]` modules only.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::enum_glob_use)
)]

pub mod duckdb;
pub mod memory;
pub mod traits;

pub use duckdb::DuckdbStorage;
pub use memory::MemoryStorage;
pub use traits::{Storage, StorageError};
