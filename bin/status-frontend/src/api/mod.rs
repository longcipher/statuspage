//! API client and response types for the StatusPage frontend.
//!
//! [`types`] re-exports the domain types from `statuscore::domain` so the
//! frontend deserialises the exact JSON shapes the axum backend serialises.
//! [`client`] wraps the browser Fetch API (`web-sys`) for WASM builds and
//! falls back to a stub on native targets so the crate still type-checks
//! under `cargo check`.

pub mod client;
pub mod types;
