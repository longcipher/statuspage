//! Stub binary target required by `cargo-leptos` for package resolution.
//!
//! `cargo-leptos` 0.3.x expects a `[[bin]]` target to exist even when building
//! only the frontend (`--frontend-only`). This stub is never compiled into the
//! WASM bundle and is never shipped — it exists solely so cargo-leptos can
//! resolve the package. The real application entry point is `lib.rs` (built as
//! a `cdylib` for `wasm32-unknown-unknown`).
//
// `clippy::print_stderr` is allowed here: this stub is a diagnostic binary
// that should never be invoked in production. `eprintln!` is the appropriate
// tool for a one-shot stderr message to an operator who ran the stub by
// mistake — pulling in `tracing` for a never-shipped stub would be overkill.
#![allow(clippy::print_stderr)]

fn main() {
    eprintln!(
        "status-frontend stub: this binary is not meant to be run. \
         Use the WASM build (`just fe-build`) and serve via the axum backend."
    );
    std::process::exit(1);
}
