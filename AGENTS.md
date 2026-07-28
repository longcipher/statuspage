# Rust Workspace Agent Instructions

## Scope

- This project is a Rust workspace with a Leptos CSR frontend.
- `bin/` contains binary crates (status-server, status-frontend).
- `crates/` contains reusable library crates (common, core, storage).

## Execution Strategy

- Maximize parallelism by dispatching subagents aggressively and consuming tokens freely to complete tasks faster.

## Tool Usage & Commands

- **NEVER execute `cargo` commands in parallel.** Rust's cargo uses strict file locks on the `target/` directory.
- ALWAYS run `cargo check`, `cargo build`, or `cargo test` sequentially. Wait for one to finish before starting the next.
- When fixing errors, execute the file `Write`/`Edit` tool FIRST, wait for it to succeed, and only THEN run `cargo` commands to verify. Do not parallelize file edits with cargo builds.

## Build Configuration

- Ensure `.cargo/config.toml` contains:
  ```toml
  [build]
  rustc-wrapper = "kache"
  ```

## Cargo Workspace Rules (Critical)

1. Never manually type dependency versions in sub-crate `Cargo.toml`; use `cargo add`.
2. Add workspace-level dependencies with:

   ```bash
   cargo add <crate> --workspace
   ```

3. Add sub-crate dependencies with:

   ```bash
   cargo add <crate> -p <crate-name> --workspace
   ```

4. Root `[workspace.dependencies]` must use full 3-digit `major.minor.patch` versions.
5. Root `[workspace.dependencies]` must not carry features by default (features go in sub-crates).
6. Sub-crates must use `workspace = true` for `version`, `edition`, shared dependencies, and lints.

## Engineering Principles

### Rust Implementation Guidelines

1. Error handling:
   - Application layer: `anyhow`.
   - Library layer: `thiserror`.
2. Database (DuckDB):
   - Use `duckdb` crate with bundled feature.
   - Prefer runtime queries.
3. Concurrency:
   - Prefer lock-free/container-first approaches (`arc-swap`, `dashmap`).
   - Avoid `Arc<Mutex<T>>` when better alternatives are available.
4. Observability:
   - Logging: `tracing` only.
   - Metrics: `metrics` + `metrics-exporter-prometheus`.
5. API docs:
   - Generate OpenAPI with `utoipa` when exposing HTTP APIs.
6. Configuration:
   - Use the `config` crate and external configuration files (prefer TOML).
7. Safety:
   - Use `unsafe` only when strictly necessary and document the safety invariants.

### Key Design Principles

- Modularity: Design each crate so it can be used as a standalone library with clear boundaries and minimal hidden coupling.
- Performance: Prefer architectures that support parallelism, memory-mapped I/O for large read-heavy workloads, optimized data structures, and lock-free data types.
- Extensibility: Use traits and generic types to support multiple implementations without invasive refactors.
- Type Safety: Maintain strong static typing across interfaces and internals, with minimal use of dynamic dispatch.

### Concurrency and Async Execution

- Prefer atomic types (`AtomicUsize`, `AtomicBool`, etc.) with explicit `Ordering` for simple shared state.
- Use `moka` for concurrent caches instead of custom LRU implementations.
- Prefer `parking_lot::{Mutex, RwLock}` over `std::sync` locks for synchronous locking.
- Release `std::sync::Mutex` and `parking_lot::Mutex` guards before hitting any `.await` point.
- Use `tokio::sync::Mutex` for locks that span across `.await` points.
- Use `tokio::task::spawn_blocking` for CPU-bound work and blocking I/O.
- Batch work or use bounded worker patterns instead of spawning massive volumes of tiny Tokio tasks.
- Channel selection:
  - Async-to-Async: `tokio::sync::mpsc` / `tokio::sync::broadcast`
  - Sync/MPMC: `crossbeam-channel` or `flume`
  - Avoid `std::sync::mpsc`

### Common Pitfalls

- Keep async tasks non-blocking; offload CPU-bound work to `spawn_blocking`.
- Handle errors explicitly and consistently with the `?` operator and concrete error types.

### What to Avoid

- Incomplete implementations: finish features before submitting.
- Large, sweeping changes: keep changes focused and reviewable.
- Mixing unrelated changes: keep one logical change per commit.

## Development Workflow

When fixing failures, identify root cause first, then apply idiomatic fixes instead of suppressing warnings or patching symptoms.

## Parallelization and Resource Utilization

- **Use as many subagents and as much token budget as needed** to complete tasks efficiently. Parallelize independent work aggressively and maximize context utilization.

- **Git Restrictions:** NEVER use `git worktree`. All code modifications MUST be made directly on the current branch in the existing working directory.

After each feature or bug fix, run:

```bash
just format
just lint
just test
```

If any command fails, report the failure and do not claim completion.

## Testing Requirements

- Unit tests: colocate with implementation (`#[cfg(test)]`).
- Integration tests: place in crate-level `tests/`.
- Add tests for behavioral changes and public API changes.

## Language Requirement

- Documentation, comments, and commit messages must be English only.
