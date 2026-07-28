# StatusPage — common dev workflows. Install: `brew install just` or `cargo install just`.
# Run `just` (no args) to list recipes.

set shell := ["bash", "-cu"]

# Default = list recipes.
default:
    @just --list

# ── Setup / Maintenance ─────────────────────────────────────────────────────

# Install all required development tools.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v cargo-nextest >/dev/null 2>&1 || cargo install --locked cargo-nextest
    command -v cargo-sweep >/dev/null 2>&1 || cargo install --locked cargo-sweep
    command -v cargo-sort >/dev/null 2>&1 || cargo install --locked cargo-sort
    command -v cargo-shear >/dev/null 2>&1 || cargo install --locked cargo-shear
    command -v typos-cli >/dev/null 2>&1 || cargo install --locked typos-cli
    command -v rumdl >/dev/null 2>&1 || cargo install --locked rumdl
    command -v leptosfmt >/dev/null 2>&1 || cargo install --locked leptosfmt
    command -v git-cliff >/dev/null 2>&1 || cargo install --locked git-cliff
    # Frontend WASM toolchain — cargo-leptos drives `fe-build`/`fe-build-dev`;
    # trunk drives `fe-dev` (it has built-in API proxy to the axum backend).
    rustup target add wasm32-unknown-unknown
    command -v cargo-leptos >/dev/null 2>&1 || cargo install --locked cargo-leptos
    command -v trunk >/dev/null 2>&1 || cargo install --locked trunk
    if [ "{{os()}}" = "macos" ]; then
      brew list lld >/dev/null 2>&1 || brew install lld
      echo "macOS lld is opt-in (brew path is machine-specific)."
      echo "For faster local links add to ~/.cargo/config.toml:"
      echo "  [target.aarch64-apple-darwin]"
      echo "  rustflags = [\"-Clink-arg=-fuse-ld=$(brew --prefix lld)/bin/ld64.lld\"]"
    elif command -v mold >/dev/null 2>&1; then
      :
    elif command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -q && sudo apt-get install -y mold
    else
      echo "install 'mold' via your package manager (.cargo/config.toml needs it on Linux)"
    fi
    git config core.hooksPath .githooks 2>/dev/null || true
    echo "setup done"

# Reclaim disk: sweep build artifacts not accessed today.
clean:
    command -v cargo-sweep >/dev/null 2>&1 || cargo install --locked cargo-sweep
    cargo sweep --time 0

# Generate documentation for the workspace.
docs:
    cargo doc --no-deps --open

# ── Formatting ───────────────────────────────────────────────────────────────

# Format all code.
format:
    rumdl fmt .
    cargo sort -w -g
    leptosfmt . -x target
    cargo fmt --all

# Auto-fix linting issues.
fix:
    rumdl check --fix .
    cargo fmt --all

# ── Lints ────────────────────────────────────────────────────────────────────

# Run all lints.
lint:
    typos
    rumdl check .
    cargo sort -w -g -c
    cargo fmt --all -- --check
    leptosfmt . --check -x target
    cargo clippy --workspace --all-targets -- -D warnings
    cargo shear

# Check for Chinese characters.
check-cn:
    rg --line-number --column "\p{Han}"

# ── Build / Run ──────────────────────────────────────────────────────────────

# Native run of the axum server. Debug-level by default; export RUST_LOG to override.
run:
    RUST_LOG="${RUST_LOG:-status_server=debug,common=info,tower_http=info,info}" \
        cargo run -p status-server

# Build the server binary (release).
build:
    cargo build -p status-server --release

# Compile gate — use instead of `cargo check`.
check:
    cargo check --workspace

# ── Frontend (Leptos CSR) ───────────────────────────────────────────────────

# Watch + serve the leptos CSR frontend on :3002 with hot reload.
# Uses trunk for dev because it has built-in API proxy to the axum backend
# on :8081 (see Trunk.toml). Production builds use `just fe-build` (cargo-leptos).
fe-dev:
    trunk serve bin/status-frontend/index.html

# Build the frontend (release) into target/site/ via cargo-leptos (pure CSR).
# cargo-leptos handles WASM compilation, wasm-bindgen glue generation, and
# JS minification. Tailwind CSS (v4) is compiled separately because the
# standalone `tailwindcss` CLI scans .rs sources for class names. Static
# assets (Plotly.js, index.html) are copied alongside the WASM bundle.
# NOTE: cargo-leptos cleans `site-root` on each build, so Tailwind CSS and
# asset copies MUST run AFTER `cargo leptos build`, not before.
fe-build:
    #!/usr/bin/env bash
    set -euo pipefail
    # 1. Build the WASM bundle + JS glue via cargo-leptos (--frontend-only = pure CSR).
    cargo leptos build --frontend-only --release
    # 2. cargo-leptos names the WASM `status_frontend.wasm`; the index.html and
    #    JS glue expect `status_frontend_bg.wasm` (wasm-bindgen convention).
    #    Rename to match so the index.html works for both trunk dev and prod.
    if [ -f target/site/pkg/status_frontend.wasm ] && [ ! -f target/site/pkg/status_frontend_bg.wasm ]; then
        mv target/site/pkg/status_frontend.wasm target/site/pkg/status_frontend_bg.wasm
    fi
    # 3. Compile Tailwind CSS (v4) → minified, self-contained main.css.
    mkdir -p target/site/style
    tailwindcss -i bin/status-frontend/style/main.css \
                -o target/site/style/main.css \
                --minify
    # 4. Copy static assets (Plotly.js) and the index.html bootstrap.
    cp bin/status-frontend/assets/plotly.min.js target/site/pkg/
    cp bin/status-frontend/index.html target/site/index.html
    echo "frontend built to target/site/"

# Build the frontend (debug) via cargo-leptos (pure CSR).
fe-build-dev:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo leptos build --frontend-only
    if [ -f target/site/pkg/status_frontend.wasm ] && [ ! -f target/site/pkg/status_frontend_bg.wasm ]; then
        mv target/site/pkg/status_frontend.wasm target/site/pkg/status_frontend_bg.wasm
    fi
    mkdir -p target/site/style
    tailwindcss -i bin/status-frontend/style/main.css \
                -o target/site/style/main.css
    cp bin/status-frontend/assets/plotly.min.js target/site/pkg/
    cp bin/status-frontend/index.html target/site/index.html
    echo "frontend built to target/site/ (debug)"

# Serve the built frontend (use after fe-build).
fe-serve:
    python3 -m http.server 3002 --directory target/site

# Build the frontend WASM directly (no wasm-bindgen glue).
fe-build-wasm:
    cargo build -p status-frontend --target wasm32-unknown-unknown --release

# ── Tests ───────────────────────────────────────────────────────────────────

# Fast: unit tests, no external services needed.
test:
    cargo test --workspace

# Run a single test binary.
test-one BIN *ARGS:
    cargo nextest run -p {{BIN}} {{ARGS}}

# Run tests with coverage.
test-coverage:
    cargo tarpaulin --all-features --workspace --timeout 300

# ── CI ───────────────────────────────────────────────────────────────────────

# Full CI check.
ci: lint test build

# Quick check that the public surface is alive on localhost:8081.
smoke:
    @echo "health:" ; curl -sS -o /dev/null -w "  %{http_code}\n" http://localhost:8081/healthz
    @echo "ready:"  ; curl -sS -o /dev/null -w "  %{http_code}\n" http://localhost:8081/readyz
    @echo "targets:"; curl -sS -o /dev/null -w "  %{http_code}\n" http://localhost:8081/api/v1/targets
