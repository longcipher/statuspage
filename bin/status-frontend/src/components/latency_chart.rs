//! Latency chart component rendered with the global Plotly.js runtime.
//!
//! Calls the global `Plotly.newPlot(...)` directly via an inline `<script>`
//! rather than going through the `plotly` Rust crate. The Rust crate's
//! `Plot::new()` calls `SystemTime::now()` to seed a div id, which panics
//! on `wasm32-unknown-unknown` with "time not implemented on this platform".
//! Calling Plotly.js directly avoids that panic, removes the `plotly` crate
//! dependency from the hot path, and keeps the chart behaviour identical.
//!
//! # Reactivity
//!
//! The component accepts a `Signal<Vec<(String, f64)>>` and re-renders the
//! chart whenever the signal updates. The signal is read inside a `move ||`
//! closure so Leptos tracks the dependency and re-evaluates on change.
//! Callers passing a plain `Vec` get an auto-converted static signal via
//! `#[prop(into)]` / `Signal::from`.
//!
//! # Plotly.js runtime
//!
//! The Plotly.js runtime is served locally from `/pkg/plotly.min.js`
//! (no CDN dependency). The runtime is loaded by `<script src=...>` in
//! `index.html` and exposed as `window.Plotly`.

use leptos::either::Either;
use leptos::prelude::*;
use serde_json::json;

/// Renders a Plotly line chart of latency over time.
///
/// `data` is a `Signal` of `(timestamp_label, latency_ms)` pairs. The chart
/// re-renders whenever the signal emits new data.
#[component]
pub fn LatencyChart(#[prop(into)] data: Signal<Vec<(String, f64)>>) -> impl IntoView {
    view! {
      <div class="p-4 sticker-card">
        <h3 class="mb-2 type-section-title" style="color: var(--theme-text)">
          "Latency (ms)"
        </h3>
        {move || {
          let d = data.get();
          if d.is_empty() {
            Either::Left(
              view! {
                <div
                  class="flex justify-center items-center w-full h-64 type-body"
                  style="color: var(--theme-text-quiet)"
                >
                  "No latency data available yet."
                </div>
              },
            )
          } else {
            let div_id = next_chart_id();
            let plot_json = build_plot_json(&d);
            let render_html = format!(
              "<div id=\"{div_id}\" class=\"w-full h-64\" role=\"img\" \
                     aria-label=\"Latency over time line chart\"></div>\
                     <script>\
                     (function() {{\
                       var el = document.getElementById('{div_id}');\
                       if (el && window.Plotly) {{\
                         window.Plotly.newPlot(el, {plot_json});\
                       }}\
                     }})();\
                     </script>",
            );
            Either::Right(
              // Build a unique div id from a monotonic counter so multiple
              // charts on the same page don't collide. We avoid
              // `SystemTime::now()` (panics in WASM) and `Uuid::now_v7()`
              // (would work but pulls in uuid v7 timing logic).
              // The inline `<script>` runs immediately after the div is
              // inserted into the DOM (Leptos sets `inner_html` on the
              // wrapper div, which evaluates the script in the page
              // context). `window.Plotly` is loaded by a `<script>` tag in
              // `index.html` so it's available by the time this runs.
              view! { <div class="w-full h-64" inner_html=render_html></div> },
            )
          }
        }}
      </div>
    }
}

/// Monotonic chart id counter — avoids any wall-clock dependency.
static CHART_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn next_chart_id() -> String {
    let n = CHART_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("latency-chart-{n}")
}

/// Build the Plotly.js JSON for a latency scatter/line chart.
///
/// Returns a JSON object `{ "data": [...], "layout": {...} }` ready to be
/// passed to `Plotly.newPlot(el, json)`.
fn build_plot_json(data: &[(String, f64)]) -> String {
    let x: Vec<&str> = data.iter().map(|(t, _)| t.as_str()).collect();
    let y: Vec<f64> = data.iter().map(|(_, v)| *v).collect();

    let plot_spec = json!({
        "data": [{
            "type": "scatter",
            "mode": "lines+markers",
            "name": "Latency",
            "x": x,
            "y": y,
        }],
        "layout": {
            "title": {"text": "Latency (ms)"},
            "height": 280,
            "margin": {"l": 50, "r": 20, "t": 40, "b": 40},
            "xaxis": {"tickangle": -45},
            "yaxis": {"title": {"text": "ms"}},
        }
    });

    plot_spec.to_string()
}
