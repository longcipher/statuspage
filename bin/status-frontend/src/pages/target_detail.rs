//! Target detail — shows the monitor's metadata, KPI cards (uptime, up/down
//! counts, latest latency), and a Plotly latency chart populated from
//! `GET /api/v1/targets/:id` and `GET /api/v1/targets/:id/results?limit=100`.

use leptos::either::Either;
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use statuscore::domain::{CheckResult, CheckStatus, Target};
use uuid::Uuid;

use crate::api::client;
use crate::components::error_state::{ErrorCallout, SkeletonDetail};
use crate::components::latency_chart::LatencyChart;
use crate::components::status_badge::CheckStatusBadge;

#[derive(Clone)]
struct TargetDetailView {
    target: Option<Target>,
    results: Vec<CheckResult>,
    error: Option<String>,
}

#[component]
pub fn TargetDetailPage() -> impl IntoView {
    let params = use_params_map();

    let id = move || {
        params.with(|p| p.get("id")).and_then(|s| Uuid::parse_str(&s).ok()).unwrap_or(Uuid::nil())
    };

    let data = LocalResource::new(move || {
        let id = id();
        async move { fetch_target_detail(id).await }
    });

    view! {
      <section class="flex flex-col gap-6">
        <A href="/targets">
          <span class="back-link">"← Back to monitors"</span>
        </A>

        <Suspense fallback=|| {
          view! { <SkeletonDetail label="Loading monitor details..." /> }
        }>
          {move || {
            data
              .get()
              .map(|view_data| {
                let TargetDetailView { target, results, error } = view_data;
                let Some(t) = target else {
                  if let Some(err) = error {
                    return Either::Left(

                      view! {
                        <ErrorCallout
                          title="Failed to load monitor"
                          message=err
                          on_retry=Box::new(move || data.refetch())
                        />
                      },
                    );
                  }
                  return Either::Left(
                    view! {
                      <ErrorCallout
                        title="Monitor not found"
                        message="This monitor may have been deleted or the link is incorrect."
                      />
                    },
                  );
                };
                let interval_secs = t.interval.as_secs();
                let group = t.group_name.clone().unwrap_or_else(|| "-".to_string());
                let kpi = Kpi::from_results(&results);
                let latest_status = results.first().map_or(CheckStatus::Error, |r| r.status);
                Either::Right(

                  view! {
                    <>
                      {error
                        .as_ref()
                        .map(|e| {
                          let err = e.clone();
                          view! {
                            <ErrorCallout
                              title="Some data could not be loaded"
                              message=err
                              on_retry=Box::new(move || data.refetch())
                            />
                          }
                        })} <header class="flex flex-col gap-2">
                        <h1 class="break-words type-page-title" style="color: var(--theme-text)">
                          {t.name.clone()}
                        </h1>
                        <p
                          class="type-mono line-clamp-1"
                          style="color: var(--theme-text-quiet)"
                          title=format!("ID: {}", t.id)
                        >
                          {format!("ID: {}", t.id)}
                        </p>
                        <dl class="grid grid-cols-2 gap-3 mt-3 sm:grid-cols-4">
                          <DetailRow label="Enabled" value=if t.enabled { "Yes" } else { "No" } />
                          <DetailRow label="Check type" value=t.check.kind() />
                          <DetailRow label="Interval" value=format!("{}s", interval_secs) />
                          <DetailRow label="Group" value=group />
                        </dl>
                      </header> <div class="flex gap-3 items-center">
                        <CheckStatusBadge status=latest_status />
                      </div> <KpiGrid kpi=kpi />
                      <LatencyChart data={
                        let mut data: Vec<(String, f64)> = results
                          .iter()
                          .map(|r| (r.timestamp.to_rfc3339(), f64::from(r.duration_ms)))
                          .collect();
                        data.reverse();
                        data
                      } />
                    </>
                  },
                )
              })
          }}
        </Suspense>
      </section>
    }
}

async fn fetch_target_detail(id: Uuid) -> TargetDetailView {
    let (target_res, results_res) =
        futures::join!(client::get_target(id), client::list_target_results(id, 100),);

    match target_res {
        Ok(target) => {
            let (results, error) = match results_res {
                Ok(r) => (r, None),
                Err(e) => (Vec::new(), Some(format!("Check results: {e}"))),
            };
            TargetDetailView { target: Some(target), results, error }
        }
        Err(e) => TargetDetailView { target: None, results: Vec::new(), error: Some(e) },
    }
}

// ── KPI cards ──────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Kpi {
    total: u32,
    up: u32,
    down: u32,
    error: u32,
    degraded: u32,
    latest_ms: u32,
    p95_ms: u32,
    uptime_pct: Option<f64>,
}

impl Kpi {
    fn from_results(rs: &[CheckResult]) -> Self {
        if rs.is_empty() {
            return Self::default();
        }
        let mut up = 0u32;
        let mut down = 0u32;
        let mut error = 0u32;
        let mut degraded = 0u32;
        let mut durations: Vec<u32> = Vec::with_capacity(rs.len());
        for r in rs {
            durations.push(r.duration_ms);
            match r.status {
                CheckStatus::Up => up += 1,
                CheckStatus::Down => down += 1,
                CheckStatus::Error => error += 1,
                CheckStatus::Degraded => degraded += 1,
                // `CheckStatus` is `#[non_exhaustive]`: a future variant is
                // neither Up nor a known failure, so skip it from the uptime
                // denominator rather than miscounting it as either side.
                _ => {}
            }
        }
        // Degraded is NOT counted as Up — it represents partial degradation
        // and must lower the uptime percentage.
        let total = up + down + error + degraded;
        let latest_ms = durations.first().copied().unwrap_or(0);
        durations.sort_unstable();
        let p95_idx = ((durations.len() as f64) * 0.95).ceil() as usize;
        let p95_ms = durations.get(p95_idx.saturating_sub(1)).copied().unwrap_or(0);
        let uptime_pct =
            if total == 0 { None } else { Some(100.0 * f64::from(up) / f64::from(total)) };
        Self { total, up, down, error, degraded, latest_ms, p95_ms, uptime_pct }
    }
}

#[component]
fn KpiGrid(kpi: Kpi) -> impl IntoView {
    let uptime_label = kpi.uptime_pct.map_or_else(|| "—".to_string(), |p| format!("{:.2}", p));
    let latest_label =
        if kpi.latest_ms == 0 { "—".to_string() } else { format!("{} ms", kpi.latest_ms) };
    let p95_label = if kpi.p95_ms == 0 { "—".to_string() } else { format!("{} ms", kpi.p95_ms) };

    let has_data = kpi.total > 0;

    view! {
      <section
        class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5"
        role="group"
        aria-label="Monitor metrics"
      >
        <StatTile
          label="Uptime"
          value=uptime_label
          unit="%"
          aria_label=kpi
            .uptime_pct
            .map_or_else(|| "Uptime: no data".to_string(), |p| format!("{:.2} percent uptime", p))
        />
        <StatTile
          label="Up"
          value=kpi.up.to_string()
          unit=""
          aria_label=format!("{} successful checks", kpi.up)
        />
        <StatTile
          label="Degraded"
          value=kpi.degraded.to_string()
          unit=""
          aria_label=format!("{} degraded checks", kpi.degraded)
        />
        <StatTile
          label="Down"
          value=kpi.down.to_string()
          unit=""
          aria_label=format!("{} failed checks", kpi.down)
        />
        <StatTile
          label="p95 latency"
          value=p95_label
          unit=""
          aria_label=if kpi.p95_ms == 0 {
            "p95 latency: no data".to_string()
          } else {
            format!("p95 latency {} milliseconds", kpi.p95_ms)
          }
        />
      </section>
      <p class="type-body" style="color: var(--theme-text-quiet)">
        {if has_data {
          format!(
            "{} checks · {} up · {} degraded · {} down · {} error · latest {}",
            kpi.total,
            kpi.up,
            kpi.degraded,
            kpi.down,
            kpi.error,
            latest_label,
          )
        } else {
          "No check results yet.".to_string()
        }}
      </p>
    }
}

#[component]
fn StatTile(
    #[prop(into)] label: String,
    #[prop(into)] value: String,
    #[prop(into)] unit: String,
    #[prop(into)] aria_label: String,
) -> impl IntoView {
    view! {
      <div class="stat-tile" role="img" aria-label=aria_label tabindex="0">
        <p class="stat-tile__value">
          {value}
          {if unit.is_empty() {
            None
          } else {
            Some(view! { <span class="stat-tile__unit">{unit}</span> })
          }}
        </p>
        <p class="stat-tile__label">{label}</p>
      </div>
    }
}

// ── Detail row ─────────────────────────────────────────────────────────────

#[component]
fn DetailRow(#[prop(into)] label: String, #[prop(into)] value: String) -> impl IntoView {
    let value_clone = value.clone();
    view! {
      <div class="flex flex-col min-w-0">
        <dt class="panel-label">{label}</dt>
        <dd class="type-mono type-data line-clamp-1" title=value_clone>
          {value}
        </dd>
      </div>
    }
}
