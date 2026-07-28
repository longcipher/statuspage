use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use eyre::WrapErr;
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use parking_lot::Mutex;
use statuscore::config::ObservabilityConfig;
use statuscore::error::Result;

#[derive(Debug)]
pub struct MetricsHandle {
    provider: SdkMeterProvider,
}

impl Drop for MetricsHandle {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            tracing::warn!(error = %e, "metrics provider shutdown failed");
        }
    }
}

pub fn init(cfg: &ObservabilityConfig) -> Result<MetricsHandle> {
    let endpoint = if cfg.metrics_otlp_endpoint.trim().is_empty() {
        cfg.openobserve.otlp_endpoint.trim().to_string()
    } else {
        cfg.metrics_otlp_endpoint.trim().to_string()
    };

    if endpoint.is_empty() {
        return Err(statuscore::error::AppError::internal_with_context(
            "METRICS_OTLP_ENDPOINT",
            "metrics_enabled = true but no OTLP endpoint configured; set \
             observability.metrics_otlp_endpoint or observability.openobserve.otlp_endpoint",
        ));
    }

    let push_interval = std::time::Duration::from_secs(cfg.metrics_push_interval_secs.max(1));

    let exporter = MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(&endpoint)
        .build()
        .wrap_err("building OTLP metric exporter")?;

    let reader = PeriodicReader::builder(exporter).with_interval(push_interval).build();

    let provider = SdkMeterProvider::builder().with_reader(reader).build();

    opentelemetry::global::set_meter_provider(provider.clone());

    let meter = provider.meter("statuspage");
    register_descriptions(&meter);

    // Bridge the `metrics` facade to OpenTelemetry. Without this, all
    // `counter!` / `gauge!` / `histogram!` macro calls are silent no-ops
    // because no `metrics::Recorder` is installed.
    let recorder = OtelRecorder::new(meter);
    if metrics::set_global_recorder(recorder).is_err() {
        tracing::warn!(
            "metrics global recorder was already set; \
             metrics facade macros will use the existing recorder"
        );
    }

    tracing::info!(
        endpoint = %endpoint,
        push_interval_secs = push_interval.as_secs(),
        "OTLP metrics exporter started"
    );

    Ok(MetricsHandle { provider })
}

fn register_descriptions(meter: &opentelemetry::metrics::Meter) {
    meter
        .u64_counter("statuspage_build_info")
        .with_description("Build version gauge")
        .build()
        .add(1, &[]);

    meter
        .u64_counter("statuspage_checks_total")
        .with_description("Total checks completed, labelled by status")
        .build();
    meter
        .u64_counter("statuspage_checks_errors_total")
        .with_description("Total check errors, labelled by kind")
        .build();
    meter
        .u64_counter("statuspage_check_redirects_total")
        .with_description("HTTP redirect hops, labelled by outcome")
        .build();
    meter
        .u64_counter("statuspage_circuit_breaker_state_changes_total")
        .with_description("Circuit breaker state transitions")
        .build();
    meter
        .u64_counter("statuspage_storage_writes_total")
        .with_description("Storage writes, labelled by store and result")
        .build();
    meter
        .u64_counter("statuspage_storage_dropped_results_total")
        .with_description("Results dropped before storage, labelled by reason")
        .build();
    meter
        .u64_counter("statuspage_notifications_dead_lettered_total")
        .with_description(
            "Incident pages that exhausted all retries without delivering, labelled by transport",
        )
        .build();

    meter
        .f64_histogram("statuspage_check_duration_ms")
        .with_description("Total check duration in milliseconds")
        .with_unit("ms")
        .build();
    meter
        .f64_histogram("statuspage_check_dns_ms")
        .with_description("DNS resolution latency in milliseconds")
        .with_unit("ms")
        .build();
    meter
        .f64_histogram("statuspage_check_connect_ms")
        .with_description("TCP connect latency in milliseconds")
        .with_unit("ms")
        .build();
    meter
        .f64_histogram("statuspage_check_tls_ms")
        .with_description("TLS handshake latency in milliseconds")
        .with_unit("ms")
        .build();
    meter
        .f64_histogram("statuspage_check_ttfb_ms")
        .with_description("HTTP time-to-first-byte in milliseconds")
        .with_unit("ms")
        .build();
    meter
        .f64_histogram("statuspage_storage_batch_size")
        .with_description("Result batch size at flush time")
        .build();
    meter
        .f64_histogram("statuspage_storage_write_duration_ms")
        .with_description("Storage write duration in milliseconds")
        .with_unit("ms")
        .build();

    // Gauges use `f64_gauge` (not `u64_gauge`) so the bridge recorder — which
    // receives `f64` values from the `metrics::GaugeFn` trait — creates handles
    // of the same instrument type, letting the SDK reuse these descriptions.
    meter
        .f64_gauge("statuspage_targets_total")
        .with_description("Targets in this process's scheduler registry")
        .build();
    meter
        .f64_gauge("statuspage_targets_enabled")
        .with_description("Configured enabled monitors counted from DuckDB, labelled by kind")
        .build();
    meter
        .f64_gauge("statuspage_users_active")
        .with_description("Non-deleted user accounts counted from DuckDB")
        .build();
    meter
        .f64_gauge("statuspage_workers_in_flight")
        .with_description("Checks currently executing")
        .build();
    meter
        .f64_gauge("statuspage_result_queue_depth")
        .with_description("Current depth of the result channel buffer")
        .build();
    meter
        .f64_gauge("statuspage_circuit_breakers_open")
        .with_description("Number of circuit breakers currently in the Open state")
        .build();

    meter
        .u64_counter("statuspage_notifications_total")
        .with_description("Alert notifications dispatched, labelled by channel and kind")
        .build();
    meter
        .u64_counter("statuspage_notifications_failures_total")
        .with_description(
            "Alert notification dispatches that returned an error, labelled by channel",
        )
        .build();
    meter
        .u64_counter("statuspage_alerts_dropped_total")
        .with_description("Incident paging signals dropped before reaching the escalation engine")
        .build();

    meter
        .u64_counter("statuspage_http_requests_total")
        .with_description("HTTP requests handled, labelled by method, route, and status class")
        .build();
    meter
        .f64_histogram("statuspage_http_request_duration_ms")
        .with_description("HTTP request latency in milliseconds, labelled by method and route")
        .with_unit("ms")
        .build();
    meter
        .f64_gauge("statuspage_http_responses_inflight")
        .with_description("HTTP requests currently being served")
        .build();
    meter
        .u64_counter("statuspage_ratelimit_drops_total")
        .with_description("Per-IP rate-limit rejections (HTTP 429)")
        .build();
}

// ── Bridge recorder: forwards `metrics` facade calls to OpenTelemetry ─────

/// A `metrics::Recorder` that forwards counter / gauge / histogram calls to
/// the OpenTelemetry SDK's `Meter`. Instruments are cached per-`Key` (name +
/// labels) in `DashMap`s so the hot path — `register_*` called by the
/// `metrics!` macros on every metric emission — is a single hashmap lookup
/// plus an `Arc` clone.
///
/// `describe_*` methods are no-ops: instrument descriptions and units are
/// registered eagerly at startup via `register_descriptions(&meter)`, and the
/// OTel SDK reuses the same instrument pool when the bridge creates handles.
struct OtelRecorder {
    meter: opentelemetry::metrics::Meter,
    counters: DashMap<Key, Arc<OtelCounter>>,
    gauges: DashMap<Key, Arc<OtelGauge>>,
    histograms: DashMap<Key, Arc<OtelHistogram>>,
}

impl OtelRecorder {
    fn new(meter: opentelemetry::metrics::Meter) -> Self {
        Self { meter, counters: DashMap::new(), gauges: DashMap::new(), histograms: DashMap::new() }
    }
}

impl Recorder for OtelRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let entry = self.counters.entry(key.to_retained()).or_insert_with(|| {
            Arc::new(OtelCounter {
                instrument: self.meter.u64_counter(key.name().to_string()).build(),
                attrs: key_to_key_values(key),
                last_absolute: AtomicU64::new(0),
            })
        });
        Counter::from_arc((*entry).clone())
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        let entry = self.gauges.entry(key.to_retained()).or_insert_with(|| {
            Arc::new(OtelGauge {
                instrument: self.meter.f64_gauge(key.name().to_string()).build(),
                attrs: key_to_key_values(key),
                current: Mutex::new(0.0),
            })
        });
        Gauge::from_arc((*entry).clone())
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        let entry = self.histograms.entry(key.to_retained()).or_insert_with(|| {
            Arc::new(OtelHistogram {
                instrument: self.meter.f64_histogram(key.name().to_string()).build(),
                attrs: key_to_key_values(key),
            })
        });
        Histogram::from_arc((*entry).clone())
    }
}

/// Counter handle: wraps an OTel `Counter<u64>` with pre-computed attributes.
///
/// `absolute()` is supported via an `AtomicU64` that tracks the last seen
/// absolute value — only the positive delta is forwarded to the OTel counter
/// (which is monotonic and cannot be set to an arbitrary value).
struct OtelCounter {
    instrument: opentelemetry::metrics::Counter<u64>,
    attrs: Vec<KeyValue>,
    last_absolute: AtomicU64,
}

impl CounterFn for OtelCounter {
    fn increment(&self, value: u64) {
        self.instrument.add(value, &self.attrs);
        self.last_absolute.fetch_add(value, Ordering::Relaxed);
    }

    fn absolute(&self, value: u64) {
        // OTel counters are monotonic (add-only). To support `absolute()`,
        // track the last seen value and only forward the positive delta.
        let mut current = self.last_absolute.load(Ordering::Relaxed);
        loop {
            if value <= current {
                return;
            }
            match self.last_absolute.compare_exchange(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.instrument.add(value - current, &self.attrs);
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// Gauge handle: wraps an OTel `Gauge<f64>` with pre-computed attributes.
///
/// OTel gauges are absolute-only (`record(value)`), but the `metrics` facade
/// supports `increment` / `decrement`. We track the running value in a
/// `Mutex<f64>` per-`Key` and emit the absolute value on every update.
struct OtelGauge {
    instrument: opentelemetry::metrics::Gauge<f64>,
    attrs: Vec<KeyValue>,
    current: Mutex<f64>,
}

impl GaugeFn for OtelGauge {
    fn increment(&self, value: f64) {
        let new_value = {
            let mut current = self.current.lock();
            *current += value;
            *current
        };
        self.instrument.record(new_value, &self.attrs);
    }

    fn decrement(&self, value: f64) {
        let new_value = {
            let mut current = self.current.lock();
            *current -= value;
            *current
        };
        self.instrument.record(new_value, &self.attrs);
    }

    fn set(&self, value: f64) {
        {
            let mut current = self.current.lock();
            *current = value;
        }
        self.instrument.record(value, &self.attrs);
    }
}

/// Histogram handle: wraps an OTel `Histogram<f64>` with pre-computed
/// attributes.
struct OtelHistogram {
    instrument: opentelemetry::metrics::Histogram<f64>,
    attrs: Vec<KeyValue>,
}

impl HistogramFn for OtelHistogram {
    fn record(&self, value: f64) {
        self.instrument.record(value, &self.attrs);
    }
}

/// Convert a `metrics::Key`'s labels into an owned `Vec<opentelemetry::KeyValue>`.
/// The result is cached alongside the instrument in the recorder's `DashMap`,
/// so this allocation happens at most once per unique (name, labels) pair.
fn key_to_key_values(key: &Key) -> Vec<KeyValue> {
    key.labels()
        .map(|label| KeyValue::new(label.key().to_string(), label.value().to_string()))
        .collect()
}

pub mod names {
    pub const CHECKS_TOTAL: &str = "statuspage_checks_total";
    pub const CHECK_DURATION_MS: &str = "statuspage_check_duration_ms";
    pub const CHECK_DNS_MS: &str = "statuspage_check_dns_ms";
    pub const CHECK_CONNECT_MS: &str = "statuspage_check_connect_ms";
    pub const CHECK_TLS_MS: &str = "statuspage_check_tls_ms";
    pub const CHECK_TTFB_MS: &str = "statuspage_check_ttfb_ms";
    pub const CHECK_REDIRECTS_TOTAL: &str = "statuspage_check_redirects_total";
    pub const CHECKS_ERRORS_TOTAL: &str = "statuspage_checks_errors_total";
    pub const STORAGE_WRITES_TOTAL: &str = "statuspage_storage_writes_total";
    pub const STORAGE_BATCH_SIZE: &str = "statuspage_storage_batch_size";
    pub const STORAGE_WRITE_DURATION_MS: &str = "statuspage_storage_write_duration_ms";
    pub const STORAGE_DROPPED_RESULTS_TOTAL: &str = "statuspage_storage_dropped_results_total";
    pub const WORKERS_IN_FLIGHT: &str = "statuspage_workers_in_flight";
    pub const RESULT_QUEUE_DEPTH: &str = "statuspage_result_queue_depth";
    pub const CIRCUIT_BREAKER_STATE_CHANGES: &str =
        "statuspage_circuit_breaker_state_changes_total";
    pub const CIRCUIT_BREAKERS_OPEN: &str = "statuspage_circuit_breakers_open";
    pub const TARGETS_ENABLED: &str = "statuspage_targets_enabled";
    pub const USERS_ACTIVE: &str = "statuspage_users_active";
    pub const HTTP_REQUESTS_TOTAL: &str = "statuspage_http_requests_total";
    pub const HTTP_REQUEST_DURATION_MS: &str = "statuspage_http_request_duration_ms";
    pub const HTTP_RESPONSES_INFLIGHT: &str = "statuspage_http_responses_inflight";
    pub const RATELIMIT_DROPS: &str = "statuspage_ratelimit_drops_total";
    pub const NOTIFICATIONS_TOTAL: &str = "statuspage_notifications_total";
    pub const NOTIFICATIONS_FAILURES: &str = "statuspage_notifications_failures_total";
    pub const NOTIFICATIONS_DEAD_LETTERED: &str = "statuspage_notifications_dead_lettered_total";
    pub const ALERTS_DROPPED: &str = "statuspage_alerts_dropped_total";
}
