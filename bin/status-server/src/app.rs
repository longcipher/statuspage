//! Application state shared across handlers.

use std::sync::Arc;

use common::email::{EmailAddress, EmailSender, LogOnlyEmailSender, build_email_sender};
use common::http_client::OutboundHttpClient;
use common::notifier::{LogNotifier, Notifier};
use common::security::SsrfGuard;
use statuscore::config::AppConfig;
use storage::Storage;

use crate::auth::AuthService;
use crate::idempotency::IdempotencyCache;
use crate::public_status_cache::PublicStatusCache;
use crate::rate_limit::IPRateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    // Held on AppState so handlers can read runtime config without
    // re-parsing.
    pub config: AppConfig,
    /// Fire-and-forget incident notifier. `Arc<dyn Notifier>` so handlers can
    /// clone the reference into `tokio::spawn` tasks without taking ownership
    /// of the state.
    pub notifier: Arc<dyn Notifier>,
    /// Transactional email sender used by the subscriber dispatch worker to
    /// deliver incident/maintenance notifications to public status-page
    /// subscribers. Defaults to `LogOnlyEmailSender`; a real transport
    /// (Resend) is built from `[email]` config when `provider != "log"`.
    pub email_sender: Arc<dyn EmailSender>,
    /// SSRF-guarded HTTPS client for outbound non-check traffic (subscriber
    /// webhook / Slack delivery). Built once at startup with
    /// [`SsrfGuard::strict`] so any URL pointing at a private IP is dropped
    /// at DNS-filter time before any TCP open. Cloned cheaply (it's a
    /// `hyper-util` `Client` wrapping an `Arc` connector).
    pub outbound_http: OutboundHttpClient,
    /// `reqwest::Client` shared by the notifier transports, the channel
    /// dispatch context, the escalation engine, and the heartbeat snitch.
    /// Distinct from `outbound_http` (a hyper-util client built for the
    /// probe path's phase-timing connector) because the notifier transports
    /// are written against `reqwest::Client`. Built with
    /// `redirect::Policy::none()` as a second layer of SSRF defence: a
    /// public webhook URL that 30x-redirects to an internal address won't
    /// be followed.
    pub notifier_http: reqwest::Client,
    /// Sender address (`From:` header) for transactional email — derived
    /// from `[email] from_address` / `from_name`. Shared by the auth
    /// service, the subscriber dispatcher, the escalation engine, and the
    /// incident coalescer's channel dispatch so every outbound mail uses
    /// the same configured identity.
    pub from_address: EmailAddress,
    /// External base URL (scheme + host + optional port) used to build links
    /// the subscriber sees in emails — unsubscribe URL, incident URL. Comes
    /// from `[auth] public_base_url` (defaults to `http://localhost:8080`).
    pub public_base_url: String,
    /// Two-layer cache for the public status page. The hot layer is a
    /// `moka::future::Cache` (30s TTL, single-flight compute); the stale
    /// fallback holds the last-good snapshot per page so a transient storage
    /// blip doesn't blank the public page. Mutations to targets / pages /
    /// incidents / maintenance call `invalidate_all` so the next read picks
    /// up fresh data.
    pub public_cache: PublicStatusCache,
    /// Auth service: session + API token + magic-link lifecycle. Shared
    /// across the auth middleware (which resolves identity per request) and
    /// the auth routes (login / logout / tokens / sessions / prefs).
    pub auth: AuthService,
    /// In-process idempotency cache for bulk endpoints that accept an
    /// `Idempotency-Key` header. 24h TTL, 64 KiB max cached body. Lost on
    /// restart — documented as a convenience for client retries, not a
    /// durable store.
    pub idempotency: IdempotencyCache,
    /// In-process per-IP rate limiter for auth endpoints (magic-link
    /// request/verify, bootstrap). `None` when
    /// `[rate_limits.per_ip].auth_endpoints_per_min == 0` (limiter
    /// disabled). Caddy enforces a coarse edge limit; this is the second
    /// line of defence for abuse-prone endpoints.
    pub auth_rate_limiter: Option<Arc<IPRateLimiter>>,
    /// In-process per-IP rate limiter for public API endpoints
    /// (`/api/public/v1/*`). `None` when
    /// `[public_status].public_per_ip_rate_limit_per_min == 0` (disabled).
    /// Protects public endpoints when the reverse proxy is bypassed.
    pub public_rate_limiter: Option<Arc<IPRateLimiter>>,
    /// In-process per-IP rate limiter for the unauthenticated heartbeat
    /// endpoint (`POST /api/v1/heartbeat/{target_id}`). `None` when
    /// `[rate_limits.per_ip].heartbeat_per_ip_per_min == 0` (disabled).
    /// Prevents an attacker from exhausting the DuckDB mutex throughput
    /// and starving legitimate API traffic.
    pub heartbeat_rate_limiter: Option<Arc<IPRateLimiter>>,
}

impl AppState {
    /// Construct with an explicit notifier. Use this when the caller has
    /// already built a specific transport (LogNotifier in dev, real channels
    /// in production). The email sender is derived from `[email]` config.
    pub fn with_notifier(
        storage: impl Storage + 'static,
        config: AppConfig,
        notifier: Arc<dyn Notifier>,
    ) -> Self {
        let outbound_http =
            common::http_client::outbound::build_outbound_client(SsrfGuard::strict());
        // Separate `reqwest::Client` for the notifier transports / channel
        // dispatch / escalation / snitch. `redirect::Policy::none()` is the
        // second layer of SSRF defence (same rationale as the probe client).
        let notifier_http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let email_sender = build_email_sender(&config.email, &outbound_http).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to build email sender; falling back to log-only");
            Arc::new(LogOnlyEmailSender::new(config.email.from_name.clone()))
        });
        let public_base_url = config.auth.public_base_url.trim_end_matches('/').to_string();
        let storage_arc: Arc<dyn Storage> = Arc::new(storage);
        let from_address =
            EmailAddress::new(config.email.from_address.clone(), config.email.from_name.clone());
        let auth = AuthService::new(
            storage_arc.clone(),
            config.auth.clone(),
            email_sender.clone(),
            from_address.clone(),
        );
        Self {
            storage: storage_arc,
            config: config.clone(),
            notifier,
            email_sender,
            outbound_http,
            notifier_http,
            from_address,
            public_base_url,
            public_cache: PublicStatusCache::new(),
            auth,
            idempotency: IdempotencyCache::new(),
            auth_rate_limiter: crate::rate_limit::build_limiter(
                config.rate_limits.per_ip.auth_endpoints_per_min,
            ),
            public_rate_limiter: crate::rate_limit::build_limiter(
                config.public_status.public_per_ip_rate_limit_per_min,
            ),
            heartbeat_rate_limiter: crate::rate_limit::build_limiter(
                config.rate_limits.per_ip.heartbeat_per_ip_per_min,
            ),
        }
    }

    /// Construct with the log-only notifier. The default for v1: every
    /// incident surfaces as a `tracing::info!` line. Real transports are
    /// wired via [`Self::with_notifier`] when an operator configures a
    /// notification channel.
    pub fn new(storage: impl Storage + 'static, config: AppConfig) -> Self {
        Self::with_notifier(storage, config, Arc::new(LogNotifier))
    }
}
