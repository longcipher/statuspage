//! In-process per-IP rate limiting for sensitive endpoints.
//!
//! Caddy already enforces coarse per-IP limits at the edge (see
//! `[rate_limits.per_ip]` — the values are mirrored there). This layer is
//! the second line of defence for endpoints that are expensive or
//! abuse-prone even at low volume:
//!
//! - `POST /api/v1/auth/magic-link/request` — sends email (costs money,
//!   spams victims).
//! - `POST /api/v1/auth/magic-link/verify` — token brute-force.
//! - `POST /api/v1/auth/bootstrap` — first-user takeover.
//!
//! Implementation: a `DashMap`-backed token bucket per client IP. Each
//! bucket holds `(tokens, last_refill)`; on every request we refill
//! proportionally to elapsed time up to `capacity`, then consume 1 token.
//! A bucket with no tokens returns 429 with the seconds-until-next-token
//! in `Retry-After`.
//!
//! Idle buckets are evicted by a background janitor (default 6h sweep,
//! 24h idle threshold) so a flood of one-off clients can't grow the map
//! unbounded. The limiter is shared via `Arc` and is cheap to clone into
//! the middleware.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::warn;

use crate::app::AppState;

/// One token bucket per IP. The bucket is mutex-guarded so concurrent
/// requests from the same IP see a consistent token count — without the
/// mutex, a burst could overdraw before any of them refilled.
#[derive(Debug)]
struct Bucket {
    /// Current token count (fractional — refills proportionally to time).
    tokens: f64,
    /// Last refill timestamp (monotonic clock — `Instant` so it's immune
    /// to wall-clock jumps).
    last_refill: Instant,
}

/// Configuration for the limiter — derived from `[rate_limits.per_ip]`.
#[derive(Debug, Clone)]
pub struct LimiterConfig {
    /// Steady-state refill rate: tokens per second.
    pub refill_per_sec: f64,
    /// Bucket capacity (max tokens). Allows short bursts above the
    /// steady-state rate. Defaults to 2× the per-minute rate.
    pub capacity: f64,
}

impl LimiterConfig {
    /// Build from a per-minute quota. Capacity is 2× the per-minute rate
    /// so legitimate double-clicks / retries don't trip.
    pub fn from_per_minute(per_minute: u32) -> Self {
        let refill_per_sec = f64::from(per_minute) / 60.0;
        let capacity = f64::from(per_minute).max(1.0) * 2.0;
        Self { refill_per_sec, capacity }
    }
}

/// In-process per-IP token-bucket rate limiter. Cloning is cheap (the
/// `DashMap` is `Arc`-ed internally via `Arc`).
#[derive(Clone)]
pub struct IPRateLimiter {
    inner: Arc<LimiterInner>,
}

struct LimiterInner {
    buckets: DashMap<IpAddr, Mutex<Bucket>>,
    cfg: LimiterConfig,
}

impl std::fmt::Debug for IPRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IPRateLimiter")
            .field("buckets", &self.inner.buckets.len())
            .field("capacity", &self.inner.cfg.capacity)
            .field("refill_per_sec", &self.inner.cfg.refill_per_sec)
            .finish_non_exhaustive()
    }
}

/// Outcome of a rate-limit check.
pub enum CheckOutcome {
    /// Request is allowed; one token was consumed.
    Allow,
    /// Request is denied; the caller should retry after the given delay.
    Deny { retry_after: Duration },
}

impl IPRateLimiter {
    /// Build a limiter from the configured per-minute quota. Returns
    /// `None` when `per_minute == 0` (limiter disabled in config).
    pub fn from_per_minute(per_minute: u32) -> Option<Self> {
        if per_minute == 0 {
            return None;
        }
        Some(Self {
            inner: Arc::new(LimiterInner {
                buckets: DashMap::new(),
                cfg: LimiterConfig::from_per_minute(per_minute),
            }),
        })
    }

    /// Check + consume one token for the given IP. On `Deny` the caller
    /// should respond 429 with `Retry-After: retry_after.as_secs()`.
    #[expect(clippy::significant_drop_tightening)]
    pub fn check(&self, ip: IpAddr) -> CheckOutcome {
        let now = Instant::now();
        let cfg = &self.inner.cfg;
        // Use `entry` so the bucket is created atomically with the lookup.
        let entry = self.inner.buckets.entry(ip).or_insert_with(|| {
            // New bucket starts full so the first burst from a fresh IP
            // is allowed up to capacity.
            Mutex::new(Bucket { tokens: cfg.capacity, last_refill: now })
        });
        let mut bucket = entry.lock();
        // Refill: tokens accumulate proportionally to elapsed time, capped
        // at capacity. Monotonic clock so a wall-clock jump can't grant
        // unbounded tokens.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = elapsed.mul_add(cfg.refill_per_sec, bucket.tokens).min(cfg.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            drop(bucket);
            CheckOutcome::Allow
        } else {
            // Time until the next whole token is available.
            let deficit = 1.0 - bucket.tokens;
            let secs = (deficit / cfg.refill_per_sec).ceil() as u64;
            let retry_after = Duration::from_secs(secs.max(1));
            drop(bucket);
            CheckOutcome::Deny { retry_after }
        }
    }

    /// Number of tracked buckets. Exposed for diagnostics / metrics.
    #[cfg_attr(not(test), expect(dead_code, reason = "diagnostic helper used only in tests"))]
    pub fn bucket_count(&self) -> usize {
        self.inner.buckets.len()
    }

    /// Evict buckets that haven't been touched in `idle_threshold`. Called
    /// by the background janitor task.
    pub fn evict_idle(&self, idle_threshold: Duration) -> usize {
        let now = Instant::now();
        let before = self.inner.buckets.len();
        self.inner.buckets.retain(|_, bucket| {
            let last = bucket.lock().last_refill;
            now.duration_since(last) < idle_threshold
        });
        before - self.inner.buckets.len()
    }
}

/// Extract the client IP from the request. Prefers `X-Forwarded-For`
/// (first hop) / RFC 7239 `Forwarded` when the immediate TCP peer is a
/// trusted proxy (per `is_trusted_proxy`); otherwise falls back to the
/// socket peer via `ConnectInfo<SocketAddr>`. Returns `None` if neither
/// is available.
///
/// The `is_trusted_proxy` gate is critical: without it, any client could
/// spoof its IP via a forged `X-Forwarded-For` header and escape the
/// per-IP rate limit bucket (or poison the `ip_hash` audit trail). The
/// caller supplies the trust predicate so this function stays free of
/// the `ipnet` / config dependency — the `guard` middleware wires it to
/// `state.config.security.trusted_proxies` (a `Vec<ipnet::IpNet>` whose
/// `contains` method is resolved via type inference, so `ipnet` need not
/// be a direct dependency of `status-server`).
pub fn client_ip<F>(
    headers: &HeaderMap,
    peer: Option<&ConnectInfo<SocketAddr>>,
    is_trusted_proxy: F,
) -> Option<IpAddr>
where
    F: Fn(IpAddr) -> bool,
{
    // Only honour XFF/Forwarded when the immediate TCP peer is a trusted
    // proxy. An untrusted peer (e.g. a direct client forging XFF) is
    // ignored — its TCP address is the real client IP.
    if let Some(peer) = peer {
        let peer_ip = peer.0.ip();
        if is_trusted_proxy(peer_ip) {
            // RFC 7239 `Forwarded:` header — preferred when present.
            if let Some(fwd) = headers.get(header::FORWARDED)
                && let Ok(s) = fwd.to_str()
                && let Some(ip) = parse_forwarded_for(s)
            {
                return Some(ip);
            }
            // Common `X-Forwarded-For:` header — first hop is the real client.
            if let Some(xff) = headers.get("x-forwarded-for")
                && let Ok(s) = xff.to_str()
                && let Some(first) = s.split(',').next()
            {
                let first = first.trim();
                if let Ok(ip) = first.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    // Fall back to the TCP peer. Requires
    // `.into_make_service_with_connect_info::<SocketAddr>()` on the
    // server — without it the extractor isn't populated.
    peer.map(|ci| ci.0.ip())
}

/// Parse the RFC 7239 `Forwarded` header's `for=...` parameter.
fn parse_forwarded_for(s: &str) -> Option<IpAddr> {
    for part in s.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("for=") {
            let rest = rest.trim_matches('"');
            if let Ok(ip) = rest.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Middleware: enforce the per-IP rate limit on the wrapped route tree.
/// On limit exceedance returns `429 Too Many Requests` with a
/// `Retry-After` header (seconds). On pass-through, calls `next`.
///
/// Usage:
/// ```ignore
/// use axum::middleware;
/// let auth_routes = Router::new()
///     .route("/magic-link/request", post(magic_link_request))
///     .layer(middleware::from_fn_with_state(state, rate_limit::guard));
/// ```
pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(limiter) = state.auth_rate_limiter.as_ref() else {
        // Limiter disabled in config — pass through.
        return next.run(req).await;
    };
    // Read ConnectInfo from request extensions (populated by
    // `into_make_service_with_connect_info::<SocketAddr>`). Optional
    // because the test harness might not insert it.
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().copied();
    // Only honour XFF/Forwarded when the peer is in the operator's
    // `trusted_proxies` CIDR list (`[security].trusted_proxies`, default
    // empty = "no reverse proxy — trust the TCP peer"). The closure
    // captures `&state.config.security.trusted_proxies` by reference;
    // `IpNet::contains` is resolved via type inference so `ipnet` need
    // not be a direct dependency of this crate.
    let trusted_proxies = &state.config.security.trusted_proxies;
    let ip = client_ip(req.headers(), peer.as_ref(), |ip: IpAddr| {
        trusted_proxies.iter().any(|net| net.contains(&ip))
    });
    let Some(ip) = ip else {
        // No client IP available — fail CLOSED. The previous behaviour
        // (fail open) let a misconfigured proxy bypass the limiter
        // entirely by stripping ConnectInfo / XFF. 429 is the safer
        // default: the operator sees the log line and fixes the
        // deployment (set `trusted_proxies`, or ensure the server is
        // started with `into_make_service_with_connect_info`).
        warn!("rate_limit: no client IP available; failing closed (429)");
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit check failed").into_response();
    };
    match limiter.check(ip) {
        CheckOutcome::Allow => next.run(req).await,
        CheckOutcome::Deny { retry_after } => {
            let retry_after_secs = retry_after.as_secs().max(1);
            let body = Body::from(
                serde_json::json!({
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": format!(
                            "too many requests from {ip}; retry after {retry_after_secs}s"
                        ),
                        "retry_after_secs": retry_after_secs,
                    }
                })
                .to_string(),
            );
            // Drain the body so the request can be dropped cleanly.
            let _ = axum::body::to_bytes(req.into_body(), 0).await;
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::RETRY_AFTER, retry_after_secs.to_string())
                .body(body)
                .unwrap_or_else(|_| StatusCode::TOO_MANY_REQUESTS.into_response())
        }
    }
}

/// Build the limiter for `AppState`. Wrapper around
/// [`IPRateLimiter::from_per_minute`] so callers don't need to import
/// the type.
pub fn build_limiter(per_minute: u32) -> Option<Arc<IPRateLimiter>> {
    IPRateLimiter::from_per_minute(per_minute).map(Arc::new)
}

/// Middleware: enforce the per-IP rate limit on public API endpoints
/// (`/api/public/v1/*`). Uses `state.public_rate_limiter` (configured
/// from `[public_status].public_per_ip_rate_limit_per_min`). On limit
/// exceedance returns `429 Too Many Requests` with a `Retry-After` header.
/// When the limiter is `None` (disabled in config), passes through.
pub async fn public_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(limiter) = state.public_rate_limiter.as_ref() else {
        return next.run(req).await;
    };
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().copied();
    let trusted_proxies = &state.config.security.trusted_proxies;
    let ip = client_ip(req.headers(), peer.as_ref(), |ip: IpAddr| {
        trusted_proxies.iter().any(|net| net.contains(&ip))
    });
    let Some(ip) = ip else {
        warn!("public_rate_limit: no client IP available; failing closed (429)");
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit check failed").into_response();
    };
    match limiter.check(ip) {
        CheckOutcome::Allow => next.run(req).await,
        CheckOutcome::Deny { retry_after } => {
            let retry_after_secs = retry_after.as_secs().max(1);
            let body = Body::from(
                serde_json::json!({
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": format!(
                            "too many requests from {ip}; retry after {retry_after_secs}s"
                        ),
                        "retry_after_secs": retry_after_secs,
                    }
                })
                .to_string(),
            );
            let _ = axum::body::to_bytes(req.into_body(), 0).await;
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::RETRY_AFTER, retry_after_secs.to_string())
                .body(body)
                .unwrap_or_else(|_| StatusCode::TOO_MANY_REQUESTS.into_response())
        }
    }
}

/// Middleware: enforce the per-IP rate limit on the unauthenticated
/// heartbeat endpoint (`POST /api/v1/heartbeat/{target_id}`). Uses
/// `state.heartbeat_rate_limiter` (configured from
/// `[rate_limits.per_ip].heartbeat_per_ip_per_min`). On limit exceedance
/// returns `429 Too Many Requests` with a `Retry-After` header. When the
/// limiter is `None` (disabled in config), passes through.
pub async fn heartbeat_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(limiter) = state.heartbeat_rate_limiter.as_ref() else {
        return next.run(req).await;
    };
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().copied();
    let trusted_proxies = &state.config.security.trusted_proxies;
    let ip = client_ip(req.headers(), peer.as_ref(), |ip: IpAddr| {
        trusted_proxies.iter().any(|net| net.contains(&ip))
    });
    let Some(ip) = ip else {
        warn!("heartbeat_rate_limit: no client IP available; failing closed (429)");
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit check failed").into_response();
    };
    match limiter.check(ip) {
        CheckOutcome::Allow => next.run(req).await,
        CheckOutcome::Deny { retry_after } => {
            let retry_after_secs = retry_after.as_secs().max(1);
            let _ = axum::body::to_bytes(req.into_body(), 0).await;
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .header(header::RETRY_AFTER, retry_after_secs.to_string())
                .body(Body::from(format!(
                    "too many heartbeat requests from {ip}; retry after {retry_after_secs}s"
                )))
                .unwrap_or_else(|_| StatusCode::TOO_MANY_REQUESTS.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers_xff(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(ip).unwrap());
        h
    }

    fn peer(ip: IpAddr) -> ConnectInfo<SocketAddr> {
        ConnectInfo(std::net::SocketAddr::new(ip, 12345))
    }

    /// Trust-all predicate — simulates an operator that has configured
    /// `trusted_proxies` to cover the test peer. Used by the XFF / Forwarded
    /// parsing tests so they exercise the header-parsing path.
    fn trust_all() -> impl Fn(IpAddr) -> bool {
        |_| true
    }

    /// Trust-none predicate — simulates a direct-to-internet deployment
    /// (`trusted_proxies = []`, the default) where no peer is a proxy.
    fn trust_none() -> impl Fn(IpAddr) -> bool {
        |_| false
    }

    #[test]
    fn parses_xff_first_hop() {
        let h = make_headers_xff("1.2.3.4, 5.6.7.8");
        // XFF is only honoured from a trusted peer — supply one.
        let p = peer("127.0.0.1".parse().unwrap());
        let ip = client_ip(&h, Some(&p), trust_all()).unwrap();
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn parses_ipv6_xff() {
        let h = make_headers_xff("2001:db8::1");
        let p = peer("127.0.0.1".parse().unwrap());
        let ip = client_ip(&h, Some(&p), trust_all()).unwrap();
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn parses_forwarded_header() {
        let mut h = HeaderMap::new();
        h.insert(header::FORWARDED, HeaderValue::from_str(r#"for="1.2.3.4""#).unwrap());
        let p = peer("127.0.0.1".parse().unwrap());
        let ip = client_ip(&h, Some(&p), trust_all()).unwrap();
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn returns_none_when_no_ip_available() {
        let h = HeaderMap::new();
        // No peer, no headers → None. (trust_all is irrelevant when peer
        // is None — the trust gate is never reached.)
        assert!(client_ip(&h, None, trust_all()).is_none());
    }

    #[test]
    fn falls_back_to_socket_peer() {
        let h = HeaderMap::new();
        let p = peer("1.2.3.4".parse().unwrap());
        // Untrusted peer (trust_none) — XFF/Forwarded ignored, peer IP used.
        let ip = client_ip(&h, Some(&p), trust_none()).unwrap();
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        // A direct client (not in trusted_proxies) forges an XFF header.
        // The forged header MUST be ignored — otherwise any client could
        // escape the per-IP rate limit bucket by sending a fake XFF.
        let h = make_headers_xff("9.9.9.9");
        let p = peer("10.0.0.1".parse().unwrap());
        let ip = client_ip(&h, Some(&p), trust_none()).unwrap();
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn trusted_peer_prefers_xff_over_peer() {
        // A trusted proxy supplies XFF — the header's first hop wins over
        // the proxy's own address.
        let h = make_headers_xff("9.9.9.9");
        let p = peer("127.0.0.1".parse().unwrap());
        let ip = client_ip(&h, Some(&p), trust_all()).unwrap();
        assert_eq!(ip.to_string(), "9.9.9.9");
    }

    #[test]
    fn no_peer_ignores_xff() {
        // Without a TCP peer we can't verify it's a trusted proxy, so XFF
        // is never consulted — returns None even if XFF is present.
        let h = make_headers_xff("1.2.3.4");
        assert!(client_ip(&h, None, trust_all()).is_none());
    }

    #[test]
    fn limiter_disabled_when_per_minute_zero() {
        assert!(IPRateLimiter::from_per_minute(0).is_none());
    }

    #[test]
    fn limiter_allows_burst_then_blocks() {
        // per_minute=5 → capacity=10, refill=5/60≈0.083/s.
        let l = IPRateLimiter::from_per_minute(5).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Burst of 10 passes.
        for i in 0..10 {
            match l.check(ip) {
                CheckOutcome::Allow => {}
                CheckOutcome::Deny { .. } => panic!("request {i} should be allowed"),
            }
        }
        // 11th is blocked.
        match l.check(ip) {
            CheckOutcome::Deny { retry_after } => {
                assert!(retry_after.as_secs() >= 1);
            }
            CheckOutcome::Allow => panic!("11th request should be denied"),
        }
        // A different IP has its own bucket.
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(matches!(l.check(ip2), CheckOutcome::Allow));
    }

    #[tokio::test]
    async fn limiter_refills_after_wait() {
        // per_minute=60 → capacity=120, refill=1/s.
        let l = IPRateLimiter::from_per_minute(60).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Drain the bucket.
        for _ in 0..120 {
            assert!(matches!(l.check(ip), CheckOutcome::Allow));
        }
        // Blocked immediately.
        assert!(matches!(l.check(ip), CheckOutcome::Deny { .. }));
        // Wait 1.1s — should refill ~1 token.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(matches!(l.check(ip), CheckOutcome::Allow));
    }

    #[test]
    fn evict_idle_removes_stale_buckets() {
        let l = IPRateLimiter::from_per_minute(60).unwrap();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Touch the bucket.
        l.check(ip);
        assert_eq!(l.bucket_count(), 1);
        // Evict with threshold 0 — should remove everything.
        let removed = l.evict_idle(Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(l.bucket_count(), 0);
    }
}
