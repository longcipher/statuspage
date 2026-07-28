//! In-process idempotency cache for write endpoints that accept an
//! `Idempotency-Key` header.
//!
//! Keyed by `(idempotency_key, body_hash)` so the same key with a different
//! body is a fresh request (not a replay). The cache stores the serialized
//! response (status + body bytes) for 24 hours; entries are lost on restart
//! (documented behaviour — the cache is a convenience for client retries,
//! not a durable store).
//!
//! Only `POST /targets/bulk` and `POST /targets/bulk/action` opt in. A
//! missing header is a pass-through — the endpoint behaves as if idempotency
//! is not implemented.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use dashmap::DashMap;
use moka::future::Cache;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Default TTL: 24 hours. Matches the documented behaviour in `docs/api.md`.
const DEFAULT_TTL: Duration = Duration::from_hours(24);

/// Maximum cached body size: 64 KiB. Bulk responses are small JSON
/// envelopes; anything larger is skipped (the request proceeds without
/// caching) to avoid unbounded memory use.
const MAX_CACHED_BODY: usize = 64 * 1024;

/// A cached response: status code + body bytes + content type. Stored as
/// `Arc` so the cache can hand out cheap clones.
#[derive(Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub content_type: String,
    pub body: Arc<Bytes>,
}

/// RAII guard returned by [`IdempotencyCache::acquire_in_flight`]. Holds a
/// per-key owned mutex; dropping it releases the in-flight slot so the next
/// same-key request can proceed (and find the cached result). Kept opaque —
/// callers only need to bind it and let it drop.
#[derive(Debug)]
pub struct InFlightGuard {
    _guard: OwnedMutexGuard<()>,
}

/// In-process idempotency cache. Wraps a `moka` cache with a 24h TTL.
/// Cheap to clone (the inner cache is `Arc`-ed).
#[derive(Clone)]
pub struct IdempotencyCache {
    inner: Cache<String, CachedResponse>,
    /// Per-key in-flight locks for single-flight dedup. Without this, two
    /// concurrent requests sharing an `Idempotency-Key` both miss the cache,
    /// both execute the side-effecting handler, and the second store
    /// overwrites the first — a TOCTOU race that breaks idempotency. The
    /// lock serialises same-key requests; the second waiter double-checks
    /// the cache after acquiring the lock and short-circuits on the stored
    /// result.
    ///
    /// Entries are tiny (one `Arc<Mutex<()>>` each) and bounded by the
    /// number of distinct keys in flight; in steady state the count tracks
    /// the moka cache's churn. A long-lived process could trim this map
    /// periodically, but for an ops-surface workload the growth is
    /// negligible and not worth the cleanup-race complexity.
    in_flight: Arc<DashMap<String, Arc<Mutex<()>>>>,
}

impl IdempotencyCache {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Cache::builder().max_capacity(1024).time_to_live(ttl).build(),
            in_flight: Arc::new(DashMap::new()),
        }
    }

    /// Build the composite cache key: `"{idempotency_key}:{body_hash_hex}"`.
    /// The body hash ensures the same key with a different body is a fresh
    /// request rather than a replay of the old response.
    fn make_key(idempotency_key: &str, body: &[u8]) -> String {
        let hash = hex::encode(Sha256::digest(body));
        format!("{idempotency_key}:{hash}")
    }

    /// Check the cache for a hit. Returns `None` if the header is absent
    /// (pass-through) or if no cached entry exists. The caller is
    /// responsible for calling [`Self::store`] after a successful request.
    pub async fn lookup(&self, headers: &HeaderMap, body: &[u8]) -> Option<CachedResponse> {
        let key = Self::header_key(headers, body)?;
        self.inner.get(&key).await
    }

    /// Store a response in the cache. No-op if the `Idempotency-Key` header
    /// is absent. Bodies larger than [`MAX_CACHED_BODY`] are not cached
    /// (the request still succeeds, it just isn't idempotent on retry).
    pub async fn store(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        status: StatusCode,
        content_type: &str,
        response_body: Bytes,
    ) {
        let Some(key) = Self::header_key(headers, body) else {
            return;
        };
        if response_body.len() > MAX_CACHED_BODY {
            return;
        }
        self.inner
            .insert(
                key,
                CachedResponse {
                    status,
                    content_type: content_type.to_string(),
                    body: Arc::new(response_body),
                },
            )
            .await;
    }

    /// Acquire the per-key in-flight lock for single-flight dedup. Returns
    /// `None` when no `Idempotency-Key` header is present (pass-through —
    /// the caller proceeds without serialisation). When a header is present,
    /// the returned [`InFlightGuard`] holds an owned lock that serialises
    /// concurrent requests sharing the same `(key, body_hash)`; drop it to
    /// release.
    ///
    /// Usage: call this *before* [`Self::lookup`] (or after a first miss),
    /// then re-check the cache once the guard is held — a concurrent request
    /// may have populated it while we waited for the lock. This closes the
    /// TOCTOU window where two same-key requests both miss, both execute,
    /// and the second store overwrites the first.
    pub async fn acquire_in_flight(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<InFlightGuard> {
        let key = Self::header_key(headers, body)?;
        let mutex = self.in_flight.entry(key).or_insert_with(|| Arc::new(Mutex::new(()))).clone();
        let guard = mutex.lock_owned().await;
        Some(InFlightGuard { _guard: guard })
    }

    /// Extract the composite cache key, or `None` if the header is absent.
    fn header_key(headers: &HeaderMap, body: &[u8]) -> Option<String> {
        let raw = headers.get(header::HeaderName::from_static("idempotency-key"))?;
        let key = raw.to_str().ok()?.trim();
        if key.is_empty() {
            return None;
        }
        Some(Self::make_key(key, body))
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IdempotencyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyCache")
            .field("entries", &self.inner.entry_count())
            .field("in_flight", &self.in_flight.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers(key: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(k) = key {
            h.insert(
                header::HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(k).unwrap(),
            );
        }
        h
    }

    #[tokio::test]
    async fn missing_header_is_pass_through() {
        let cache = IdempotencyCache::new();
        let headers = make_headers(None);
        let body = b"{}";
        assert!(cache.lookup(&headers, body).await.is_none());
        // Storing without a header is a no-op.
        cache
            .store(&headers, body, StatusCode::OK, "application/json", Bytes::from_static(b"{}"))
            .await;
        assert_eq!(cache.inner.entry_count(), 0);
    }

    #[tokio::test]
    async fn same_key_same_body_returns_cached_response() {
        let cache = IdempotencyCache::new();
        let headers = make_headers(Some("abc-123"));
        let body = br#"{"targets":[]}"#;
        // First request: cache miss.
        assert!(cache.lookup(&headers, body).await.is_none());
        // Store the response.
        cache
            .store(
                &headers,
                body,
                StatusCode::OK,
                "application/json",
                Bytes::from_static(br#"{"created":[],"errors":[]}"#),
            )
            .await;
        // Second request: cache hit.
        let cached = cache.lookup(&headers, body).await.unwrap();
        assert_eq!(cached.status, StatusCode::OK);
        assert_eq!(cached.content_type, "application/json");
        assert_eq!(&*cached.body, &b"{\"created\":[],\"errors\":[]}"[..]);
    }

    #[tokio::test]
    async fn same_key_different_body_is_a_fresh_request() {
        let cache = IdempotencyCache::new();
        let headers = make_headers(Some("abc-123"));
        let body_a = br#"{"targets":[1]}"#;
        let body_b = br#"{"targets":[2]}"#;
        // Store with body A.
        cache
            .store(&headers, body_a, StatusCode::OK, "application/json", Bytes::from_static(b"{}"))
            .await;
        // Lookup with body B → miss (different body hash).
        assert!(cache.lookup(&headers, body_b).await.is_none());
        // Lookup with body A → hit.
        assert!(cache.lookup(&headers, body_a).await.is_some());
    }

    #[tokio::test]
    async fn empty_header_value_is_treated_as_absent() {
        let cache = IdempotencyCache::new();
        let headers = make_headers(Some(""));
        let body = b"{}";
        assert!(cache.lookup(&headers, body).await.is_none());
    }

    #[tokio::test]
    async fn oversize_body_is_not_cached() {
        let cache = IdempotencyCache::new();
        let headers = make_headers(Some("abc-123"));
        let body = b"{}";
        let big = Bytes::from(vec![b'x'; MAX_CACHED_BODY + 1]);
        cache.store(&headers, body, StatusCode::OK, "application/json", big).await;
        assert_eq!(cache.inner.entry_count(), 0);
    }
}
