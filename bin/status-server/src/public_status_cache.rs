//! Two-layer cache for the public status page.
//!
//! - **Hot layer**: `moka::future::Cache` with a short TTL (30s default).
//!   Concurrent requests for the same page id share one compute via
//!   `try_get_with`; the others wait on the future and receive the same
//!   `Arc<PublicStatusPage>`.
//! - **Stale fallback** (`last_good`): a `parking_lot::RwLock<HashMap<…>>`
//!   that captures the last successful snapshot per page id. When the
//!   compute closure errors, [`PublicStatusCache::get_or_compute`] serves
//!   the stale snapshot (still within its TTL window) so a transient storage
//!   failure does not blank the public page.
//!
//! Mutations to targets / status-pages / incidents / maintenance should call
//! [`PublicStatusCache::invalidate_page`] (or [`Self::invalidate_all`]) so
//! the next read picks up fresh data instead of waiting for the TTL to elapse.

use std::collections::HashMap;
use std::sync::Arc;

use statuscore::domain::PublicStatusPage;
use uuid::Uuid;

/// Default TTL for the hot layer. Long enough to absorb a burst of public
/// reads; short enough that a status change is reflected within half a
/// minute on the public page (faster if `invalidate` is wired up).
pub const DEFAULT_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Hot-layer capacity. A self-hosted instance rarely has more than a few
/// status pages; 256 is ample headroom and bounds memory in pathological
/// cases.
pub const DEFAULT_CAPACITY: u64 = 256;

/// Outcome of [`PublicStatusCache::get_or_compute`]. `Fresh` carries a
/// freshly-computed snapshot (or its hot-layer cached copy); `Stale` means
/// the compute failed and the last-good snapshot was served instead.
#[derive(Debug)]
pub enum CacheLookup {
    Fresh(Arc<PublicStatusPage>),
    Stale(Arc<PublicStatusPage>),
}

#[derive(Clone)]
pub struct PublicStatusCache {
    inner: moka::future::Cache<Uuid, Arc<PublicStatusPage>>,
    // `parking_lot::RwLock` is not `Clone`, so we wrap it in an `Arc` to give
    // `PublicStatusCache` a cheap `Clone` (the `moka` cache is already
    // internally `Arc`-ed, so cloning it is also cheap). This lets
    // `PublicStatusCache` live on the `Clone`-able `AppState`.
    last_good: Arc<parking_lot::RwLock<HashMap<Uuid, Arc<PublicStatusPage>>>>,
}

impl PublicStatusCache {
    /// Build with the default TTL (30s) and capacity (256).
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    /// Build with a custom TTL. Capacity stays at `DEFAULT_CAPACITY`.
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self::with_capacity_and_ttl(DEFAULT_CAPACITY, ttl)
    }

    /// Build with a custom capacity and TTL.
    pub fn with_capacity_and_ttl(capacity: u64, ttl: std::time::Duration) -> Self {
        Self {
            inner: moka::future::Cache::builder().max_capacity(capacity).time_to_live(ttl).build(),
            last_good: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    /// Fetch a snapshot for `page_id`, computing it via `compute_fn` if the
    /// hot layer misses. Single-flight: concurrent callers for the same key
    /// share the in-flight compute. On compute error, the last-good
    /// snapshot (if any) is served as [`CacheLookup::Stale`]; if there is no
    /// last-good snapshot, `compute_fn`'s error is propagated.
    pub async fn get_or_compute<F, Fut>(
        &self,
        page_id: Uuid,
        compute_fn: F,
    ) -> Result<CacheLookup, statuscore::error::AppError>
    where
        F: FnOnce(Uuid) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = statuscore::error::Result<PublicStatusPage>>
            + Send
            + 'static,
    {
        // `try_get_with` deduplicates concurrent computes for the same key.
        // The closure returns `Result<Arc<PublicStatusPage>, ()>`; on
        // success we also stash into `last_good`. On failure moka does not
        // store anything, and the outer `Err` path serves the stale snapshot.
        let stale_snapshot = self.last_good.read().get(&page_id).cloned();
        match self
            .inner
            .try_get_with(page_id, async move {
                match compute_fn(page_id).await {
                    Ok(page) => {
                        let arc = Arc::new(page);
                        self.last_good.write().insert(page_id, Arc::clone(&arc));
                        Ok(arc)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, error_dbg = ?e, page_id = %page_id, "public_status_cache: compute failed");
                        Err(())
                    }
                }
            })
            .await
        {
            Ok(arc) => Ok(CacheLookup::Fresh(arc)),
            Err(_) => match stale_snapshot {
                Some(arc) => Ok(CacheLookup::Stale(arc)),
                None => Err(statuscore::error::AppError::internal_with_context(
                    "PUBLIC_STATUS_EMPTY",
                    "no cached status page snapshot available after compute failure",
                )),
            },
        }
    }

    /// Invalidate the hot entry for a specific status page.
    /// The stale fallback is intentionally retained so a transient outage
    /// does not blank the page.
    pub async fn invalidate_page(&self, page_id: Uuid) {
        self.inner.invalidate(&page_id).await;
    }

    /// Drop every hot entry. The stale fallback map is also cleared (use
    /// this only when the entire dataset has been replaced, e.g. on tenant
    /// reset).
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
        self.last_good.write().clear();
    }

    /// Number of entries currently resident in the hot layer.
    #[expect(dead_code)]
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

impl Default for PublicStatusCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PublicStatusCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicStatusCache")
            .field("hot_entries", &self.inner.entry_count())
            .field("stale_entries", &self.last_good.read().len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use statuscore::domain::{OverallState, OverallStatus};

    fn make_page(label: &str) -> PublicStatusPage {
        PublicStatusPage {
            overall: OverallStatus { state: OverallState::Operational, label: label.to_string() },
            generated_at: chrono::Utc::now(),
            site_name: label.to_string(),
            groups: Vec::new(),
            active_incidents: Vec::new(),
            recent_incidents: Vec::new(),
            recent_incidents_has_more: false,
            active_maintenance: Vec::new(),
            upcoming_maintenance: Vec::new(),
            logo_hash: None,
        }
    }

    #[tokio::test]
    async fn serves_computed_value() {
        let cache = PublicStatusCache::new();
        let id = Uuid::now_v7();
        let lookup = cache
            .get_or_compute(id, |_| async move { Ok(make_page("Page A")) })
            .await
            .expect("compute should succeed");
        match lookup {
            CacheLookup::Fresh(arc) => assert_eq!(arc.site_name, "Page A"),
            CacheLookup::Stale(_) => panic!("expected fresh, got stale"),
        }
    }

    #[tokio::test]
    async fn serves_stale_on_failure_after_success() {
        let cache = PublicStatusCache::new();
        let id = Uuid::now_v7();
        // First call succeeds, populating last_good.
        cache
            .get_or_compute(id, |_| async move { Ok(make_page("Good")) })
            .await
            .expect("first compute succeeds");
        // Force a hot miss by invalidating, then compute fails → must serve stale.
        cache.invalidate_page(id).await;
        let result = cache
            .get_or_compute(id, |_| async move {
                Err(statuscore::error::AppError::internal_with_context("X", "transient"))
            })
            .await
            .expect("stale fallback should be served");
        match result {
            CacheLookup::Stale(arc) => assert_eq!(arc.site_name, "Good"),
            CacheLookup::Fresh(_) => panic!("expected stale, got fresh"),
        }
    }

    #[tokio::test]
    async fn returns_error_when_no_stale_available() {
        let cache = PublicStatusCache::new();
        let id = Uuid::now_v7();
        let result = cache
            .get_or_compute(id, |_| async move {
                Err(statuscore::error::AppError::internal_with_context("X", "no data"))
            })
            .await;
        assert!(result.is_err(), "expected error when no stale fallback");
    }

    #[tokio::test]
    async fn invalidate_drops_hot_entry() {
        let cache = PublicStatusCache::new();
        let id = Uuid::now_v7();
        cache.get_or_compute(id, |_| async move { Ok(make_page("First")) }).await.ok();
        cache.invalidate_page(id).await;
        assert_eq!(cache.inner.entry_count(), 0);
    }
}
