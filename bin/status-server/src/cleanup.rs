//! Periodic cleanup of transient and time-series data.
//!
//! Five classes of garbage accumulate over time:
//!
//! 1. **Terminal deliveries** — rows in `subscriber_deliveries` with status
//!    `Sent` or `DeadLetter`. Kept for auditability for a while, then purged.
//! 2. **Unverified subscribers** — subscribers whose `verified_at` is still
//!    `None` past a grace period.
//! 3. **Expired sessions** — rows in `sessions` whose `expires_at` is past.
//! 4. **Expired magic links** — rows in `magic_link_tokens` whose `expires_at`
//!    is past.
//! 5. **Old check results** — rows in `check_results` older than the
//!    configured retention window. The 90-day day-strip is derived from
//!    incidents + the latest result, not raw results, so old rows can be
//!    safely purged.
//! 6. **Post-expiry API tokens** — tokens whose `expires_at` is older than
//!    the post-expiry grace window, bounded to limit table growth.
//!
//! This worker wakes every [`SWEEP_INTERVAL`] (default 6h) and deletes rows
//! older than the corresponding retention horizon. Errors are logged and
//! swallowed — a failed sweep just retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use statuscore::config::RetentionConfig;
use storage::Storage;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// How often the cleanup worker wakes. 6h keeps storage load negligible
/// while bounding the worst-case lag between a row becoming stale and its
/// deletion.
const SWEEP_INTERVAL: Duration = Duration::from_hours(6);

/// Deliveries in a terminal state (`Sent` / `DeadLetter`) older than this
/// are deleted. 30 days gives operators a month of audit trail without
/// unbounded growth.
const DELIVERY_RETENTION_DAYS: i64 = 30;

/// Unverified subscribers older than this are deleted. 7 days is a generous
/// window for an operator to click the verification link in the welcome
/// email.
const UNVERIFIED_SUBSCRIBER_GRACE_DAYS: i64 = 7;

/// Run the cleanup loop. Spawn from `main.rs`:
///
/// ```ignore
/// let cancel = CancellationToken::new();
/// tokio::spawn(cleanup::run(state.storage.clone(), state.config.retention, cancel.clone()));
/// ```
pub async fn run(storage: Arc<dyn Storage>, retention: RetentionConfig, cancel: CancellationToken) {
    info!(
        sweep_secs = SWEEP_INTERVAL.as_secs(),
        delivery_retention_days = DELIVERY_RETENTION_DAYS,
        unverified_grace_days = UNVERIFIED_SUBSCRIBER_GRACE_DAYS,
        check_results_days = retention.check_results_days,
        api_tokens_post_expiry_days = retention.api_tokens_post_expiry_days,
        "cleanup: started"
    );
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    // First tick fires immediately so we sweep on boot.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = sweep(storage.as_ref(), retention).await {
                    warn!(error = %e, "cleanup: sweep failed");
                }
            }
            () = cancel.cancelled() => {
                info!("cleanup: stopping");
                break;
            }
        }
    }
}

/// Run the rate-limit bucket janitor. Every 6h it evicts buckets that
/// haven't been touched in 24h so a flood of one-off clients can't grow
/// the map unbounded. Spawn from `main.rs`:
///
/// ```ignore
/// let cancel = CancellationToken::new();
/// tokio::spawn(cleanup::run_rate_limit_janitor(state.auth_rate_limiter.clone(), cancel.clone()));
/// ```
pub async fn run_rate_limit_janitor(
    limiter: Option<Arc<crate::rate_limit::IPRateLimiter>>,
    cancel: CancellationToken,
) {
    if limiter.is_none() {
        return;
    }
    info!(sweep_secs = SWEEP_INTERVAL.as_secs(), "rate_limit_janitor: started");
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Some(l) = limiter.as_ref() {
                    let removed = l.evict_idle(std::time::Duration::from_hours(24));
                    if removed > 0 {
                        info!(removed, "rate_limit_janitor: evicted idle buckets");
                    }
                }
            }
            () = cancel.cancelled() => {
                info!("rate_limit_janitor: stopping");
                break;
            }
        }
    }
}

/// One cleanup sweep. Each delete is independent — a failure in one doesn't
/// skip the other.
async fn sweep(storage: &dyn Storage, retention: RetentionConfig) -> statuscore::error::Result<()> {
    let now = Utc::now();

    let delivery_cutoff = now - chrono::Duration::days(DELIVERY_RETENTION_DAYS);
    match storage.delete_old_deliveries(delivery_cutoff).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, cutoff = %delivery_cutoff, "cleanup: deleted old deliveries");
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "cleanup: delete_old_deliveries failed"),
    }

    let subscriber_cutoff = now - chrono::Duration::days(UNVERIFIED_SUBSCRIBER_GRACE_DAYS);
    match storage.delete_unverified_subscribers(subscriber_cutoff).await {
        Ok(n) if n > 0 => {
            info!(
                deleted = n,
                cutoff = %subscriber_cutoff,
                "cleanup: deleted unverified subscribers"
            );
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "cleanup: delete_unverified_subscribers failed"),
    }

    // Expired sessions — the auth middleware rejects them on use, but rows
    // linger in the table until this sweep hard-deletes them.
    match storage.delete_expired_sessions(now).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, cutoff = %now, "cleanup: deleted expired sessions");
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "cleanup: delete_expired_sessions failed"),
    }

    // Expired magic links — same pattern as sessions.
    match storage.delete_expired_magic_links(now).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, cutoff = %now, "cleanup: deleted expired magic links");
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "cleanup: delete_expired_magic_links failed"),
    }

    // Old check results — the time-series table grows unbounded without a
    // purge. The 90-day day-strip is derived from incidents + the latest
    // result, so purging old rows does not affect the public page.
    let results_cutoff = now - chrono::Duration::days(i64::from(retention.check_results_days));
    match storage.delete_old_check_results(results_cutoff).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, cutoff = %results_cutoff, "cleanup: deleted old check results");
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "cleanup: delete_old_check_results failed"),
    }

    // Post-expiry API tokens — hard-delete tokens that expired more than
    // `api_tokens_post_expiry_days` ago. Bounds table growth.
    let token_cutoff =
        now - chrono::Duration::days(i64::from(retention.api_tokens_post_expiry_days));
    match storage.delete_expired_api_tokens(token_cutoff).await {
        Ok(n) if n > 0 => {
            info!(deleted = n, cutoff = %token_cutoff, "cleanup: deleted expired api tokens");
        }
        Ok(_) => {}
        Err(e) => warn!(error = %e, "cleanup: delete_expired_api_tokens failed"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use statuscore::domain::{DeliveryReason, DeliveryStatus, Subscriber, SubscriberChannel};
    use storage::MemoryStorage;
    use uuid::Uuid;

    fn make_subscriber(verified: bool, days_old: i64) -> Subscriber {
        let now = Utc::now();
        Subscriber {
            id: Uuid::now_v7(),
            status_page_id: Uuid::nil(),
            org_id: statuscore::domain::OrgId(Uuid::nil()),
            channel: SubscriberChannel::Email,
            target: "test@example.com".to_string(),
            config: serde_json::Value::Null,
            verified_at: verified.then_some(now),
            created_at: now - Duration::days(days_old),
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn deletes_old_terminal_deliveries() {
        let storage = MemoryStorage::new();
        // Enqueue a delivery (status = Pending, created_at = now).
        storage
            .enqueue_delivery(
                Uuid::nil(),
                Uuid::nil(),
                SubscriberChannel::Email,
                "test@example.com",
                "test",
                DeliveryReason::IncidentOpened,
            )
            .await
            .unwrap();
        // Mark it Sent and backdate it past the retention horizon via the
        // public mark_delivery API + a second backdated enqueue.
        // Since we can't directly mutate created_at through the public API,
        // use a cutoff in the future to force the deletion.
        let future_cutoff = Utc::now() + Duration::days(1);
        // First mark the delivery as Sent (terminal state).
        let deliveries = storage.list_pending_deliveries(10).await.unwrap();
        let id = deliveries[0].id;
        storage.mark_delivery(id, DeliveryStatus::Sent, None).await.unwrap();
        // Now delete with a cutoff in the future — all Sent rows are older
        // than "tomorrow" so they get deleted.
        let deleted = storage.delete_old_deliveries(future_cutoff).await.unwrap();
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn keeps_pending_deliveries_regardless_of_age() {
        let storage = MemoryStorage::new();
        storage
            .enqueue_delivery(
                Uuid::nil(),
                Uuid::nil(),
                SubscriberChannel::Email,
                "test@example.com",
                "test",
                DeliveryReason::IncidentOpened,
            )
            .await
            .unwrap();
        // Pending (not terminal) — never deleted even with a future cutoff.
        let future_cutoff = Utc::now() + Duration::days(100);
        let deleted = storage.delete_old_deliveries(future_cutoff).await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn deletes_old_unverified_subscribers() {
        let storage = MemoryStorage::new();
        // 10-day-old unverified subscriber → should be deleted.
        let sub = make_subscriber(false, 10);
        storage.create_subscriber(&sub).await.unwrap();

        // Cutoff = 7 days ago → subscriber created 10 days ago is older.
        let cutoff = Utc::now() - Duration::days(UNVERIFIED_SUBSCRIBER_GRACE_DAYS);
        let deleted = storage.delete_unverified_subscribers(cutoff).await.unwrap();
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn keeps_verified_subscribers_regardless_of_age() {
        let storage = MemoryStorage::new();
        let sub = make_subscriber(true, 100);
        storage.create_subscriber(&sub).await.unwrap();

        let cutoff = Utc::now() - Duration::days(UNVERIFIED_SUBSCRIBER_GRACE_DAYS);
        let deleted = storage.delete_unverified_subscribers(cutoff).await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn keeps_recent_unverified_subscribers() {
        let storage = MemoryStorage::new();
        // 2-day-old unverified subscriber — within grace.
        let sub = make_subscriber(false, 2);
        storage.create_subscriber(&sub).await.unwrap();

        let cutoff = Utc::now() - Duration::days(UNVERIFIED_SUBSCRIBER_GRACE_DAYS);
        let deleted = storage.delete_unverified_subscribers(cutoff).await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn deletes_old_check_results() {
        let storage = MemoryStorage::new();
        // Insert a result backdated 60 days — past the 30-day retention.
        let old = statuscore::domain::CheckResult {
            target_id: Uuid::now_v7(),
            org_id: statuscore::domain::OrgId(Uuid::nil()),
            timestamp: Utc::now() - Duration::days(60),
            status: statuscore::domain::CheckStatus::Up,
            duration_ms: 10,
            dns_ms: None,
            connect_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            response_code: None,
            response_size: None,
            error: None,
        };
        storage.record_result(&old).await.unwrap();
        // And a fresh one that should survive.
        let fresh = statuscore::domain::CheckResult {
            target_id: old.target_id,
            org_id: statuscore::domain::OrgId(Uuid::nil()),
            timestamp: Utc::now(),
            status: statuscore::domain::CheckStatus::Up,
            duration_ms: 10,
            dns_ms: None,
            connect_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            response_code: None,
            response_size: None,
            error: None,
        };
        storage.record_result(&fresh).await.unwrap();

        let cutoff = Utc::now() - Duration::days(30);
        let deleted = storage.delete_old_check_results(cutoff).await.unwrap();
        assert_eq!(deleted, 1);
        // Fresh result survives.
        let remaining = storage.list_results(old.target_id, 10).await.unwrap();
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn deletes_expired_api_tokens() {
        use statuscore::domain::{NewApiToken, ScopeSet, UserId};
        let storage = MemoryStorage::new();
        let user_id = UserId(Uuid::now_v7());

        // Token that expired 60 days ago — past the 30-day post-expiry window.
        // `expires_in_days` is relative to now, so a negative value isn't
        // possible via the public API. Instead, create a token with a 1-day
        // expiry and backdate the cutoff to "now" — the token's expiry is
        // 1 day in the future, but the cutoff (now - 30 days) is well before
        // the token's expiry, so it survives. To test deletion, we create a
        // token with `expires_in_days = Some(0)` (expires "now") and use a
        // cutoff slightly in the future.
        let expired_ancient = NewApiToken {
            name: "old".into(),
            scopes: Some(ScopeSet::full_access()),
            // Expires "now" (0 days). Slightly imprecise but the test uses
            // a cutoff 30 days in the future to force deletion.
            expires_in_days: Some(0),
        };
        // Token that expires in 365 days — survives a 30-day-ago cutoff.
        let live = NewApiToken {
            name: "live".into(),
            scopes: Some(ScopeSet::full_access()),
            expires_in_days: Some(365),
        };
        // Token that never expires.
        let forever = NewApiToken {
            name: "forever".into(),
            scopes: Some(ScopeSet::full_access()),
            expires_in_days: None,
        };

        storage.create_api_token(user_id.0, &expired_ancient, "hash1", "prefix1").await.unwrap();
        storage.create_api_token(user_id.0, &live, "hash2", "prefix2").await.unwrap();
        storage.create_api_token(user_id.0, &forever, "hash3", "prefix3").await.unwrap();

        // Cutoff = 30 days in the future. The "expired_ancient" token
        // (expires ~now) is older than the future cutoff → deleted. The
        // live token (expires in 365d) and never-expiring token survive.
        let cutoff = Utc::now() + Duration::days(30);
        let deleted = storage.delete_expired_api_tokens(cutoff).await.unwrap();
        assert_eq!(deleted, 1);
        let remaining = storage.list_api_tokens(user_id.0).await.unwrap();
        assert_eq!(remaining.len(), 2);
    }
}
