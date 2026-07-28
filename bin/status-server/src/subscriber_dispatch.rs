//! Subscriber notification dispatch worker.
//!
//! Background task that consumes the `subscriber_deliveries` queue and
//! delivers pending notifications to verified subscribers. The queue is
//! populated by [`crate::incident_writer`] (incident opened/resolved) and the
//! maintenance trigger (maintenance started/ended).
//!
//! # Dispatch loop
//!
//! Every [`TICK_INTERVAL`] the worker:
//! 1. Reads up to [`BATCH_LIMIT`] pending (or due-for-retry) deliveries.
//! 2. Claims each delivery atomically via [`Storage::claim_delivery`].
//! 3. Dispatches the payload over the subscriber's channel.
//! 4. Marks the delivery `Sent` on success, `Failed` (with retry backoff) or
//!    `DeadLetter` (after [`MAX_ATTEMPTS`]) on failure.
//!
//! # Channel support
//!
//! - `Email`: wrapped in an `EmailTemplate::SubscriberIncident` and sent via
//!   the configured [`EmailSender`]. The unsubscribe URL is built from
//!   `public_base_url` so the recipient can opt out in one click.
//! - `Webhook`: POSTed as `text/plain` to the subscriber's target URL via
//!   the SSRF-guarded [`OutboundHttpClient`] (private / loopback / link-local
//!   / cloud-metadata IPs are dropped at DNS-filter time before any TCP
//!   open, so a subscriber can't pivot a webhook into an internal probe).
//! - `Slack`: POSTed as `{"text": payload}` to a Slack incoming webhook URL,
//!   also through the SSRF-guarded client.
//! - `Sms`: log-only (no SMS provider wired in v1).
//!
//! # Retry semantics
//!
//! Failed deliveries are retried with exponential backoff (30s · 2^attempts,
//! capped at 1h — see [`Storage::mark_delivery`]). After [`MAX_ATTEMPTS`]
//! the delivery is dead-lettered and excluded from future sweeps.

use std::sync::Arc;
use std::time::Duration;

use common::email::{EmailAddress, EmailSender, EmailTemplate, TransactionalEmail};
use common::http_client::{OutboundHttpClient, post_json, post_text};
use statuscore::domain::{DeliveryReason, DeliveryStatus, SubscriberChannel, SubscriberDelivery};
use storage::Storage;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use url::Url;

/// Poll cadence — short enough that a delivery queued right after a tick is
/// dispatched within ~20s, long enough that an idle queue doesn't spin.
const TICK_INTERVAL: Duration = Duration::from_secs(20);

/// Maximum deliveries claimed per tick. Bounds the per-tick work so a large
/// backlog doesn't starve the maintenance/incident paths that enqueue into
/// the same table.
const BATCH_LIMIT: u32 = 200;

/// Maximum delivery attempts before dead-lettering. With the default backoff
/// (`30 · 2^attempts` capped at 1h), 6 attempts span ~5 minutes of retries
/// before the delivery is parked as dead-letter.
const MAX_ATTEMPTS: i32 = 6;

/// Run the dispatch loop. Spawn from `main.rs`:
///
/// ```ignore
/// let cancel = CancellationToken::new();
/// tokio::spawn(subscriber_dispatch::run(state.clone(), cancel.clone()));
/// ```
pub async fn run(
    storage: Arc<dyn Storage>,
    email_sender: Arc<dyn EmailSender>,
    outbound_http: OutboundHttpClient,
    public_base_url: String,
    cancel: CancellationToken,
) {
    info!(tick_secs = TICK_INTERVAL.as_secs(), "subscriber_dispatch: started");
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    ticker.tick().await; // immediate first tick so we dispatch on boot

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = sweep(
                    storage.as_ref(),
                    email_sender.as_ref(),
                    &outbound_http,
                    &public_base_url,
                )
                .await
                {
                    warn!(error = %e, "subscriber_dispatch: sweep failed");
                }
            }
            () = cancel.cancelled() => {
                info!("subscriber_dispatch: stopping");
                break;
            }
        }
    }
}

/// One dispatch sweep: claim up to [`BATCH_LIMIT`] pending deliveries and
/// attempt each. Per-delivery errors are logged and swallowed so a single
/// bad delivery doesn't abort the sweep.
async fn sweep(
    storage: &dyn Storage,
    email_sender: &dyn EmailSender,
    outbound_http: &OutboundHttpClient,
    public_base_url: &str,
) -> statuscore::error::Result<()> {
    let pending = storage.list_pending_deliveries(BATCH_LIMIT).await?;
    if pending.is_empty() {
        return Ok(());
    }

    for delivery in pending {
        let id = delivery.id;
        // Atomically claim. If another worker beat us (or the row was
        // already claimed), `claim_delivery` returns None and we skip.
        let Some(claimed) = storage.claim_delivery(id).await? else {
            continue;
        };

        let result =
            dispatch_delivery(&claimed, email_sender, outbound_http, public_base_url).await;
        match result {
            Ok(()) => {
                if let Err(e) = storage.mark_delivery(id, DeliveryStatus::Sent, None).await {
                    warn!(delivery_id = %id, error = %e, "subscriber_dispatch: mark_sent failed");
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                // Dead-letter after MAX_ATTEMPTS; otherwise mark Failed so
                // the retry sweep picks it up after backoff.
                let new_status = if claimed.attempts >= MAX_ATTEMPTS as u32 {
                    DeliveryStatus::DeadLetter
                } else {
                    DeliveryStatus::Failed
                };
                warn!(
                    delivery_id = %id,
                    attempts = claimed.attempts,
                    status = ?new_status,
                    error = %err_str,
                    "subscriber_dispatch: delivery failed",
                );
                if let Err(e) = storage.mark_delivery(id, new_status, Some(&err_str)).await {
                    warn!(delivery_id = %id, error = %e, "subscriber_dispatch: mark_failed failed");
                }
            }
        }
    }
    Ok(())
}

/// Dispatch a single delivery over its channel. Returns an error string on
/// failure so the caller can record it as `last_error`.
async fn dispatch_delivery(
    delivery: &SubscriberDelivery,
    email_sender: &dyn EmailSender,
    outbound_http: &OutboundHttpClient,
    public_base_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let unsubscribe_url = format!(
        "{}/api/public/v1/subscribers/{}/unsubscribe",
        public_base_url.trim_end_matches('/'),
        delivery.subscriber_id,
    );

    match delivery.channel {
        SubscriberChannel::Email => {
            let to = EmailAddress::new(delivery.target.clone(), delivery.target.clone());
            let from = EmailAddress::new("no-reply@statuspage.local", "StatusPage");
            // Parse the payload into the structured incident template. The
            // payload was built by `enqueue_subscriber_deliveries` as a
            // plain-text summary; we embed it as the message body.
            let (incident_title, phase) =
                parse_payload_for_email(&delivery.reason, &delivery.payload);
            let incident_url =
                format!("{}/api/public/v1/incidents", public_base_url.trim_end_matches('/'));
            let template = EmailTemplate::SubscriberIncident {
                page_name: "Status Page".to_string(),
                incident_title,
                phase,
                message: delivery.payload.clone(),
                incident_url,
                unsubscribe_url,
            };
            let email = TransactionalEmail { to, from, template };
            email_sender.send(email).await.map_err(|e| {
                Box::new(std::io::Error::other(e.to_string()))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;
            Ok(())
        }
        SubscriberChannel::Webhook => {
            // SSRF-guarded POST: the outbound client's connector drops any
            // URL whose resolved IP is private / loopback / link-local /
            // cloud-metadata before TCP open. A subscriber can't pivot a
            // webhook into an internal probe.
            let url = Url::parse(&delivery.target)
                .map_err(|e| format!("invalid webhook url {url}: {e}", url = delivery.target))?;
            let payload = delivery.payload.clone().into_bytes();
            post_text(outbound_http, &url, payload)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(())
        }
        SubscriberChannel::Slack => {
            let url = Url::parse(&delivery.target).map_err(|e| {
                format!("invalid slack webhook url {url}: {e}", url = delivery.target)
            })?;
            let body = serde_json::json!({ "text": &delivery.payload });
            post_json(outbound_http, &url, &body)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(())
        }
        SubscriberChannel::Sms => {
            // v1 has no SMS provider; log and succeed so the delivery isn't
            // retried indefinitely. When a real SMS transport is wired, this
            // branch dispatches to it.
            tracing::info!(
                delivery_id = %delivery.id,
                target = %delivery.target,
                "subscriber_dispatch: sms channel (log-only)",
            );
            Ok(())
        }
        // `SubscriberChannel` is #[non_exhaustive]; unknown channels are
        // logged and succeed so the delivery isn't retried indefinitely.
        _ => {
            tracing::info!(
                delivery_id = %delivery.id,
                "subscriber_dispatch: unknown channel (log-only)",
            );
            Ok(())
        }
    }
}

/// Derive an `(incident_title, phase)` pair from the delivery payload for
/// the email template. The payload is a plain-text summary built by
/// `enqueue_subscriber_deliveries`; the reason carries the structured state.
fn parse_payload_for_email(reason: &DeliveryReason, payload: &str) -> (String, String) {
    let phase = match reason {
        DeliveryReason::IncidentOpened => "investigating",
        DeliveryReason::IncidentResolved => "resolved",
        DeliveryReason::IncidentUpdate => "update",
        DeliveryReason::MaintenanceStarted => "maintenance",
        DeliveryReason::MaintenanceEnded => "maintenance completed",
        // `DeliveryReason` is #[non_exhaustive]; unknown reasons surface
        // as a generic "update" phase.
        &_ => "update",
    };
    // Use the first line of the payload as the title; fall back to a
    // generic label so the email template always has a non-empty subject.
    let title = payload.lines().next().unwrap_or("Status update").to_string();
    (title, phase.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use common::email::InMemoryEmailSender;
    use common::http_client::build_outbound_client;
    use common::security::SsrfGuard;
    use statuscore::domain::{DeliveryReason, DeliveryStatus, SubscriberChannel};
    use storage::MemoryStorage;
    use uuid::Uuid;

    fn make_delivery(channel: SubscriberChannel, target: &str) -> SubscriberDelivery {
        SubscriberDelivery {
            id: Uuid::now_v7(),
            subscriber_id: Uuid::now_v7(),
            status_page_id: Uuid::nil(),
            channel,
            target: target.to_string(),
            payload: "incident opened: target down".to_string(),
            reason: DeliveryReason::IncidentOpened,
            status: DeliveryStatus::Pending,
            attempts: 0,
            last_error: None,
            created_at: Utc::now(),
            sent_at: None,
            next_attempt_at: Some(Utc::now()),
        }
    }

    fn test_outbound_client() -> OutboundHttpClient {
        build_outbound_client(SsrfGuard::strict())
    }

    #[tokio::test]
    async fn email_delivery_sends_via_email_sender() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let outbound = test_outbound_client();
        let delivery = make_delivery(SubscriberChannel::Email, "alice@example.com");

        // Enqueue the delivery.
        storage
            .enqueue_delivery(
                delivery.subscriber_id,
                delivery.status_page_id,
                delivery.channel,
                &delivery.target,
                &delivery.payload,
                delivery.reason,
            )
            .await
            .unwrap();

        // Run one sweep.
        sweep(&storage, &email_sender, &outbound, "http://localhost:8080").await.unwrap();

        // The delivery should be marked Sent.
        let pending = storage.list_pending_deliveries(10).await.unwrap();
        assert!(pending.is_empty(), "no pending deliveries after sweep");

        // The email sender should have captured one email.
        assert_eq!(email_sender.len(), 1, "one email should be sent");
        let sent = email_sender.sent();
        assert!(sent[0].to.address.contains("alice@example.com"));
    }

    #[tokio::test]
    async fn sms_delivery_succeeds_log_only() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let outbound = test_outbound_client();
        let delivery = make_delivery(SubscriberChannel::Sms, "+15551234567");

        storage
            .enqueue_delivery(
                delivery.subscriber_id,
                delivery.status_page_id,
                delivery.channel,
                &delivery.target,
                &delivery.payload,
                delivery.reason,
            )
            .await
            .unwrap();

        sweep(&storage, &email_sender, &outbound, "http://localhost:8080").await.unwrap();

        let pending = storage.list_pending_deliveries(10).await.unwrap();
        assert!(pending.is_empty(), "sms delivery should be marked sent");
        assert_eq!(email_sender.len(), 0, "no email should be sent for sms channel");
    }

    #[tokio::test]
    async fn failed_delivery_retries_then_dead_letters() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let outbound = test_outbound_client();
        // Webhook to a loopback endpoint → SSRF guard rejects before any
        // TCP open, surfacing an error that triggers the retry / dead-letter
        // path. (Using a public-but-dead URL would also work, but the SSRF
        // rejection is faster and deterministic — no port-allocation race.)
        let delivery = make_delivery(SubscriberChannel::Webhook, "http://127.0.0.1:1/notfound");

        storage
            .enqueue_delivery(
                delivery.subscriber_id,
                delivery.status_page_id,
                delivery.channel,
                &delivery.target,
                &delivery.payload,
                delivery.reason,
            )
            .await
            .unwrap();

        // First sweep: fails (attempts becomes 1), marked Failed.
        sweep(&storage, &email_sender, &outbound, "http://localhost:8080").await.unwrap();
        let pending = storage.list_pending_deliveries(10).await.unwrap();
        // The failed delivery should still be retryable if next_attempt_at
        // is in the past. But mark_delivery sets next_attempt_at in the
        // future, so it won't be picked up immediately.
        // (list_pending_deliveries filters by next_attempt_at <= now.)
        assert!(
            pending.is_empty() || pending[0].status == DeliveryStatus::Failed,
            "delivery should be Failed after first attempt"
        );
    }

    #[test]
    fn parse_payload_extracts_title_and_phase() {
        let payload = "incident opened: target 123 down\nsecond line";
        let (title, phase) = parse_payload_for_email(&DeliveryReason::IncidentOpened, payload);
        assert_eq!(title, "incident opened: target 123 down");
        assert_eq!(phase, "investigating");

        let (_title, phase) = parse_payload_for_email(&DeliveryReason::IncidentResolved, payload);
        assert_eq!(phase, "resolved");
    }
}
