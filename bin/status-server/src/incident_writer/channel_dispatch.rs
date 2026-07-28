//! Target-bound notification channel dispatch.
//!
//! When an incident is auto-opened or auto-resolved by the coalescer, this
//! module reads the target's `alerts` list (a list of `AlertBinding {
//! channel_id }`) and dispatches a notification to each bound channel.
//!
//! The dispatch is fire-and-forget: each channel send runs in its own
//! spawned task so a slow transport (e.g. a PagerDuty API that takes 5s)
//! never blocks the incident coalescer. Storage reads (target + channels)
//! happen inline on the calling task because they're cheap local DuckDB
//! reads; only the network send is spawned.
//!
//! # Transport selection
//!
//! - `Email` channels are routed through the shared [`EmailSender`] with an
//!   [`EmailTemplate::IncidentAlert`] envelope. This bypasses
//!   [`common::notifier::build_notifier`] (which falls back to `LogNotifier`
//!   for email) so a configured transactional provider (Resend, log, memory)
//!   actually delivers the alert.
//! - Every other kind goes through [`Notifier::notify_incident`] so
//!   transports with a richer payload shape (e.g. PagerDuty Events API v2)
//!   get the incident context they need — PagerDuty uses the incident id as
//!   its dedup key, so a later `resolve` matches the `trigger` that opened
//!   the page.
//!
//! This is distinct from [`crate::incident_writer::enqueue_subscriber_deliveries`]
//! which enqueues deliveries to *public status-page subscribers* (email /
//! webhook / Slack targets that end-users subscribe to). Channel dispatch
//! here targets *operator notification channels* (the ops team's PagerDuty,
//! Slack #alerts, etc.) bound directly to the monitor.

use std::sync::Arc;

use common::email::{EmailAddress, EmailSender, EmailTemplate, TransactionalEmail};
use common::notifier::{IncidentNotice, NoticeReason};
use statuscore::domain::{ChannelConfig, DeliveryReason, EmailConfig, Incident, IncidentSeverity};
use storage::Storage;
use tracing::warn;
use uuid::Uuid;

/// Context required to dispatch a notification to a target's bound channels.
///
/// Bundles the shared email transport + sender identity + public base URL +
/// SSRF-guarded HTTP client so the coalescer can pass a single value through
/// `evaluate_target` → `dispatch_to_target_channels` without enumerating
/// parameters at every call site. The email sender is `Arc`-cloned into
/// per-channel spawned tasks; the base URL, from address, and HTTP client
/// are `Clone`-cheap.
#[derive(Clone)]
pub struct ChannelDispatchCtx {
    pub email_sender: Arc<dyn EmailSender>,
    pub from_address: EmailAddress,
    pub public_base_url: String,
    /// SSRF-guarded `reqwest::Client` shared with `build_notifier` so every
    /// notifier transport (webhook / Slack / PagerDuty / …) reuses one
    /// client built once at boot with the SSRF guard wired in. Cloned
    /// cheaply (it's an `Arc` underneath).
    pub outbound_http: reqwest::Client,
}

impl ChannelDispatchCtx {
    /// Build a context from the app's shared state. The fields are cloned
    /// (Arc / String) so the context can outlive the `AppState` borrow.
    pub fn new(
        email_sender: Arc<dyn EmailSender>,
        from_address: EmailAddress,
        public_base_url: String,
        outbound_http: reqwest::Client,
    ) -> Self {
        Self { email_sender, from_address, public_base_url, outbound_http }
    }
}

/// Dispatch a notification to every notification channel bound to the
/// incident's target. Reads the target's `alerts` list, fetches each
/// channel by id, builds a notifier, and spawns a send task per channel.
///
/// Errors are logged and swallowed — the incident row is the source of
/// truth, not the delivery. A missing target (deleted between incident
/// open and dispatch) is a no-op.
pub async fn dispatch_to_target_channels(
    storage: &dyn Storage,
    ctx: &ChannelDispatchCtx,
    incident: &Incident,
    reason: DeliveryReason,
) {
    // A nil target_id means the incident was created manually without a
    // target — nothing to dispatch to.
    if incident.target_id == Uuid::nil() {
        return;
    }

    let target = match storage.get_target(incident.target_id).await {
        Ok(t) => t,
        Err(e) => {
            warn!(
                target_id = %incident.target_id,
                error = %e,
                "channel_dispatch: target not found, skipping channel dispatch"
            );
            return;
        }
    };

    if target.alerts.is_empty() {
        return;
    }

    let notice_reason = match reason {
        DeliveryReason::IncidentOpened => NoticeReason::Opened,
        DeliveryReason::IncidentResolved => NoticeReason::Resolved,
        // The coalescer only dispatches on open / resolve; other reasons
        // would come from the escalation engine, which has its own path.
        _ => NoticeReason::Opened,
    };

    // Load active silence rules for this target once per incident. The
    // dispatch loop filters per-channel / per-reason in-memory — one query
    // instead of one per channel. A failure to load silences is logged but
    // non-fatal: we'd rather over-deliver than block the dispatch path.
    let active_silences = match storage.list_active_silences_for_target(target.id).await {
        Ok(rules) => rules,
        Err(e) => {
            warn!(
                target_id = %target.id,
                error = %e,
                "channel_dispatch: failed to load active silence rules; proceeding without filtering"
            );
            Vec::new()
        }
    };
    if !active_silences.is_empty() {
        tracing::debug!(
            target_id = %target.id,
            silence_count = active_silences.len(),
            "channel_dispatch: active silence rules attached"
        );
    }

    for binding in target.alerts.iter() {
        let channel = match storage.get_notification_channel(binding.channel_id).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    channel_id = %binding.channel_id,
                    error = %e,
                    "channel_dispatch: channel not found, skipping"
                );
                continue;
            }
        };

        // Skip disabled channels — the operator explicitly turned them off.
        if !channel.enabled {
            continue;
        }
        // Skip email channels that haven't been verified yet.
        if channel.awaiting_verification() {
            continue;
        }

        // Silence check: if any active rule suppresses
        // (target_id, Some(channel_id), reason), skip this channel. A
        // rule with `target_id = None` matches every target but was
        // already filtered by `list_active_silences_for_target`; the
        // per-channel `channel_id` filter applies here.
        let silenced =
            active_silences.iter().any(|r| r.matches(target.id, Some(channel.id), reason));
        if silenced {
            tracing::info!(
                channel_id = %channel.id,
                target_id = %target.id,
                reason = ?reason,
                "channel_dispatch: notification suppressed by silence rule"
            );
            continue;
        }

        let config = channel.config.clone();
        let channel_name = channel.name.clone();
        let channel_id = channel.id;

        // Email channels are routed through the shared `EmailSender` so a
        // configured transactional provider actually delivers the alert.
        // `build_notifier` would fall back to `LogNotifier` for email
        // (there is no SMTP transport wired through the `Notifier` trait).
        // The `EmailConfig` is cloned out of `config` so the spawned task
        // owns its own copy and we don't borrow across the spawn boundary.
        if let ChannelConfig::Email(email_cfg) = &config {
            let email_sender = ctx.email_sender.clone();
            let from = ctx.from_address.clone();
            let base = ctx.public_base_url.clone();
            let incident_clone = incident.clone();
            let email_cfg_clone = email_cfg.clone();
            tokio::spawn(async move {
                send_email_alert(
                    email_sender.as_ref(),
                    &from,
                    &base,
                    &email_cfg_clone,
                    &incident_clone,
                    notice_reason,
                )
                .await;
            });
            continue;
        }

        // Every other kind goes through `notify_incident` so transports
        // with a richer payload shape (e.g. PagerDuty Events API v2) get
        // the incident context they need. The `IncidentNotice` borrows the
        // incident and channel name, so we move owned copies into the task
        // and build the notice inside the async block — the references then
        // point at stack locals that outlive the `notify_incident` call.
        let incident_owned = incident.clone();
        let outbound_http = ctx.outbound_http.clone();
        tokio::spawn(async move {
            let notifier = match common::notifier::build_notifier(&config, &outbound_http) {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        channel_id = %channel_id,
                        error = %e,
                        "channel_dispatch: build_notifier failed"
                    );
                    return;
                }
            };
            let notice = IncidentNotice {
                incident: &incident_owned,
                reason: notice_reason,
                component_name: Some(&channel_name),
            };
            if let Err(e) = notifier.notify_incident(&notice).await {
                warn!(
                    channel_id = %channel_id,
                    channel_name = %channel_name,
                    error = %e,
                    "channel_dispatch: notify_incident failed"
                );
            }
        });
    }
}

/// Send an `IncidentAlert` email to the channel's configured recipient.
/// Errors are logged and swallowed — the incident row is the source of
/// truth, not the delivery. The body mirrors the plain-text summary the
/// chat transports send so email and chat surfaces read consistently.
async fn send_email_alert(
    email_sender: &dyn EmailSender,
    from: &EmailAddress,
    public_base_url: &str,
    email_cfg: &EmailConfig,
    incident: &Incident,
    reason: NoticeReason,
) {
    let body = format_incident_body(incident, reason);
    // The stop URL lets the recipient disable just this channel — built
    // from the public base URL so it works regardless of which frontend
    // the operator reaches the API through. `stop_url` is intentionally
    // `None` for now (one-click unsubscribe is suppressed for incident
    // alerts — see `EmailTemplate::list_unsubscribe_url`); the body link
    // is the deliberate-action path.
    let _ = public_base_url; // reserved for a future in-body link
    let template = EmailTemplate::IncidentAlert { body, org_name: None, stop_url: None };
    let email = TransactionalEmail {
        to: EmailAddress::new(email_cfg.to.clone(), email_cfg.to.clone()),
        from: from.clone(),
        template,
    };
    if let Err(e) = email_sender.send(email).await {
        warn!(
            to = %email_cfg.to,
            error = %e,
            "channel_dispatch: incident alert email failed"
        );
    }
}

/// Render the plain-text body for an incident alert email. Mirrors the
/// wording the chat transports emit via `format_notice_message` so a
/// human reading email and a human reading Slack see the same narration.
fn format_incident_body(incident: &Incident, reason: NoticeReason) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let severity = match incident.severity {
        IncidentSeverity::Minor => "MINOR",
        IncidentSeverity::Major => "MAJOR",
        IncidentSeverity::Critical => "CRITICAL",
        // `IncidentSeverity` is #[non_exhaustive]; unknown severities
        // surface as a generic label so the body always has a tag.
        _ => "UNKNOWN",
    };
    let _ = writeln!(s, "[{severity}] incident {}", reason.as_str());
    if let Some(title) = &incident.public_title {
        let _ = writeln!(s, "Title: {title}");
    }
    if let Some(desc) = &incident.public_description {
        let _ = writeln!(s, "Description: {desc}");
    }
    let _ = writeln!(s, "Started: {}", incident.started_at);
    if let Some(end) = incident.ended_at {
        let _ = writeln!(s, "Ended: {end}");
    } else {
        let _ = writeln!(s, "Status: ongoing");
    }
    if let Some(dur) = incident.duration_secs {
        let _ = writeln!(s, "Duration: {dur}s");
    }
    s
}
