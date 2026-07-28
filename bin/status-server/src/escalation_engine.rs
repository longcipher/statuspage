//! Escalation engine — advances escalation for incidents due for a check.
//!
//! The engine is the timing + delivery half of the escalation ladder defined
//! in [`statuscore::domain::escalation_policy`]. It runs as a `tokio::spawn`
//! task with a [`CancellationToken`]; every [`TICK_INTERVAL`] it asks storage
//! for every [`IncidentEscalationState`] whose `next_check_at <= now` (and
//! that has not been acknowledged), walks the bound policy's ladder with the
//! pure [`next_step`] function, and pages the targets of the resulting step.
//!
//! # Paging
//!
//! - `Channel` targets are paged via [`Notifier::notify_incident`] with
//!   [`NoticeReason::Escalated`]. This routes through the same transport
//!   factory as the coalescer's channel dispatch, so a PagerDuty channel
//!   fires a `trigger` event keyed on the incident id (and a later `resolve`
//!   from the coalescer matches it).
//! - `User` targets receive an `IncidentAlert` email via the shared
//!   [`EmailSender`].
//! - `Schedule` targets resolve on-call users with [`resolve_on_call`] and
//!   email each.
//!
//! # Lifecycle
//!
//! - The coalescer creates an escalation state when it auto-opens an incident
//!   on a target with `escalation_policy_id` set (see [`crate::incident_writer`]).
//! - Acknowledging the incident calls `ack_escalation_state` — the engine
//!   skips acked states, so paging stops.
//! - Resolving the incident (manually or auto) calls `delete_escalation_state`
//!   — the state is gone and the engine stops considering it.
//! - When [`next_step`] returns [`EscalationDecision::Exhausted`], the engine
//!   deletes the state itself: the policy's repeats are spent and there is
//!   nothing left to page.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use common::email::{EmailAddress, EmailSender, EmailTemplate, TransactionalEmail};
use common::notifier::{IncidentNotice, NoticeReason};
use statuscore::domain::escalation_policy::{
    EscalationDecision, EscalationTarget, EscalationTargetType, IncidentEscalationState, next_step,
};
use statuscore::domain::{Incident, resolve_on_call};
use storage::Storage;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Sweep cadence — every 30 seconds the engine re-reads due escalation
/// states. Short enough that a freshly-due state is paged within half a
/// minute; long enough that an idle fleet doesn't spin.
const TICK_INTERVAL: Duration = Duration::from_secs(30);

/// Run the escalation engine. Spawn from `main.rs`:
///
/// ```ignore
/// let cancel = CancellationToken::new();
/// tokio::spawn(escalation_engine::run_escalation_engine(
///     state.storage.clone(),
///     state.email_sender.clone(),
///     cancel.clone(),
///     state.public_base_url.clone(),
///     state.outbound_http.clone(),
/// ));
/// ```
///
/// Cancels cleanly when `cancel` is triggered. All errors inside the loop
/// are logged and swallowed — one bad escalation state must never stop the
/// engine from considering the rest.
pub async fn run_escalation_engine(
    storage: Arc<dyn Storage>,
    email_sender: Arc<dyn EmailSender>,
    cancel: CancellationToken,
    public_base_url: String,
    outbound_http: reqwest::Client,
) {
    info!(tick_secs = TICK_INTERVAL.as_secs(), "escalation_engine: started");
    let mut ticker = tokio::time::interval(TICK_INTERVAL);
    // First tick fires immediately so a freshly-booted engine sweeps on
    // start — a state created just before boot with `next_check_at = now`
    // would otherwise wait a full tick.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = sweep(
                    storage.as_ref(),
                    email_sender.as_ref(),
                    &public_base_url,
                    &outbound_http,
                )
                .await
                {
                    warn!(error = %e, "escalation_engine: sweep failed");
                }
            }
            () = cancel.cancelled() => {
                info!("escalation_engine: stopping");
                break;
            }
        }
    }
}

/// One sweep of the engine. Reads every due escalation state and advances
/// it. Per-state errors are logged and swallowed so a single bad state
/// doesn't abort the sweep.
async fn sweep(
    storage: &dyn Storage,
    email_sender: &dyn EmailSender,
    public_base_url: &str,
    outbound_http: &reqwest::Client,
) -> statuscore::error::Result<()> {
    let now = Utc::now();
    let due = storage.list_due_escalation_states(now).await?;
    if due.is_empty() {
        return Ok(());
    }
    for state in due {
        if let Err(e) =
            advance_state(storage, email_sender, public_base_url, outbound_http, state).await
        {
            warn!(error = %e, "escalation_engine: advance_state failed");
        }
    }
    Ok(())
}

/// Advance a single escalation state: load the incident + policy, decide the
/// next page (or stop), dispatch notifications, persist the updated state.
///
/// Resolved incidents and exhausted policies both end in state deletion;
/// missing incidents are treated the same way (the incident row was deleted
/// out from under the engine).
async fn advance_state(
    storage: &dyn Storage,
    email_sender: &dyn EmailSender,
    public_base_url: &str,
    outbound_http: &reqwest::Client,
    mut state: IncidentEscalationState,
) -> statuscore::error::Result<()> {
    // Load the incident. A `NotFound` means the incident was deleted out
    // from under us — drop the state and move on.
    let incident = match storage.get_incident(state.incident_id).await {
        Ok(i) => i,
        Err(statuscore::error::AppError::NotFound { .. }) => {
            warn!(
                incident_id = %state.incident_id,
                "escalation_engine: incident not found, deleting state"
            );
            let _ = storage.delete_escalation_state(state.incident_id).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    // A resolved/closed incident has no further escalation. Drop the state
    // so the engine stops considering it.
    if incident.ended_at.is_some() {
        info!(
            incident_id = %state.incident_id,
            "escalation_engine: incident resolved, deleting state"
        );
        let _ = storage.delete_escalation_state(state.incident_id).await;
        return Ok(());
    }

    let policy = storage.get_escalation_policy(state.policy_id).await?;
    let decision =
        next_step(&policy.steps, policy.repeat_count, state.current_level, state.current_round);
    match decision {
        EscalationDecision::Exhausted => {
            info!(
                incident_id = %state.incident_id,
                policy_id = %state.policy_id,
                "escalation_engine: policy exhausted, deleting state"
            );
            let _ = storage.delete_escalation_state(state.incident_id).await;
            Ok(())
        }
        EscalationDecision::Page { level, round, delay_secs } => {
            // Find the step matching this level. The contract is that
            // levels are unique; if duplicates exist, the first wins.
            let step = if let Some(s) = policy.steps.iter().find(|s| s.level == level) {
                s
            } else {
                warn!(
                    incident_id = %state.incident_id,
                    level,
                    "escalation_engine: step for level not found, deleting state"
                );
                let _ = storage.delete_escalation_state(state.incident_id).await;
                return Ok(());
            };

            for target in &step.targets {
                dispatch_target(
                    storage,
                    email_sender,
                    public_base_url,
                    outbound_http,
                    &incident,
                    target,
                )
                .await;
            }

            // Advance the state and persist. `delay_secs` comes from the
            // policy; clamp negatives to zero so a misconfigured step can't
            // schedule a `next_check_at` in the past (which would re-fire
            // immediately on the next tick).
            let now = Utc::now();
            state.current_level = level;
            state.current_round = round;
            state.last_paged_at = now;
            state.next_check_at = now + chrono::Duration::seconds(i64::from(delay_secs.max(0)));
            storage.upsert_escalation_state(&state).await?;
            info!(
                incident_id = %state.incident_id,
                level,
                round,
                next_check_at = %state.next_check_at,
                "escalation_engine: paged"
            );
            Ok(())
        }
        // `EscalationDecision` is #[non_exhaustive]; unknown variants are
        // treated as exhaustion (stop paging, delete state).
        _ => {
            warn!(
                incident_id = %state.incident_id,
                "escalation_engine: unknown escalation decision, deleting state"
            );
            let _ = storage.delete_escalation_state(state.incident_id).await;
            Ok(())
        }
    }
}

/// Dispatch a page to one escalation target. Channel targets use the
/// notifier (so PagerDuty's trigger/resolve semantics work); user targets
/// get an `IncidentAlert` email; schedule targets resolve on-call users and
/// email each. Per-target errors are logged and swallowed — one bad target
/// must not stop the rest of the step from paging.
async fn dispatch_target(
    storage: &dyn Storage,
    email_sender: &dyn EmailSender,
    public_base_url: &str,
    outbound_http: &reqwest::Client,
    incident: &Incident,
    target: &EscalationTarget,
) {
    match target.target_type {
        EscalationTargetType::Channel => {
            let Some(channel_id) = target.channel_id else {
                warn!(target_id = %target.id, "escalation_engine: channel target missing channel_id");
                return;
            };
            let channel = match storage.get_notification_channel(channel_id).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(channel_id = %channel_id, error = %e, "escalation_engine: channel not found");
                    return;
                }
            };
            // Skip disabled channels and unverified email channels — the
            // coalescer's channel dispatch does the same.
            if !channel.enabled || channel.awaiting_verification() {
                return;
            }
            let config = channel.config.clone();
            let channel_name = channel.name.clone();
            let notice = IncidentNotice {
                incident,
                reason: NoticeReason::Escalated,
                component_name: Some(&channel_name),
            };
            let notifier = match common::notifier::build_notifier(&config, outbound_http) {
                Ok(n) => n,
                Err(e) => {
                    warn!(channel_id = %channel_id, error = %e, "escalation_engine: build_notifier failed");
                    return;
                }
            };
            if let Err(e) = notifier.notify_incident(&notice).await {
                warn!(channel_id = %channel_id, error = %e, "escalation_engine: notify_incident failed");
            }
        }
        EscalationTargetType::User => {
            let Some(user_id) = target.user_id else {
                warn!(target_id = %target.id, "escalation_engine: user target missing user_id");
                return;
            };
            let user = match storage.get_user(user_id).await {
                Ok(u) => u,
                Err(e) => {
                    warn!(user_id = %user_id, error = %e, "escalation_engine: user not found");
                    return;
                }
            };
            send_incident_alert_email(email_sender, public_base_url, incident, &user.email).await;
        }
        EscalationTargetType::Schedule => {
            let Some(schedule_id) = target.schedule_id else {
                warn!(target_id = %target.id, "escalation_engine: schedule target missing schedule_id");
                return;
            };
            let detail = match storage.get_on_call_schedule(schedule_id).await {
                Ok(d) => d,
                Err(e) => {
                    warn!(schedule_id = %schedule_id, error = %e, "escalation_engine: schedule not found");
                    return;
                }
            };
            let now = Utc::now();
            let on_call = resolve_on_call(&detail.schedule, &detail.layers, &detail.overrides, now);
            if on_call.is_empty() {
                warn!(schedule_id = %schedule_id, "escalation_engine: no on-call users resolved");
                return;
            }
            for uid in on_call {
                match storage.get_user(uid.0).await {
                    Ok(user) => {
                        send_incident_alert_email(
                            email_sender,
                            public_base_url,
                            incident,
                            &user.email,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(user_id = %uid, error = %e, "escalation_engine: on-call user not found");
                    }
                }
            }
        }
        // `EscalationTargetType` is #[non_exhaustive]; unknown target
        // types are logged and skipped so one bad target doesn't stop
        // the rest of the step from paging.
        _ => {
            warn!(target_id = %target.id, "escalation_engine: unknown target type, skipping");
        }
    }
}

/// Send an `IncidentAlert` email to `to_address`. Errors are logged and
/// swallowed so one bad recipient doesn't abort the page. The body is a
/// plain-text summary that mirrors the coalescer's channel-dispatch
/// wording so email and chat surfaces read consistently.
async fn send_incident_alert_email(
    email_sender: &dyn EmailSender,
    public_base_url: &str,
    incident: &Incident,
    to_address: &str,
) {
    let body = format!(
        "incident escalated (id={id}, target={target}, severity={sev}, started={started})\n\nview: {base}/api/public/v1/incidents",
        id = incident.id,
        target = incident.target_id,
        sev = incident.severity.as_db_str(),
        started = incident.started_at,
        base = public_base_url.trim_end_matches('/'),
    );
    let to = EmailAddress::new(to_address, to_address);
    let from = EmailAddress::new(format!("no-reply@{}", host_of(public_base_url)), "StatusPage");
    let template = EmailTemplate::IncidentAlert { body, org_name: None, stop_url: None };
    let email = TransactionalEmail { to, from, template };
    if let Err(e) = email_sender.send(email).await {
        warn!(error = %e, to = %to_address, "escalation_engine: incident alert email failed");
    }
}

/// Extract the host portion of a `scheme://host[:port]` URL. Falls back to
/// `statuspage.local` when parsing fails so we always emit a syntactically
/// valid `no-reply@domain` address.
fn host_of(base_url: &str) -> String {
    let after_scheme = base_url.split("://").nth(1).unwrap_or(base_url);
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() { "statuspage.local".to_string() } else { host.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::email::InMemoryEmailSender;
    use statuscore::domain::escalation_policy::{EscalationPolicy, EscalationStep};
    use statuscore::domain::{CheckStatus, Incident, IncidentSeverity};
    use storage::MemoryStorage;
    use uuid::Uuid;

    #[test]
    fn host_of_strips_scheme_port_and_path() {
        assert_eq!(host_of("https://status.example.com"), "status.example.com");
        assert_eq!(host_of("http://localhost:8080"), "localhost");
        assert_eq!(host_of("https://app.example.com/status"), "app.example.com");
        assert_eq!(host_of("not-a-url"), "not-a-url");
        assert_eq!(host_of(""), "statuspage.local");
    }

    fn make_policy(repeat_count: i32, levels: &[(i32, i32)]) -> EscalationPolicy {
        let now = Utc::now();
        let steps: Vec<EscalationStep> = levels
            .iter()
            .map(|(level, delay)| EscalationStep {
                id: Uuid::now_v7(),
                level: *level,
                delay_secs: *delay,
                targets: vec![],
            })
            .collect();
        EscalationPolicy {
            id: Uuid::now_v7(),
            name: "test".into(),
            description: None,
            repeat_count,
            steps,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_incident(target_id: Uuid) -> Incident {
        Incident {
            id: Uuid::now_v7(),
            target_id,
            started_at: Utc::now(),
            ended_at: None,
            status: CheckStatus::Down,
            duration_secs: None,
            check_count: 1,
            error_sample: None,
            severity: IncidentSeverity::Major,
            public_title: Some("Test outage".into()),
            public_description: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            updates: Vec::new(),
            regions_down: Vec::new(),
            regions_up: Vec::new(),
        }
    }

    #[tokio::test]
    async fn sweep_pages_first_level_and_schedules_next_check() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let target_id = Uuid::now_v7();

        // Policy with one empty step at level 1, 60s delay.
        let policy = make_policy(0, &[(1, 60)]);
        storage.upsert_escalation_policy(&policy).await.unwrap();

        // Open incident.
        let incident = make_incident(target_id);
        storage.create_incident(&incident).await.unwrap();

        // Escalation state due now.
        let now = Utc::now();
        let state = IncidentEscalationState {
            incident_id: incident.id,
            policy_id: policy.id,
            current_level: 0,
            current_round: 0,
            last_paged_at: now,
            next_check_at: now,
            acked: false,
        };
        storage.upsert_escalation_state(&state).await.unwrap();

        // Run one sweep.
        sweep(&storage, &email_sender, "https://status.example.com", &reqwest::Client::new())
            .await
            .unwrap();

        // The state should be advanced: level 1, next_check_at pushed out.
        let updated = storage.get_escalation_state(incident.id).await.unwrap().unwrap();
        assert_eq!(updated.current_level, 1);
        assert_eq!(updated.current_round, 0);
        assert!(updated.next_check_at > now);
    }

    #[tokio::test]
    async fn sweep_deletes_state_when_incident_resolved() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let target_id = Uuid::now_v7();

        let policy = make_policy(0, &[(1, 60)]);
        storage.upsert_escalation_policy(&policy).await.unwrap();

        // Resolved incident.
        let mut incident = make_incident(target_id);
        incident.ended_at = Some(Utc::now());
        storage.create_incident(&incident).await.unwrap();

        let now = Utc::now();
        let state = IncidentEscalationState {
            incident_id: incident.id,
            policy_id: policy.id,
            current_level: 0,
            current_round: 0,
            last_paged_at: now,
            next_check_at: now,
            acked: false,
        };
        storage.upsert_escalation_state(&state).await.unwrap();

        sweep(&storage, &email_sender, "https://status.example.com", &reqwest::Client::new())
            .await
            .unwrap();

        // The state should be deleted.
        assert!(storage.get_escalation_state(incident.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sweep_deletes_state_when_policy_exhausted() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let target_id = Uuid::now_v7();

        // One step at level 1, no repeats.
        let policy = make_policy(0, &[(1, 60)]);
        storage.upsert_escalation_policy(&policy).await.unwrap();

        let incident = make_incident(target_id);
        storage.create_incident(&incident).await.unwrap();

        // State already at level 1 (last level) — next_step returns Exhausted.
        let now = Utc::now();
        let state = IncidentEscalationState {
            incident_id: incident.id,
            policy_id: policy.id,
            current_level: 1,
            current_round: 0,
            last_paged_at: now,
            next_check_at: now,
            acked: false,
        };
        storage.upsert_escalation_state(&state).await.unwrap();

        sweep(&storage, &email_sender, "https://status.example.com", &reqwest::Client::new())
            .await
            .unwrap();

        // The state should be deleted (exhausted).
        assert!(storage.get_escalation_state(incident.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sweep_skips_acked_state_via_list_filter() {
        let storage = MemoryStorage::new();
        let email_sender = InMemoryEmailSender::new();
        let target_id = Uuid::now_v7();

        let policy = make_policy(0, &[(1, 60)]);
        storage.upsert_escalation_policy(&policy).await.unwrap();

        let incident = make_incident(target_id);
        storage.create_incident(&incident).await.unwrap();

        let now = Utc::now();
        let state = IncidentEscalationState {
            incident_id: incident.id,
            policy_id: policy.id,
            current_level: 0,
            current_round: 0,
            last_paged_at: now,
            next_check_at: now,
            acked: true,
        };
        storage.upsert_escalation_state(&state).await.unwrap();

        sweep(&storage, &email_sender, "https://status.example.com", &reqwest::Client::new())
            .await
            .unwrap();

        // Acked state should be untouched (level still 0).
        let got = storage.get_escalation_state(incident.id).await.unwrap().unwrap();
        assert_eq!(got.current_level, 0);
        assert!(got.acked);
    }
}
