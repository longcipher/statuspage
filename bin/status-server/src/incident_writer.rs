//! Incident coalescer — automatically opens and closes incidents based on
//! the stream of check results.
//!
//! The writer is a *follower* of `check_results`: it never modifies the
//! hot write path or blocks probes. After each probe, the scheduler calls
//! [`evaluate_target`], which reads the target's recent results and decides:
//!
//! - `>= FLAP_THRESHOLD` consecutive non-`Up` results and no open incident
//!   → INSERT a new incident (auto-open).
//! - `>= FLAP_THRESHOLD` consecutive `Up` results and an open incident
//!   → close it (`ended_at` = first `Up` timestamp).
//!
//! Maintenance windows suppress auto-open: results are still recorded, but
//! the writer skips creating incidents for targets inside an active
//! maintenance window.
//!
//! The writer is idempotent: the same input produces no extra writes on
//! re-evaluation. `find_open_incident_for_target` ensures only one open
//! incident per target exists.
//!
//! # Decoupled background evaluator
//!
//! In addition to the per-probe [`evaluate_target`] (still called by the
//! scheduler for low-latency auto-open), [`run_background_evaluator`]
//! periodically scans the whole fleet and re-evaluates every target. This
//! catches state changes the per-probe path might miss (e.g. a probe that
//! stopped reporting, results written by an out-of-process agent). The
//! background path uses [`Storage::recent_results_for_targets`] for a
//! single batched read instead of N+1 per-target reads.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use statuscore::domain::{
    CheckResult, CheckStatus, DeliveryReason, Incident, IncidentEscalationState, IncidentSeverity,
    SubscriberChannel,
};
use storage::Storage;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

mod channel_dispatch;
pub use channel_dispatch::ChannelDispatchCtx;
use channel_dispatch::dispatch_to_target_channels;

/// Number of consecutive non-`Up` results required to open an incident.
/// Matches the reference project's default `flap_threshold = 2`.
const FLAP_THRESHOLD: usize = 2;

/// Maximum number of recent results to examine. Kept small so the
/// evaluation is cheap even for high-frequency monitors.
const LOOKBACK: u32 = 10;

/// Background sweep cadence — every 30 seconds the evaluator re-scans the
/// whole fleet. Short enough that an out-of-band writer (an agent pushing
/// results directly to storage) is reflected within half a minute; long
/// enough that the storage load is negligible.
const BACKGROUND_INTERVAL: Duration = Duration::from_secs(30);

/// Evaluate a single target's recent results and open/close an incident
/// as needed. Called by the scheduler after each `record_result`.
///
/// `ctx` carries the shared email transport + sender identity used by
/// [`dispatch_to_target_channels`] when an incident opens or resolves.
/// Pass `None` in tests that don't assert on dispatch side effects.
///
/// Errors are logged and swallowed — a failure here must not crash the
/// scheduler or skip subsequent targets.
pub async fn evaluate_target(
    storage: &dyn Storage,
    target_id: Uuid,
    ctx: Option<&ChannelDispatchCtx>,
) {
    if let Err(e) = evaluate_target_inner(storage, target_id, ctx).await {
        warn!(target_id = %target_id, error = %e, error_dbg = ?e, "incident_writer: evaluate failed");
    }
}

async fn evaluate_target_inner(
    storage: &dyn Storage,
    target_id: Uuid,
    ctx: Option<&ChannelDispatchCtx>,
) -> statuscore::error::Result<()> {
    // Suppress auto-open during maintenance windows.
    if storage.is_target_in_active_maintenance(target_id).await? {
        return Ok(());
    }

    let results = storage.list_results(target_id, LOOKBACK).await?;
    if results.is_empty() {
        return Ok(());
    }

    decide_and_apply_incident_state(storage, target_id, &results, ctx, "per-probe").await
}

/// Core incident state transition logic shared between the per-probe
/// [`evaluate_target_inner`] and the background [`evaluate_results`]. Both
/// callers feed a pre-fetched slice of recent results (newest-first) and
/// share the same auto-open / auto-close / dispatch / escalation-seed
/// pipeline. `source` tags log lines so an operator can tell which path
/// fired a transition (`"per-probe"` vs `"background"`). Returns
/// `Ok(())` on completion or a storage error.
///
/// The two call sites used to carry near-identical copies of this body;
/// the shared helper keeps the threshold / open / close / dispatch
/// contract in one place so they can't drift.
async fn decide_and_apply_incident_state(
    storage: &dyn Storage,
    target_id: Uuid,
    results: &[CheckResult],
    ctx: Option<&ChannelDispatchCtx>,
    source: &'static str,
) -> statuscore::error::Result<()> {
    // `list_results` / `recent_results_for_targets` return newest-first; we
    // want oldest-first for consecutive-run analysis.
    let mut ordered: Vec<&CheckResult> = results.iter().collect();
    ordered.reverse();

    let open = storage.find_open_incident_for_target(target_id).await?;

    // Count the trailing run of non-Up results (newest end of the slice).
    let bad_run = ordered.iter().rev().take_while(|r| r.status != CheckStatus::Up).count();
    // Count the trailing run of Up results.
    let good_run = ordered.iter().rev().take_while(|r| r.status == CheckStatus::Up).count();

    if bad_run >= FLAP_THRESHOLD && open.is_none() {
        // Auto-open: find the first non-Up result as the incident start.
        let first_bad = ordered.iter().find(|r| r.status != CheckStatus::Up);
        if let Some(first) = first_bad {
            let incident = Incident {
                id: Uuid::now_v7(),
                target_id,
                started_at: first.timestamp,
                ended_at: None,
                status: first.status,
                duration_secs: None,
                check_count: bad_run as u64,
                error_sample: first.error.clone(),
                severity: IncidentSeverity::Major,
                public_title: Some(format!("Auto-detected outage for target {}", target_id)),
                public_description: first.error.clone(),
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                updates: Vec::new(),
                regions_down: Vec::new(),
                regions_up: Vec::new(),
            };
            match storage.create_incident(&incident).await {
                Ok(created) => {
                    info!(
                        incident_id = %created.id,
                        target_id = %target_id,
                        source = %source,
                        "incident_writer: auto-opened incident"
                    );
                    // Fire-and-forget subscriber delivery enqueue. Errors
                    // are logged and never propagated — the incident row
                    // is the source of truth, not the delivery.
                    if let Err(e) = enqueue_subscriber_deliveries(
                        storage,
                        &created,
                        DeliveryReason::IncidentOpened,
                    )
                    .await
                    {
                        warn!(error = %e, "incident_writer: subscriber delivery enqueue failed");
                    }
                    // Dispatch to the target's bound notification channels
                    // (Slack/PagerDuty/etc.). Reads the target's `alerts`
                    // list, builds a notifier per channel, and spawns a
                    // send task per channel so slow transports never block
                    // the coalescer. Skipped when no `ctx` is supplied
                    // (test path).
                    if let Some(ctx) = ctx {
                        dispatch_to_target_channels(
                            storage,
                            ctx,
                            &created,
                            DeliveryReason::IncidentOpened,
                        )
                        .await;
                    }
                    // Seed the escalation engine: if the target has an
                    // escalation policy, create the per-incident state so
                    // the engine's next tick pages the first rung. The
                    // first check is delayed by the policy's first step
                    // delay so the engine doesn't immediately re-notify
                    // the same channels that just received an `Opened`
                    // page (see M-6). Errors are logged — the incident
                    // row is the source of truth, not the escalation
                    // state.
                    seed_escalation_state(storage, target_id, created.id).await;
                }
                Err(statuscore::error::AppError::Conflict { .. }) => {
                    // Another writer raced us — the incident already exists.
                    // Safe to ignore.
                }
                Err(e) => return Err(e),
            }
        }
        return Ok(());
    }

    if good_run >= FLAP_THRESHOLD
        && let Some(open_incident) = open
    {
        // Auto-close: find the first Up result as the recovery time.
        let first_good = ordered.iter().find(|r| r.status == CheckStatus::Up);
        let ended_at = first_good.map_or_else(Utc::now, |r| r.timestamp);
        let duration_secs = (ended_at - open_incident.started_at).num_seconds().max(0) as u64;

        let mut updated = open_incident;
        updated.ended_at = Some(ended_at);
        updated.duration_secs = Some(duration_secs);
        updated.updated_at = Some(Utc::now());

        storage.update_incident(&updated).await?;
        info!(
            incident_id = %updated.id,
            target_id = %target_id,
            duration_secs,
            source = %source,
            "incident_writer: auto-closed incident"
        );
        if let Err(e) =
            enqueue_subscriber_deliveries(storage, &updated, DeliveryReason::IncidentResolved).await
        {
            warn!(error = %e, "incident_writer: subscriber delivery enqueue failed");
        }
        if let Some(ctx) = ctx {
            dispatch_to_target_channels(storage, ctx, &updated, DeliveryReason::IncidentResolved)
                .await;
        }
        // Drop the escalation state so the engine stops paging. Idempotent
        // — a no-op when no state existed (target had no policy).
        if let Err(e) = storage.delete_escalation_state(updated.id).await {
            warn!(error = %e, "incident_writer: delete_escalation_state failed");
        }
    }

    Ok(())
}

/// Background evaluator: every [`BACKGROUND_INTERVAL`], scan every target
/// and re-evaluate its incident state. Uses
/// [`Storage::recent_results_for_targets`] for a single batched read so the
/// scan is O(1) storage round-trips regardless of fleet size.
///
/// `ctx` carries the shared email transport + sender identity used by
/// [`dispatch_to_target_channels`] when an incident opens or resolves.
///
/// Cancels cleanly when `cancel` is triggered. Spawn this from `main.rs` /
/// `app.rs`:
///
/// ```ignore
/// let cancel = CancellationToken::new();
/// tokio::spawn(incident_writer::run_background_evaluator(
///     state.storage.clone(),
///     ctx,
///     cancel.clone(),
/// ));
/// ```
pub async fn run_background_evaluator(
    storage: Arc<dyn Storage>,
    ctx: ChannelDispatchCtx,
    cancel: CancellationToken,
) {
    info!(
        interval_secs = BACKGROUND_INTERVAL.as_secs(),
        "incident_writer: background evaluator started"
    );
    let mut ticker = tokio::time::interval(BACKGROUND_INTERVAL);
    // First tick fires immediately so we sweep on boot.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = run_background_sweep(storage.as_ref(), &ctx).await {
                    warn!(error = %e, "incident_writer: background sweep failed");
                }
            }
            () = cancel.cancelled() => {
                info!("incident_writer: background evaluator stopping");
                break;
            }
        }
    }
}

/// One sweep of the background evaluator. Reads all targets, batches their
/// recent results, and re-evaluates each. Errors per target are logged and
/// swallowed so a single bad target doesn't abort the sweep.
async fn run_background_sweep(
    storage: &dyn Storage,
    ctx: &ChannelDispatchCtx,
) -> statuscore::error::Result<()> {
    let targets = storage.list_targets().await?;
    let target_ids: Vec<Uuid> = targets.iter().filter(|t| t.enabled).map(|t| t.id).collect();
    if target_ids.is_empty() {
        return Ok(());
    }

    let batch = storage.recent_results_for_targets(&target_ids, LOOKBACK).await?;

    for id in &target_ids {
        let results = match batch.get(id) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        // Skip targets inside an active maintenance window — the per-probe
        // path already suppresses these, but the background path may run
        // between probes.
        if storage.is_target_in_active_maintenance(*id).await? {
            continue;
        }
        if let Err(e) = evaluate_results(storage, *id, results, Some(ctx)).await {
            warn!(target_id = %id, error = %e, "incident_writer: background evaluate failed");
        }
    }
    Ok(())
}

/// Re-evaluate a target's incident state from a pre-fetched slice of
/// results. Mirrors [`evaluate_target_inner`] but accepts the results
/// directly so the background path can batch the reads. The shared
/// transition logic lives in [`decide_and_apply_incident_state`].
async fn evaluate_results(
    storage: &dyn Storage,
    target_id: Uuid,
    results: &[CheckResult],
    ctx: Option<&ChannelDispatchCtx>,
) -> statuscore::error::Result<()> {
    decide_and_apply_incident_state(storage, target_id, results, ctx, "background").await
}

/// Seed the per-incident escalation state when an incident is auto-opened on
/// a target that carries an `escalation_policy_id`. The state is created
/// with `next_check_at = now + policy.steps[0].delay_secs` so the engine's
/// first page is delayed by the policy's first rung.
///
/// # Why delay the first check (M-6)
///
/// The coalescer's auto-open path already dispatched an `Opened`
/// notification to the target's bound channels (via
/// [`dispatch_to_target_channels`]). If the escalation engine's first tick
/// fired immediately (`next_check_at = now`), it would page the first
/// rung's targets within seconds — and those targets frequently overlap
/// with the channels the coalescer just notified (the same Slack channel
/// bound both as a target alert and as escalation step 1). The operator
/// sees a duplicate page within seconds of incident open, which is noise.
/// Delaying the first check by the policy's first step delay gives the
/// `Opened` page time to land (and be acknowledged) before escalation
/// kicks in — matching the operator's mental model that escalation is for
/// *unacknowledged* incidents, not a re-broadcast of the open notice.
///
/// If the policy or its first step is unavailable, the seed falls back to
/// `next_check_at = now` so a misconfigured policy doesn't silently
/// suppress escalation. No-op (and silent) when the target has no policy
/// or the target row is gone — neither is an error condition.
///
/// Errors are logged and swallowed: the incident row is the source of
/// truth, not the escalation state, and a failure here must not abort the
/// coalescer's auto-open path.
async fn seed_escalation_state(storage: &dyn Storage, target_id: Uuid, incident_id: Uuid) {
    let target = match storage.get_target(target_id).await {
        Ok(t) => t,
        Err(e) => {
            warn!(target_id = %target_id, error = %e, "incident_writer: get_target for escalation seed failed");
            return;
        }
    };
    let Some(policy_id) = target.escalation_policy_id else {
        return;
    };

    // Read the policy's first step delay so the first escalation check is
    // pushed past the coalescer's `Opened` dispatch. A failure to load the
    // policy is logged but non-fatal: seed with `delay = 0` (page on the
    // next engine tick) so a transient storage error doesn't silently
    // suppress escalation entirely.
    let first_step_delay_secs: i64 = match storage.get_escalation_policy(policy_id).await {
        Ok(policy) => policy.steps.first().map_or(0, |s| i64::from(s.delay_secs.max(0))),
        Err(e) => {
            warn!(
                policy_id = %policy_id,
                error = %e,
                "incident_writer: get_escalation_policy for seed failed; seeding with next_check_at = now"
            );
            0
        }
    };

    let now = Utc::now();
    let next_check_at = now + chrono::Duration::seconds(first_step_delay_secs);
    let state = IncidentEscalationState {
        incident_id,
        policy_id,
        current_level: 0,
        current_round: 0,
        last_paged_at: now,
        next_check_at,
        acked: false,
    };
    if let Err(e) = storage.upsert_escalation_state(&state).await {
        warn!(incident_id = %incident_id, error = %e, "incident_writer: upsert_escalation_state failed");
    }
}

/// Enqueue subscriber deliveries for an incident state change. Looks up
/// every status page that includes the incident's target, then for each
/// page enqueues a delivery to every verified subscriber.
///
/// Errors here are logged by the caller; this function returns the first
/// storage error so the caller can decide whether to retry.
async fn enqueue_subscriber_deliveries(
    storage: &dyn Storage,
    incident: &Incident,
    reason: DeliveryReason,
) -> statuscore::error::Result<()> {
    // Build target_id → Vec<status_page_id> index by scanning every page's
    // component list. For a self-hosted app with a handful of pages this is
    // cheap; a larger deployment would add a reverse lookup table.
    let pages = storage.list_status_pages().await?;
    let mut pages_with_target: Vec<Uuid> = Vec::new();
    for page in &pages {
        if !page.enabled {
            continue;
        }
        let components = storage.list_status_page_components(page.id.0).await?;
        if components.iter().any(|c| c.target_id == incident.target_id) {
            pages_with_target.push(page.id.0);
        }
    }

    let payload = format!(
        "incident {} {} (target={}, severity={}, started={})",
        match reason {
            DeliveryReason::IncidentOpened => "opened",
            DeliveryReason::IncidentResolved => "resolved",
            _ => "updated",
        },
        incident.id,
        incident.target_id,
        incident.severity.as_db_str(),
        incident.started_at,
    );

    for page_id in &pages_with_target {
        let subscribers = storage.list_subscribers(*page_id).await?;
        for sub in subscribers {
            if !sub.is_verified() {
                continue;
            }
            // The subscriber channel dictates the wire transport. The
            // dispatcher (a separate worker) reads the queued row and
            // formats the payload per channel.
            let channel = match SubscriberChannel::from_db_str(sub.channel.as_db_str()) {
                Some(c) => c,
                None => continue,
            };
            if let Err(e) = storage
                .enqueue_delivery(sub.id, *page_id, channel, &sub.target, &payload, reason)
                .await
            {
                warn!(error = %e, subscriber_id = %sub.id, "incident_writer: enqueue_delivery failed");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use statuscore::domain::OrgId;
    use storage::MemoryStorage;

    fn make_result(target_id: Uuid, status: CheckStatus, secs_ago: i64) -> CheckResult {
        CheckResult {
            target_id,
            org_id: OrgId(Uuid::nil()),
            timestamp: Utc::now() - chrono::Duration::seconds(secs_ago),
            status,
            duration_ms: 100,
            dns_ms: None,
            connect_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            response_code: None,
            response_size: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn opens_incident_after_threshold_bad_results() {
        let storage = MemoryStorage::new();
        let target_id = Uuid::now_v7();
        // Two consecutive Down results → should open.
        for (i, status) in [CheckStatus::Down, CheckStatus::Down].iter().enumerate() {
            let r = make_result(target_id, *status, 10 - i as i64);
            storage.record_result(&r).await.unwrap();
        }
        evaluate_target(&storage, target_id, None).await;
        let open = storage.find_open_incident_for_target(target_id).await.unwrap();
        assert!(open.is_some(), "incident should be auto-opened");
    }

    #[tokio::test]
    async fn does_not_open_below_threshold() {
        let storage = MemoryStorage::new();
        let target_id = Uuid::now_v7();
        // Only one Down result → should NOT open.
        let r = make_result(target_id, CheckStatus::Down, 5);
        storage.record_result(&r).await.unwrap();
        evaluate_target(&storage, target_id, None).await;
        let open = storage.find_open_incident_for_target(target_id).await.unwrap();
        assert!(open.is_none(), "incident should not open below threshold");
    }

    #[tokio::test]
    async fn closes_incident_after_threshold_good_results() {
        let storage = MemoryStorage::new();
        let target_id = Uuid::now_v7();
        // Open an incident manually, then add two Up results.
        let incident = Incident {
            id: Uuid::now_v7(),
            target_id,
            started_at: Utc::now() - chrono::Duration::seconds(60),
            ended_at: None,
            status: CheckStatus::Down,
            duration_secs: None,
            check_count: 3,
            error_sample: None,
            severity: IncidentSeverity::Major,
            public_title: Some("Test outage".into()),
            public_description: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            updates: Vec::new(),
            regions_down: Vec::new(),
            regions_up: Vec::new(),
        };
        storage.create_incident(&incident).await.unwrap();

        for (i, status) in [CheckStatus::Up, CheckStatus::Up].iter().enumerate() {
            let r = make_result(target_id, *status, 5 - i as i64);
            storage.record_result(&r).await.unwrap();
        }
        evaluate_target(&storage, target_id, None).await;
        let open = storage.find_open_incident_for_target(target_id).await.unwrap();
        assert!(open.is_none(), "incident should be auto-closed");
    }

    #[tokio::test]
    async fn suppresses_open_during_maintenance() {
        let storage = MemoryStorage::new();
        let target_id = Uuid::now_v7();
        // Create an active maintenance window for this target.
        let window = statuscore::domain::MaintenanceWindow {
            id: Uuid::now_v7(),
            title: "Maintenance".into(),
            description: None,
            starts_at: Utc::now() - chrono::Duration::minutes(5),
            ends_at: Utc::now() + chrono::Duration::minutes(5),
            component_ids: vec![target_id],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            write_source: statuscore::domain::WriteSource::default(),
        };
        storage.create_maintenance_window(&window).await.unwrap();

        // Two Down results → would normally open, but maintenance suppresses.
        for (i, status) in [CheckStatus::Down, CheckStatus::Down].iter().enumerate() {
            let r = make_result(target_id, *status, 10 - i as i64);
            storage.record_result(&r).await.unwrap();
        }
        evaluate_target(&storage, target_id, None).await;
        let open = storage.find_open_incident_for_target(target_id).await.unwrap();
        assert!(open.is_none(), "incident should not open during maintenance");
    }
}
