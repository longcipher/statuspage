//! PagerDuty notifier — POSTs to the Events API v2 enqueue endpoint.
//!
//! `Opened`/`Reopened`/`Escalated` notices trigger a page keyed on the
//! incident id; `Resolved` resolves the matching dedup key. The plain
//! [`Notifier::send`] path always triggers with a message-derived dedup key
//! (it has no incident context). Failures are surfaced via `Result`; non-2xx
//! responses are returned as `Err` so the dispatcher can surface them.
//!
//! The `routing_key` is held as a [`SecretString`] so it never leaks
//! through `Debug` output.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::{IncidentSeverity, PagerDutyConfig};
use statuscore::error::{AppError, Result};

use crate::notifier::{IncidentNotice, NoticeReason, Notifier, format_notice_message};

const EVENTS_API_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// A PagerDuty notifier. Posts Events API v2 envelopes to the enqueue
/// endpoint with a 15s timeout.
pub struct PagerDutyNotifier {
    routing_key: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for PagerDutyNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PagerDutyNotifier").finish_non_exhaustive()
    }
}

impl PagerDutyNotifier {
    /// Build a notifier from a [`PagerDutyConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: PagerDutyConfig, client: reqwest::Client) -> Self {
        Self { routing_key: SecretString::from(config.routing_key), client }
    }

    /// Build a notifier from a [`PagerDutyConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: PagerDutyConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("pagerduty notifier: client build");
        Self::new_with_client(config, client)
    }

    async fn enqueue(
        &self,
        event_action: &str,
        dedup_key: &str,
        summary: &str,
        severity: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "routing_key": self.routing_key.expose_secret(),
            "event_action": event_action,
            "dedup_key": dedup_key,
            "payload": {
                "summary": summary,
                "severity": severity,
                "source": "statuspage",
            }
        });
        let resp = self
            .client
            .post(EVENTS_API_URL)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "pagerduty notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}

const fn severity_for(severity: IncidentSeverity) -> &'static str {
    match severity {
        IncidentSeverity::Critical => "critical",
        IncidentSeverity::Major => "error",
        IncidentSeverity::Minor => "warning",
        // `IncidentSeverity` is `#[non_exhaustive]`: future variants must
        // not panic the dispatcher. Default to the least alarming level so
        // a novel severity still pages without overstating urgency.
        _ => "info",
    }
}

#[async_trait]
impl Notifier for PagerDutyNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        // No incident context: derive a stable dedup key from the message so
        // repeat sends of the same message coalesce on PagerDuty's side.
        let dedup_key: String = message.chars().take(255).collect();
        self.enqueue("trigger", &dedup_key, message, "error").await
    }

    async fn notify_incident(&self, notice: &IncidentNotice<'_>) -> Result<()> {
        let inc = notice.incident;
        // The incident id is the dedup key: a later `resolve` for the same
        // incident matches the `trigger` that opened it.
        let dedup_key = inc.id.to_string();
        let summary = format_notice_message(notice);
        let severity = severity_for(inc.severity);
        let event_action = match notice.reason {
            NoticeReason::Resolved => "resolve",
            NoticeReason::Opened | NoticeReason::Reopened | NoticeReason::Escalated => "trigger",
        };
        self.enqueue(event_action, &dedup_key, &summary, severity).await
    }
}
