//! Slack notifier — POSTs `{"text": message}` to a Slack incoming webhook.
//!
//! Slack incoming webhooks accept a JSON body of `{"text": "…"}`. The shared
//! POST + non-2xx → `Err` mapping lives in [`JsonWebhookNotifier`]; this
//! transport only defines the body shape.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::SlackConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

/// A Slack notifier. Posts `{"text": message}` to the configured
/// incoming-webhook URL via the shared [`JsonWebhookNotifier`].
pub struct SlackNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for SlackNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackNotifier").finish_non_exhaustive()
    }
}

impl SlackNotifier {
    /// Build a notifier from a [`SlackConfig`] and a pre-configured
    /// `reqwest::Client`.
    ///
    /// The client should be built once at boot with the SSRF guard wired in
    /// and shared across transports; each transport's `new_with_client`
    /// accepts it rather than building its own. The webhook URL is wrapped
    /// in a [`SecretString`] so it never leaks through `Debug` formatting
    /// (Slack incoming-webhook URLs carry a workspace token in the path).
    pub fn new_with_client(config: SlackConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    /// Build a notifier from a [`SlackConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] with a client built via
    /// `crate::http_client::outbound::build_outbound_client` (or the
    /// reqwest equivalent) so webhook URLs pointing at private IP ranges
    /// are rejected before any TCP open. Kept for tests that don't care
    /// about SSRF.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: SlackConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("slack notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for SlackNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
