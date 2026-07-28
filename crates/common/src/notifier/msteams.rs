//! MS Teams notifier — POSTs an Adaptive Card to a Teams Workflows webhook.
//!
//! Teams Workflows webhooks expect an Adaptive Card envelope. The message is
//! placed as the `text` of a single `TextBlock`. The shared POST + non-2xx →
//! `Err` mapping lives in [`JsonWebhookNotifier`]; this transport only
//! defines the body shape.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::MsTeamsConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

/// An MS Teams notifier. Posts an Adaptive Card with the message as a
/// `TextBlock` to the configured webhook URL via the shared
/// [`JsonWebhookNotifier`].
pub struct MsTeamsNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for MsTeamsNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsTeamsNotifier").finish_non_exhaustive()
    }
}

impl MsTeamsNotifier {
    /// Build a notifier from an [`MsTeamsConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: MsTeamsConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    /// Build a notifier from an [`MsTeamsConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: MsTeamsConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("msteams notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for MsTeamsNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "body": [{ "type": "TextBlock", "text": message }]
                }
            }]
        });
        self.webhook.post_json(&body).await
    }
}
