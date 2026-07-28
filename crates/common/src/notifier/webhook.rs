//! Webhook notifier — POSTs the message as a JSON body to a configured URL.
//!
//! Used by the notification dispatch path when an operator configures a
//! webhook channel. The body shape is `{"text": "<message>"}`, matching
//! the Slack incoming webhook contract (and most generic webhook
//! consumers). The shared POST + non-2xx → `Err` mapping lives in
//! [`JsonWebhookNotifier`]; this transport only defines the body shape.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

/// A webhook notifier. Posts `{"text": message}` to the configured URL via
/// the shared [`JsonWebhookNotifier`].
pub struct WebhookNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for WebhookNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookNotifier").finish_non_exhaustive()
    }
}

impl WebhookNotifier {
    /// Build a notifier that posts to `url` using a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(url: String, client: reqwest::Client) -> Self {
        let url = SecretString::from(url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    /// Build a notifier that posts to `url` with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("webhook notifier: client build");
        Self::new_with_client(url, client)
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
