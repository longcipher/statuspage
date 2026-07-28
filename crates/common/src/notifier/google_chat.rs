//! Google Chat notifier — POSTs `{"text": message}` to a Google Chat space
//! webhook.
//!
//! Google Chat incoming webhooks accept a JSON body of `{"text": "…"}`.
//! The shared POST + non-2xx → `Err` mapping lives in
//! [`JsonWebhookNotifier`]; this transport only defines the body shape.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::GoogleChatConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

/// A Google Chat notifier. Posts `{"text": message}` to the configured
/// webhook URL via the shared [`JsonWebhookNotifier`].
pub struct GoogleChatNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for GoogleChatNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleChatNotifier").finish_non_exhaustive()
    }
}

impl GoogleChatNotifier {
    /// Build a notifier from a [`GoogleChatConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: GoogleChatConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    /// Build a notifier from a [`GoogleChatConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: GoogleChatConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("google chat notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for GoogleChatNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
