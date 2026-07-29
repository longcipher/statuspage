//! Clickup notifier — POSTs `{"text": message}` to a clickup webhook.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::ClickUpConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

pub struct ClickUpNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for ClickUpNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClickUpNotifier").finish_non_exhaustive()
    }
}

impl ClickUpNotifier {
    pub fn new_with_client(config: ClickUpConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: ClickUpConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("clickup notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for ClickUpNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
