//! N8N notifier — POSTs `{"text": message}` to a n8n webhook.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::N8nConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

pub struct N8nNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for N8nNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("N8nNotifier").finish_non_exhaustive()
    }
}

impl N8nNotifier {
    pub fn new_with_client(config: N8nConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: N8nConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("n8n notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for N8nNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
