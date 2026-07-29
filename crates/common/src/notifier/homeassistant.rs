//! Homeassistant notifier — POSTs `{"text": message}` to a homeassistant webhook.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::HomeAssistantConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

pub struct HomeAssistantNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for HomeAssistantNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HomeAssistantNotifier").finish_non_exhaustive()
    }
}

impl HomeAssistantNotifier {
    pub fn new_with_client(config: HomeAssistantConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: HomeAssistantConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("homeassistant notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for HomeAssistantNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
