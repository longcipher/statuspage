//! Signl4 notifier — POSTs `{"text": message}` to a SIGNL4 webhook.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::SIGNL4Config;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

pub struct SIGNL4Notifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for SIGNL4Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SIGNL4Notifier").finish_non_exhaustive()
    }
}

impl SIGNL4Notifier {
    pub fn new_with_client(config: SIGNL4Config, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: SIGNL4Config) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("SIGNL4 notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for SIGNL4Notifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
