//! Zapier notifier — POSTs `{"text": message}` to a zapier webhook.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use statuscore::domain::ZapierConfig;
use statuscore::error::Result;

use crate::notifier::Notifier;
use crate::notifier::common::JsonWebhookNotifier;

pub struct ZapierNotifier {
    webhook: JsonWebhookNotifier,
}

impl std::fmt::Debug for ZapierNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZapierNotifier").finish_non_exhaustive()
    }
}

impl ZapierNotifier {
    pub fn new_with_client(config: ZapierConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(config.webhook_url);
        Self { webhook: JsonWebhookNotifier::new(url, client) }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: ZapierConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("zapier notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for ZapierNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "text": message });
        self.webhook.post_json(&body).await
    }
}
