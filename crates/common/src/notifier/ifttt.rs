//! IFTTT notifier — POSTs to an IFTTT webhook.

use std::time::Duration;

use async_trait::async_trait;
use statuscore::domain::IFTTTConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct IFTTTNotifier {
    url: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for IFTTTNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IFTTTNotifier").finish_non_exhaustive()
    }
}

impl IFTTTNotifier {
    pub fn new_with_client(config: IFTTTConfig, client: reqwest::Client) -> Self {
        Self {
            url: format!(
                "https://maker.ifttt.com/trigger/{}/with/key/{}",
                config.event_name, config.webhook_key
            ),
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: IFTTTConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("ifttt notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for IFTTTNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "value1": message });
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "ifttt notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
