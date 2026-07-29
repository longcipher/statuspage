//! Signal notifier — POSTs a message via signal-cli-rest-api.

use std::time::Duration;

use async_trait::async_trait;
use statuscore::domain::SignalConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct SignalNotifier {
    api_url: String,
    phone_number: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for SignalNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalNotifier").finish_non_exhaustive()
    }
}

impl SignalNotifier {
    pub fn new_with_client(config: SignalConfig, client: reqwest::Client) -> Self {
        Self {
            api_url: config.api_url.trim_end_matches('/').to_string(),
            phone_number: config.phone_number,
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: SignalConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("signal notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for SignalNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let url = format!("{}/v2/send", self.api_url);
        let body = serde_json::json!({
            "message": message,
            "number": self.phone_number,
        });
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "signal notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
