//! Splunk notifier — POSTs to a Splunk HEC endpoint.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::SplunkConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct SplunkNotifier {
    hec_url: String,
    hec_token: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for SplunkNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplunkNotifier").finish_non_exhaustive()
    }
}

impl SplunkNotifier {
    pub fn new_with_client(config: SplunkConfig, client: reqwest::Client) -> Self {
        Self {
            hec_url: config.hec_url.trim_end_matches('/').to_string(),
            hec_token: SecretString::from(config.hec_token),
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: SplunkConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("splunk notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for SplunkNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "event": { "message": message, "source": "statuspage" } });
        let resp = self
            .client
            .post(&self.hec_url)
            .header("content-type", "application/json")
            .header("authorization", format!("Splunk {}", self.hec_token.expose_secret()))
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "splunk notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
