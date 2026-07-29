//! Opsgenie notifier — POSTs to the Opsgenie v2 Alerts API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::OpsgenieConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

const API_URL: &str = "https://api.opsgenie.com/v2/alerts";

pub struct OpsgenieNotifier {
    api_key: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for OpsgenieNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsgenieNotifier").finish_non_exhaustive()
    }
}

impl OpsgenieNotifier {
    pub fn new_with_client(config: OpsgenieConfig, client: reqwest::Client) -> Self {
        Self { api_key: SecretString::from(config.api_key), client }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: OpsgenieConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("opsgenie notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for OpsgenieNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "message": message });
        let resp = self
            .client
            .post(API_URL)
            .header("content-type", "application/json")
            .header("authorization", format!("GenieKey {}", self.api_key.expose_secret()))
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "opsgenie notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
