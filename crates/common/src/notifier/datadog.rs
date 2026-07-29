//! Datadog notifier — POSTs to the Datadog Events API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::DatadogConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

const API_URL: &str = "https://api.datadoghq.com/api/v1/events";

pub struct DatadogNotifier {
    api_key: SecretString,
    app_key: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for DatadogNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogNotifier").finish_non_exhaustive()
    }
}

impl DatadogNotifier {
    pub fn new_with_client(config: DatadogConfig, client: reqwest::Client) -> Self {
        Self {
            api_key: SecretString::from(config.api_key),
            app_key: SecretString::from(config.app_key),
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: DatadogConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("datadog notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for DatadogNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({
            "title": "Statuspage Alert",
            "text": message,
            "alert_type": "warning",
            "source": "statuspage"
        });
        let resp = self
            .client
            .post(API_URL)
            .header("content-type", "application/json")
            .header("dd-api-key", self.api_key.expose_secret())
            .header("dd-application-key", self.app_key.expose_secret())
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "datadog notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
