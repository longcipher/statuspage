//! New Relic notifier — POSTs to the New Relic Events API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::NewRelicConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct NewRelicNotifier {
    api_key: SecretString,
    account_id: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for NewRelicNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewRelicNotifier").finish_non_exhaustive()
    }
}

impl NewRelicNotifier {
    pub fn new_with_client(config: NewRelicConfig, client: reqwest::Client) -> Self {
        Self { api_key: SecretString::from(config.api_key), account_id: config.account_id, client }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: NewRelicConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("newrelic notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for NewRelicNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let url = format!(
            "https://insights-collector.newrelic.com/v1/accounts/{}/events",
            self.account_id
        );
        let body = serde_json::json!({
            "eventType": "StatuspageAlert",
            "message": message,
            "source": "statuspage"
        });
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-insert-key", self.api_key.expose_secret())
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "newrelic notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
