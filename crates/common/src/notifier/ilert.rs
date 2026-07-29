//! Ilert notifier — POSTs to the Ilert Events API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::IlertConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

const API_URL: &str = "https://api.ilert.com/api/v1/events";

pub struct IlertNotifier {
    api_key: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for IlertNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IlertNotifier").finish_non_exhaustive()
    }
}

impl IlertNotifier {
    pub fn new_with_client(config: IlertConfig, client: reqwest::Client) -> Self {
        Self { api_key: SecretString::from(config.api_key), client }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: IlertConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("ilert notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for IlertNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({
            "summary": message,
            "eventType": "ALERT",
            "alertSource": "statuspage"
        });
        let resp = self
            .client
            .post(API_URL)
            .header("content-type", "application/json")
            .header("authorization", format!("APIKey {}", self.api_key.expose_secret()))
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "ilert notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
