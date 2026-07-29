//! incident.io notifier — POSTs an alert to incident.io.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::IncidentioConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

const API_URL: &str = "https://api.incident.io/v2/alerts";

pub struct IncidentioNotifier {
    api_key: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for IncidentioNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncidentioNotifier").finish_non_exhaustive()
    }
}

impl IncidentioNotifier {
    pub fn new_with_client(config: IncidentioConfig, client: reqwest::Client) -> Self {
        Self { api_key: SecretString::from(config.api_key), client }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: IncidentioConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("incidentio notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for IncidentioNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({
            "alert_source": "statuspage",
            "title": "Statuspage Alert",
            "description": message,
            "status": "firing"
        });
        let resp = self
            .client
            .post(API_URL)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.api_key.expose_secret()))
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "incidentio notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
