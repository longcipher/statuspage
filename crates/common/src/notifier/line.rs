//! LINE notifier — POSTs a message via the LINE Messaging API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::LineConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

const API_URL: &str = "https://api.line.me/v2/bot/message/broadcast";

pub struct LineNotifier {
    channel_access_token: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for LineNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineNotifier").finish_non_exhaustive()
    }
}

impl LineNotifier {
    pub fn new_with_client(config: LineConfig, client: reqwest::Client) -> Self {
        Self { channel_access_token: SecretString::from(config.channel_access_token), client }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: LineConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("line notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for LineNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({
            "messages": [{ "type": "text", "text": message }]
        });
        let resp = self
            .client
            .post(API_URL)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", self.channel_access_token.expose_secret()),
            )
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "line notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
