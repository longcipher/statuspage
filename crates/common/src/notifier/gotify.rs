//! Gotify notifier — POSTs a message to a Gotify server.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::GotifyConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct GotifyNotifier {
    url: String,
    app_token: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for GotifyNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GotifyNotifier").finish_non_exhaustive()
    }
}

impl GotifyNotifier {
    pub fn new_with_client(config: GotifyConfig, client: reqwest::Client) -> Self {
        let base = config.server_url.trim_end_matches('/');
        Self {
            url: format!("{base}/message"),
            app_token: SecretString::from(config.app_token),
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: GotifyConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("gotify notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for GotifyNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "message": message, "title": "Statuspage Alert" });
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("x-gotify-key", self.app_token.expose_secret())
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "gotify notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
