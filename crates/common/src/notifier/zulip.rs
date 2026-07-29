//! Zulip notifier — POSTs a message to a Zulip stream.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::ZulipConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct ZulipNotifier {
    server_url: String,
    email: String,
    api_key: SecretString,
    stream: String,
    topic: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for ZulipNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZulipNotifier").finish_non_exhaustive()
    }
}

impl ZulipNotifier {
    pub fn new_with_client(config: ZulipConfig, client: reqwest::Client) -> Self {
        Self {
            server_url: config.server_url.trim_end_matches('/').to_string(),
            email: config.email,
            api_key: SecretString::from(config.api_key),
            stream: config.stream,
            topic: config.topic,
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: ZulipConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("zulip notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for ZulipNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let url = format!("{}/api/v1/messages", self.server_url);
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/x-www-form-urlencoded")
            .basic_auth(&self.email, Some(self.api_key.expose_secret()))
            .body(format!(
                "type=stream&to={}&topic={}&content={}",
                self.stream, self.topic, message
            ))
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "zulip notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
