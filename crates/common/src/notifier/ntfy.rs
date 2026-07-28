//! ntfy notifier — POSTs the message body to `{server_url}/{topic}`.
//!
//! ntfy publishes are plain-text POSTs to the topic URL. An optional access
//! token is sent as `Authorization: Bearer {token}` for protected servers.
//! The token is held as a [`SecretString`] so it never leaks through
//! `Debug` output.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::NtfyConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

/// An ntfy notifier. Posts the message as the request body to
/// `{server_url}/{topic}` with a 10s timeout, attaching an `Authorization:
/// Bearer` header when an access token is configured.
pub struct NtfyNotifier {
    url: String,
    access_token: Option<SecretString>,
    client: reqwest::Client,
}

impl std::fmt::Debug for NtfyNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtfyNotifier").finish_non_exhaustive()
    }
}

impl NtfyNotifier {
    /// Build a notifier from an [`NtfyConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: NtfyConfig, client: reqwest::Client) -> Self {
        // `server_url` is validated as the server root (no path) and
        // `topic` is validated as alphanumeric/_/-, so joining with a single
        // slash is safe and never produces a double slash or path traversal.
        let base = config.server_url.trim_end_matches('/');
        let url = format!("{base}/{}", config.topic);
        let access_token = config.access_token.map(SecretString::from);
        Self { url, access_token, client }
    }

    /// Build a notifier from an [`NtfyConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: NtfyConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("ntfy notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let mut req = self
            .client
            .post(&self.url)
            .header("content-type", "text/plain")
            .body(message.to_string());
        if let Some(token) = &self.access_token {
            req = req.header("authorization", format!("Bearer {}", token.expose_secret()));
        }
        let resp = req.send().await.map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "ntfy notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
