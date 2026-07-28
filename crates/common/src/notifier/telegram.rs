//! Telegram notifier — POSTs to the Bot API `sendMessage` endpoint.
//!
//! Uses a per-channel bot token and chat id. The bot token is embedded in
//! the request URL path (`/bot{token}/sendMessage`), so the URL is held as
//! a [`SecretString`] to keep it out of `Debug` output.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::TelegramConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

/// A Telegram notifier. Posts `{"chat_id": …, "text": message}` to
/// `https://api.telegram.org/bot{bot_token}/sendMessage` with a 10s timeout.
///
/// The full URL (which contains the bot token) is stored as a
/// [`SecretString`] so it never leaks through `Debug`.
pub struct TelegramNotifier {
    url: SecretString,
    chat_id: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for TelegramNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramNotifier").finish_non_exhaustive()
    }
}

impl TelegramNotifier {
    /// Build a notifier from a [`TelegramConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: TelegramConfig, client: reqwest::Client) -> Self {
        let url = SecretString::from(format!(
            "https://api.telegram.org/bot{}/sendMessage",
            config.bot_token
        ));
        Self { url, chat_id: config.chat_id, client }
    }

    /// Build a notifier from a [`TelegramConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: TelegramConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("telegram notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let body = serde_json::json!({ "chat_id": self.chat_id, "text": message });
        let payload = serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        let resp = self
            .client
            // `SecretString::expose_secret()` already returns `&str`; the
            // extra `.as_str()` would use the unstable `str_as_str` feature.
            .post(self.url.expose_secret())
            .header("content-type", "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "telegram notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
