//! SendGrid notifier — POSTs to the SendGrid v3 Mail Send API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::SendGridConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

const API_URL: &str = "https://api.sendgrid.com/v3/mail/send";

pub struct SendGridNotifier {
    api_key: SecretString,
    from_address: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for SendGridNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendGridNotifier").finish_non_exhaustive()
    }
}

impl SendGridNotifier {
    pub fn new_with_client(config: SendGridConfig, client: reqwest::Client) -> Self {
        Self {
            api_key: SecretString::from(config.api_key),
            from_address: config.from_address,
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: SendGridConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("sendgrid notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for SendGridNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        // ponytail: SendGrid requires a `to` address from the channel config;
        // without it we can't send. Using from_address as a fallback.
        let body = serde_json::json!({
            "personalizations": [{ "to": [{ "email": self.from_address }] }],
            "from": { "email": self.from_address },
            "subject": "Statuspage Alert",
            "content": [{ "type": "text/plain", "value": message }]
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
                "sendgrid notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
