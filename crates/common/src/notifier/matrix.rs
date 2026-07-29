//! Matrix notifier — POSTs a message to a Matrix room via the client API.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::MatrixConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct MatrixNotifier {
    homeserver_url: String,
    access_token: SecretString,
    room_id: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for MatrixNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixNotifier").finish_non_exhaustive()
    }
}

impl MatrixNotifier {
    pub fn new_with_client(config: MatrixConfig, client: reqwest::Client) -> Self {
        Self {
            homeserver_url: config.homeserver_url.trim_end_matches('/').to_string(),
            access_token: SecretString::from(config.access_token),
            room_id: config.room_id,
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: MatrixConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("matrix notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for MatrixNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let txn_id = uuid::Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.homeserver_url, self.room_id, txn_id
        );
        let body = serde_json::json!({ "msgtype": "m.text", "body": message });
        let resp = self
            .client
            .put(&url)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.access_token.expose_secret()))
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "matrix notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
