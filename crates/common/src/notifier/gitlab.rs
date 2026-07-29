//! GitLab notifier — Creates a GitLab issue for notifications.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::GitLabConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct GitLabNotifier {
    api_url: String,
    repo: String,
    token: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for GitLabNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitLabNotifier").finish_non_exhaustive()
    }
}

impl GitLabNotifier {
    pub fn new_with_client(config: GitLabConfig, client: reqwest::Client) -> Self {
        Self {
            api_url: config.api_url.trim_end_matches('/').to_string(),
            repo: config.repo,
            token: SecretString::from(config.token),
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: GitLabConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("gitlab notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for GitLabNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let encoded_repo =
            url::form_urlencoded::byte_serialize(self.repo.as_bytes()).collect::<String>();
        let url = format!("{}/projects/{}/issues", self.api_url, encoded_repo);
        let body = serde_json::json!({ "title": "Statuspage Alert", "description": message });
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.token.expose_secret()))
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "gitlab notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
