//! GitHub notifier — Creates a GitHub issue for notifications.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::GitHubConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct GitHubNotifier {
    api_url: String,
    repo: String,
    token: SecretString,
    client: reqwest::Client,
}

impl std::fmt::Debug for GitHubNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubNotifier").finish_non_exhaustive()
    }
}

impl GitHubNotifier {
    pub fn new_with_client(config: GitHubConfig, client: reqwest::Client) -> Self {
        Self {
            api_url: config.api_url.trim_end_matches('/').to_string(),
            repo: config.repo,
            token: SecretString::from(config.token),
            client,
        }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: GitHubConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("github notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for GitHubNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let url = format!("{}/repos/{}/issues", self.api_url, self.repo);
        let body = serde_json::json!({ "title": "Statuspage Alert", "body": message });
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.token.expose_secret()))
            .header("accept", "application/vnd.github+json")
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "github notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
