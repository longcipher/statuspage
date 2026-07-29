use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

fn default_gitea_api_url() -> String {
    "https://gitea.com/api/v1".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GiteaConfig {
    /// Repository (owner/repo).
    pub repo: String,
    /// Access token.
    pub token: String,
    /// Gitea API base URL.
    #[serde(default = "default_gitea_api_url")]
    pub api_url: String,
}

impl TransportConfig for GiteaConfig {
    const KIND: ChannelKind = ChannelKind::Gitea;

    fn redact_in_place(&mut self) {
        self.token = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.token == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.repo.trim().is_empty() || !self.repo.contains('/') {
            return Err("repo must be in owner/repo format".into());
        }
        if self.token.trim().is_empty() {
            return Err("token is required".into());
        }
        require_https(&self.api_url, "api_url")?;
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        Some(&self.api_url)
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
