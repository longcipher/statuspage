use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

fn default_gitlab_api_url() -> String {
    "https://gitlab.com/api/v4".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GitLabConfig {
    /// Repository (owner/repo or numeric ID).
    pub repo: String,
    /// Personal access token.
    pub token: String,
    /// GitLab API base URL.
    #[serde(default = "default_gitlab_api_url")]
    pub api_url: String,
}

impl TransportConfig for GitLabConfig {
    const KIND: ChannelKind = ChannelKind::GitLab;

    fn redact_in_place(&mut self) {
        self.token = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.token == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.repo.trim().is_empty() {
            return Err("repo is required".into());
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
