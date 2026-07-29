use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GotifyConfig {
    /// Gotify server URL.
    pub server_url: String,
    /// Application token for authentication.
    pub app_token: String,
}

impl TransportConfig for GotifyConfig {
    const KIND: ChannelKind = ChannelKind::Gotify;

    fn redact_in_place(&mut self) {
        self.app_token = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.app_token == MASK
    }

    fn validate(&self) -> Result<(), String> {
        require_https(&self.server_url, "server_url")?;
        if self.app_token.trim().is_empty() {
            return Err("app_token is required".into());
        }
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        Some(&self.server_url)
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
