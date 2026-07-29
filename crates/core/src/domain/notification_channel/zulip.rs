use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ZulipConfig {
    /// Zulip server URL.
    pub server_url: String,
    /// Bot email address.
    pub email: String,
    /// Bot API key.
    pub api_key: String,
    /// Stream to send notifications to.
    pub stream: String,
    /// Topic within the stream.
    pub topic: String,
}

impl TransportConfig for ZulipConfig {
    const KIND: ChannelKind = ChannelKind::Zulip;

    fn redact_in_place(&mut self) {
        self.api_key = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.api_key == MASK
    }

    fn validate(&self) -> Result<(), String> {
        require_https(&self.server_url, "server_url")?;
        if self.email.trim().is_empty() {
            return Err("email is required".into());
        }
        if self.api_key.trim().is_empty() {
            return Err("api_key is required".into());
        }
        if self.stream.trim().is_empty() {
            return Err("stream is required".into());
        }
        if self.topic.trim().is_empty() {
            return Err("topic is required".into());
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
