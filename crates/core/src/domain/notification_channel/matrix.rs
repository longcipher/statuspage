use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MatrixConfig {
    /// Matrix homeserver URL.
    pub homeserver_url: String,
    /// Access token for authentication.
    pub access_token: String,
    /// Room ID to send notifications to.
    pub room_id: String,
}

impl TransportConfig for MatrixConfig {
    const KIND: ChannelKind = ChannelKind::Matrix;

    fn redact_in_place(&mut self) {
        self.access_token = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.access_token == MASK
    }

    fn validate(&self) -> Result<(), String> {
        require_https(&self.homeserver_url, "homeserver_url")?;
        if self.access_token.trim().is_empty() {
            return Err("access_token is required".into());
        }
        if self.room_id.trim().is_empty() {
            return Err("room_id is required".into());
        }
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        Some(&self.homeserver_url)
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
