use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LineConfig {
    /// LINE channel access token.
    pub channel_access_token: String,
}

impl TransportConfig for LineConfig {
    const KIND: ChannelKind = ChannelKind::Line;

    fn redact_in_place(&mut self) {
        self.channel_access_token = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.channel_access_token == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.channel_access_token.trim().is_empty() {
            return Err("channel_access_token is required".into());
        }
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        None
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
