use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SendGridConfig {
    /// SendGrid API key.
    pub api_key: String,
    /// Sender email address.
    pub from_address: String,
}

impl TransportConfig for SendGridConfig {
    const KIND: ChannelKind = ChannelKind::SendGrid;

    fn redact_in_place(&mut self) {
        self.api_key = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.api_key == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.api_key.trim().is_empty() {
            return Err("api_key is required".into());
        }
        if self.from_address.trim().is_empty() || !self.from_address.contains('@') {
            return Err("from_address must be a valid email".into());
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
