use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IFTTTConfig {
    /// IFTTT webhook key.
    pub webhook_key: String,
    /// IFTTT event name.
    pub event_name: String,
}

impl TransportConfig for IFTTTConfig {
    const KIND: ChannelKind = ChannelKind::Ifttt;

    fn redact_in_place(&mut self) {
        self.webhook_key = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.webhook_key == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.webhook_key.trim().is_empty() {
            return Err("webhook_key is required".into());
        }
        if self.event_name.trim().is_empty() {
            return Err("event_name is required".into());
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
