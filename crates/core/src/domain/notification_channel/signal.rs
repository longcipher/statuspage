use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SignalConfig {
    /// Signal phone number (sender).
    pub phone_number: String,
    /// Signal REST API URL.
    pub api_url: String,
}

impl TransportConfig for SignalConfig {
    const KIND: ChannelKind = ChannelKind::Signal;

    fn redact_in_place(&mut self) {
        self.api_url = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.api_url == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.phone_number.trim().is_empty() {
            return Err("phone_number is required".into());
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
