use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SIGNL4Config {
    /// SIGNL4 webhook URL.
    pub webhook_url: String,
    /// Webhook secret for authentication.
    pub secret: String,
}

impl TransportConfig for SIGNL4Config {
    const KIND: ChannelKind = ChannelKind::SIGNL4;

    fn redact_in_place(&mut self) {
        self.webhook_url = MASK.to_string();
        self.secret = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.webhook_url == MASK || self.secret == MASK
    }

    fn validate(&self) -> Result<(), String> {
        require_https(&self.webhook_url, "webhook_url")?;
        if self.secret.trim().is_empty() {
            return Err("secret is required".into());
        }
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        Some(&self.webhook_url)
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
