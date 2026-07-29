use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig, require_https};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SplunkConfig {
    /// Splunk HEC URL.
    pub hec_url: String,
    /// Splunk HEC token.
    pub hec_token: String,
}

impl TransportConfig for SplunkConfig {
    const KIND: ChannelKind = ChannelKind::Splunk;

    fn redact_in_place(&mut self) {
        self.hec_token = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.hec_token == MASK
    }

    fn validate(&self) -> Result<(), String> {
        require_https(&self.hec_url, "hec_url")?;
        if self.hec_token.trim().is_empty() {
            return Err("hec_token is required".into());
        }
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        Some(&self.hec_url)
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
