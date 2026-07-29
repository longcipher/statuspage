use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct OpsgenieConfig {
    /// API key for Opsgenie.
    pub api_key: String,
    /// Opsgenie region (us or eu).
    pub region: String,
}

impl TransportConfig for OpsgenieConfig {
    const KIND: ChannelKind = ChannelKind::Opsgenie;

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
        if !["us", "eu"].contains(&self.region.as_str()) {
            return Err("region must be us or eu".into());
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
