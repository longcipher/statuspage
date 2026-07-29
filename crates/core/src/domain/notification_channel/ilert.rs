use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IlertConfig {
    /// Ilert API key.
    pub api_key: String,
}

impl TransportConfig for IlertConfig {
    const KIND: ChannelKind = ChannelKind::Ilert;

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
        Ok(())
    }

    fn abuse_url(&self) -> Option<&str> {
        None
    }

    fn operator_managed(&self) -> bool {
        false
    }
}
