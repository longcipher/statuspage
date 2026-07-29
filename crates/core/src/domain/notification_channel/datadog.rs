use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::{MASK, TransportConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DatadogConfig {
    /// Datadog API key.
    pub api_key: String,
    /// Datadog application key.
    pub app_key: String,
}

impl TransportConfig for DatadogConfig {
    const KIND: ChannelKind = ChannelKind::Datadog;

    fn redact_in_place(&mut self) {
        self.api_key = MASK.to_string();
        self.app_key = MASK.to_string();
    }

    fn has_redaction_sentinel(&self) -> bool {
        self.api_key == MASK || self.app_key == MASK
    }

    fn validate(&self) -> Result<(), String> {
        if self.api_key.trim().is_empty() {
            return Err("api_key is required".into());
        }
        if self.app_key.trim().is_empty() {
            return Err("app_key is required".into());
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
