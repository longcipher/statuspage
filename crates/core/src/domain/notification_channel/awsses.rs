use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ChannelKind;
use super::transport::TransportConfig;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AwsSesConfig {
    /// AWS region.
    pub region: String,
    /// Sender email address.
    pub from_address: String,
}

impl TransportConfig for AwsSesConfig {
    const KIND: ChannelKind = ChannelKind::AwsSes;

    fn redact_in_place(&mut self) {}

    fn has_redaction_sentinel(&self) -> bool {
        false
    }

    fn validate(&self) -> Result<(), String> {
        if self.region.trim().is_empty() {
            return Err("region is required".into());
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
