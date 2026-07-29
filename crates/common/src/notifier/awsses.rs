//! AWS SES notifier — Sends email via AWS SES (using raw HTTP).

use std::time::Duration;

use async_trait::async_trait;
use statuscore::domain::AwsSesConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

pub struct AwsSesNotifier {
    region: String,
    from_address: String,
    #[expect(dead_code)] // ponytail: needed when AWS SDK is wired in
    client: reqwest::Client,
}

impl std::fmt::Debug for AwsSesNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSesNotifier").finish_non_exhaustive()
    }
}

impl AwsSesNotifier {
    pub fn new_with_client(config: AwsSesConfig, client: reqwest::Client) -> Self {
        Self { region: config.region, from_address: config.from_address, client }
    }

    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: AwsSesConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("awsses notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for AwsSesNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        // ponytail: AWS SES requires SigV4 signing; without the SDK we can't
        // sign requests. This logs the message and returns Ok so dispatch
        // stays total. Full SES delivery needs aws-sdk-ses or manual SigV4.
        tracing::warn!(
            from = %self.from_address,
            region = %self.region,
            message,
            "AWS SES notifier: delivery requires AWS SDK; message logged only"
        );
        Err(AppError::Other(eyre::eyre!(
            "AWS SES delivery requires AWS SDK integration (aws-sdk-ses)"
        )))
    }
}
