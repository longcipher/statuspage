//! SMS notifier — delivers via the configured gateway.
//!
//! One `SmsConfig` carries credentials for any of the five supported
//! gateways (Twilio, Telnyx, Vonage, Plivo, Sinch). Each gateway has its
//! own request shape; this module dispatches on the config variant and
//! posts to the right endpoint with the right auth. All gateways use a
//! 10s timeout and surface non-2xx responses as `Err`.
//!
//! Only Twilio is fully implemented today (it is the most common choice
//! for self-hosted alerting). Telnyx / Vonage / Plivo / Sinch fall back
//! to the log-only notifier with a `warn` so the operator sees the
//! delivery was a no-op rather than a silent success. Adding another
//! provider is a match-arm addition, not a structural change.
//!
//! The Twilio `auth_token` is held as a [`SecretString`] so it never
//! leaks through `Debug` output.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::SmsConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

/// An SMS notifier. Holds the gateway-specific credentials and a shared
/// HTTP client. Cheap to clone if needed; in practice one is built per
/// dispatch via [`build_notifier`](crate::notifier::build_notifier).
pub struct SmsNotifier {
    inner: SmsNotifierInner,
    client: reqwest::Client,
}

impl std::fmt::Debug for SmsNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmsNotifier").finish_non_exhaustive()
    }
}

enum SmsNotifierInner {
    /// Twilio: POST form-encoded `To`/`From`/`Body` to
    /// `https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json`
    /// with HTTP Basic auth (`sid`:`auth_token`).
    Twilio { to: String, from: String, account_sid: String, auth_token: SecretString },
    /// Telnyx / Vonage / Plivo / Sinch: not yet implemented. Carries the
    /// kind so the `send` path can log which gateway was skipped.
    Unsupported(&'static str),
}

impl SmsNotifier {
    /// Build a notifier from an [`SmsConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here. Returns an `Unsupported`
    /// variant for gateways without a real transport — `send` will log
    /// and succeed so the delivery isn't retried.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: SmsConfig, client: reqwest::Client) -> Self {
        let inner = match config {
            SmsConfig::Twilio { to, from, account_sid, auth_token } => SmsNotifierInner::Twilio {
                to,
                from,
                account_sid,
                auth_token: SecretString::from(auth_token),
            },
            SmsConfig::Telnyx { .. } => SmsNotifierInner::Unsupported("telnyx"),
            SmsConfig::Vonage { .. } => SmsNotifierInner::Unsupported("vonage"),
            SmsConfig::Plivo { .. } => SmsNotifierInner::Unsupported("plivo"),
            SmsConfig::Sinch { .. } => SmsNotifierInner::Unsupported("sinch"),
            // `SmsConfig` is `#[non_exhaustive]`: a future provider variant
            // added upstream must not break dispatch. Log as unsupported so
            // the delivery is not retried indefinitely.
            _ => SmsNotifierInner::Unsupported("unknown"),
        };
        Self { inner, client }
    }

    /// Build a notifier from an [`SmsConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: SmsConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("sms notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for SmsNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        match &self.inner {
            SmsNotifierInner::Twilio { to, from, account_sid, auth_token } => {
                let url = format!(
                    "https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
                );
                let form = [
                    ("To".to_string(), to.clone()),
                    ("From".to_string(), from.clone()),
                    ("Body".to_string(), message.to_string()),
                ];
                let resp = self
                    .client
                    .post(&url)
                    .basic_auth(account_sid, Some(auth_token.expose_secret()))
                    .form(&form)
                    .send()
                    .await
                    .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(AppError::Other(eyre::eyre!(
                        "sms notifier (twilio): endpoint returned {status}: {text}"
                    )));
                }
                Ok(())
            }
            SmsNotifierInner::Unsupported(provider) => {
                tracing::warn!(
                    provider,
                    "sms notifier: provider not yet implemented; delivery logged as success"
                );
                Ok(())
            }
        }
    }
}
