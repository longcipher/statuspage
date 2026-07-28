//! Shared helpers for JSON-webhook-style notifiers.
//!
//! Slack, Discord, Google Chat, MS Teams, and the generic webhook transport
//! all POST a JSON body to an incoming-webhook URL and check the response
//! status. [`JsonWebhookNotifier`] encapsulates that shared POST + status
//! logic so each transport only defines its body shape.
//!
//! The webhook URL is held as a [`SecretString`](secrecy::SecretString):
//! Slack/Google Chat/MS Teams incoming-webhook URLs carry a workspace token
//! in the path, and a generic webhook URL may carry a shared secret in a
//! query parameter. Wrapping the URL prevents it from leaking through
//! `Debug` formatting.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use statuscore::error::{AppError, Result};

/// A generic notifier that POSTs a JSON body to a webhook URL.
///
/// Shared by Slack, Discord, Google Chat, MS Teams, and generic webhook
/// transports. Each transport wraps this and supplies its own body
/// construction; the POST, timeout, and non-2xx → `Err` mapping live here.
pub struct JsonWebhookNotifier {
    /// Webhook URL. `SecretString` because incoming-webhook URLs typically
    /// carry a token in the path (Slack) or query (generic webhook).
    url: SecretString,
    /// Pre-built HTTP client. Injected by the caller so the SSRF guard,
    /// TLS roots, and timeout policy are owned by the boot path, not by
    /// each transport.
    client: reqwest::Client,
}

impl std::fmt::Debug for JsonWebhookNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonWebhookNotifier").finish_non_exhaustive()
    }
}

impl JsonWebhookNotifier {
    /// Build a new notifier from a secret URL and a pre-configured client.
    ///
    /// The client should be built once at boot with the SSRF guard wired in
    /// (see `crate::http_client::outbound`) and shared across transports;
    /// each transport's `new_with_client` accepts it and forwards it here.
    pub const fn new(url: SecretString, client: reqwest::Client) -> Self {
        Self { url, client }
    }

    /// POST a JSON-serialisable body to the webhook URL with a 10s timeout.
    ///
    /// Returns `Err` on any transport error or non-2xx response; the caller
    /// (channel dispatch) is responsible for logging the error. The response
    /// body is captured into the error message for diagnostics (bounded by
    /// reqwest's internal buffer).
    pub async fn post_json<T: Serialize + Sync + ?Sized>(&self, body: &T) -> Result<()> {
        let payload = serde_json::to_string(body)
            .map_err(|e| AppError::Other(eyre::eyre!("serialising webhook body: {e}")))?;
        let resp = self
            .client
            // `SecretString::expose_secret()` already returns `&str`; the
            // extra `.as_str()` would use the unstable `str_as_str` feature.
            .post(self.url.expose_secret())
            .header("content-type", "application/json")
            .timeout(Duration::from_secs(10))
            .body(payload)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!("webhook request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!("webhook endpoint returned {status}: {text}")));
        }
        Ok(())
    }
}
