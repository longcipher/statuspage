//! Pushover notifier — POSTs to the Pushover Messages API.
//!
//! Pushover delivers to user/group keys via a per-application token. The
//! API is a simple form-encoded POST to `https://api.pushover.net/1/messages.json`.
//! Failures are surfaced via `Result`; non-2xx responses are returned as
//! `Err` so the dispatcher can surface them.
//!
//! Emergency priority (2) is exposed when `config.emergency` is set —
//! Pushover repeats the alert until the recipient acknowledges it. The
//! receipt id returned by the API is currently not captured (the
//! incident-row `provider_receipt` field is the eventual home for it);
//! for now emergency sends are fire-and-forget and rely on the recipient
//! acknowledging in the Pushover app directly.
//!
//! The `token` (application token) and `user` (user/group key) are held
//! as [`SecretString`]s so they never leak through `Debug` output.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::PushoverConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

/// A Pushover notifier. Posts form-encoded `token`/`user`/`message` (and
/// optional `device`/`priority`) to the Messages API with a 10s timeout.
pub struct PushoverNotifier {
    token: SecretString,
    user: SecretString,
    device: Option<String>,
    emergency: bool,
    client: reqwest::Client,
}

impl std::fmt::Debug for PushoverNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushoverNotifier").finish_non_exhaustive()
    }
}

impl PushoverNotifier {
    /// Build a notifier from a [`PushoverConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: PushoverConfig, client: reqwest::Client) -> Self {
        Self {
            token: SecretString::from(config.token),
            user: SecretString::from(config.user),
            device: config.device,
            emergency: config.emergency,
            client,
        }
    }

    /// Build a notifier from a [`PushoverConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: PushoverConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("pushover notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for PushoverNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        // Pushover's API is form-encoded. `priority` is 2 (emergency) only
        // when the channel opted in; otherwise 0 (normal). Emergency sends
        // require `expire` (max retry window) and `retry` (repeat interval)
        // — we use the documented maxima so the recipient gets paged
        // aggressively until they acknowledge.
        let mut form = vec![
            ("token".to_string(), self.token.expose_secret().to_string()),
            ("user".to_string(), self.user.expose_secret().to_string()),
            ("message".to_string(), message.to_string()),
        ];
        if let Some(device) = &self.device {
            form.push(("device".to_string(), device.clone()));
        }
        if self.emergency {
            form.push(("priority".to_string(), "2".to_string()));
            // `expire` is the seconds Pushover will keep retrying (max 10800).
            form.push(("expire".to_string(), "10800".to_string()));
            // `retry` is the seconds between retries (min 30).
            form.push(("retry".to_string(), "60".to_string()));
        } else {
            form.push(("priority".to_string(), "0".to_string()));
        }

        let resp = self
            .client
            .post("https://api.pushover.net/1/messages.json")
            .form(&form)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "pushover notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
