//! WhatsApp notifier — delivers via the WhatsApp Business Cloud API.
//!
//! The Cloud API only delivers free-form text inside the 24-hour service
//! window. Outside that window — which is exactly when an alerting
//! channel needs to deliver — the API requires a pre-approved template
//! with a single body parameter carrying the alert text. The
//! [`WhatsAppConfig`] therefore requires a `template_name`; we send the
//! message as that template's body parameter so alerts land regardless
//! of the service window.
//!
//! Endpoint: `POST https://graph.facebook.com/v18.0/{phone_number_id}/messages`
//! Auth: `Bearer {access_token}`. 10s timeout; non-2xx returned as `Err`.
//!
//! The `access_token` is held as a [`SecretString`] so it never leaks
//! through `Debug` output.

use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use statuscore::domain::WhatsAppConfig;
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

/// A WhatsApp Cloud API notifier. Sends the message as a template body
/// parameter so delivery works outside the 24-hour service window.
pub struct WhatsAppNotifier {
    url: String,
    access_token: SecretString,
    to: String,
    template_name: String,
    language_code: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for WhatsAppNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsAppNotifier").finish_non_exhaustive()
    }
}

impl WhatsAppNotifier {
    /// Build a notifier from a [`WhatsAppConfig`] and a pre-configured
    /// `reqwest::Client`. See [`SlackNotifier::new_with_client`] for the
    /// SSRF rationale; the same applies here.
    ///
    /// [`SlackNotifier::new_with_client`]: crate::notifier::slack::SlackNotifier::new_with_client
    pub fn new_with_client(config: WhatsAppConfig, client: reqwest::Client) -> Self {
        // Cloud API version pinned to v18.0 (a stable, widely-available
        // release). Bumping is a deliberate operator choice; the API
        // shape used here has been stable since v14.
        let url = format!("https://graph.facebook.com/v18.0/{}/messages", config.phone_number_id);
        Self {
            url,
            access_token: SecretString::from(config.access_token),
            to: config.to,
            template_name: config.template_name,
            // Default to `en` when the operator didn't specify — matches
            // the Cloud API's own default for template language.
            language_code: config.language_code.unwrap_or_else(|| "en".to_string()),
            client,
        }
    }

    /// Build a notifier from a [`WhatsAppConfig`] with a self-built client.
    ///
    /// Deprecated: the self-built client bypasses the SSRF guard. Use
    /// [`Self::new_with_client`] for production paths. Kept for tests.
    #[deprecated(note = "use new_with_client for SSRF safety")]
    pub fn new(config: WhatsAppConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("whatsapp notifier: client build");
        Self::new_with_client(config, client)
    }
}

#[async_trait]
impl Notifier for WhatsAppNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        // Body shape per Cloud API docs for a template with a single body
        // parameter. The template must exist in the WhatsApp Business
        // Manager and be approved; the operator pre-creates it with the
        // single `{{1}}` placeholder.
        let body = serde_json::json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": self.to,
            "type": "template",
            "template": {
                "name": self.template_name,
                "language": { "code": self.language_code },
                "components": [
                    {
                        "type": "body",
                        "parameters": [
                            { "type": "text", "text": message }
                        ]
                    }
                ]
            }
        });
        let resp = self
            .client
            .post(&self.url)
            .bearer_auth(self.access_token.expose_secret())
            .header("content-type", "application/json")
            .body(serde_json::to_string(&body).map_err(|e| AppError::Other(eyre::eyre!(e)))?)
            .send()
            .await
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Other(eyre::eyre!(
                "whatsapp notifier: endpoint returned {status}: {text}"
            )));
        }
        Ok(())
    }
}
