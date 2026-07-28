//! Email notifier — sends a plain-text email via SMTP.
//!
//! Uses `lettre` for SMTP delivery. The notifier is constructed with a
//! pre-built `AsyncSmtpTransport` and a `from` address; each `send` call
//! emits a single email to the configured recipient.

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use statuscore::error::{AppError, Result};

use crate::notifier::Notifier;

/// Configuration for the SMTP transport.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port (587 for STARTTLS, 465 for implicit TLS).
    pub port: u16,
    /// SMTP authentication username.
    pub username: String,
    /// SMTP authentication password.
    pub password: String,
    /// Sender address (`From:` header).
    pub from: String,
    /// Recipient address (`To:` header).
    pub to: String,
    /// Use TLS (STARTTLS for port 587, implicit TLS for port 465).
    pub use_tls: bool,
}

/// An email notifier. Sends `message` as the plain-text body of an email
/// from `config.from` to `config.to`.
pub struct EmailNotifier {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    to: String,
}

impl std::fmt::Debug for EmailNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailNotifier")
            .field("from", &self.from)
            .field("to", &self.to)
            .finish_non_exhaustive()
    }
}

impl EmailNotifier {
    /// Build an email notifier from an [`SmtpConfig`].
    pub fn new(config: SmtpConfig) -> Self {
        let creds = Credentials::new(config.username, config.password);
        let transport = if config.use_tls {
            if config.port == 465 {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                    .expect("email notifier: relay build")
                    .port(config.port)
                    .credentials(creds)
                    .build()
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .expect("email notifier: starttls build")
                    .port(config.port)
                    .credentials(creds)
                    .build()
            }
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                .port(config.port)
                .credentials(creds)
                .build()
        };
        Self { transport, from: config.from, to: config.to }
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        let email = Message::builder()
            .from(
                self.from
                    .parse()
                    .map_err(|e| AppError::Other(eyre::eyre!("invalid from address: {e}")))?,
            )
            .to(self
                .to
                .parse()
                .map_err(|e| AppError::Other(eyre::eyre!("invalid to address: {e}")))?)
            .subject("StatusPage Incident Notification")
            .header(ContentType::TEXT_PLAIN)
            .body(message.to_string())
            .map_err(|e| AppError::Other(eyre::eyre!(e)))?;

        self.transport.send(email).await.map_err(|e| AppError::Other(eyre::eyre!(e)))?;
        Ok(())
    }
}
