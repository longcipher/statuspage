//! Notification channel dispatchers.
//!
//! This module exposes the dispatch trait and a log-only fallback. Real
//! transports (webhook, email, slack, discord, …) live in submodules and are
//! wired via [`build_notifier`] when an operator configures a channel. The
//! log-only fallback is the production default when no transport is
//! configured — every incident surfaces as a `tracing::info!` line.
//!
//! `clippy::expect_used` is allowed module-wide: the deprecated `new()`
//! constructors on each notifier build a `reqwest::Client` via
//! `Client::builder().build().expect(...)`. That call only fails on
//! allocator exhaustion or TLS-backend init failure — both are
//! process-fatal conditions where panicking at construction is the correct
//! behaviour (the server cannot serve notifications without a working HTTP
//! client). The production path ([`build_notifier`]) takes a pre-built
//! `&reqwest::Client` (built once at boot with the SSRF guard wired in) and
//! forwards a clone to each transport's `new_with_client`, so no
//! `Client::builder()` runs in steady state. The workspace denies
//! `expect_used` elsewhere to keep hot paths panic-free; this module is the
//! documented exception for the deprecated test-only constructors.
#![allow(clippy::expect_used)]

pub mod common;
pub mod discord;
pub mod email;
pub mod google_chat;
pub mod msteams;
pub mod ntfy;
pub mod pagerduty;
pub mod pushover;
pub mod slack;
pub mod sms;
pub mod telegram;
pub mod webhook;
pub mod whatsapp;

use async_trait::async_trait;
use statuscore::domain::ChannelConfig;
use statuscore::domain::{Incident, IncidentSeverity};
use statuscore::error::Result;

use crate::notifier::discord::DiscordNotifier;
use crate::notifier::google_chat::GoogleChatNotifier;
use crate::notifier::msteams::MsTeamsNotifier;
use crate::notifier::ntfy::NtfyNotifier;
use crate::notifier::pagerduty::PagerDutyNotifier;
use crate::notifier::pushover::PushoverNotifier;
use crate::notifier::slack::SlackNotifier;
use crate::notifier::sms::SmsNotifier;
use crate::notifier::telegram::TelegramNotifier;
use crate::notifier::whatsapp::WhatsAppNotifier;

/// A notification channel. Implementations deliver a rendered message to a
/// single transport (Slack, Discord, email, webhook, …).
///
/// # Method precedence
///
/// [`Notifier::notify_incident`] is the **production path**: it carries the
/// full structured incident context (severity, reason, component, timing)
/// so transports with a richer payload shape (e.g. PagerDuty Events API v2)
/// can map it onto their native envelope.
///
/// [`Notifier::send`] exists for backwards compatibility and testing: simple
/// text-only transports implement `send` and inherit the default
/// `notify_incident` (which formats the notice and delegates to `send`).
/// New production code should call `notify_incident` directly.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Deliver a pre-rendered plain-text message. Kept for backwards
    /// compatibility and text-only tests; production callers should prefer
    /// [`Self::notify_incident`].
    async fn send(&self, message: &str) -> Result<()>;

    /// Deliver a structured incident notice. The default implementation
    /// formats the notice into a plain-text message and delegates to
    /// [`Self::send`]; transports with a richer payload shape (e.g.
    /// PagerDuty Events API v2) override this.
    async fn notify_incident(&self, notice: &IncidentNotice<'_>) -> Result<()> {
        let message = format_notice_message(notice);
        self.send(&message).await
    }
}

/// Why a notification is being sent. Drives wording and (for PagerDuty)
/// the event action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeReason {
    /// A new incident was opened.
    Opened,
    /// The incident was resolved.
    Resolved,
    /// A previously resolved incident was reopened.
    Reopened,
    /// The incident was escalated to a higher urgency or target.
    Escalated,
}

impl NoticeReason {
    /// Stable lowercase word for this reason, used in message rendering.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Resolved => "resolved",
            Self::Reopened => "reopened",
            Self::Escalated => "escalated",
        }
    }
}

/// A structured incident notification. Carries the incident being reported,
/// the reason this delivery is being made, and an optional component name
/// for message context.
#[derive(Debug, Clone)]
pub struct IncidentNotice<'a> {
    /// The incident being reported.
    pub incident: &'a Incident,
    /// Why this delivery is being made.
    pub reason: NoticeReason,
    /// Human-readable component name for message context, if known.
    pub component_name: Option<&'a str>,
}

/// Render an [`IncidentNotice`] into a plain-text message. Used by the
/// default [`Notifier::notify_incident`] implementation and by transports
/// that embed the message in a richer envelope (e.g. PagerDuty).
pub fn format_notice_message(notice: &IncidentNotice<'_>) -> String {
    use std::fmt::Write as _;
    let inc = notice.incident;
    let mut s = String::new();
    let severity = match inc.severity {
        IncidentSeverity::Minor => "MINOR",
        IncidentSeverity::Major => "MAJOR",
        IncidentSeverity::Critical => "CRITICAL",
        // `IncidentSeverity` is `#[non_exhaustive]`: render unknown future
        // variants as a visible sentinel rather than panicking the dispatcher.
        _ => "UNKNOWN",
    };
    let _ = writeln!(s, "[{severity}] incident {}", notice.reason.as_str());
    if let Some(name) = notice.component_name {
        let _ = writeln!(s, "Component: {name}");
    }
    if let Some(title) = &inc.public_title {
        let _ = writeln!(s, "Title: {title}");
    }
    if let Some(desc) = &inc.public_description {
        let _ = writeln!(s, "Description: {desc}");
    }
    let _ = writeln!(s, "Started: {}", inc.started_at);
    if let Some(end) = inc.ended_at {
        let _ = writeln!(s, "Ended: {end}");
    } else {
        let _ = writeln!(s, "Status: ongoing");
    }
    if let Some(dur) = inc.duration_secs {
        let _ = writeln!(s, "Duration: {dur}s");
    }
    s
}

/// Log-only notifier: emits the message via `tracing` and succeeds. Used in
/// development and as the fallback when no real transport is configured.
#[derive(Debug)]
pub struct LogNotifier;

#[async_trait]
impl Notifier for LogNotifier {
    async fn send(&self, message: &str) -> Result<()> {
        tracing::info!(message, "notification sent (log-only)");
        Ok(())
    }
}

/// Build the appropriate [`Notifier`] for a [`ChannelConfig`]. Transports
/// without a dedicated implementation (operator-managed or out-of-scope
/// kinds) fall back to [`LogNotifier`] so dispatch is total over every
/// channel kind.
///
/// `client` is the SSRF-safe outbound HTTP client built once at boot (see
/// `crate::http_client::outbound`). It is cloned per transport —
/// `reqwest::Client` is internally `Arc`'d, so the clone is cheap and
/// shares the connection pool. Each transport's `new_with_client` consumes
/// the clone; the deprecated `new()` constructors (self-built client, no
/// SSRF guard) are kept only for tests.
///
/// `TelegramApp` is operator-managed: delivery uses a central bot token
/// the operator configures out-of-band, not a per-channel secret. Until
/// that operator-bot infrastructure is wired, it falls back to
/// [`LogNotifier`]; the per-channel `Telegram` (BYO bot token) is fully
/// implemented. `WhatsAppApp` (operator-managed WhatsApp) is the same
/// story. `Email` is handled separately via the shared `EmailSender`
/// (see `bin/status-server/src/incident_writer/channel_dispatch.rs`).
pub fn build_notifier(
    config: &ChannelConfig,
    client: &reqwest::Client,
) -> Result<Box<dyn Notifier>> {
    let client = client.clone();
    let notifier: Box<dyn Notifier> = match config {
        ChannelConfig::Webhook(c) => {
            Box::new(webhook::WebhookNotifier::new_with_client(c.url.clone(), client))
        }
        ChannelConfig::Slack(c) => Box::new(SlackNotifier::new_with_client(c.clone(), client)),
        ChannelConfig::Telegram(c) => {
            Box::new(TelegramNotifier::new_with_client(c.clone(), client))
        }
        ChannelConfig::Pushover(c) => {
            Box::new(PushoverNotifier::new_with_client(c.clone(), client))
        }
        ChannelConfig::Sms(c) => Box::new(SmsNotifier::new_with_client(c.clone(), client)),
        ChannelConfig::WhatsApp(c) => {
            Box::new(WhatsAppNotifier::new_with_client(c.clone(), client))
        }
        // Operator-managed transports: delivery uses a central operator
        // credential, not a per-channel secret. The per-channel config
        // only carries the destination (chat_id / phone). Wiring the
        // operator-bot infrastructure is future work; until then these
        // fall back to LogNotifier so dispatch stays total.
        ChannelConfig::TelegramApp(_) | ChannelConfig::WhatsAppApp(_) | ChannelConfig::Email(_) => {
            Box::new(LogNotifier)
        }
        ChannelConfig::Discord(c) => Box::new(DiscordNotifier::new_with_client(c.clone(), client)),
        ChannelConfig::MsTeams(c) => Box::new(MsTeamsNotifier::new_with_client(c.clone(), client)),
        ChannelConfig::GoogleChat(c) => {
            Box::new(GoogleChatNotifier::new_with_client(c.clone(), client))
        }
        ChannelConfig::PagerDuty(c) => {
            Box::new(PagerDutyNotifier::new_with_client(c.clone(), client))
        }
        ChannelConfig::Ntfy(c) => Box::new(NtfyNotifier::new_with_client(c.clone(), client)),
        // `ChannelConfig` is `#[non_exhaustive]`: a future variant added
        // upstream must not break dispatch. Fall back to `LogNotifier` so
        // delivery stays total (same rationale as the operator-managed
        // transports above).
        _ => Box::new(LogNotifier),
    };
    Ok(notifier)
}

/// Truncate `s` to `max_bytes` on a UTF-8 char boundary, appending `…` when
/// truncated. Shared by transports whose upstream caps by bytes (e.g. ntfy's
/// 4096-byte limit). Inlined here so HTTP-outbound error summarisation does
/// not depend on a notifier implementation.
pub(crate) fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let budget = max_bytes.saturating_sub('…'.len_utf8());
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if i + c.len_utf8() > budget {
            break;
        }
        end = i + c.len_utf8();
    }
    let mut out = s[..end].to_string();
    out.push('…');
    out
}
