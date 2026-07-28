//! Magic-link domain types for email-based passwordless login.
//!
//! Token format: 32 random bytes base64url-no-pad (43 chars). The DB stores
//! an argon2id hash + a 16-char prefix for lookup narrowing. Tokens expire
//! after `magic_link.expiry_minutes` (default 15). Consumption is atomic:
//! `UPDATE ... SET used_at = now() WHERE id = ? AND used_at IS NULL`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A magic-link row projected from the `magic_link_tokens` table.
#[derive(Debug, Clone)]
pub struct MagicLinkRow {
    pub id: Uuid,
    pub email: String,
    /// Argon2id PHC string.
    pub token_hash: String,
    /// First 16 chars of the raw token (index for lookup).
    pub token_prefix: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// `None` = unused; `Some(ts)` = consumed at that time.
    pub used_at: Option<DateTime<Utc>>,
    pub ip_hash: Option<String>,
    /// Same-origin path to redirect to after login (open-redirect-safe).
    pub redirect_after: Option<String>,
}

/// Result of creating a magic link: the raw token (emailed once) + the row.
#[derive(Debug, Clone)]
pub struct CreatedMagicLink {
    pub raw_token: String,
    pub row: MagicLinkRow,
}

/// Outcome of consuming a magic-link token.
#[derive(Debug)]
#[non_exhaustive]
pub enum MagicLinkConsumeOutcome {
    /// Token was valid and atomically marked used. Returns the row so the
    /// caller can log in the matching user.
    Consumed(MagicLinkRow),
    /// Token not found, already used, or expired.
    Invalid,
}

/// Generate a new raw magic-link token: 32 bytes base64url-no-pad.
pub fn generate_raw_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Slice the first `prefix_len` chars for index lookup.
pub fn slice_prefix(raw: &str, prefix_len: usize) -> &str {
    let n = prefix_len.min(raw.len());
    &raw[..n]
}
