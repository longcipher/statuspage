//! OAuth domain types for GitHub/Google login.
//!
//! The OAuth flow is three-phase:
//! - Phase 0: generate `state`, persist its SHA-256 hash, redirect to
//!   provider authorize URL.
//! - Phase A: callback — atomically consume `state`, exchange `code` for
//!   an access token, fetch user info from provider.
//! - Phase B: find-or-create user by `(provider, provider_user_id)` or by
//!   verified email, link identity, create session.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::UserId;

/// Supported OAuth login providers. Slack/Discord are "connect"-only
/// (channel attach) and not included here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OauthProvider {
    Github,
    Google,
}

impl OauthProvider {
    pub const ALL: &'static [Self] = &[Self::Github, Self::Google];

    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Google => "google",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        Some(match s {
            "github" => Self::Github,
            "google" => Self::Google,
            _ => return None,
        })
    }
}

/// Identity fetched from the OAuth provider after token exchange. The
/// `verified_email` is only `Some` when the provider explicitly attests
/// verification (GitHub: `primary && verified`; Google: `email_verified`).
#[derive(Debug, Clone)]
pub struct RemoteIdentity {
    pub provider: OauthProvider,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    /// Only set when the provider attests email verification.
    pub verified_email: Option<String>,
    pub display_name: Option<String>,
}

/// A row in the `oauth_identities` table linking a user to a provider
/// identity. Primary key: `(provider, provider_user_id)`.
#[derive(Debug, Clone)]
pub struct OauthIdentity {
    pub user_id: UserId,
    pub provider: OauthProvider,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login_at: DateTime<Utc>,
}

/// A consumed OAuth state row (atomic DELETE-RETURNING).
#[derive(Debug, Clone)]
pub struct ConsumedOauthState {
    pub provider: OauthProvider,
    pub redirect_after: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Generate a new random OAuth state parameter: 32 bytes base64url.
pub fn generate_state() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute `sha256_hex(state)` — the lookup key stored in the DB.
pub fn hash_state(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

/// Normalize an email for lookup: trim + lowercase. Storage is
/// case-insensitive in spirit (DuckDB lacks CITEXT, so we normalize on
/// write and on read).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
