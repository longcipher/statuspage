//! Session domain types for cookie-based browser auth.
//!
//! The session cookie value is 32 random bytes base64url-encoded (43 chars).
//! The DB stores only `sha256_hex(cookie_value)` as `id_hash` — a table leak
//! yields hashes, not replayable tokens. Double timeout: absolute (from
//! creation) + idle (from last use).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::UserId;

/// A session row projected from the `sessions` table. The cookie value
/// itself is never stored — `id_hash` is `sha256_hex` of it.
#[derive(Debug, Clone)]
pub struct SessionRow {
    /// `sha256_hex(cookie_value)` — primary key in the sessions table.
    pub id_hash: String,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Salted SHA-256 of the client IP at creation (for anomaly display).
    pub ip_hash: Option<String>,
    /// Salted SHA-256 of the User-Agent at creation.
    pub user_agent_hash: Option<String>,
}

/// Outcome of looking up a session by cookie value.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionLookupOutcome {
    /// Session is valid and within both timeouts.
    Active(SessionRow),
    /// Session exists but exceeded absolute or idle timeout. The caller
    /// should delete the row and clear the browser cookie.
    Expired,
    /// No row matched the hash — the cookie value is bogus or already
    /// destroyed.
    Missing,
}

/// A new session about to be persisted. The raw cookie value is returned
/// to the caller so it can set the browser cookie; only the hash is stored.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub user_id: UserId,
    pub expires_at: DateTime<Utc>,
    pub ip_hash: Option<String>,
    pub user_agent_hash: Option<String>,
}

/// A session list entry for the "active sessions" account page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    /// The `id_hash` — used as the row identifier for revocation. Safe to
    /// expose to the owning user (it's already a hash).
    pub id_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_hash: Option<String>,
    pub user_agent_hash: Option<String>,
    /// Whether this entry corresponds to the cookie on the current request.
    pub is_current: bool,
}

/// Result of creating a session: the raw cookie value (returned once so the
/// caller can `Set-Cookie`) + the row that was persisted.
#[derive(Debug, Clone)]
pub struct CreatedSession {
    pub cookie_value: String,
    pub row: SessionRow,
}

/// Generate a new random session cookie value: 32 bytes base64url-no-pad.
pub fn generate_cookie_value() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute `sha256_hex(cookie_value)` — the lookup key stored in the DB.
pub fn hash_cookie_value(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

/// Helper to create a UUIDv7 for session-related rows when an explicit id
/// is needed (login audit, etc.).
pub fn now_v7() -> Uuid {
    Uuid::now_v7()
}
