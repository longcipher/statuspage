//! API token domain types for programmatic (Bearer) auth.
//!
//! Token format: `sm_live_` + 32 random bytes base64url-no-pad (43 chars) =
//! 51 chars total. The DB stores an argon2id hash (not the raw token) and a
//! 16-char prefix for lookup narrowing. The prefix is a non-unique index —
//! argon2 verify distinguishes candidates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::UserId;

/// The visible prefix that identifies a StatusPage API token.
pub const TOKEN_PREFIX: &str = "sm_live_";

/// Default length of the prefix stored for lookup narrowing. 16 chars =
/// `sm_live_` (8) + 8 random chars = ~48 bits of entropy in the prefix.
pub const DEFAULT_PREFIX_VISIBLE_CHARS: usize = 16;

/// Maximum token expiry in days (advisory, enforced at creation).
pub const MAX_EXPIRY_DAYS: u32 = 365;

/// A token row projected from the `api_tokens` table. The raw token is
/// never stored — `token_hash` is an argon2id PHC string.
#[derive(Debug, Clone)]
pub struct ApiTokenRow {
    pub id: Uuid,
    pub user_id: UserId,
    pub name: String,
    /// Argon2id PHC string — verified via `token_hash::verify(raw, &hash)`.
    pub token_hash: String,
    /// First N chars of the raw token (non-unique index for lookup).
    pub token_prefix: String,
    pub scopes: ScopeSet,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// `None` = never expires.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A token with only the publicly-safe fields (no hash). Returned by
/// list/get handlers — the raw token is unrecoverable.
#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenInfo {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: ScopeSet,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<ApiTokenRow> for ApiTokenInfo {
    fn from(r: ApiTokenRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            token_prefix: r.token_prefix,
            scopes: r.scopes,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            expires_at: r.expires_at,
        }
    }
}

/// Result of creating a token: the raw value (shown once) + the row.
#[derive(Debug, Clone)]
pub struct CreatedApiToken {
    pub raw_token: String,
    pub info: ApiTokenInfo,
}

/// Outcome of looking up a token by its raw value.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApiTokenLookupOutcome {
    Active(ApiTokenRow),
    Invalid,
}

/// Payload to create a new API token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewApiToken {
    pub name: String,
    pub scopes: Option<ScopeSet>,
    /// Expiry in days from now. `None` = no expiry.
    pub expires_in_days: Option<u32>,
}

/// Update payload for an API token (rename only — scopes/expiry immutable
/// after creation; rotate by delete + create).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenUpdate {
    pub name: String,
}

/// Generate a new raw API token: `sm_live_` + 32 random bytes base64url.
pub fn generate_raw_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    format!("{TOKEN_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Slice the first `prefix_len` chars of a raw token for index lookup.
pub fn slice_prefix(raw: &str, prefix_len: usize) -> &str {
    let n = prefix_len.min(raw.len());
    &raw[..n]
}

// ── Scopes ─────────────────────────────────────────────────────────────

/// A single permission scope in `resource:action` format. `write` implies
/// `read`; `full_access` is the superset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Scope {
    TargetsRead,
    TargetsWrite,
    TargetsDelete,
    TargetsExecute,
    ChannelsRead,
    ChannelsWrite,
    ChannelsDelete,
    IncidentsRead,
    IncidentsWrite,
    OncallRead,
    OncallWrite,
    MaintenanceRead,
    MaintenanceWrite,
    MaintenanceDelete,
    StatusPageRead,
    StatusPageWrite,
    StatusPageDelete,
    VariablesRead,
    VariablesWrite,
    /// Superset — grants every scope.
    FullAccess,
}

impl Scope {
    pub const ALL: &'static [Self] = &[
        Self::TargetsRead,
        Self::TargetsWrite,
        Self::TargetsDelete,
        Self::TargetsExecute,
        Self::ChannelsRead,
        Self::ChannelsWrite,
        Self::ChannelsDelete,
        Self::IncidentsRead,
        Self::IncidentsWrite,
        Self::OncallRead,
        Self::OncallWrite,
        Self::MaintenanceRead,
        Self::MaintenanceWrite,
        Self::MaintenanceDelete,
        Self::StatusPageRead,
        Self::StatusPageWrite,
        Self::StatusPageDelete,
        Self::VariablesRead,
        Self::VariablesWrite,
        Self::FullAccess,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetsRead => "targets:read",
            Self::TargetsWrite => "targets:write",
            Self::TargetsDelete => "targets:delete",
            Self::TargetsExecute => "targets:execute",
            Self::ChannelsRead => "channels:read",
            Self::ChannelsWrite => "channels:write",
            Self::ChannelsDelete => "channels:delete",
            Self::IncidentsRead => "incidents:read",
            Self::IncidentsWrite => "incidents:write",
            Self::OncallRead => "oncall:read",
            Self::OncallWrite => "oncall:write",
            Self::MaintenanceRead => "maintenance:read",
            Self::MaintenanceWrite => "maintenance:write",
            Self::MaintenanceDelete => "maintenance:delete",
            Self::StatusPageRead => "status_page:read",
            Self::StatusPageWrite => "status_page:write",
            Self::StatusPageDelete => "status_page:delete",
            Self::VariablesRead => "variables:read",
            Self::VariablesWrite => "variables:write",
            Self::FullAccess => "full_access",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        Some(match s {
            "targets:read" => Self::TargetsRead,
            "targets:write" => Self::TargetsWrite,
            "targets:delete" => Self::TargetsDelete,
            "targets:execute" => Self::TargetsExecute,
            "channels:read" => Self::ChannelsRead,
            "channels:write" => Self::ChannelsWrite,
            "channels:delete" => Self::ChannelsDelete,
            "incidents:read" => Self::IncidentsRead,
            "incidents:write" => Self::IncidentsWrite,
            "oncall:read" => Self::OncallRead,
            "oncall:write" => Self::OncallWrite,
            "maintenance:read" => Self::MaintenanceRead,
            "maintenance:write" => Self::MaintenanceWrite,
            "maintenance:delete" => Self::MaintenanceDelete,
            "status_page:read" => Self::StatusPageRead,
            "status_page:write" => Self::StatusPageWrite,
            "status_page:delete" => Self::StatusPageDelete,
            "variables:read" => Self::VariablesRead,
            "variables:write" => Self::VariablesWrite,
            "full_access" => Self::FullAccess,
            _ => return None,
        })
    }
}

/// A set of scopes granted to a token. Serialized as a JSON array of
/// scope strings. `FullAccess` implies all scopes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeSet(pub Vec<Scope>);

impl ScopeSet {
    /// Create a scope set with just `full_access`.
    pub fn full_access() -> Self {
        Self(vec![Scope::FullAccess])
    }

    /// Check whether the set grants the requested scope. `FullAccess`
    /// implies everything. `write` implies `read` for the same resource.
    pub fn grants(&self, required: Scope) -> bool {
        if self.0.contains(&Scope::FullAccess) {
            return true;
        }
        if self.0.contains(&required) {
            return true;
        }
        // write implies read for the same resource
        let write_scope = match required {
            Scope::TargetsRead => Some(Scope::TargetsWrite),
            Scope::ChannelsRead => Some(Scope::ChannelsWrite),
            Scope::IncidentsRead => Some(Scope::IncidentsWrite),
            Scope::OncallRead => Some(Scope::OncallWrite),
            Scope::MaintenanceRead => Some(Scope::MaintenanceWrite),
            Scope::StatusPageRead => Some(Scope::StatusPageWrite),
            Scope::VariablesRead => Some(Scope::VariablesWrite),
            _ => None,
        };
        write_scope.is_some_and(|w| self.0.contains(&w))
    }

    /// Serialize to a JSON string for DB storage.
    pub fn to_json(&self) -> String {
        let strs: Vec<&str> = self.0.iter().map(|s| s.as_str()).collect();
        serde_json::to_string(&strs).unwrap_or_else(|_| "[]".to_string())
    }

    /// Deserialize from a JSON string (array of scope strings).
    pub fn from_json(s: &str) -> Self {
        let strs: Vec<String> = serde_json::from_str(s).unwrap_or_default();
        Self(strs.iter().filter_map(|s| Scope::parse_str(s)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_set_full_access_grants_everything() {
        let set = ScopeSet::full_access();
        for s in Scope::ALL {
            assert!(set.grants(*s), "full_access should grant {:?}", s);
        }
    }

    #[test]
    fn scope_set_write_implies_read() {
        let set = ScopeSet(vec![Scope::TargetsWrite]);
        assert!(set.grants(Scope::TargetsRead));
        assert!(set.grants(Scope::TargetsWrite));
        assert!(!set.grants(Scope::TargetsDelete));
    }

    #[test]
    fn scope_set_json_round_trip() {
        let set = ScopeSet(vec![Scope::TargetsRead, Scope::IncidentsWrite]);
        let json = set.to_json();
        let back = ScopeSet::from_json(&json);
        assert_eq!(set, back);
    }

    #[test]
    fn token_format_has_correct_prefix() {
        let raw = generate_raw_token();
        assert!(raw.starts_with(TOKEN_PREFIX));
        assert!(raw.len() > TOKEN_PREFIX.len() + 16);
    }
}
