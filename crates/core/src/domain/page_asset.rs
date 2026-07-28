//! Per-status-page asset slots. One enum owns the slug ↔ slot mapping and the
//! per-slot upload policy (allowed MIME types + max byte size), so adding a
//! slot is a one-spot change.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A named asset attached to a status page. Reserved future slots:
/// `Background`, `Favicon`, `OgImage`, `Font`, `CustomCss` — add the variant,
/// its `as_str`/`parse` arm, and a `policy` arm to wire one.
///
/// Serializes as the lowercase slot slug (`"logo"`) so the JSON shape matches
/// the URL path segment used by the upload/download endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AssetSlot {
    Logo,
}

/// Per-slot upload constraints. The configurable hook for "what may this slot
/// hold" — handlers gate uploads on it before the bytes ever reach the store.
#[derive(Debug, Clone)]
pub struct SlotPolicy {
    pub allowed_content_types: &'static [&'static str],
    pub max_byte_size: u64,
}

impl AssetSlot {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logo => "logo",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "logo" => Some(Self::Logo),
            _ => None,
        }
    }

    pub const fn policy(self) -> SlotPolicy {
        match self {
            Self::Logo => SlotPolicy {
                allowed_content_types: &["image/png", "image/jpeg", "image/webp"],
                // Mirrors the default `max_logo_size_bytes` (1 MiB).
                max_byte_size: 1_048_576,
            },
        }
    }
}

/// A stored asset row. The `data` blob is the raw file bytes; `hash` is a
/// sha256 hex of the data, used as a cache-buster in the public logo URL and
/// surfaced in `PublicOrgBranding.logo_hash` so the frontend can detect
/// changes without re-fetching the blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageAsset {
    pub status_page_id: Uuid,
    pub slot: AssetSlot,
    pub content_type: String,
    /// Raw asset bytes. Stored as a BLOB in DuckDB. Kept small by the
    /// per-slot `max_byte_size` policy (1 MiB for the logo).
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// `sha256_hex(data)` — cache-buster and integrity check.
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Serialize/deserialize `Vec<u8>` as a base64 string in JSON so the asset
/// can round-trip through the API without the caller handling raw bytes.
mod serde_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        B64.encode(data).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_str_round_trips() {
        assert_eq!(AssetSlot::parse(AssetSlot::Logo.as_str()), Some(AssetSlot::Logo));
        assert_eq!(AssetSlot::parse("nope"), None);
    }

    #[test]
    fn logo_policy_allows_images() {
        let p = AssetSlot::Logo.policy();
        assert!(p.allowed_content_types.contains(&"image/png"));
        assert!(p.max_byte_size > 0);
    }
}
