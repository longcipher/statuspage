//! Shared serde helpers for PATCH-style update semantics.

use serde::{Deserialize, Deserializer};

/// Deserialize a `Option<Option<T>>` to distinguish three PATCH states:
/// - `None` (field absent) → `None` (no change)
/// - `Some(null)` → `Some(None)` (clear the field)
/// - `Some(value)` → `Some(Some(value))` (set the field)
pub fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer)
}
