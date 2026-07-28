use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::preferences::TimeFormat;

/// Strongly-typed user id. Wrapping `Uuid` prevents accidentally passing a
/// `UserId` where an `OrgId` is expected (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = String, format = "uuid")]
pub struct UserId(pub Uuid);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A registered user. Single-tenant: no org/membership fields.
///
/// Auth credentials live in separate tables (`oauth_identities`,
/// `magic_link_tokens`); the `User` row itself carries only profile +
/// preference data. `email_verified_at` is set when an OAuth provider
/// attests a verified email or when a magic-link login succeeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub display_name: Option<String>,
    /// When the user's email was verified (OAuth attestation or magic-link
    /// login). `None` for users created without a verified email.
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Last activity timestamp (session touch, debounced 60s). Used for
    /// "recently active" display and inactive-user cleanup.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// UI theme preference persisted to the backend so it roams across
    /// browsers. The frontend also stores a local copy for instant load.
    pub theme: AppTheme,
    /// 12h/24h/auto timestamp rendering preference.
    pub time_format: TimeFormat,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Soft-delete tombstone. Soft-deleted users can be recovered within
    /// the retention window; after that a purge job hard-deletes the row.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Payload to create a new user (OAuth callback or magic-link first login).
#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub display_name: Option<String>,
    pub email_verified: bool,
}

/// Update fields for a user profile. All fields optional — `None` means
/// "don't change".
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UserUpdate {
    pub display_name: Option<String>,
    pub theme: Option<AppTheme>,
    pub time_format: Option<TimeFormat>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AppTheme {
    #[default]
    Default,
    Terminal,
    Winter,
    Dark,
    Night,
    Dim,
    Nord,
    Dracula,
    Corporate,
    Light,
    Cupcake,
    Cyberpunk,
    Synthwave,
}

impl AppTheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Terminal => "terminal",
            Self::Winter => "winter",
            Self::Dark => "dark",
            Self::Night => "night",
            Self::Dim => "dim",
            Self::Nord => "nord",
            Self::Dracula => "dracula",
            Self::Corporate => "corporate",
            Self::Light => "light",
            Self::Cupcake => "cupcake",
            Self::Cyberpunk => "cyberpunk",
            Self::Synthwave => "synthwave",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "default" => Self::Default,
            "terminal" => Self::Terminal,
            "winter" => Self::Winter,
            "dark" => Self::Dark,
            "night" => Self::Night,
            "dim" => Self::Dim,
            "nord" => Self::Nord,
            "dracula" => Self::Dracula,
            "corporate" => Self::Corporate,
            "light" => Self::Light,
            "cupcake" => Self::Cupcake,
            "cyberpunk" => Self::Cyberpunk,
            "synthwave" => Self::Synthwave,
            other => {
                tracing::warn!(value = other, "unknown user.theme in DB, falling back to default");
                Self::Default
            }
        }
    }

    pub const ALL: &'static [&'static str] = &[
        "default",
        "terminal",
        "winter",
        "dark",
        "night",
        "dim",
        "nord",
        "dracula",
        "corporate",
        "light",
        "cupcake",
        "cyberpunk",
        "synthwave",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_theme_from_db_round_trips_known_values() {
        for s in AppTheme::ALL {
            assert_eq!(AppTheme::from_db(s).as_str(), *s);
        }
        assert_eq!(AppTheme::from_db("garbage").as_str(), "default");
    }
}
