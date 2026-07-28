//! API response and request types.
//!
//! Most types are re-exported from `statuscore::domain` so the frontend
//! deserialises the exact JSON shapes the axum backend serialises. The
//! exceptions are:
//!
//! * `NewStatusPage` / `StatusPageUpdate` — the domain versions only derive
//!   `Deserialize` (the backend only reads them). The frontend needs to
//!   serialise them too when sending `POST` / `PATCH` bodies, so local
//!   mirrors with both derives are defined here. Their field layout and
//!   `serde` attributes match the domain versions exactly, keeping the wire
//!   shape identical.
//! * `NewIncidentUpdateBody` — mirrors the private request-body struct in
//!   `bin/status-server/src/api/mod.rs`, which is never re-exported from
//!   `statuscore::domain`.
//!
//! `LatencyPoint` is a local alias matching the backend's `Vec<(String, f64)>`
//! history payload (ISO-8601 timestamp + duration_ms).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use statuscore::domain::{IncidentStatusPhase, PublicOrgBranding};
use uuid::Uuid;

// Response + shared request types — re-exported from the domain crate so the
// frontend deserialises the exact JSON shapes the axum backend serialises.
// `NewTarget` and `TargetUpdate` already derive both `Serialize` and
// `Deserialize` in the domain, so they can be sent as request bodies.
pub use statuscore::domain::{Incident, NewTarget, StatusPage, Target, TargetUpdate};

/// `(timestamp_label, duration_ms)` for the latency chart. The backend returns
/// these as a `Vec<(String, f64)>` sorted ascending by timestamp.
pub type LatencyPoint = (String, f64);

/// Request body for `POST /api/v1/status-pages`.
///
/// Local mirror of `statuscore::domain::NewStatusPage` (which only derives
/// `Deserialize`). Field layout and `serde` attributes are identical so the
/// wire shape matches the backend's `Json<NewStatusPage>` extractor.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewStatusPage {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
}

/// Request body for `PATCH /api/v1/status-pages/:id`.
///
/// Local mirror of `statuscore::domain::StatusPageUpdate` (which only derives
/// `Deserialize`). Field layout and `serde` attributes are identical so the
/// wire shape matches the backend's `Json<StatusPageUpdate>` extractor.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StatusPageUpdate {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub enabled: Option<bool>,
    pub branding: Option<PublicOrgBranding>,
}

/// Request body for `POST /api/v1/incidents/:id/updates`.
///
/// Mirrors the private `NewIncidentUpdateBody` struct in
/// `bin/status-server/src/api/mod.rs`: `phase` + `message` are required,
/// `posted_at` is optional (the server defaults it to `Utc::now()` when
/// omitted). Defined locally because the backend never re-exports this
/// struct from `statuscore::domain`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewIncidentUpdateBody {
    pub phase: IncidentStatusPhase,
    pub message: String,
    #[serde(default)]
    pub posted_at: Option<DateTime<Utc>>,
}

// ── Public status page types ───────────────────────────────────────────────
//
// Re-exported from `statuscore::domain::public` so the frontend deserialises
// the exact JSON shapes the backend's `/api/public/v1/*` endpoints emit.
// `public_status_page.rs` imports the remaining public types directly from
// `statuscore::domain::public`, so only the types referenced through
// `crate::api::types` (by `client.rs`) are re-exported here.
pub use statuscore::domain::public::PublicStatusPage;

// ── Auth types ────────────────────────────────────────────────────────────
//
// Mirrors the JSON shapes returned by `/api/v1/auth/*` endpoints. The
// backend's `public_user_view` / `session_view` helpers produce these
// shapes; they are not re-exported from `statuscore::domain`, so the
// frontend defines local mirrors with `Deserialize` only (the frontend
// never sends these back — it only reads them from login / session
// responses).

/// Public user view returned by auth endpoints.
///
/// Fields are deserialised from the API response so the shape stays in
/// sync with the backend; not every field is read by the frontend yet
/// (e.g. `theme` / `time_format` will be wired to the settings page).
#[derive(Debug, Clone, Deserialize)]
#[expect(dead_code, reason = "API response shape; fields populated by serde")]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub theme: String,
    pub time_format: String,
}

/// `GET /api/v1/auth/bootstrap` response.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapStatus {
    pub bootstrap_needed: bool,
}

/// Response from bootstrap create + magic-link verify: `{ user, session }`.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthSession {
    pub user: AuthUser,
}

// ── Structured API error types ─────────────────────────────────────────────

/// Structured API error from the backend's JSON error response.
#[expect(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiErrorResponse {
    pub error: ApiErrorBody,
}

/// The error body inside an API error response.
#[expect(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

impl std::fmt::Display for ApiErrorBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}
