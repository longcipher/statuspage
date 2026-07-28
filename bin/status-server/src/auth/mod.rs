//! Auth subsystem: session + API token + magic-link + CSRF.
//!
//! Single-tenant self-hosted: no org/membership. The first user is created
//! via the bootstrap endpoint (magic link to a configured email); subsequent
//! logins use magic-link or (optionally) OAuth GitHub. API tokens are
//! Bearer-auth for CLI/automation. CSRF is enforced on browser mutations
//! via a custom header (`X-Requested-With`).

pub mod middleware;
pub mod routes;
pub mod service;

pub use middleware::RequireAuth;
pub use routes::routes;
pub use service::AuthService;
