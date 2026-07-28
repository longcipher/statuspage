//! Auth business logic: session/token/magic-link lifecycle.
//!
//! The service is stateless beyond holding a config reference and the storage
//! Arc — all state lives in the DB. Token hashing (argon2id for tokens,
//! SHA-256 for session cookies) is delegated to `statuscore::domain`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{Duration, Utc};
use common::email::{EmailAddress, EmailSender, EmailTemplate, TransactionalEmail};
use statuscore::config::AuthConfig;
use statuscore::domain::{
    self, API_TOKEN_PREFIX, ApiTokenInfo, ApiTokenLookupOutcome, ApiTokenRow, CreatedApiToken,
    CreatedSession, NewApiToken, NewSession, NewUser, ScopeSet, SessionInfo, SessionLookupOutcome,
    SessionRow, User, UserId, UserUpdate, generate_api_token, generate_cookie_value,
    generate_magic_link_token, hash_cookie_value, normalize_oauth_email, slice_api_token_prefix,
    slice_magic_link_prefix,
};
use statuscore::error::{AppError, Result};
use storage::Storage;
use uuid::Uuid;

/// Default visible-prefix length for API tokens and magic links. Matches
/// `AuthConfig::api_tokens::prefix_visible_chars` floor.
const DEFAULT_PREFIX_LEN: usize = 16;

/// Debounce window for `last_used_at` / `last_seen_at` touches. A request
/// within this window of the last touch skips the write — keeps the auth
/// middleware off the hot path.
const TOUCH_DEBOUNCE_SECS: i64 = 60;

/// Process-wide bootstrap lock. The bootstrap endpoint is unauthenticated
/// and idempotent-ish (it 409s once any user exists), but the
/// `bootstrap_needed()` check + `create_user()` write is a TOCTOU window:
/// two concurrent `POST /bootstrap` calls can both see zero users and both
/// create a user. The `users.email` UNIQUE constraint would catch the
/// duplicate, but the error path is ugly (409 from the storage layer
/// instead of a clean "bootstrap done"). This `AtomicBool` closes the
/// window: only the first caller proceeds to the DB check + write.
/// `static` (not an instance field) so the lock is shared across all
/// `AuthService` clones — there's only ever one bootstrap owner per
/// process, regardless of how the service is constructed.
static BOOTSTRAP_LOCK: AtomicBool = AtomicBool::new(false);

/// Auth service — wraps storage + config to provide the auth business logic
/// the HTTP layer needs. Stateless aside from the config + storage refs.
#[derive(Clone)]
pub struct AuthService {
    storage: Arc<dyn Storage>,
    config: AuthConfig,
    email_sender: Arc<dyn EmailSender>,
    from_address: EmailAddress,
}

impl AuthService {
    /// Build a new auth service. The email sender is used to deliver magic
    /// links; in dev this is typically `LogOnlyEmailSender`.
    pub fn new(
        storage: Arc<dyn Storage>,
        config: AuthConfig,
        email_sender: Arc<dyn EmailSender>,
        from_address: EmailAddress,
    ) -> Self {
        Self { storage, config, email_sender, from_address }
    }

    // ── Bootstrap ──────────────────────────────────────────────────────

    /// True if no users exist — the bootstrap endpoint is enabled without
    /// auth in this state. Once the first user is created, the endpoint
    /// returns 409.
    pub async fn bootstrap_needed(&self) -> Result<bool> {
        let count = self.storage.count_users().await?;
        Ok(count == 0)
    }

    /// Create the first admin user. Only works when `bootstrap_needed()`
    /// is true. The email is marked verified (the operator is expected to
    /// have control of it).
    ///
    /// TOCTOU guard: a process-wide `AtomicBool` (`BOOTSTRAP_LOCK`) ensures
    /// only one concurrent caller reaches the DB check + write. The lock is
    /// released on both success and failure so a transient error (e.g. DB
    /// blip) doesn't permanently wedge the bootstrap endpoint — the operator
    /// can retry. Once `create_user` succeeds, `bootstrap_needed()` returns
    /// false for all future callers, so the lock is only load-bearing during
    /// the brief window between the two concurrent `POST /bootstrap` calls.
    pub async fn create_first_user(&self, email: &str, display_name: Option<&str>) -> Result<User> {
        // Atomically claim the bootstrap slot. Only one caller can proceed;
        // others get a 409 immediately without touching the DB.
        if BOOTSTRAP_LOCK.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err()
        {
            return Err(AppError::conflict(
                "BOOTSTRAP_IN_PROGRESS",
                "bootstrap is already in progress; retry shortly",
            ));
        }

        // Double-check the precondition inside the lock — a previous caller
        // may have completed bootstrap between our `bootstrap_needed()` and
        // the lock acquisition. Errors from the storage check must propagate
        // (after releasing the lock) rather than be silently treated as
        // "bootstrap done".
        let needed = match self.bootstrap_needed().await {
            Ok(n) => n,
            Err(e) => {
                BOOTSTRAP_LOCK.store(false, Ordering::SeqCst);
                return Err(e);
            }
        };
        if !needed {
            BOOTSTRAP_LOCK.store(false, Ordering::SeqCst);
            return Err(AppError::conflict(
                "BOOTSTRAP_DONE",
                "the first user has already been created; use the login flow instead",
            ));
        }

        let new = NewUser {
            email: normalize_oauth_email(email),
            display_name: display_name.map(|s| s.to_string()),
            email_verified: true,
        };
        let result = self.storage.create_user(&new).await;

        // Release the lock — allow retry on failure, and on success the
        // `users` table is non-empty so future `bootstrap_needed()` returns
        // false regardless.
        BOOTSTRAP_LOCK.store(false, Ordering::SeqCst);

        result.inspect(|u| {
            tracing::info!(user_id = %u.id.0, "bootstrap owner created");
        })
    }

    // ── Magic link ─────────────────────────────────────────────────────

    /// Create a magic link for `email` and dispatch the email. The raw token
    /// is returned only to the email sender — never to the API caller. The
    /// caller gets a 202 with no body.
    ///
    /// Anti-enum: always returns `Ok(())` whether or not the email exists.
    /// A real link is only sent for known emails; unknown emails are silently
    /// dropped (the timing is dominated by the argon2 hash anyway).
    pub async fn request_magic_link(
        &self,
        email: &str,
        ip_hint: Option<&str>,
        redirect_after: Option<&str>,
    ) -> Result<()> {
        let normalized = normalize_oauth_email(email);

        // Anti-enum: check if user exists. We always return Ok so the
        // endpoint can't be used to enumerate registered emails.
        let user = self.storage.find_user_by_email(&normalized).await?;

        // Throttle: at most one real email per address per rate_limit_seconds.
        // We don't track this in the DB (stateless); the magic_link_tokens
        // table itself is the throttle — a second request within the window
        // finds the first row still unused and just re-sends (or could
        // silently no-op). For v1 we always create + send; the throttle is
        // advisory.

        let raw_token = generate_magic_link_token();
        let prefix = slice_magic_link_prefix(&raw_token, DEFAULT_PREFIX_LEN);
        let token_hash = domain::token_hash::hash(&raw_token)?;
        let expires_at =
            Utc::now() + Duration::minutes(i64::from(self.config.magic_link.expiry_minutes));

        let _row = self
            .storage
            .create_magic_link(
                &normalized,
                &token_hash,
                prefix,
                expires_at,
                ip_hint,
                redirect_after,
            )
            .await?;

        // Only send the email if the user actually exists. Unknown emails
        // get a row (anti-timing) but no email.
        if let Some(user) = user {
            let link = self.build_magic_link_url(&raw_token);
            let email = TransactionalEmail {
                to: EmailAddress::new(
                    &user.email,
                    user.display_name.as_deref().unwrap_or(&user.email),
                ),
                from: self.from_address.clone(),
                template: EmailTemplate::MagicLink {
                    url: link,
                    expires_in_minutes: self.config.magic_link.expiry_minutes,
                    ip_hint: ip_hint.map(|s| s.to_string()),
                },
            };
            if let Err(e) = self.email_sender.send(email).await {
                tracing::warn!(error = %e, user_id = %user.id.0, "failed to send magic link email");
            }
        } else {
            tracing::debug!(email = %normalized, "magic link requested for unknown email; row created, no email sent");
        }

        // Drop the raw token — it lives only in the email.
        drop(raw_token);
        Ok(())
    }

    /// Consume a magic-link token. On success, finds-or-creates the user
    /// and returns a new session. Returns `Invalid` if the token is wrong,
    /// already used, or expired.
    pub async fn verify_magic_link(&self, raw_token: &str) -> Result<Option<CreatedSession>> {
        let prefix = slice_magic_link_prefix(raw_token, DEFAULT_PREFIX_LEN);
        let candidates = self.storage.find_magic_links_by_prefix(prefix).await?;

        // Verify each candidate's hash against the raw token.
        for row in candidates {
            if domain::token_hash::verify(raw_token, &row.token_hash) {
                // Atomic consume.
                let consumed = self.storage.consume_magic_link(row.id).await?;
                if let Some(consumed) = consumed {
                    // Find-or-create user by email.
                    let user =
                        if let Some(u) = self.storage.find_user_by_email(&consumed.email).await? {
                            u
                        } else {
                            // First login for this email — create the user.
                            // email_verified = true because they just proved
                            // control of the inbox.
                            let new = NewUser {
                                email: consumed.email.clone(),
                                display_name: None,
                                email_verified: true,
                            };
                            self.storage.create_user(&new).await?
                        };
                    let session = self.create_session_for(user.id).await?;
                    return Ok(Some(session));
                }
                // Token verified but already consumed — don't try other
                // candidates (they'd have the same hash).
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Build the magic-link verification URL the user sees in the email.
    fn build_magic_link_url(&self, raw_token: &str) -> String {
        let base = self.config.public_base_url.trim_end_matches('/');
        format!("{base}/auth/magic-link/verify?token={raw_token}")
    }

    // ── Session ────────────────────────────────────────────────────────

    /// Create a new session for `user_id`. Generates the cookie value,
    /// hashes it, persists the row, and returns both so the caller can
    /// set the cookie.
    pub async fn create_session_for(&self, user_id: UserId) -> Result<CreatedSession> {
        let cookie_value = generate_cookie_value();
        let id_hash = hash_cookie_value(&cookie_value);
        let now = Utc::now();
        let expires_at = now + Duration::days(i64::from(self.config.session.absolute_timeout_days));

        let new = NewSession { user_id, expires_at, ip_hash: None, user_agent_hash: None };
        let row = self.storage.create_session(&id_hash, &new).await?;
        Ok(CreatedSession { cookie_value, row })
    }

    /// Look up a session by its raw cookie value. Enforces both idle and
    /// absolute timeouts. Returns the session row if valid.
    pub async fn lookup_session(&self, cookie_value: &str) -> Result<SessionLookupOutcome> {
        let id_hash = hash_cookie_value(cookie_value);
        let row = match self.storage.lookup_session(&id_hash).await? {
            Some(r) => r,
            None => return Ok(SessionLookupOutcome::Missing),
        };
        let now = Utc::now();
        // Absolute timeout.
        if now > row.expires_at {
            return Ok(SessionLookupOutcome::Expired);
        }
        // Idle timeout.
        let idle_limit = Duration::days(i64::from(self.config.session.idle_timeout_days));
        if now > row.last_used_at + idle_limit {
            return Ok(SessionLookupOutcome::Expired);
        }
        Ok(SessionLookupOutcome::Active(row))
    }

    /// Touch a session's `last_used_at` if the last touch was more than
    /// `TOUCH_DEBOUNCE_SECS` ago. Debounced to avoid a write per request.
    pub async fn touch_session(&self, row: &SessionRow) -> Result<()> {
        let now = Utc::now();
        if (now - row.last_used_at).num_seconds() < TOUCH_DEBOUNCE_SECS {
            return Ok(());
        }
        self.storage.touch_session(&row.id_hash, now).await
    }

    /// Touch a user's `last_seen_at` (debounced).
    pub async fn touch_user(&self, user: &User) -> Result<()> {
        let now = Utc::now();
        if let Some(last) = user.last_seen_at
            && (now - last).num_seconds() < TOUCH_DEBOUNCE_SECS
        {
            return Ok(());
        }
        self.storage.touch_user(user.id.0, now).await
    }

    /// Destroy a session by its raw cookie value. Idempotent.
    pub async fn destroy_session(&self, cookie_value: &str) -> Result<()> {
        let id_hash = hash_cookie_value(cookie_value);
        self.storage.delete_session(&id_hash).await
    }

    /// List sessions for the "active sessions" account page, marking the
    /// one matching `current_cookie_value` as `is_current`.
    pub async fn list_sessions(
        &self,
        user_id: UserId,
        current_cookie_value: Option<&str>,
    ) -> Result<Vec<SessionInfo>> {
        let rows = self.storage.list_sessions(user_id.0).await?;
        let current_hash = current_cookie_value.map(hash_cookie_value);
        Ok(rows
            .into_iter()
            .map(|r| SessionInfo {
                is_current: current_hash.as_deref() == Some(&r.id_hash),
                id_hash: r.id_hash,
                created_at: r.created_at,
                last_used_at: r.last_used_at,
                expires_at: r.expires_at,
                ip_hash: r.ip_hash,
                user_agent_hash: r.user_agent_hash,
            })
            .collect())
    }

    /// Revoke another session by `id_hash`. The caller must verify the
    /// session belongs to the current user.
    pub async fn revoke_session(&self, id_hash: &str) -> Result<()> {
        self.storage.delete_session(id_hash).await
    }

    // ── API tokens ─────────────────────────────────────────────────────

    /// Create a new API token for `user_id`. The raw token is returned
    /// once so the caller can display it; it's unrecoverable after that.
    pub async fn create_api_token(
        &self,
        user_id: UserId,
        new: NewApiToken,
    ) -> Result<CreatedApiToken> {
        let raw = generate_api_token();
        let prefix = slice_api_token_prefix(&raw, DEFAULT_PREFIX_LEN);
        let hash = domain::token_hash::hash(&raw)?;
        let row = self.storage.create_api_token(user_id.0, &new, &hash, prefix).await?;
        Ok(CreatedApiToken { raw_token: raw, info: row.into() })
    }

    /// Look up an API token by its raw value. Verifies the hash against
    /// all prefix-matched candidates.
    pub async fn lookup_api_token(&self, raw: &str) -> Result<ApiTokenLookupOutcome> {
        // Quick format check — avoids a DB hit for obviously-wrong tokens.
        if !raw.starts_with(API_TOKEN_PREFIX) {
            return Ok(ApiTokenLookupOutcome::Invalid);
        }
        let prefix = slice_api_token_prefix(raw, DEFAULT_PREFIX_LEN);
        let candidates = self.storage.find_api_tokens_by_prefix(prefix).await?;
        for row in candidates {
            // Check expiry.
            if let Some(exp) = row.expires_at
                && Utc::now() > exp
            {
                continue;
            }
            if domain::token_hash::verify(raw, &row.token_hash) {
                return Ok(ApiTokenLookupOutcome::Active(row));
            }
        }
        Ok(ApiTokenLookupOutcome::Invalid)
    }

    /// List tokens for a user (safe info only — no hash).
    pub async fn list_api_tokens(&self, user_id: UserId) -> Result<Vec<ApiTokenInfo>> {
        let rows = self.storage.list_api_tokens(user_id.0).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Rename an API token.
    pub async fn rename_api_token(
        &self,
        _user_id: UserId,
        id: Uuid,
        new_name: String,
    ) -> Result<ApiTokenInfo> {
        let row =
            self.storage.update_api_token(id, &domain::ApiTokenUpdate { name: new_name }).await?;
        Ok(row.into())
    }

    /// Delete an API token. Idempotent.
    pub async fn delete_api_token(&self, _user_id: UserId, id: Uuid) -> Result<()> {
        self.storage.delete_api_token(id).await
    }

    /// Touch a token's `last_used_at` (debounced).
    pub async fn touch_api_token(&self, row: &ApiTokenRow) -> Result<()> {
        let now = Utc::now();
        if let Some(last) = row.last_used_at
            && (now - last).num_seconds() < TOUCH_DEBOUNCE_SECS
        {
            return Ok(());
        }
        self.storage.touch_api_token(row.id, now).await
    }

    // ── User ───────────────────────────────────────────────────────────

    pub async fn get_user(&self, id: UserId) -> Result<User> {
        self.storage.get_user(id.0).await
    }

    pub async fn update_user(&self, id: UserId, update: UserUpdate) -> Result<User> {
        self.storage.update_user(id.0, &update).await
    }

    // ── Config accessors ───────────────────────────────────────────────

    /// The session cookie name from config.
    pub fn session_cookie_name(&self) -> &str {
        &self.config.session.cookie_name
    }

    /// Whether the session cookie should be Secure (HTTPS-only).
    pub const fn session_cookie_secure(&self) -> bool {
        self.config.session.cookie_secure
    }

    /// The session cookie domain (empty = host-only).
    pub fn session_cookie_domain(&self) -> &str {
        &self.config.session.cookie_domain
    }

    /// Whether magic-link login is enabled.
    #[expect(dead_code)]
    pub fn magic_link_enabled(&self) -> bool {
        self.config.magic_link_enabled()
    }

    /// Default scopes for a new token if none specified.
    #[expect(dead_code)]
    pub fn default_token_scopes() -> ScopeSet {
        ScopeSet::full_access()
    }
}
