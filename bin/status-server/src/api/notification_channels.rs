//! Notification channel CRUD + test endpoint.
//!
//! - `GET /notification-channels` — list channels (secrets redacted).
//! - `POST /notification-channels` — create channel (validates config,
//!   redacts secrets in response).
//! - `GET /notification-channels/{id}` — get channel (secrets redacted).
//! - `PATCH /notification-channels/{id}` — update channel.
//! - `DELETE /notification-channels/{id}` — delete channel (also unbinds
//!   from all targets).
//! - `POST /notification-channels/{id}/test` — send a test notification
//!   using the channel's stored config.
//! - `POST /notification-channels/{id}/request-verification` — for email
//!   channels, generate a verification token and email the recipient a
//!   verify/decline link. Other kinds return 409; already-verified
//!   channels return 409.
//!
//! Every response carries a `config` field with the secrets masked (URLs
//! hidden behind a sentinel mask). The masked fields round-trip on a
//! subsequent PATCH unchanged — re-submitting the masked value preserves
//! the stored secret.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use statuscore::domain::{
    ChannelConfig, ChannelKind, NewNotificationChannel, NotificationChannel,
    NotificationChannelUpdate,
};
use uuid::Uuid;

use crate::api::error::{ApiError, ApiResult};
use crate::app::AppState;

/// Verification token lifetime. Long enough that an operator adding a
/// channel on Friday can confirm on Monday; short enough that a leaked
/// link ages out before it becomes a long-term escalation surface.
const VERIFICATION_TOKEN_HOURS: u32 = 24;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/notification-channels", get(list_channels).post(create_channel))
        .route(
            "/notification-channels/{id}",
            get(get_channel).patch(update_channel).delete(delete_channel),
        )
        .route("/notification-channels/{id}/test", post(test_channel))
        .route("/notification-channels/{id}/request-verification", post(request_verification))
}

async fn list_channels(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let mut channels: Vec<NotificationChannel> = state.storage.list_notification_channels().await?;
    // Mask in place so secrets never leave the API boundary.
    for ch in &mut channels {
        ch.config.redact_in_place();
    }
    Ok(Json(channels))
}

async fn create_channel(
    State(state): State<AppState>,
    Json(new_channel): Json<NewNotificationChannel>,
) -> ApiResult<impl IntoResponse> {
    // Validate name + config before persisting so an invalid channel never
    // reaches storage. A failed validate returns 400 with the reason.
    if let Err(reason) = statuscore::domain::validate_channel_name(&new_channel.name) {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_CHANNEL_NAME",
            reason,
        )));
    }
    if let Err(reason) = new_channel.config.validate() {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_CHANNEL_CONFIG",
            reason,
        )));
    }

    let mut created = state.storage.create_notification_channel(&new_channel).await?;
    // Redact in the response copy; storage keeps the plaintext.
    created.config.redact_in_place();
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let mut channel = state.storage.get_notification_channel(id).await?;
    channel.config.redact_in_place();
    Ok(Json(channel))
}

async fn update_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(update): Json<NotificationChannelUpdate>,
) -> ApiResult<impl IntoResponse> {
    if let Some(name) = &update.name
        && let Err(reason) = statuscore::domain::validate_channel_name(name)
    {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_CHANNEL_NAME",
            reason,
        )));
    }
    if let Some(config) = &update.config
        && let Err(reason) = config.validate()
    {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "INVALID_CHANNEL_CONFIG",
            reason,
        )));
    }

    let mut updated = state.storage.update_notification_channel(id, &update).await?;
    updated.config.redact_in_place();
    Ok(Json(updated))
}

async fn delete_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    // Unbind from every target before deleting so no dangling binding rows
    // survive the channel.
    state.storage.unbind_channel_everywhere(id).await?;
    state.storage.delete_notification_channel(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /notification-channels/{id}/test` — send a test notification using
/// the channel's stored config. Returns 200 with a small body on success,
/// 500 with the error on failure. The dispatch is synchronous so the
/// operator gets immediate feedback (the transports are all sub-second).
async fn test_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let channel = state.storage.get_notification_channel(id).await?;
    if !channel.enabled {
        return Err(ApiError(statuscore::error::AppError::bad_request(
            "CHANNEL_DISABLED",
            "channel is disabled; enable it before testing",
        )));
    }

    // Build a notifier for this channel's transport and send a test message.
    // Failures are surfaced as 500 with the underlying error so the operator
    // sees the actual transport message (auth failure, bad URL, etc.).
    let notifier = match common::notifier::build_notifier(&channel.config, &state.notifier_http) {
        Ok(n) => n,
        Err(e) => {
            return Err(ApiError(statuscore::error::AppError::internal_with_context(
                "NOTIFIER_BUILD",
                e.to_string(),
            )));
        }
    };
    let message =
        format!("Test notification from channel {} ({})", channel.name, channel.kind.as_db_str());
    notifier.send(&message).await.map_err(|e| {
        ApiError(statuscore::error::AppError::internal_with_context("NOTIFIER_SEND", e.to_string()))
    })?;
    Ok((StatusCode::OK, Json(serde_json::json!({"status": "sent"}))))
}

/// `POST /notification-channels/{id}/request-verification` — for an email
/// channel, generate a single-use verification token and email the
/// recipient a verify/decline link pair. Returns 204 on success so the
/// caller can't probe for the recipient address; the email itself is the
/// confirmation.
///
/// Returns:
/// - `404` if the channel doesn't exist.
/// - `409 CHANNEL_NOT_EMAIL` if the channel isn't an email channel (only
///   email requires address confirmation before delivery).
/// - `409 CHANNEL_ALREADY_VERIFIED` if the channel is already verified.
/// - `409 CHANNEL_DISABLED` if the channel is disabled (a disabled channel
///   can't be verified — re-enable first).
/// - `500` if the verification email fails to send. The token is still
///   persisted (the operator can re-request), but the failure is surfaced
///   so the operator knows the email didn't go out.
async fn request_verification(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let channel = state.storage.get_notification_channel(id).await?;

    // Only email channels require address verification — every other kind
    // is operator-configured and trusted on save.
    if channel.kind != ChannelKind::Email {
        return Err(ApiError(statuscore::error::AppError::Conflict {
            code: "CHANNEL_NOT_EMAIL",
            message: "only email channels require verification".to_string(),
        }));
    }
    if channel.verified_at.is_some() {
        return Err(ApiError(statuscore::error::AppError::Conflict {
            code: "CHANNEL_ALREADY_VERIFIED",
            message: "channel is already verified".to_string(),
        }));
    }
    if !channel.enabled {
        return Err(ApiError(statuscore::error::AppError::Conflict {
            code: "CHANNEL_DISABLED",
            message: "channel is disabled; re-enable before requesting verification".to_string(),
        }));
    }

    let ChannelConfig::Email(email_cfg) = &channel.config else {
        // Defensive: kind says Email but config doesn't match — a data
        // integrity issue. Surface as 500 so the operator can investigate.
        return Err(ApiError(statuscore::error::AppError::internal_with_context(
            "CHANNEL_CONFIG_MISMATCH",
            "channel kind is email but config is not EmailConfig".to_string(),
        )));
    };

    // Generate a single-use token: 32 random bytes base64url-no-pad (43
    // chars, ~122 bits of entropy). The raw token goes in the email link;
    // only `sha256_hex(raw)` is stored (the storage trait contract). The
    // token is consumed atomically by the verify endpoint so a leak can't
    // be replayed.
    let raw_token = statuscore::domain::generate_cookie_value();
    let token_hash = statuscore::domain::hash_cookie_value(&raw_token);
    let expires_at = Utc::now() + chrono::Duration::hours(i64::from(VERIFICATION_TOKEN_HOURS));
    state.storage.create_channel_verification_token(channel.id, &token_hash, expires_at).await?;

    // Build the verify / decline URLs. Both are public GET endpoints so a
    // mail client's link preview works and a one-click List-Unsubscribe
    // header (RFC 8058) can carry the decline URL for inbox-level refusal.
    let base = state.public_base_url.trim_end_matches('/');
    let verify_url = format!("{base}/api/public/v1/notification-channels/verify?token={raw_token}");
    let decline_url =
        format!("{base}/api/public/v1/notification-channels/decline?token={raw_token}");

    // Send the verification email. The from address is the configured
    // transactional identity (Resend / log / memory); the to address is
    // the channel's recipient. `org_name` is `None` in v1 (single-tenant)
    // — multi-tenancy plugs in here when introduced.
    let email = common::email::TransactionalEmail {
        to: common::email::EmailAddress::new(email_cfg.to.clone(), email_cfg.to.clone()),
        from: state.from_address.clone(),
        template: common::email::EmailTemplate::ChannelVerification {
            channel_name: channel.name.clone(),
            verify_url,
            expires_hours: VERIFICATION_TOKEN_HOURS,
            org_name: None,
            decline_url: Some(decline_url),
        },
    };
    if let Err(e) = state.email_sender.send(email).await {
        // The token is persisted (so a re-request would consume a fresh
        // one), but surface the failure so the operator knows the email
        // didn't go out. A common cause is `[email] provider = "log"` in
        // dev — the operator sees the verify URL in the tracing output.
        tracing::warn!(
            channel_id = %channel.id,
            to = %email_cfg.to,
            error = %e,
            "request_verification: email send failed"
        );
        return Err(ApiError(statuscore::error::AppError::internal_with_context(
            "VERIFICATION_EMAIL_SEND",
            e.to_string(),
        )));
    }

    // 204 with no body — the email itself is the confirmation. Avoid
    // echoing the recipient address so a compromised session can't probe
    // for inboxes via this endpoint.
    Ok(StatusCode::NO_CONTENT)
}
