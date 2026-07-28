//! Argon2id hashing for high-value secrets (API tokens, magic-link tokens).
//!
//! Session cookies use SHA-256 (lookup is by hash, so the index is the hash
//! itself — see `session::hash_cookie_value`). API tokens and magic-link
//! tokens use a non-unique prefix index, so multiple rows can match a prefix
//! and the verifier must distinguish candidates by PHC-string comparison.
//! Argon2id is the right choice here: it's slow enough to make a leaked hash
//! table brute-resistant, and the PHC string is self-describing (algorithm +
//! parameters + salt + hash), so a future parameter rotation just produces a
//! new PHC string that verifies correctly without a migration.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;

use crate::error::{AppError, Result};

/// Hash a raw secret with Argon2id, returning the PHC string.
///
/// Parameters are fixed at the OWASP-recommended minimums (m=19 MiB, t=2, p=1)
/// — fast enough for a single verify on the auth path, slow enough that a
/// full hash leak resists offline brute force. The salt is per-token random
/// (generated via `rand::rng()`, then B64-encoded into a `SaltString`).
pub fn hash(raw: &str) -> Result<String> {
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|e| {
        AppError::internal_with_context("TOKEN_HASH", format!("argon2 params: {e}"))
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0u8; Salt::RECOMMENDED_LENGTH];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| AppError::internal_with_context("TOKEN_HASH", format!("salt encode: {e}")))?;
    let phc = argon2
        .hash_password(raw.as_bytes(), &salt)
        .map_err(|e| AppError::internal_with_context("TOKEN_HASH", format!("argon2 hash: {e}")))?;
    Ok(phc.to_string())
}

/// Verify a raw secret against a stored PHC string. Returns `true` if the
/// secret matches, `false` otherwise (including on malformed PHC strings —
/// a corrupt hash row is treated as "no match" rather than an error so the
/// caller can fall through to the next candidate).
pub fn verify(raw: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(raw.as_bytes(), &parsed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let raw = "sm_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_AB";
        let phc = hash(raw).unwrap();
        assert!(verify(raw, &phc));
        assert!(!verify("wrong", &phc));
    }

    #[test]
    fn verify_rejects_malformed_phc() {
        assert!(!verify("anything", "not-a-phc-string"));
        assert!(!verify("anything", ""));
    }

    #[test]
    fn hash_is_unique_per_call() {
        // Same input, two hashes — salts differ, PHC strings differ.
        let raw = "sm_live_duplicate_test_value";
        let a = hash(raw).unwrap();
        let b = hash(raw).unwrap();
        assert_ne!(a, b);
        assert!(verify(raw, &a));
        assert!(verify(raw, &b));
    }
}
