use std::{collections::BTreeMap, sync::Arc};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_TOKEN_TTL_SECONDS: i64 = 60;
const NOT_BEFORE_OFFSET_SECONDS: i64 = 5;

#[derive(Clone)]
pub struct ProviderAuthenticator {
    issuer: String,
    audience: String,
    keys: Arc<BTreeMap<String, DecodingKey>>,
    clock_skew_seconds: u64,
}

impl ProviderAuthenticator {
    pub fn from_public_keys_json(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        public_keys_json: &str,
    ) -> Result<Self, AuthError> {
        let issuer = issuer.into();
        let audience = audience.into();
        if issuer.is_empty() || audience.is_empty() {
            return Err(AuthError::InvalidConfiguration);
        }
        let encoded: BTreeMap<String, String> =
            serde_json::from_str(public_keys_json).map_err(|_| AuthError::InvalidConfiguration)?;
        if encoded.is_empty() {
            return Err(AuthError::InvalidConfiguration);
        }
        let mut keys = BTreeMap::new();
        for (key_id, pem) in encoded {
            if !valid_key_id(&key_id) {
                return Err(AuthError::InvalidConfiguration);
            }
            let key = DecodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|_| AuthError::InvalidConfiguration)?;
            keys.insert(key_id, key);
        }
        Ok(Self {
            issuer,
            audience,
            keys: Arc::new(keys),
            clock_skew_seconds: 5,
        })
    }

    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        expected_action: &str,
    ) -> Result<ProviderClaims, AuthError> {
        let token = headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingCredentials)?
            .to_str()
            .map_err(|_| AuthError::InvalidCredentials)?
            .strip_prefix("Bearer ")
            .filter(|value| !value.is_empty())
            .ok_or(AuthError::InvalidCredentials)?;
        self.verify(token, expected_action)
    }

    pub fn verify(&self, token: &str, expected_action: &str) -> Result<ProviderClaims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::InvalidCredentials)?;
        if header.alg != Algorithm::EdDSA {
            return Err(AuthError::InvalidCredentials);
        }
        let key_id = header.kid.ok_or(AuthError::InvalidCredentials)?;
        let key = self
            .keys
            .get(&key_id)
            .ok_or(AuthError::InvalidCredentials)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]);
        validation.leeway = self.clock_skew_seconds;
        let claims = decode::<ProviderClaims>(token, key, &validation)
            .map_err(|_| AuthError::InvalidCredentials)?
            .claims;
        if claims.action != expected_action || claims.generation <= 0 {
            return Err(AuthError::InvalidCommand);
        }
        if claims.expires_at <= claims.issued_at
            || claims.expires_at.saturating_sub(claims.issued_at) > MAX_TOKEN_TTL_SECONDS
            || claims.issued_at.checked_sub(NOT_BEFORE_OFFSET_SECONDS) != Some(claims.not_before)
        {
            return Err(AuthError::InvalidCredentials);
        }
        let skew =
            i64::try_from(self.clock_skew_seconds).map_err(|_| AuthError::InvalidConfiguration)?;
        if claims.issued_at > Utc::now().timestamp().saturating_add(skew) {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(claims)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "sub")]
    pub subject: Uuid,
    /// Owner account user resolved from the principal. `sub` remains the
    /// command-authentication PrincipalId.
    #[serde(default)]
    pub user_id: Option<Uuid>,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub service_instance_id: Uuid,
    pub action: String,
    pub generation: i64,
    #[serde(rename = "jti")]
    pub jwt_id: Uuid,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "nbf")]
    pub not_before: i64,
    #[serde(rename = "exp")]
    pub expires_at: i64,
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthError {
    #[error("provider credentials are missing")]
    MissingCredentials,
    #[error("provider credentials are invalid or expired")]
    InvalidCredentials,
    #[error("provider command does not match the request")]
    InvalidCommand,
    #[error("provider authentication is not configured correctly")]
    InvalidConfiguration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    const PRIVATE: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICKoEEWPLg2OazcyTWzBEw/mMPPXatNOUcEUWDHo2y0Y\n-----END PRIVATE KEY-----\n";
    const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcBpAFx4KtN1FYwvSN0XJMWSGiAJPjzetPXEiuMX2azg=\n-----END PUBLIC KEY-----\n";
    #[test]
    fn provider_tokens_are_short_lived_audience_action_and_key_scoped()
    -> Result<(), Box<dyn std::error::Error>> {
        let auth = ProviderAuthenticator::from_public_keys_json(
            "test",
            "heterocloud-vpc",
            &serde_json::json!({"fixture":PUBLIC}).to_string(),
        )?;
        let now = Utc::now().timestamp();
        let action = "service-instance.reconcile";
        let c = ProviderClaims {
            issuer: "test".into(),
            audience: "heterocloud-vpc".into(),
            subject: Uuid::from_u128(1),
            user_id: None,
            organization_id: Uuid::from_u128(2),
            project_id: Uuid::from_u128(3),
            service_instance_id: Uuid::from_u128(4),
            action: action.into(),
            generation: 1,
            jwt_id: Uuid::from_u128(5),
            issued_at: now,
            not_before: now - 5,
            expires_at: now + 60,
        };
        let sign = |claims: &ProviderClaims, kid: &str| {
            let mut h = Header::new(Algorithm::EdDSA);
            h.kid = Some(kid.into());
            encode(&h, claims, &EncodingKey::from_ed_pem(PRIVATE)?)
        };
        assert_eq!(auth.verify(&sign(&c, "fixture")?, action)?, c);
        assert!(
            auth.verify(&sign(&c, "fixture")?, "service-instance.delete")
                .is_err()
        );
        assert!(auth.verify(&sign(&c, "unknown")?, action).is_err());
        let mut wrong = c.clone();
        wrong.audience = "heterocloud-flash".into();
        assert!(auth.verify(&sign(&wrong, "fixture")?, action).is_err());
        let mut long = c.clone();
        long.expires_at = now + 61;
        assert!(auth.verify(&sign(&long, "fixture")?, action).is_err());
        let mut future = c.clone();
        future.issued_at += 30;
        future.not_before += 30;
        future.expires_at += 30;
        assert!(auth.verify(&sign(&future, "fixture")?, action).is_err());
        let mut expired = c.clone();
        expired.issued_at -= 120;
        expired.not_before -= 120;
        expired.expires_at -= 120;
        assert!(auth.verify(&sign(&expired, "fixture")?, action).is_err());
        let mut generation = c;
        generation.generation = 0;
        assert!(auth.verify(&sign(&generation, "fixture")?, action).is_err());
        Ok(())
    }
}
