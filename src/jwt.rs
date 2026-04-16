/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

//! Generic JWT utility for providers that need JWT authentication.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "ring")]
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};

/// Service account JSON fields needed for JWT creation.
#[derive(Debug, Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    // other fields are ignored
}

/// Claims for Google OAuth2 JWT.
#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

/// Encode a byte slice as base64url without padding.
fn base64_url_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Create a signed JWT using the service account private key.
/// Returns the JWT as a compact string.
pub fn create_jwt(sa: &ServiceAccount, scopes: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Header
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let header_b64 = base64_url_encode(serde_json::to_string(&header)?.as_bytes());

    // Timestamps
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let exp = now + 3600; // 1 hour validity

    // Claims
    let claims = JwtClaims {
        iss: sa.client_email.clone(),
        scope: scopes.to_string(),
        aud: sa.token_uri.clone(),
        exp,
        iat: now,
    };
    let claims_b64 = base64_url_encode(serde_json::to_string(&claims)?.as_bytes());

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    // Sign using RSA SHA256
    let pem_content = sa
        .private_key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("\n", "")
        .replace("\r", "");
    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(pem_content.trim())
        .map_err(|e| format!("Invalid base64 in private key: {}", e))?;
    let key_pair = RsaKeyPair::from_pkcs8(&der_bytes)?;
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    let rng = SystemRandom::new();
    key_pair.sign(
        &RSA_PKCS1_SHA256,
        &rng,
        signing_input.as_bytes(),
        &mut signature,
    )?;
    let signature_b64 = base64_url_encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

/// Exchange a JWT for an OAuth2 access token.
pub async fn exchange_jwt_for_token(
    token_uri: &str,
    jwt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt),
    ];
    let body = serde_urlencoded::to_string(&params).map_err(|e| e.to_string())?;
    let resp: serde_json::Value = client
        .post(token_uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?
        .json()
        .await?;
    if let Some(token) = resp.get("access_token") {
        Ok(token.as_str().unwrap_or_default().to_string())
    } else {
        Err("Failed to obtain access token".into())
    }
}
