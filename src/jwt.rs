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
    signature::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RsaKeyPair},
};

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RsaKeyPair},
};

#[derive(Debug, Clone, Copy)]
pub enum JwtSignAlgorithm {
    Rs256,
    Ps256,
}

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

/// Parse a PKCS#8 PEM-encoded RSA private key into an `RsaKeyPair`.
/// Supports both `BEGIN PRIVATE KEY` (PKCS#8) and `BEGIN RSA PRIVATE KEY` (PKCS#1).
/// Encrypted PEMs (`BEGIN ENCRYPTED PRIVATE KEY`) are not supported.
pub fn parse_rsa_pkcs8_pem(pem: &str) -> Result<RsaKeyPair, Box<dyn std::error::Error>> {
    if pem.contains("ENCRYPTED PRIVATE KEY") {
        return Err("encrypted PEM private keys are not supported".into());
    }
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        return Err(
            "PKCS#1 (BEGIN RSA PRIVATE KEY) format is not supported, please convert to PKCS#8"
                .into(),
        );
    }
    let pem_content = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace(" ", "");
    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(pem_content.trim())
        .map_err(|e| format!("Invalid base64 in private key: {}", e))?;
    RsaKeyPair::from_pkcs8(&der_bytes).map_err(|e| format!("Invalid PKCS#8 RSA key: {}", e).into())
}

/// Sign `data` with RSA-SHA256 using a key pair, returning the raw signature bytes.
pub fn rsa_sha256_sign(
    key_pair: &RsaKeyPair,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut signature = vec![0u8; signature_len(key_pair)];
    let rng = SystemRandom::new();
    key_pair.sign(&RSA_PKCS1_SHA256, &rng, data, &mut signature)?;
    Ok(signature)
}

/// Create a signed JWT using the service account private key.
/// Returns the JWT as a compact string.
pub fn create_jwt(sa: &ServiceAccount, scopes: &str) -> Result<String, Box<dyn std::error::Error>> {
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let header_b64 = base64_url_encode(serde_json::to_string(&header)?.as_bytes());

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let exp = now + 3600;

    let claims = JwtClaims {
        iss: sa.client_email.clone(),
        scope: scopes.to_string(),
        aud: sa.token_uri.clone(),
        exp,
        iat: now,
    };
    let claims_b64 = base64_url_encode(serde_json::to_string(&claims)?.as_bytes());

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let key_pair = parse_rsa_pkcs8_pem(&sa.private_key)?;
    let signature = rsa_sha256_sign(&key_pair, signing_input.as_bytes())?;
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
    let body = serde_urlencoded::to_string(params).map_err(|e| e.to_string())?;
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

#[cfg(feature = "ring")]
fn signature_len(key_pair: &RsaKeyPair) -> usize {
    key_pair.public().modulus_len()
}

#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
fn signature_len(key_pair: &RsaKeyPair) -> usize {
    key_pair.public_modulus_len()
}

pub fn parse_pkcs8_pem(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let stripped = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("\n", "")
        .replace("\r", "");
    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(stripped.trim())
        .map_err(|e| format!("Invalid base64 in private key: {}", e))?;
    Ok(der_bytes)
}

pub fn rsa_sha512_sign(
    private_key_pem: &str,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let der_bytes = parse_pkcs8_pem(private_key_pem)?;
    let key_pair = RsaKeyPair::from_pkcs8(&der_bytes)?;
    let mut signature = vec![0u8; signature_len(&key_pair)];
    let rng = SystemRandom::new();
    key_pair.sign(&RSA_PKCS1_SHA512, &rng, data, &mut signature)?;
    Ok(signature)
}

pub fn sign_jwt(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    private_key_pem: &str,
    algorithm: JwtSignAlgorithm,
) -> Result<String, Box<dyn std::error::Error>> {
    let header_b64 = base64_url_encode(serde_json::to_string(header)?.as_bytes());
    let claims_b64 = base64_url_encode(serde_json::to_string(claims)?.as_bytes());
    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let key_pair = parse_rsa_pkcs8_pem(private_key_pem)?;
    let mut signature = vec![0u8; signature_len(&key_pair)];
    let rng = SystemRandom::new();
    match algorithm {
        JwtSignAlgorithm::Rs256 => {
            key_pair.sign(
                &RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut signature,
            )?;
        }
        JwtSignAlgorithm::Ps256 => {
            key_pair.sign(
                &RSA_PSS_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut signature,
            )?;
        }
    }
    let signature_b64 = base64_url_encode(&signature);
    Ok(format!("{}.{}", signing_input, signature_b64))
}

