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

use crate::DnsUpdater;
use crate::providers::route53::{Route53Config, Route53Provider};

#[tokio::test]
async fn test_route53_provider_creation() {
    let config = Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: Some("us-east-1".to_string()),
        hosted_zone_id: Some("test_zone_id".to_string()),
        private_zone_only: Some(false),
    };

    // Test that provider creation succeeds
    let _provider = Route53Provider::new(config);
}

#[tokio::test]
async fn test_route53_updater_creation() {
    let config = Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: Some("us-west-2".to_string()),
        hosted_zone_id: None,
        private_zone_only: Some(true),
    };

    // Test that DnsUpdater creation succeeds
    let updater = DnsUpdater::new_route53(config).unwrap();
    match updater {
        DnsUpdater::Route53(_) => {
            // Successfully created Route53 updater
        }
        _ => panic!("Expected Route53 provider"),
    }
}

#[tokio::test]
async fn test_route53_config_defaults() {
    let config = Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: None, // Should default to us-east-1
        hosted_zone_id: None,
        private_zone_only: None, // Should default to false
    };

    // Test that provider creation with defaults succeeds
    let _provider = Route53Provider::new(config);
}

#[tokio::test]
async fn test_route53_config_with_session_token() {
    let config = Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: Some("test_session_token".to_string()),
        region: Some("eu-west-1".to_string()),
        hosted_zone_id: Some("Z1234567890".to_string()),
        private_zone_only: Some(true),
    };

    // Test that provider creation with session token succeeds
    let _provider = Route53Provider::new(config);
}

#[tokio::test]
async fn test_route53_config_minimal() {
    let config = Route53Config {
        access_key_id: "test_access_key".to_string(),
        secret_access_key: "test_secret_key".to_string(),
        session_token: None,
        region: None,
        hosted_zone_id: None,
        private_zone_only: None,
    };

    // Test that minimal config works
    let updater = DnsUpdater::new_route53(config).unwrap();
    match updater {
        DnsUpdater::Route53(_) => {
            // Successfully created Route53 updater with minimal config
        }
        _ => panic!("Expected Route53 provider"),
    }
}
