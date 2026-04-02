/*
 * Copyright (c) 2024 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart DNS Update Client.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top of the repository.
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
            assert!(true);
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
            assert!(true);
        }
        _ => panic!("Expected Route53 provider"),
    }
}
