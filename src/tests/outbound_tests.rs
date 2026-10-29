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

use crate::{
    DnsUpdater, Error,
    http::{HttpClientBuilder, MAX_BODY_SNIPPET, body_snippet, build_client},
    providers::{
        lightsail::LightsailConfig, oraclecloud::OracleCloudConfig, route53::Route53Config,
        volcengine::VolcengineConfig,
    },
    utils::{MAX_REGION_LEN, validate_region},
};
use std::{io::ErrorKind, net::TcpListener};

const VALID_REGIONS: &[&str] = &[
    "us-east-1",
    "cn-hangzhou",
    "ap-guangzhou",
    "eu-frankfurt-1",
    "cn-north-1",
    "a",
];

fn invalid_regions() -> Vec<String> {
    vec![
        "x.attacker.example/#".to_string(),
        "a/b".to_string(),
        "a:80".to_string(),
        "a@b".to_string(),
        "US-EAST-1".to_string(),
        "us-East-1".to_string(),
        String::new(),
        "a".repeat(MAX_REGION_LEN + 1),
        "cn-hangzhóu".to_string(),
        "us_east_1".to_string(),
        "us east 1".to_string(),
        "us-east-1\n".to_string(),
        "a?b".to_string(),
        "a%2fb".to_string(),
    ]
}

fn assert_no_connection(listener: &TcpListener) {
    match listener.accept() {
        Err(err) if err.kind() == ErrorKind::WouldBlock => {}
        Ok((_, peer)) => panic!("redirect target received a connection from {peer}"),
        Err(err) => panic!("unexpected accept error: {err}"),
    }
}

// A 3xx response is returned as an error and the Location target is never contacted.
#[tokio::test]
async fn redirects_are_not_followed() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
    target.set_nonblocking(true).expect("nonblocking target");
    let location = format!("http://{}/stolen", target.local_addr().expect("addr"));

    let mut server = mockito::Server::new_async().await;
    for status in [301u16, 302, 303, 307, 308] {
        let path = format!("/redirect-{status}");
        let mock = server
            .mock("GET", path.as_str())
            .with_status(usize::from(status))
            .with_header("location", &location)
            .expect(2)
            .create_async()
            .await;
        let url = format!("{}{path}", server.url());

        let err = HttpClientBuilder::default()
            .build()
            .get(url.as_str())
            .send_raw()
            .await
            .expect_err("redirect must not be followed");
        assert!(
            matches!(&err, Error::Api(msg) if msg.starts_with(&format!("HTTP {status}"))),
            "unexpected error for {status}: {err:?}"
        );

        let response = build_client(None)
            .get(url.as_str())
            .send()
            .await
            .expect("raw request");
        assert_eq!(response.status().as_u16(), status);

        mock.assert_async().await;
        assert_no_connection(&target);
    }
}

// Error messages built from non-2xx bodies are capped at MAX_BODY_SNIPPET bytes.
#[tokio::test]
async fn error_body_snippet_is_capped() {
    let mut server = mockito::Server::new_async().await;
    let body = "é".repeat(MAX_BODY_SNIPPET * 4);
    for status in [400, 500] {
        let path = format!("/status-{status}");
        server
            .mock("GET", path.as_str())
            .with_status(status)
            .with_body(&body)
            .create_async()
            .await;
        let err = HttpClientBuilder::default()
            .build()
            .get(format!("{}{path}", server.url()))
            .send_raw()
            .await
            .expect_err("non-2xx must fail");
        let Error::Api(msg) = err else {
            panic!("unexpected error: {err:?}");
        };
        let snippet_len = msg.chars().filter(|c| *c == 'é').count() * 'é'.len_utf8();
        assert_eq!(snippet_len, MAX_BODY_SNIPPET, "{msg}");
        assert!(msg.len() < MAX_BODY_SNIPPET + 16, "len {}", msg.len());
    }
}

// The snippet helper trims, keeps short bodies intact and truncates on a char boundary.
#[test]
fn body_snippet_truncates_on_char_boundary() {
    assert_eq!(body_snippet("  short body \n"), "short body");
    assert_eq!(body_snippet(""), "");

    let exact = "a".repeat(MAX_BODY_SNIPPET);
    assert_eq!(body_snippet(&exact), exact);

    let mut misaligned = "a".repeat(MAX_BODY_SNIPPET - 1);
    misaligned.push_str("€tail");
    let snippet = body_snippet(&misaligned);
    assert_eq!(snippet.len(), MAX_BODY_SNIPPET - 1);
    assert!(snippet.bytes().all(|b| b == b'a'));
}

// Real region names pass validation and host-altering strings are rejected.
#[test]
fn region_validation() {
    for region in VALID_REGIONS {
        assert!(validate_region(region).is_ok(), "{region} rejected");
    }
    assert!(validate_region(&"a".repeat(MAX_REGION_LEN)).is_ok());
    for region in invalid_regions() {
        assert!(
            matches!(validate_region(&region), Err(Error::InvalidRegion)),
            "{region:?} accepted"
        );
    }
}

// Every constructor that places a region in a hostname or signature rejects invalid regions.
#[test]
fn provider_constructors_reject_invalid_regions() {
    for region in VALID_REGIONS {
        assert!(
            DnsUpdater::new_alidns("k", "s", Some(region), None::<&str>, None::<&str>, None)
                .is_ok()
        );
        assert!(DnsUpdater::new_huaweicloud("k", "s", region, None).is_ok());
        assert!(DnsUpdater::new_tencentcloud("k", "s", Some(region), None::<&str>, None).is_ok());
        assert!(DnsUpdater::new_lightsail(lightsail_config(Some(region))).is_ok());
        assert!(DnsUpdater::new_route53(route53_config(Some(region))).is_ok());
        assert!(DnsUpdater::new_volcengine(volcengine_config(Some(region))).is_ok());
    }

    assert!(DnsUpdater::new_alidns("k", "s", Some(""), None::<&str>, None::<&str>, None).is_ok());
    assert!(DnsUpdater::new_tencentcloud("k", "s", Some(""), None::<&str>, None).is_ok());
    assert!(DnsUpdater::new_lightsail(lightsail_config(None)).is_ok());
    assert!(DnsUpdater::new_route53(route53_config(None)).is_ok());
    assert!(DnsUpdater::new_volcengine(volcengine_config(None)).is_ok());

    for region in invalid_regions() {
        let region = region.as_str();
        let results = [
            (!region.is_empty()).then(|| {
                DnsUpdater::new_alidns("k", "s", Some(region), None::<&str>, None::<&str>, None)
            }),
            (!region.is_empty())
                .then(|| DnsUpdater::new_tencentcloud("k", "s", Some(region), None::<&str>, None)),
            (!region.is_empty()).then(|| DnsUpdater::new_huaweicloud("k", "s", region, None)),
            Some(DnsUpdater::new_lightsail(lightsail_config(Some(region)))),
            Some(DnsUpdater::new_route53(route53_config(Some(region)))),
            Some(DnsUpdater::new_volcengine(volcengine_config(Some(region)))),
            (!region.is_empty()).then(|| DnsUpdater::new_oraclecloud(oracle_config(region))),
        ];
        for (idx, result) in results.into_iter().enumerate() {
            if let Some(result) = result {
                assert!(
                    matches!(result, Err(Error::InvalidRegion)),
                    "constructor {idx} accepted {region:?}"
                );
            }
        }
    }
}

fn lightsail_config(region: Option<&str>) -> LightsailConfig {
    LightsailConfig {
        access_key_id: "k".to_string(),
        secret_access_key: "s".to_string(),
        session_token: None,
        region: region.map(str::to_string),
        domain: None,
        request_timeout: None,
    }
}

fn route53_config(region: Option<&str>) -> Route53Config {
    Route53Config {
        access_key_id: "k".to_string(),
        secret_access_key: "s".to_string(),
        session_token: None,
        region: region.map(str::to_string),
        hosted_zone_id: None,
        private_zone_only: None,
        endpoint: None,
    }
}

fn volcengine_config(region: Option<&str>) -> VolcengineConfig {
    VolcengineConfig {
        access_key: "k".to_string(),
        secret_key: "s".to_string(),
        region: region.map(str::to_string),
        host: None,
        scheme: None,
        request_timeout: None,
    }
}

fn oracle_config(region: &str) -> OracleCloudConfig {
    OracleCloudConfig {
        tenancy_ocid: "t".to_string(),
        user_ocid: "u".to_string(),
        fingerprint: "f".to_string(),
        private_key_pem: String::new(),
        private_key_password: None,
        region: region.to_string(),
        compartment_ocid: "c".to_string(),
        request_timeout: None,
    }
}
