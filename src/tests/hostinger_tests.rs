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

#[cfg(test)]
mod tests {
    use crate::{
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord,
        providers::hostinger::HostingerProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> HostingerProvider {
        HostingerProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_hostinger("test_token", Some(Duration::from_secs(30)));
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::Hostinger(..))));
    }

    #[test]
    fn empty_token_rejected() {
        let result = HostingerProvider::new("", None);
        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("empty")));
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_only_this_type() {
        let mut server = mockito::Server::new_async().await;

        let delete_mock = server
            .mock("DELETE", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "filters": [{ "name": "www", "type": "TXT" }]
            })))
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        delete_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_treats_not_found_as_ok() {
        let mut server = mockito::Server::new_async().await;

        let delete_mock = server
            .mock("DELETE", "/api/dns/v1/zones/example.com")
            .with_status(404)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "absent.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        delete_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_replaces_target_keeps_other_rrsets() {
        let mut server = mockito::Server::new_async().await;

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [
                    {
                        "name": "www",
                        "type": "A",
                        "ttl": 600,
                        "records": [
                            { "content": "2.2.2.2" },
                            { "content": "3.3.3.3" }
                        ]
                    }
                ]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                    DnsRecord::A("3.3.3.3".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        put_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("mismatch")));
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_to_rrset_merges_non_duplicates() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body(
                json!([
                    {
                        "name": "www",
                        "type": "A",
                        "ttl": 3600,
                        "records": [
                            { "content": "1.1.1.1" }
                        ]
                    },
                    {
                        "name": "@",
                        "type": "TXT",
                        "ttl": 3600,
                        "records": [{ "content": "untouched" }]
                    }
                ])
                .to_string(),
            )
            .create();

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [
                    {
                        "name": "www",
                        "type": "A",
                        "ttl": 3600,
                        "records": [
                            { "content": "1.1.1.1" },
                            { "content": "2.2.2.2" }
                        ]
                    }
                ]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_creates_when_absent() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body("[]")
            .create();

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [{
                    "name": "new",
                    "type": "A",
                    "ttl": 300,
                    "records": [{ "content": "9.9.9.9" }]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "new.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_from_rrset_filters_and_puts() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body(
                json!([
                    {
                        "name": "www",
                        "type": "A",
                        "ttl": 3600,
                        "records": [
                            { "content": "1.1.1.1" },
                            { "content": "2.2.2.2" },
                            { "content": "3.3.3.3" }
                        ]
                    }
                ])
                .to_string(),
            )
            .create();

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [{
                    "name": "www",
                    "type": "A",
                    "ttl": 3600,
                    "records": [
                        { "content": "1.1.1.1" },
                        { "content": "3.3.3.3" }
                    ]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_when_empty() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body(
                json!([
                    {
                        "name": "www",
                        "type": "A",
                        "ttl": 3600,
                        "records": [
                            { "content": "1.1.1.1" }
                        ]
                    }
                ])
                .to_string(),
            )
            .create();

        let delete_mock = server
            .mock("DELETE", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "filters": [{ "name": "www", "type": "A" }]
            })))
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_value_noop() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body(
                json!([
                    {
                        "name": "www",
                        "type": "A",
                        "ttl": 3600,
                        "records": [{ "content": "1.1.1.1" }]
                    }
                ])
                .to_string(),
            )
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zone_get.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body(
                json!([
                    {
                        "name": "@",
                        "type": "MX",
                        "ttl": 3600,
                        "records": [
                            { "content": "10 mx1.example.com." },
                            { "content": "20 mx2.example.com." }
                        ]
                    }
                ])
                .to_string(),
            )
            .create();

        let provider = setup_provider(server.url().as_str());

        let records = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();

        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            priority: 10,
            exchange: "mx1.example.com".to_string(),
        })));
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            priority: 20,
            exchange: "mx2.example.com".to_string(),
        })));
        zone_get.assert();
    }

    #[tokio::test]
    async fn list_rrset_missing_returns_empty() {
        let mut server = mockito::Server::new_async().await;

        let zone_get = server
            .mock("GET", "/api/dns/v1/zones/example.com")
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url().as_str());

        let records = provider
            .list_rrset("absent.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();

        assert!(records.is_empty());
        zone_get.assert();
    }

    #[tokio::test]
    async fn set_rrset_apex_mx_with_fqdn_normalization() {
        let mut server = mockito::Server::new_async().await;

        let put_mock = server
            .mock("PUT", "/api/dns/v1/zones/example.com")
            .match_body(mockito::Matcher::Json(json!({
                "overwrite": true,
                "zone": [{
                    "name": "@",
                    "type": "MX",
                    "ttl": 3600,
                    "records": [{ "content": "10 mx.example.com." }]
                }]
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mx.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        put_mock.assert();
    }
}
