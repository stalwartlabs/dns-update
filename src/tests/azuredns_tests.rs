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
    use crate::providers::azuredns::{AzureDnsConfig, AzureDnsProvider, AzureEnvironment};
    use crate::{DnsRecord, DnsRecordType, DnsUpdater};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn config() -> AzureDnsConfig {
        AzureDnsConfig {
            tenant_id: "tenant-123".to_string(),
            client_id: "client-123".to_string(),
            client_secret: "secret-123".to_string(),
            subscription_id: "sub-1".to_string(),
            resource_group: "rg-1".to_string(),
            environment: AzureEnvironment::Public,
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup_provider(login_url: &str, mgmt_url: &str) -> AzureDnsProvider {
        AzureDnsProvider::new(config())
            .expect("provider")
            .with_endpoints(login_url, mgmt_url)
            .with_cached_token("cached-token")
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_azuredns(config());
        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::AzureDns(..))));
    }

    #[test]
    fn environment_parsing() {
        assert_eq!(
            AzureEnvironment::from_str_lossy("public"),
            AzureEnvironment::Public
        );
        assert_eq!(
            AzureEnvironment::from_str_lossy("China"),
            AzureEnvironment::China
        );
        assert_eq!(
            AzureEnvironment::from_str_lossy("usgovernment"),
            AzureEnvironment::UsGovernment
        );
        assert_eq!(
            AzureEnvironment::from_str_lossy("unknown"),
            AzureEnvironment::Public
        );
    }

    #[tokio::test]
    async fn set_rrset_replaces_existing_records() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .match_header("authorization", "Bearer cached-token")
            .match_body(Matcher::Json(json!({
                "properties": {
                    "TTL": 120,
                    "ARecords": [
                        {"ipv4Address": "1.1.1.1"},
                        {"ipv4Address": "2.2.2.2"}
                    ]
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                120,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_with_empty_vec_deletes() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/TXT/host",
            )
            .match_query(Matcher::Any)
            .match_header("authorization", "Bearer cached-token")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                60,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(crate::Error::Api(ref msg)) if msg.contains("mismatch")));
    }

    #[tokio::test]
    async fn set_rrset_rejects_multiple_cname() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::CNAME,
                60,
                vec![
                    DnsRecord::CNAME("a.example.com".to_string()),
                    DnsRecord::CNAME("b.example.com".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(crate::Error::Api(ref msg)) if msg.contains("CNAME")));
    }

    #[tokio::test]
    async fn add_to_rrset_merges_with_existing() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("ETag", "etag-1")
            .with_body(
                r#"{
                    "etag": "etag-1",
                    "properties": {
                        "TTL": 120,
                        "ARecords": [{"ipv4Address": "1.1.1.1"}]
                    }
                }"#,
            )
            .create();
        let put_mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .match_header("if-match", "etag-1")
            .match_body(Matcher::Json(json!({
                "properties": {
                    "TTL": 120,
                    "ARecords": [
                        {"ipv4Address": "1.1.1.1"},
                        {"ipv4Address": "2.2.2.2"}
                    ]
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                120,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        get_mock.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                60,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn remove_from_rrset_filters_and_puts_remaining() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("ETag", "etag-9")
            .with_body(
                r#"{
                    "etag": "etag-9",
                    "properties": {
                        "TTL": 300,
                        "ARecords": [
                            {"ipv4Address": "1.1.1.1"},
                            {"ipv4Address": "2.2.2.2"}
                        ]
                    }
                }"#,
            )
            .create();
        let put_mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .match_header("if-match", "etag-9")
            .match_body(Matcher::Json(json!({
                "properties": {
                    "TTL": 300,
                    "ARecords": [{"ipv4Address": "2.2.2.2"}]
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        get_mock.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_when_empty_after_filter() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("ETag", "etag-z")
            .with_body(
                r#"{
                    "etag": "etag-z",
                    "properties": {
                        "TTL": 300,
                        "ARecords": [{"ipv4Address": "1.1.1.1"}]
                    }
                }"#,
            )
            .create();
        let delete_mock = server
            .mock(
                "DELETE",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .match_header("if-match", "etag-z")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        get_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_404_is_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/missing",
            )
            .match_query(Matcher::Any)
            .with_status(404)
            .with_body(r#"{"error":{"code":"NotFound","message":"missing"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "missing.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        get_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/TXT/host",
            )
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(
                r#"{
                    "etag": "x",
                    "properties": {
                        "TTL": 60,
                        "TXTRecords": [
                            {"value": ["hello"]},
                            {"value": ["chunkA", "chunkB"]}
                        ]
                    }
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let records = provider
            .list_rrset("host.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list_rrset");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0], DnsRecord::TXT("hello".to_string()));
        assert_eq!(records[1], DnsRecord::TXT("chunkAchunkB".to_string()));
        get_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_missing_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock(
                "GET",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/none",
            )
            .match_query(Matcher::Any)
            .with_status(404)
            .with_body(r#"{"error":{"code":"NotFound","message":"missing"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let records = provider
            .list_rrset("none.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset");

        assert!(records.is_empty());
        get_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_unsupported_tlsa_errors() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .list_rrset("any.example.com", DnsRecordType::TLSA, "example.com")
            .await;
        assert!(
            matches!(result, Err(crate::Error::Unsupported(ref msg)) if msg.contains("not supported"))
        );
    }

    #[tokio::test]
    #[ignore = "integration test requires real Azure tenant credentials"]
    async fn integration_smoke() {
        let cfg = AzureDnsConfig {
            tenant_id: std::env::var("AZURE_TENANT_ID").unwrap_or_default(),
            client_id: std::env::var("AZURE_CLIENT_ID").unwrap_or_default(),
            client_secret: std::env::var("AZURE_CLIENT_SECRET").unwrap_or_default(),
            subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").unwrap_or_default(),
            resource_group: std::env::var("AZURE_RESOURCE_GROUP").unwrap_or_default(),
            environment: AzureEnvironment::Public,
            request_timeout: Some(Duration::from_secs(10)),
        };
        let provider = AzureDnsProvider::new(cfg).expect("provider");
        let _ = provider
            .set_rrset(
                "smoke.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("hello".to_string())],
                "example.com",
            )
            .await;
    }
}
