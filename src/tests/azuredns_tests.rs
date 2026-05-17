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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, MXRecord, SRVRecord};
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
        assert_eq!(AzureEnvironment::from_str_lossy("public"), AzureEnvironment::Public);
        assert_eq!(AzureEnvironment::from_str_lossy("China"), AzureEnvironment::China);
        assert_eq!(AzureEnvironment::from_str_lossy("usgovernment"), AzureEnvironment::UsGovernment);
        assert_eq!(AzureEnvironment::from_str_lossy("unknown"), AzureEnvironment::Public);
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::UrlEncoded(
                "api-version".into(),
                "2018-05-01".into(),
            ))
            .match_header("authorization", "Bearer cached-token")
            .match_body(mockito::Matcher::Json(json!({
                "properties": {
                    "TTL": 300,
                    "ARecords": [{"ipv4Address": "1.2.3.4"}]
                }
            })))
            .with_status(200)
            .with_body(r#"{"id":"recordset-id"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/TXT/_acme-challenge",
            )
            .match_query(Matcher::Any)
            .match_body(Matcher::Json(json!({
                "properties": {
                    "TTL": 60,
                    "TXTRecords": [{"value": ["abcd"]}]
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("abcd".to_string()),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn update_mx_record_sends_if_match() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/MX/@",
            )
            .match_query(Matcher::Any)
            .match_header("if-match", "*")
            .match_header("authorization", "Bearer cached-token")
            .match_body(Matcher::Json(json!({
                "properties": {
                    "TTL": 120,
                    "MXRecords": [{"preference": 10, "exchange": "mail.example.com"}]
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .update(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                120,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .match_header("authorization", "Bearer cached-token")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn delete_missing_is_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/missing",
            )
            .match_query(Matcher::Any)
            .with_status(404)
            .with_body(r#"{"error":{"code":"NotFound","message":"record not found"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn create_srv_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/SRV/_sip._tcp",
            )
            .match_query(Matcher::Any)
            .match_body(Matcher::Json(json!({
                "properties": {
                    "TTL": 60,
                    "SRVRecords": [{
                        "priority": 5,
                        "weight": 10,
                        "port": 443,
                        "target": "sip.example.com"
                    }]
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "_sip._tcp.example.com",
                DnsRecord::SRV(SRVRecord {
                    target: "sip.example.com".to_string(),
                    priority: 5,
                    weight: 10,
                    port: 443,
                }),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn unsupported_tlsa_returns_api_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .delete("foo.example.com", "example.com", DnsRecordType::TLSA)
            .await;

        assert!(matches!(result, Err(crate::Error::Api(ref msg)) if msg.contains("not supported")));
    }

    #[tokio::test]
    async fn server_error_maps_to_api_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .with_status(500)
            .with_body(r#"{"error":{"code":"InternalError","message":"oops"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        match result {
            Err(crate::Error::Api(message)) => {
                assert!(message.contains("oops"));
            }
            other => panic!("expected API error, got {:?}", other),
        }
        mock.assert();
    }

    #[tokio::test]
    async fn token_exchange_caches_access_token() {
        let mut server = mockito::Server::new_async().await;
        let token_mock = server
            .mock("POST", "/tenant-123/oauth2/v2.0/token")
            .match_body(Matcher::Regex("grant_type=client_credentials".into()))
            .with_status(200)
            .with_body(r#"{"access_token":"fresh-token","expires_in":3600,"token_type":"Bearer"}"#)
            .expect(1)
            .create();
        let put_mock = server
            .mock(
                "PUT",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/dnsZones/example.com/A/host",
            )
            .match_query(Matcher::Any)
            .match_header("authorization", "Bearer fresh-token")
            .with_status(200)
            .with_body("{}")
            .expect(2)
            .create();

        let provider = AzureDnsProvider::new(config())
            .expect("provider")
            .with_endpoints(server.url().as_str(), server.url().as_str());

        let r1 = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        let r2 = provider
            .create(
                "host.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        token_mock.assert();
        put_mock.assert();
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
            .create(
                "smoke.example.com",
                DnsRecord::TXT("hello".to_string()),
                60,
                "example.com",
            )
            .await;
    }
}
