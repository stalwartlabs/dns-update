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
    use crate::providers::edgedns::{EdgeDnsConfig, EdgeDnsProvider};
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord};
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn provider_with_endpoint(endpoint: &str) -> EdgeDnsProvider {
        let config = EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: "client-token-value".to_string(),
            client_secret: "client-secret-value".to_string(),
            access_token: "access-token-value".to_string(),
            account_switch_key: None,
            request_timeout: Some(Duration::from_secs(5)),
        };
        EdgeDnsProvider::new(config).unwrap().with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .match_header("content-type", "application/json")
            .match_header(
                "authorization",
                Matcher::Regex(
                    "^EG1-HMAC-SHA256 client_token=client-token-value;access_token=access-token-value;timestamp=[^;]+;nonce=[^;]+;signature=.+"
                        .to_string(),
                ),
            )
            .match_body(Matcher::Json(json!({
                "name": "www.example.com",
                "type": "A",
                "ttl": 300,
                "rdata": ["1.2.3.4"]
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn update_put_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/AAAA",
            )
            .match_body(Matcher::Json(json!({
                "name": "www.example.com",
                "type": "AAAA",
                "ttl": 600,
                "rdata": ["2001:db8::1"]
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
                600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn update_falls_back_to_create_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let put_mock = server
            .mock(
                "PUT",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;
        let post_mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .match_body(Matcher::Json(json!({
                "name": "www.example.com",
                "type": "A",
                "ttl": 300,
                "rdata": ["9.9.9.9"]
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update failed: {:?}", result);
        put_mock.assert_async().await;
        post_mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/TXT",
            )
            .with_status(204)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_missing_record_is_ok() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/config-dns/v2/zones/example.com/names/gone.example.com/types/A",
            )
            .with_status(404)
            .with_body(r#"{"detail":"not found"}"#)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .delete("gone.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_mx_record_formats_priority() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/example.com/types/MX",
            )
            .match_body(Matcher::Json(json!({
                "name": "example.com",
                "type": "MX",
                "ttl": 3600,
                "rdata": ["10 mail.example.com."]
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_txt_record_quotes_value() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/_acme-challenge.example.com/types/TXT",
            )
            .match_body(Matcher::Json(json!({
                "name": "_acme-challenge.example.com",
                "type": "TXT",
                "ttl": 300,
                "rdata": ["\"validation-token\""]
            })))
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("validation-token".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {:?}", result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_tlsa_returns_api_error() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .create(
                "_443._tcp.example.com",
                DnsRecord::TLSA(crate::TLSARecord {
                    cert_usage: crate::TlsaCertUsage::DaneEe,
                    selector: crate::TlsaSelector::Spki,
                    matching: crate::TlsaMatching::Sha256,
                    cert_data: vec![0xde, 0xad],
                }),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn create_propagates_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .with_status(401)
            .with_body(r#"{"detail":"bad signature"}"#)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn account_switch_key_is_sent() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/config-dns/v2/zones/example.com/names/www.example.com/types/A",
            )
            .match_header("x-accountswitchkey", "switch-me")
            .with_status(201)
            .with_body("{}")
            .create_async()
            .await;

        let config = EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: "ct".to_string(),
            client_secret: "cs".to_string(),
            access_token: "at".to_string(),
            account_switch_key: Some("switch-me".to_string()),
            request_timeout: Some(Duration::from_secs(5)),
        };
        let provider = EdgeDnsProvider::new(config)
            .unwrap()
            .with_endpoint(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {:?}", result);
        mock.assert_async().await;
    }

    #[test]
    fn updater_factory_creates_edgedns_variant() {
        let updater = DnsUpdater::new_edgedns(EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: "ct".to_string(),
            client_secret: "cs".to_string(),
            access_token: "at".to_string(),
            account_switch_key: None,
            request_timeout: None,
        })
        .unwrap();
        assert!(matches!(updater, DnsUpdater::EdgeDns(_)));
    }

    #[test]
    fn missing_credentials_rejected() {
        let res = EdgeDnsProvider::new(EdgeDnsConfig {
            host: "edgedns.akamaiapis.net".to_string(),
            client_token: String::new(),
            client_secret: "cs".to_string(),
            access_token: "at".to_string(),
            account_switch_key: None,
            request_timeout: None,
        });
        assert!(matches!(res, Err(Error::Client(_))));
    }

    #[tokio::test]
    #[ignore = "Requires Akamai EdgeGrid credentials and a managed zone"]
    async fn integration_test() {
        let host = std::env::var("AKAMAI_HOST").unwrap_or_default();
        let client_token = std::env::var("AKAMAI_CLIENT_TOKEN").unwrap_or_default();
        let client_secret = std::env::var("AKAMAI_CLIENT_SECRET").unwrap_or_default();
        let access_token = std::env::var("AKAMAI_ACCESS_TOKEN").unwrap_or_default();
        let zone = std::env::var("AKAMAI_TEST_ZONE").unwrap_or_default();
        assert!(!host.is_empty(), "set AKAMAI_HOST");
        assert!(!client_token.is_empty(), "set AKAMAI_CLIENT_TOKEN");
        assert!(!client_secret.is_empty(), "set AKAMAI_CLIENT_SECRET");
        assert!(!access_token.is_empty(), "set AKAMAI_ACCESS_TOKEN");
        assert!(!zone.is_empty(), "set AKAMAI_TEST_ZONE");

        let provider = EdgeDnsProvider::new(EdgeDnsConfig {
            host,
            client_token,
            client_secret,
            access_token,
            account_switch_key: std::env::var("AKAMAI_ACCOUNT_SWITCH_KEY").ok(),
            request_timeout: Some(Duration::from_secs(30)),
        })
        .unwrap();

        let name = format!("dns-update-test.{zone}");
        let create_result = provider
            .create(
                &name,
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                &zone,
            )
            .await;
        assert!(create_result.is_ok(), "create: {:?}", create_result);
        let delete_result = provider.delete(&name, &zone, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete: {:?}", delete_result);
    }
}
