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
    use crate::providers::lightsail::{LightsailConfig, LightsailProvider};
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord};
    use mockito::Matcher;
    use serde_json::{Value, json};
    use std::time::Duration;

    fn provider_with_endpoint(endpoint: &str) -> LightsailProvider {
        let config = LightsailConfig {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
            region: Some("us-east-1".to_string()),
            domain: Some("example.com".to_string()),
            request_timeout: Some(Duration::from_secs(5)),
        };
        LightsailProvider::new(config).unwrap().with_endpoint(endpoint)
    }

    fn build_url(server_url: &str) -> String {
        server_url.trim_end_matches('/').to_string()
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .match_header("content-type", "application/x-amz-json-1.1")
            .match_body(Matcher::Json(json!({
                "domainName": "example.com",
                "domainEntry": {
                    "name": "www.example.com",
                    "target": "1.2.3.4",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
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
    async fn create_mx_record_serializes_priority() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainName": "example.com",
                "domainEntry": {
                    "name": "example.com",
                    "target": "10 mail.example.com.",
                    "type": "MX"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                300,
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
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainName": "example.com",
                "domainEntry": {
                    "name": "challenge.example.com",
                    "target": "\"abc123\"",
                    "type": "TXT"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .create(
                "challenge.example.com",
                DnsRecord::TXT("abc123".to_string()),
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
    async fn delete_record_lookups_then_deletes() {
        let mut server = mockito::Server::new_async().await;
        let get_domain_response = json!({
            "domain": {
                "name": "example.com",
                "domainEntries": [
                    {
                        "id": "entry-123",
                        "name": "www.example.com",
                        "target": "1.2.3.4",
                        "type": "A"
                    }
                ]
            }
        });
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(get_domain_response.to_string())
            .create_async()
            .await;

        let delete_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.DeleteDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainName": "example.com",
                "domainEntry": {
                    "id": "entry-123",
                    "name": "www.example.com",
                    "target": "1.2.3.4",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "delete failed: {:?}", result);
        get_mock.assert_async().await;
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_missing_record_is_ok() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": []
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok());
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_record_propagates_400_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .with_status(400)
            .with_body(r#"{"__type":"InvalidInputException","message":"bad"}"#)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .create(
                "bad.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn update_creates_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": []
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let create_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update failed: {:?}", result);
        get_mock.assert_async().await;
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn signs_authorization_header() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header(
                "authorization",
                Matcher::Regex(
                    "^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/.*lightsail/aws4_request.*"
                        .to_string(),
                ),
            )
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .create(
                "x.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {:?}", result);
        mock.assert_async().await;
    }

    #[test]
    fn updater_factory_creates_lightsail_variant() {
        let updater = DnsUpdater::new_lightsail(LightsailConfig {
            access_key_id: "id".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            region: None,
            domain: None,
            request_timeout: None,
        })
        .unwrap();
        assert!(matches!(updater, DnsUpdater::Lightsail(_)));
    }

    #[test]
    fn dns_record_serialization_smoke() {
        let value: Value = serde_json::from_str(r#"{"name":"x","target":"y","type":"A"}"#).unwrap();
        assert_eq!(value["type"], "A");
    }

    #[tokio::test]
    #[ignore = "Requires AWS credentials and a Lightsail-managed domain"]
    async fn integration_test() {
        let access = std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
        let secret = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
        let domain = std::env::var("LIGHTSAIL_DOMAIN").unwrap_or_default();
        let region = std::env::var("LIGHTSAIL_REGION").ok();
        assert!(!access.is_empty(), "set AWS_ACCESS_KEY_ID");
        assert!(!secret.is_empty(), "set AWS_SECRET_ACCESS_KEY");
        assert!(!domain.is_empty(), "set LIGHTSAIL_DOMAIN");

        let provider = LightsailProvider::new(LightsailConfig {
            access_key_id: access,
            secret_access_key: secret,
            session_token: None,
            region,
            domain: Some(domain.clone()),
            request_timeout: Some(Duration::from_secs(30)),
        })
        .unwrap();

        let test_name = format!("dns-update-test.{domain}");
        let create_result = provider
            .create(
                &test_name,
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                &domain,
            )
            .await;
        assert!(create_result.is_ok(), "create failed: {:?}", create_result);

        let delete_result = provider
            .delete(&test_name, &domain, DnsRecordType::A)
            .await;
        assert!(delete_result.is_ok(), "delete failed: {:?}", delete_result);
    }
}
