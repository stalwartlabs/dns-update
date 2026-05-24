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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error};
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
        LightsailProvider::new(config)
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn build_url(server_url: &str) -> String {
        server_url.trim_end_matches('/').to_string()
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
    async fn set_rrset_empty_vec_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-a",
                                "name": "www.example.com",
                                "target": "1.1.1.1",
                                "type": "A"
                            },
                            {
                                "id": "id-b",
                                "name": "www.example.com",
                                "target": "::1",
                                "type": "AAAA"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.DeleteDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainName": "example.com",
                "domainEntry": {
                    "id": "id-a",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_diffs_creates_missing_and_deletes_extras() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-keep",
                                "name": "www.example.com",
                                "target": "1.1.1.1",
                                "type": "A"
                            },
                            {
                                "id": "id-drop",
                                "name": "www.example.com",
                                "target": "9.9.9.9",
                                "type": "A"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.DeleteDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainEntry": { "id": "id-drop" }
            })))
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let create_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainName": "example.com",
                "domainEntry": {
                    "name": "www.example.com",
                    "target": "2.2.2.2",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        delete_mock.assert_async().await;
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_idempotent_no_writes_when_matched() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-1",
                                "name": "www.example.com",
                                "target": "1.1.1.1",
                                "type": "A"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {:?}", result);
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn set_rrset_rejects_caa() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn set_rrset_rejects_tlsa() {
        let provider = provider_with_endpoint("http://127.0.0.1:1");
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn add_to_rrset_empty_vec_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {:?}", result);
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-1",
                                "name": "www.example.com",
                                "target": "1.1.1.1",
                                "type": "A"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let create_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.CreateDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainEntry": {
                    "name": "www.example.com",
                    "target": "2.2.2.2",
                    "type": "A"
                }
            })))
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_vec_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {:?}", result);
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_present_skips_absent() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-1",
                                "name": "www.example.com",
                                "target": "1.1.1.1",
                                "type": "A"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let delete_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.DeleteDomainEntry")
            .match_body(Matcher::PartialJson(json!({
                "domainEntry": { "id": "id-1" }
            })))
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {:?}", result);
        get_mock.assert_async().await;
        delete_mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_returns_filtered_records() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-a",
                                "name": "www.example.com",
                                "target": "1.1.1.1",
                                "type": "A"
                            },
                            {
                                "id": "id-b",
                                "name": "www.example.com",
                                "target": "2.2.2.2",
                                "type": "A"
                            },
                            {
                                "id": "id-c",
                                "name": "www.example.com",
                                "target": "::1",
                                "type": "AAAA"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_unquotes_txt() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-t",
                                "name": "challenge.example.com",
                                "target": "\"abc123\"",
                                "type": "TXT"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .list_rrset("challenge.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result, vec![DnsRecord::TXT("abc123".to_string())]);
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_rrset_unquotes_chunked_txt() {
        let mut server = mockito::Server::new_async().await;
        let chunked_target = format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(45));
        let get_mock = server
            .mock("POST", "/")
            .match_header("x-amz-target", "Lightsail_20161128.GetDomain")
            .with_status(200)
            .with_body(
                json!({
                    "domain": {
                        "name": "example.com",
                        "domainEntries": [
                            {
                                "id": "id-t",
                                "name": "long.example.com",
                                "target": chunked_target,
                                "type": "TXT"
                            }
                        ]
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = provider_with_endpoint(&build_url(&server.url()));
        let result = provider
            .list_rrset("long.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result, vec![DnsRecord::TXT("a".repeat(300))]);
        get_mock.assert_async().await;
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
        let set_result = provider
            .set_rrset(
                &test_name,
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                &domain,
            )
            .await;
        assert!(set_result.is_ok(), "set_rrset failed: {:?}", set_result);

        let listed = provider
            .list_rrset(&test_name, DnsRecordType::A, &domain)
            .await
            .expect("list_rrset failed");
        assert_eq!(listed.len(), 2);

        let cleanup = provider
            .set_rrset(&test_name, DnsRecordType::A, 300, Vec::new(), &domain)
            .await;
        assert!(cleanup.is_ok(), "cleanup failed: {:?}", cleanup);
    }
}
