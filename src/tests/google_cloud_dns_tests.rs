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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord,
        providers::google_cloud_dns::{GoogleCloudDnsConfig, GoogleCloudDnsProvider},
    };
    use serde_json::json;
    use std::time::Duration;

    fn service_account_json() -> String {
        json!({
            "client_email": "svc@example.iam.gserviceaccount.com",
            "private_key": "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
            "token_uri": "https://oauth2.googleapis.com/token"
        })
        .to_string()
    }

    fn config() -> GoogleCloudDnsConfig {
        GoogleCloudDnsConfig {
            service_account_json: service_account_json(),
            project_id: "test-project".to_string(),
            managed_zone: Some("example-zone".to_string()),
            private_zone: false,
            impersonate_service_account: None,
            request_timeout: Some(Duration::from_secs(1)),
        }
    }

    fn setup_provider(dns_base_url: &str, iam_base_url: &str) -> GoogleCloudDnsProvider {
        GoogleCloudDnsProvider::new(config())
            .expect("provider")
            .with_endpoints(dns_base_url, iam_base_url)
            .with_cached_token("cached-token")
    }

    #[tokio::test]
    async fn impersonation_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/v1/projects/-/serviceAccounts/impersonated@example.iam.gserviceaccount.com:generateAccessToken",
            )
            .match_header("authorization", "Bearer source-token")
            .match_body(mockito::Matcher::Json(json!({
                "scope": ["https://www.googleapis.com/auth/ndev.clouddns.readwrite"],
                "lifetime": "3600s"
            })))
            .with_status(200)
            .with_body(r#"{"accessToken":"impersonated-token"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .impersonate_access_token(
                "source-token",
                "impersonated@example.iam.gserviceaccount.com",
            )
            .await;

        assert_eq!(result.expect("token"), "impersonated-token");
        mock.assert();
    }

    #[tokio::test]
    async fn impersonation_failure_mapping() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/v1/projects/-/serviceAccounts/impersonated@example.iam.gserviceaccount.com:generateAccessToken",
            )
            .with_status(403)
            .with_body(r#"{"error":{"message":"permission denied"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .impersonate_access_token(
                "source-token",
                "impersonated@example.iam.gserviceaccount.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_no_existing_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "missing.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "missing.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_existing() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1"]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "deletions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-del"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_replaces_existing_with_multiple_records() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1"]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 120,
                    "rrdatas": ["2.2.2.2", "3.3.3.3"]
                }],
                "deletions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-replace"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                120,
                vec![
                    DnsRecord::A("2.2.2.2".parse().expect("ipv4")),
                    DnsRecord::A("3.3.3.3".parse().expect("ipv4")),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_idempotent_skips_when_unchanged() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1"]}]}"#)
            .expect(1)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .expect(0)
            .with_status(200)
            .with_body(r#"{"id":"unused"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().expect("ipv4"))],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".into())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")));
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_to_rrset_creates_union_with_existing() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1"]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1", "2.2.2.2"]
                }],
                "deletions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-add"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().expect("ipv4")),
                    DnsRecord::A("2.2.2.2".parse().expect("ipv4")),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_idempotent_when_all_present() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1","2.2.2.2"]}]}"#)
            .expect(1)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .expect(0)
            .with_status(200)
            .with_body(r#"{}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().expect("ipv4")),
                    DnsRecord::A("2.2.2.2".parse().expect("ipv4")),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_creates_new_rrset_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "fresh.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "fresh.example.com.",
                    "type": "A",
                    "ttl": 60,
                    "rrdatas": ["9.9.9.9"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-fresh"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "fresh.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("9.9.9.9".parse().expect("ipv4"))],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_from_rrset_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "absent.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "absent.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().expect("ipv4"))],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
        list_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1"]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .expect(0)
            .with_status(200)
            .with_body(r#"{}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().expect("ipv4"))],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_removes_subset_keeps_rest() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1","2.2.2.2"]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["2.2.2.2"]
                }],
                "deletions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1", "2.2.2.2"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-subset"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().expect("ipv4"))],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_removes_all_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1"]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "deletions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-all"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().expect("ipv4"))],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"A","ttl":300,"rrdatas":["1.1.1.1","2.2.2.2"]}]}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list");

        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().expect("ipv4")),
                DnsRecord::A("2.2.2.2".parse().expect("ipv4")),
            ]
        );
        list_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_missing_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "absent.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .list_rrset("absent.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list");

        assert!(result.is_empty());
        list_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_parses_each_supported_type() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "host.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "MX".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"host.example.com.","type":"MX","ttl":60,"rrdatas":["10 mail.example.com."]}]}"#)
            .create();
        server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "host.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"host.example.com.","type":"TXT","ttl":60,"rrdatas":["\"hello world\""]}]}"#)
            .create();
        server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "_sip._tcp.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "SRV".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"_sip._tcp.example.com.","type":"SRV","ttl":60,"rrdatas":["5 10 443 sip.example.com."]}]}"#)
            .create();
        server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "host.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "CAA".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"host.example.com.","type":"CAA","ttl":60,"rrdatas":["0 issue \"letsencrypt.org\""]}]}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());

        let mx = provider
            .list_rrset("host.example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("mx");
        assert_eq!(
            mx,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".into(),
                priority: 10,
            })]
        );

        let txt = provider
            .list_rrset("host.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("txt");
        assert_eq!(txt, vec![DnsRecord::TXT("hello world".into())]);

        let srv = provider
            .list_rrset("_sip._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await
            .expect("srv");
        assert_eq!(
            srv,
            vec![DnsRecord::SRV(SRVRecord {
                target: "sip.example.com".into(),
                priority: 5,
                weight: 10,
                port: 443,
            })]
        );

        let caa = provider
            .list_rrset("host.example.com", DnsRecordType::CAA, "example.com")
            .await
            .expect("caa");
        assert_eq!(
            caa,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".into()),
                options: vec![],
            })]
        );
    }

    #[tokio::test]
    async fn add_to_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".into())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")));
    }

    #[tokio::test]
    async fn remove_from_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("nope".into())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")));
    }
}
