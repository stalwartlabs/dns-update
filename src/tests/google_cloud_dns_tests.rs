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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, KeyValue, MXRecord, SRVRecord,
        TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
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

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_google_cloud_dns(config());

        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::GoogleCloudDns(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_header("authorization", "Bearer cached-token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "test.example.com.",
                    "type": "A",
                    "ttl": 300,
                    "rrdatas": ["1.1.1.1"]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-1"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().expect("ipv4")),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "test.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .match_header("authorization", "Bearer cached-token")
            .with_status(200)
            .with_body(r#"{"rrsets":[{"name":"test.example.com.","type":"TXT","ttl":60,"rrdatas":["\"old\""]}]}"#)
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_header("authorization", "Bearer cached-token")
            .match_body(mockito::Matcher::Json(json!({
                "additions": [{
                    "name": "test.example.com.",
                    "type": "TXT",
                    "ttl": 120,
                    "rrdatas": ["\"new value\""]
                }],
                "deletions": [{
                    "name": "test.example.com.",
                    "type": "TXT",
                    "ttl": 60,
                    "rrdatas": ["\"old\""]
                }]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-2"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::TXT("new value".to_string()),
                120,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
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
        let delete_mock = server
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
            .with_body(r#"{"id":"change-3"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn resolve_managed_zone_uses_longest_suffix_match() {
        let mut server = mockito::Server::new_async().await;
        let zones_mock = server
            .mock("GET", "/dns/v1/projects/test-project/managedZones")
            .match_header("authorization", "Bearer cached-token")
            .with_status(200)
            .with_body(
                r#"{"managedZones":[{"name":"example-zone","dnsName":"example.com.","visibility":"public"},{"name":"dev-zone","dnsName":"dev.example.com.","visibility":"public"}]}"#,
            )
            .create();
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/dev-zone/changes",
            )
            .with_status(200)
            .with_body(r#"{"id":"change-dev"}"#)
            .create();

        let mut cfg = config();
        cfg.managed_zone = None;
        let provider = GoogleCloudDnsProvider::new(cfg)
            .expect("provider")
            .with_endpoints(server.url().as_str(), server.url().as_str())
            .with_cached_token("cached-token");

        let zone = provider
            .create(
                "api.dev.example.com",
                DnsRecord::A("1.1.1.1".parse().expect("ipv4")),
                300,
                "example.com",
            )
            .await;

        assert!(zone.is_ok());
        zones_mock.assert();
        change_mock.assert();
    }

    #[tokio::test]
    async fn resolve_managed_zone_filters_private_zones() {
        let mut server = mockito::Server::new_async().await;
        let zones_mock = server
            .mock("GET", "/dns/v1/projects/test-project/managedZones")
            .with_status(200)
            .with_body(
                r#"{"managedZones":[{"name":"public-zone","dnsName":"example.com.","visibility":"public"},{"name":"private-zone","dnsName":"example.com.","visibility":"private"}]}"#,
            )
            .create();
        let create_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/private-zone/changes",
            )
            .with_status(200)
            .with_body(r#"{"id":"change-private"}"#)
            .create();

        let mut cfg = config();
        cfg.managed_zone = None;
        cfg.private_zone = true;
        let provider = GoogleCloudDnsProvider::new(cfg)
            .expect("provider")
            .with_endpoints(server.url().as_str(), server.url().as_str())
            .with_cached_token("cached-token");

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().expect("ipv4")),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        zones_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn delete_missing_record_is_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock(
                "GET",
                "/dns/v1/projects/test-project/managedZones/example-zone/rrsets",
            )
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "missing.example.com.".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        list_mock.assert();
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
    async fn record_serialization_cases() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/dns/v1/projects/test-project/managedZones/example-zone/changes",
            )
            .match_body(mockito::Matcher::Json(json!({
                "additions": [
                    {
                        "name": "text.example.com.",
                        "type": "TXT",
                        "ttl": 60,
                        "rrdatas": ["\"hello \\\"world\\\"\""]
                    }
                ]
            })))
            .with_status(200)
            .with_body(r#"{"id":"change-text"}"#)
            .create();

        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .create(
                "text.example.com",
                DnsRecord::TXT("hello \"world\"".to_string()),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();

        let tlsa = TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(tlsa.to_string(), "3 1 1 deadbeef");

        let caa = CAARecord::Issue {
            issuer_critical: false,
            name: Some("letsencrypt.org".to_string()),
            options: vec![KeyValue {
                key: "accounturi".to_string(),
                value: "https://example.test/acct/1".to_string(),
            }],
        };
        let (flags, tag, value) = caa.clone().decompose();
        assert_eq!(flags, 0);
        assert_eq!(tag, "issue");
        assert_eq!(
            value,
            "letsencrypt.org; accounturi=https://example.test/acct/1"
        );

        let mx = MXRecord {
            exchange: "mail.example.com".to_string(),
            priority: 10,
        };
        assert_eq!(mx.to_string(), "10 mail.example.com");

        let srv = SRVRecord {
            target: "sip.example.com".to_string(),
            priority: 5,
            weight: 10,
            port: 443,
        };
        assert_eq!(srv.to_string(), "5 10 443 sip.example.com");
    }
}
