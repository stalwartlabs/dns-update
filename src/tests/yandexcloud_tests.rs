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

#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]

#[cfg(test)]
mod tests {
    use crate::{
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord,
        providers::yandexcloud::{YandexCloudConfig, YandexCloudProvider},
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn config() -> YandexCloudConfig {
        let key_json = json!({
            "id": "key-id",
            "service_account_id": "svc-account",
            "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            key_json.to_string().as_bytes(),
        );
        YandexCloudConfig {
            iam_token_b64: encoded,
            folder_id: "folder-1".into(),
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup_provider(iam: &str, dns: &str) -> YandexCloudProvider {
        YandexCloudProvider::new(config())
            .expect("provider")
            .with_endpoints(iam, dns)
            .with_cached_token("cached-token")
    }

    fn mock_zone_lookup(server: &mut ServerGuard, zone_apex: &str, zone_id: &str) -> Mock {
        let filter = format!("zone=\"{}.\"", zone_apex.trim_end_matches('.'));
        let response_zone = format!("{}.", zone_apex.trim_end_matches('.'));
        server
            .mock("GET", "/dns/v1/zones")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("folderId".into(), "folder-1".into()),
                Matcher::UrlEncoded("pageSize".into(), "100".into()),
                Matcher::UrlEncoded("filter".into(), filter),
            ]))
            .match_header("authorization", "Bearer cached-token")
            .with_status(200)
            .with_body(
                json!({
                    "dnsZones": [
                        {"id": zone_id, "zone": response_zone}
                    ],
                    "nextPageToken": "",
                })
                .to_string(),
            )
            .create()
    }

    fn mock_get_record_set(
        server: &mut ServerGuard,
        zone_id: &str,
        name: &str,
        record_type: &str,
        response: Option<serde_json::Value>,
    ) -> Mock {
        let mock = server
            .mock(
                "GET",
                format!("/dns/v1/zones/{zone_id}:getRecordSet").as_str(),
            )
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), name.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
            ]))
            .match_header("authorization", "Bearer cached-token");
        match response {
            Some(body) => mock.with_status(200).with_body(body.to_string()).create(),
            None => mock.with_status(404).with_body("{}").create(),
        }
    }

    fn mock_upsert(
        server: &mut ServerGuard,
        zone_id: &str,
        expected_body: serde_json::Value,
    ) -> Mock {
        server
            .mock(
                "POST",
                format!("/dns/v1/zones/{zone_id}:upsertRecordSets").as_str(),
            )
            .match_header("authorization", "Bearer cached-token")
            .match_body(Matcher::Json(expected_body))
            .with_status(200)
            .with_body("{}")
            .create()
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_yandexcloud(config());
        assert!(matches!(updater, Ok(DnsUpdater::YandexCloud(..))));
    }

    #[test]
    fn missing_folder_rejected() {
        let cfg = YandexCloudConfig {
            iam_token_b64: "abc".into(),
            folder_id: String::new(),
            request_timeout: None,
        };
        assert!(YandexCloudProvider::new(cfg).is_err());
    }

    #[tokio::test]
    async fn list_zones_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/dns/v1/zones")
            .match_query(Matcher::Any)
            .with_status(401)
            .create();
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got: {:?}",
            result
        );
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_with_no_existing_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(&mut server, "zone-1", "missing", "A", None);
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "missing.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zones.assert();
        get.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_existing() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(
            &mut server,
            "zone-1",
            "doomed",
            "A",
            Some(json!({
                "name": "doomed",
                "type": "A",
                "ttl": 600,
                "data": ["1.2.3.4", "5.6.7.8"],
            })),
        );
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [{
                    "name": "doomed",
                    "type": "A",
                    "ttl": 600,
                    "data": ["1.2.3.4", "5.6.7.8"],
                }],
                "replacements": [],
                "merges": [],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "doomed.example.com",
                DnsRecordType::A,
                0,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zones.assert();
        get.assert();
        upsert.assert();
    }

    #[tokio::test]
    async fn set_rrset_replaces_with_multiple_records() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [],
                "replacements": [{
                    "name": "mail",
                    "type": "MX",
                    "ttl": 600,
                    "data": ["10 mx1.example.com.", "20 mx2.example.com."],
                }],
                "merges": [],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "mail.example.com",
                DnsRecordType::MX,
                600,
                vec![
                    DnsRecord::MX(MXRecord {
                        priority: 10,
                        exchange: "mx1.example.com".into(),
                    }),
                    DnsRecord::MX(MXRecord {
                        priority: 20,
                        exchange: "mx2.example.com".into(),
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zones.assert();
        upsert.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_mismatched_record_type() {
        let provider = setup_provider("http://localhost:1", "http://localhost:1");
        let result = provider
            .set_rrset(
                "x.example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::AAAA("::1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "expected type mismatch, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn set_rrset_rejects_tlsa() {
        let provider = setup_provider("http://localhost:1", "http://localhost:1");
        let result = provider
            .set_rrset(
                "x.example.com",
                DnsRecordType::TLSA,
                60,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref m)) if m.contains("TLSA")),
            "expected TLSA rejection, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn add_to_rrset_empty_is_noop() {
        let provider = setup_provider("http://localhost:1", "http://localhost:1");
        let result = provider
            .add_to_rrset("x.example.com", DnsRecordType::A, 60, vec![], "example.com")
            .await;
        assert!(
            result.is_ok(),
            "add_to_rrset(empty) should be noop: {result:?}"
        );
    }

    #[tokio::test]
    async fn add_to_rrset_uses_merges() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(&mut server, "zone-1", "test", "A", None);
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [],
                "replacements": [],
                "merges": [{
                    "name": "test",
                    "type": "A",
                    "ttl": 300,
                    "data": ["9.9.9.9"],
                }],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        zones.assert();
        get.assert();
        upsert.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_is_noop() {
        let provider = setup_provider("http://localhost:1", "http://localhost:1");
        let result = provider
            .remove_from_rrset("x.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(
            result.is_ok(),
            "remove_from_rrset(empty) should be noop: {result:?}"
        );
    }

    #[tokio::test]
    async fn remove_from_rrset_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(&mut server, "zone-1", "x", "A", None);
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "x.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        zones.assert();
        get.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_filters_and_replaces() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(
            &mut server,
            "zone-1",
            "test",
            "A",
            Some(json!({
                "name": "test",
                "type": "A",
                "ttl": 300,
                "data": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            })),
        );
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [],
                "replacements": [{
                    "name": "test",
                    "type": "A",
                    "ttl": 300,
                    "data": ["1.1.1.1", "3.3.3.3"],
                }],
                "merges": [],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        zones.assert();
        get.assert();
        upsert.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_last_record_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(
            &mut server,
            "zone-1",
            "test",
            "A",
            Some(json!({
                "name": "test",
                "type": "A",
                "ttl": 300,
                "data": ["1.1.1.1"],
            })),
        );
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [{
                    "name": "test",
                    "type": "A",
                    "ttl": 300,
                    "data": ["1.1.1.1"],
                }],
                "replacements": [],
                "merges": [],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        zones.assert();
        get.assert();
        upsert.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(
            &mut server,
            "zone-1",
            "test",
            "A",
            Some(json!({
                "name": "test",
                "type": "A",
                "ttl": 300,
                "data": ["1.1.1.1"],
            })),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        zones.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(
            &mut server,
            "zone-1",
            "test",
            "A",
            Some(json!({
                "name": "test",
                "type": "A",
                "ttl": 300,
                "data": ["1.1.1.1", "2.2.2.2"],
            })),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset failed: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], DnsRecord::A("1.1.1.1".parse().unwrap()));
        assert_eq!(records[1], DnsRecord::A("2.2.2.2".parse().unwrap()));
        zones.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_404_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let get = mock_get_record_set(&mut server, "zone-1", "absent", "TXT", None);
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .list_rrset("absent.example.com", DnsRecordType::TXT, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset failed: {result:?}");
        assert!(result.unwrap().is_empty());
        zones.assert();
        get.assert();
    }

    #[tokio::test]
    async fn list_rrset_rejects_tlsa() {
        let provider = setup_provider("http://localhost:1", "http://localhost:1");
        let result = provider
            .list_rrset("x.example.com", DnsRecordType::TLSA, "example.com")
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref m)) if m.contains("TLSA")),
            "expected TLSA rejection, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn set_rrset_at_apex_uses_at_subdomain() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [],
                "replacements": [{
                    "name": "@",
                    "type": "TXT",
                    "ttl": 300,
                    "data": ["v=spf1 -all"],
                }],
                "merges": [],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("v=spf1 -all".into())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zones.assert();
        upsert.assert();
    }

    #[tokio::test]
    async fn set_rrset_txt_short_value_is_unquoted() {
        let mut server = mockito::Server::new_async().await;
        let zones = mock_zone_lookup(&mut server, "example.com", "zone-1");
        let upsert = mock_upsert(
            &mut server,
            "zone-1",
            json!({
                "deletions": [],
                "replacements": [{
                    "name": "txt",
                    "type": "TXT",
                    "ttl": 60,
                    "data": ["hello world"],
                }],
                "merges": [],
            }),
        );
        let provider = setup_provider(server.url().as_str(), server.url().as_str());
        let result = provider
            .set_rrset(
                "txt.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("hello world".into())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zones.assert();
        upsert.assert();
    }
}
