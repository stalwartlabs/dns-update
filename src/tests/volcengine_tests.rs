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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord,
        providers::volcengine::{VolcengineConfig, VolcengineProvider},
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    fn config() -> VolcengineConfig {
        VolcengineConfig {
            access_key: "AKID-test".into(),
            secret_key: "secret-test".into(),
            region: Some("cn-north-1".into()),
            host: None,
            scheme: Some("http".into()),
            request_timeout: Some(Duration::from_secs(2)),
        }
    }

    fn setup_provider(endpoint: &str) -> VolcengineProvider {
        VolcengineProvider::new(config())
            .expect("provider")
            .with_endpoint(endpoint)
    }

    fn mock_list_zones(server: &mut ServerGuard, zone_name: &str, zone_id: i64) -> Mock {
        server
            .mock("POST", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("Action".into(), "ListZones".into()),
                Matcher::UrlEncoded("Version".into(), "2018-08-01".into()),
            ]))
            .with_status(200)
            .with_body(
                json!({
                    "Result": {
                        "Total": 1,
                        "Zones": [{"ZID": zone_id, "ZoneName": zone_name}]
                    }
                })
                .to_string(),
            )
            .create()
    }

    fn mock_list_records(
        server: &mut ServerGuard,
        host: &str,
        record_type: &str,
        records: Value,
    ) -> Mock {
        server
            .mock("POST", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("Action".into(), "ListRecords".into()),
                Matcher::UrlEncoded("Version".into(), "2018-08-01".into()),
            ]))
            .match_body(Matcher::PartialJson(json!({
                "Host": host,
                "Type": record_type,
            })))
            .with_status(200)
            .with_body(
                json!({
                    "Result": {
                        "Total": records.as_array().map(|a| a.len()).unwrap_or(0),
                        "Records": records,
                    }
                })
                .to_string(),
            )
            .create()
    }

    fn mock_create_record(server: &mut ServerGuard, body_matcher: Value, record_id: &str) -> Mock {
        server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "CreateRecord".into()))
            .match_body(Matcher::PartialJson(body_matcher))
            .with_status(200)
            .with_body(json!({"Result": {"RecordID": record_id}}).to_string())
            .create()
    }

    fn mock_delete_record(server: &mut ServerGuard, record_id: &str) -> Mock {
        server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "DeleteRecord".into()))
            .match_body(Matcher::JsonString(
                json!({"RecordID": record_id}).to_string(),
            ))
            .with_status(200)
            .with_body("{}")
            .create()
    }

    #[test]
    fn test_dns_updater_creation() {
        let updater = DnsUpdater::new_volcengine(config());
        assert!(matches!(updater, Ok(DnsUpdater::Volcengine(..))));
    }

    #[test]
    fn test_missing_credentials_rejected() {
        let cfg = VolcengineConfig {
            access_key: String::new(),
            secret_key: String::new(),
            region: None,
            host: None,
            scheme: None,
            request_timeout: None,
        };
        assert!(VolcengineProvider::new(cfg).is_err());
    }

    #[tokio::test]
    async fn test_list_zones_unauthorized_propagates() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "ListZones".into()))
            .with_status(401)
            .with_body("unauthorized")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)), "got {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(&mut server, "host", "A", json!([]));
        let create1 = mock_create_record(
            &mut server,
            json!({
                "ZID": 42, "Host": "host", "Type": "A", "Value": "1.1.1.1", "TTL": 300,
            }),
            "rec-1",
        );
        let create2 = mock_create_record(
            &mut server,
            json!({
                "ZID": 42, "Host": "host", "Type": "A", "Value": "2.2.2.2", "TTL": 300,
            }),
            "rec-2",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        create1.assert();
        create2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(
            &mut server,
            "host",
            "A",
            json!([
                {"RecordID": "rec-1", "Host": "host", "Type": "A", "Value": "1.1.1.1"}
            ]),
        );
        let _no_create = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "CreateRecord".into()))
            .expect(0)
            .create();
        let _no_delete = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "DeleteRecord".into()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diff_deletes_extras_and_adds_new() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(
            &mut server,
            "host",
            "A",
            json!([
                {"RecordID": "rec-keep", "Host": "host", "Type": "A", "Value": "1.1.1.1"},
                {"RecordID": "rec-stale", "Host": "host", "Type": "A", "Value": "9.9.9.9"}
            ]),
        );
        let delete_stale = mock_delete_record(&mut server, "rec-stale");
        let create_new = mock_create_record(
            &mut server,
            json!({
                "ZID": 42, "Host": "host", "Type": "A", "Value": "8.8.8.8", "TTL": 300,
            }),
            "rec-new",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_for_type() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 7);
        let list = mock_list_records(
            &mut server,
            "gone",
            "A",
            json!([
                {"RecordID": "rec-x", "Host": "gone", "Type": "A", "Value": "1.2.3.4"},
                {"RecordID": "rec-y", "Host": "gone", "Type": "A", "Value": "5.6.7.8"}
            ]),
        );
        let dx = mock_delete_record(&mut server, "rec-x");
        let dy = mock_delete_record(&mut server, "rec-y");

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "gone.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        dx.assert();
        dy.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);

        let list_a = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "ListRecords".into()))
            .match_body(Matcher::PartialJson(json!({
                "Host": "shared", "Type": "A",
            })))
            .with_status(200)
            .with_body(
                json!({
                    "Result": {"Total": 0, "Records": []}
                })
                .to_string(),
            )
            .expect(1)
            .create();

        let txt_list_must_not_fire = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "ListRecords".into()))
            .match_body(Matcher::PartialJson(json!({
                "Host": "shared", "Type": "TXT",
            })))
            .expect(0)
            .create();

        let create = mock_create_record(
            &mut server,
            json!({
                "ZID": 42, "Host": "shared", "Type": "A", "Value": "1.1.1.1", "TTL": 300,
            }),
            "rec-a",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list_a.assert();
        txt_list_must_not_fire.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(
            &mut server,
            "_acme",
            "TXT",
            json!([
                {"RecordID": "rec-old", "Host": "_acme", "Type": "TXT", "Value": "\"existing\""}
            ]),
        );
        let create = mock_create_record(
            &mut server,
            json!({
                "ZID": 42, "Host": "_acme", "Type": "TXT", "Value": "\"new-token\"", "TTL": 60,
            }),
            "rec-new",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", "/").expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(
            &mut server,
            "_acme",
            "TXT",
            json!([
                {"RecordID": "rec-keep", "Host": "_acme", "Type": "TXT", "Value": "\"keep-me\""},
                {"RecordID": "rec-drop", "Host": "_acme", "Type": "TXT", "Value": "\"drop-me\""}
            ]),
        );
        let del = mock_delete_record(&mut server, "rec-drop");

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("POST", "/").expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(
            &mut server,
            "test",
            "A",
            json!([
                {"RecordID": "rec-1", "Host": "test", "Type": "A", "Value": "1.1.1.1"}
            ]),
        );
        let _no_delete = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "DeleteRecord".into()))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_priority_encoded_in_value_not_weight() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(&mut server, "@", "MX", json!([]));

        let create = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "CreateRecord".into()))
            .match_body(Matcher::JsonString(
                json!({
                    "ZID": 42,
                    "Host": "@",
                    "Type": "MX",
                    "Value": "10 mail.example.com",
                    "TTL": 3600,
                })
                .to_string(),
            ))
            .with_status(200)
            .with_body(json!({"Result": {"RecordID": "rec-mx"}}).to_string())
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_value_format() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(&mut server, "_imaps._tcp", "SRV", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "ZID": 42,
                "Host": "_imaps._tcp",
                "Type": "SRV",
                "Value": "10 5 993 mail.example.com",
                "TTL": 3600,
            }),
            "rec-srv",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_imaps._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_value_format() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(&mut server, "@", "CAA", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "ZID": 42,
                "Host": "@",
                "Type": "CAA",
                "Value": "0 issue \"letsencrypt.org\"",
                "TTL": 3600,
            }),
            "rec-caa",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                3600,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unsupported(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_signing_uses_lowercase_dns_service_code() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("POST", "/")
            .match_query(Matcher::UrlEncoded("Action".into(), "ListZones".into()))
            .match_header("authorization", Matcher::Regex("/dns/request".into()))
            .with_status(200)
            .with_body(
                json!({
                    "Result": {
                        "Total": 1,
                        "Zones": [{"ZID": 1, "ZoneName": "example.com"}]
                    }
                })
                .to_string(),
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::A, "example.com")
            .await;
        let _ = result;
        zone.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(
            &mut server,
            "host",
            "MX",
            json!([
                {"RecordID": "rec-1", "Host": "host", "Type": "MX", "Value": "10 mail1.example.com"},
                {"RecordID": "rec-2", "Host": "host", "Type": "MX", "Value": "20 mail2.example.com"}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::MX, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset failed: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            exchange: "mail1.example.com".to_string(),
            priority: 10,
        })));
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            exchange: "mail2.example.com".to_string(),
            priority: 20,
        })));
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_apex_host_uses_at_sign() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_list_zones(&mut server, "example.com", 42);
        let list = mock_list_records(&mut server, "@", "A", json!([]));
        let create = mock_create_record(
            &mut server,
            json!({
                "ZID": 42, "Host": "@", "Type": "A", "Value": "1.2.3.4", "TTL": 60,
            }),
            "rec-apex",
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires VOLC_ACCESSKEY, VOLC_SECRETKEY, VOLC_ORIGIN, VOLC_FQDN"]
    async fn integration_test() {
        let access_key = std::env::var("VOLC_ACCESSKEY").unwrap_or_default();
        let secret_key = std::env::var("VOLC_SECRETKEY").unwrap_or_default();
        let origin = std::env::var("VOLC_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("VOLC_FQDN").unwrap_or_default();
        assert!(!access_key.is_empty() && !secret_key.is_empty());
        assert!(!origin.is_empty() && !fqdn.is_empty());

        let provider = VolcengineProvider::new(VolcengineConfig {
            access_key,
            secret_key,
            region: None,
            host: None,
            scheme: None,
            request_timeout: Some(Duration::from_secs(30)),
        })
        .unwrap();

        provider
            .set_rrset(
                fqdn.as_str(),
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([1, 1, 1, 1].into())],
                origin.as_str(),
            )
            .await
            .expect("set_rrset failed");
        provider
            .set_rrset(
                fqdn.as_str(),
                DnsRecordType::A,
                300,
                vec![],
                origin.as_str(),
            )
            .await
            .expect("cleanup failed");
    }
}
