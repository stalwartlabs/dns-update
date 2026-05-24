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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::dynu::DynuProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN_ID: i64 = 9007481;

    fn setup_provider(endpoint: String) -> DynuProvider {
        DynuProvider::new("test_key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_get_root(server: &mut ServerGuard, hostname: &str, domain_name: &str) -> Mock {
        server
            .mock("GET", format!("/dns/getroot/{hostname}").as_str())
            .match_header("api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"statusCode":200,"id":{DOMAIN_ID},"domainName":"{domain_name}","hostname":"{hostname}","node":"sub"}}"#
            ))
            .create()
    }

    fn mock_list_records(
        server: &mut ServerGuard,
        hostname: &str,
        record_type: &str,
        body: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", format!("/dns/record/{hostname}").as_str())
            .match_query(Matcher::UrlEncoded("recordType".into(), record_type.into()))
            .match_header("api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create()
    }

    fn ok_records(items: serde_json::Value) -> serde_json::Value {
        json!({"statusCode": 200, "dnsRecords": items})
    }

    fn ok_body() -> &'static str {
        r#"{"statusCode":200}"#
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let list = mock_list_records(&mut server, "host.example.com", "A", ok_records(json!([])));

        let create_1 = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "recordType": "A",
                "domainName": "example.com",
                "nodeName": "host",
                "hostname": "host.example.com",
                "state": true,
                "ttl": 300,
                "ipv4Address": "1.1.1.1",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create_2 = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "recordType": "A",
                "domainName": "example.com",
                "nodeName": "host",
                "hostname": "host.example.com",
                "state": true,
                "ttl": 300,
                "ipv4Address": "2.2.2.2",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "host.example.com",
            "A",
            ok_records(json!([
                {
                    "id": 1,
                    "recordType": "A",
                    "hostname": "host.example.com",
                    "ipv4Address": "1.1.1.1"
                }
            ])),
        );
        let no_post = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .expect(0)
            .create();
        let no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dns/{DOMAIN_ID}/record/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        no_post.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "host.example.com",
            "A",
            ok_records(json!([
                {"id": 100, "recordType": "A", "hostname": "host.example.com", "ipv4Address": "1.1.1.1"},
                {"id": 200, "recordType": "A", "hostname": "host.example.com", "ipv4Address": "9.9.9.9"}
            ])),
        );
        let delete_stale = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/200").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create_new = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "recordType": "A",
                "hostname": "host.example.com",
                "ipv4Address": "8.8.8.8",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "gone.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "gone.example.com",
            "A",
            ok_records(json!([
                {"id": 11, "recordType": "A", "hostname": "gone.example.com", "ipv4Address": "1.2.3.4"},
                {"id": 22, "recordType": "A", "hostname": "gone.example.com", "ipv4Address": "5.6.7.8"}
            ])),
        );
        let del_a = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/11").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();
        let del_b = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/22").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "gone.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        del_a.assert();
        del_b.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_on_empty_owner_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "fresh.example.com", "example.com");
        let list = mock_list_records(&mut server, "fresh.example.com", "A", ok_records(json!([])));
        let no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();
        let no_post = server.mock("POST", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "fresh.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        no_delete.assert();
        no_post.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "_acme.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "_acme.example.com",
            "TXT",
            ok_records(json!([
                {"id": 7, "recordType": "TXT", "hostname": "_acme.example.com", "textData": "existing"}
            ])),
        );
        let create_new = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "recordType": "TXT",
                "textData": "new-token",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        root.assert();
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        no_call.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "_acme.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "_acme.example.com",
            "TXT",
            ok_records(json!([
                {"id": 41, "recordType": "TXT", "hostname": "_acme.example.com", "textData": "keep-me"},
                {"id": 42, "recordType": "TXT", "hostname": "_acme.example.com", "textData": "drop-me"}
            ])),
        );
        let delete = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/42").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();
        let no_other_delete = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/41").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        root.assert();
        list.assert();
        delete.assert();
        no_other_delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_early_return() {
        let mut server = mockito::Server::new_async().await;
        let no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        no_call.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_values_absent() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "host.example.com",
            "A",
            ok_records(json!([
                {"id": 1, "recordType": "A", "hostname": "host.example.com", "ipv4Address": "1.1.1.1"}
            ])),
        );
        let no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        root.assert();
        list.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_api_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_filters_by_type_protects_other_types_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "shared.example.com", "example.com");
        let list_a = server
            .mock("GET", "/dns/record/shared.example.com")
            .match_query(Matcher::UrlEncoded("recordType".into(), "A".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_records(json!([])).to_string())
            .expect(1)
            .create();
        let no_txt_get = server
            .mock("GET", "/dns/record/shared.example.com")
            .match_query(Matcher::UrlEncoded("recordType".into(), "TXT".into()))
            .expect(0)
            .create();
        let create = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "recordType": "A",
                "hostname": "shared.example.com",
                "ipv4Address": "1.1.1.1",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list_a.assert();
        no_txt_get.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_empty_node_name() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "example.com", "example.com");
        let list = mock_list_records(&mut server, "example.com", "MX", ok_records(json!([])));
        let create = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "recordType": "MX",
                "domainName": "example.com",
                "nodeName": "",
                "hostname": "example.com",
                "state": true,
                "ttl": 3600,
                "host": "mail.example.com",
                "priority": 10,
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_replaces_two_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "_25._tcp.mail.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "_25._tcp.mail.example.com",
            "TLSA",
            ok_records(json!([
                {
                    "id": 901,
                    "recordType": "TLSA",
                    "hostname": "_25._tcp.mail.example.com",
                    "certificateUsage": 3,
                    "selector": 1,
                    "matchingType": 1,
                    "certificate": "aa"
                },
                {
                    "id": 902,
                    "recordType": "TLSA",
                    "hostname": "_25._tcp.mail.example.com",
                    "certificateUsage": 2,
                    "selector": 1,
                    "matchingType": 1,
                    "certificate": "bb"
                }
            ])),
        );
        let del_1 = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/901").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();
        let del_2 = server
            .mock("DELETE", format!("/dns/{DOMAIN_ID}/record/902").as_str())
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create_ee = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "recordType": "TLSA",
                "certificateUsage": 3,
                "certificate": "cc",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();
        let create_ta = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "recordType": "TLSA",
                "certificateUsage": 2,
                "certificate": "dd",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xcc],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xdd],
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        del_1.assert();
        del_2.assert();
        create_ee.assert();
        create_ta.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_creates() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "example.com", "example.com");
        let list = mock_list_records(&mut server, "example.com", "CAA", ok_records(json!([])));
        let create = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "recordType": "CAA",
                "flag": 0,
                "tag": "issue",
                "caaValue": "letsencrypt.org",
            })))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
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
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cname_strips_trailing_dot_before_diff() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "alias.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "alias.example.com",
            "CNAME",
            ok_records(json!([
                {"id": 33, "recordType": "CNAME", "hostname": "alias.example.com", "host": "target.example.com"}
            ])),
        );
        let no_post = server
            .mock("POST", format!("/dns/{DOMAIN_ID}/record").as_str())
            .expect(0)
            .create();
        let no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "alias.example.com",
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME("target.example.com.".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        root.assert();
        list.assert();
        no_post.assert();
        no_delete.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_typed_records() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "host.example.com", "example.com");
        let list = mock_list_records(
            &mut server,
            "host.example.com",
            "A",
            ok_records(json!([
                {"id": 1, "recordType": "A", "hostname": "host.example.com", "ipv4Address": "1.2.3.4"},
                {"id": 2, "recordType": "A", "hostname": "host.example.com", "ipv4Address": "5.6.7.8"}
            ])),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        let records = result.expect("list_rrset failed");
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.2.3.4".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("5.6.7.8".parse().unwrap())));
        root.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_empty_returns_empty_vec() {
        let mut server = mockito::Server::new_async().await;
        let root = mock_get_root(&mut server, "empty.example.com", "example.com");
        let list = mock_list_records(&mut server, "empty.example.com", "A", ok_records(json!([])));

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("empty.example.com", DnsRecordType::A, "example.com")
            .await;
        let records = result.expect("list_rrset failed");
        assert!(records.is_empty());
        root.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_type_mismatch_returns_api_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_type_mismatch_returns_api_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/dns/getroot/host.example.com")
            .with_status(401)
            .with_body(r#"{"statusCode":401,"message":"Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    #[ignore = "Requires DYNU_API_KEY, DYNU_ORIGIN, DYNU_FQDN env vars"]
    async fn integration_test() {
        let key = std::env::var("DYNU_API_KEY").unwrap_or_default();
        let origin = std::env::var("DYNU_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("DYNU_FQDN").unwrap_or_default();
        assert!(!key.is_empty(), "Set DYNU_API_KEY");
        assert!(!origin.is_empty(), "Set DYNU_ORIGIN");
        assert!(!fqdn.is_empty(), "Set DYNU_FQDN");

        let updater = DnsUpdater::new_dynu(key, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .set_rrset(
                &fqdn,
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("test".into())],
                &origin,
            )
            .await;
        assert!(create_result.is_ok(), "set_rrset failed: {create_result:?}");

        let cleanup = updater
            .set_rrset(&fqdn, DnsRecordType::TXT, 300, vec![], &origin)
            .await;
        assert!(cleanup.is_ok(), "set_rrset cleanup failed: {cleanup:?}");
    }
}
