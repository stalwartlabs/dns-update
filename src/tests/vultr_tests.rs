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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::vultr::VultrProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN: &str = "example.com";

    fn setup_provider(endpoint: String) -> VultrProvider {
        VultrProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn list_path() -> String {
        format!("/domains/{DOMAIN}/records")
    }

    fn mock_list(server: &mut ServerGuard, records: serde_json::Value) -> Mock {
        server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::UrlEncoded("per_page".into(), "500".into()))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "records": records,
                    "meta": {"total": 0, "links": {"next": "", "prev": ""}}
                }))
                .unwrap(),
            )
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, id: &str) -> Mock {
        server
            .mock("DELETE", format!("/domains/{DOMAIN}/records/{id}").as_str())
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create()
    }

    fn mock_post_match(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("POST", format!("/domains/{DOMAIN}/records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"record":{"id":"new-id"}}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "www",
                "type": "A",
                "data": "1.2.3.4",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "a1", "type": "A", "name": "www", "data": "1.2.3.4", "priority": 0, "ttl": 300}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/domains/{DOMAIN}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "11", "type": "A", "name": "host", "data": "1.1.1.1", "priority": 0, "ttl": 300},
                {"id": "22", "type": "A", "name": "host", "data": "9.9.9.9", "priority": 0, "ttl": 300}
            ]),
        );
        let delete_stale = mock_delete(&mut server, "22");
        let create_new = mock_post_match(
            &mut server,
            json!({
                "name": "host",
                "type": "A",
                "data": "8.8.8.8",
                "ttl": 300,
            }),
        );

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
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_at_owner_and_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "33", "type": "A", "name": "gone", "data": "1.2.3.4", "priority": 0, "ttl": 300},
                {"id": "44", "type": "A", "name": "gone", "data": "5.6.7.8", "priority": 0, "ttl": 300}
            ]),
        );
        let del33 = mock_delete(&mut server, "33");
        let del44 = mock_delete(&mut server, "44");

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
        list.assert();
        del33.assert();
        del44.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_preserves_other_types() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "a", "type": "A", "name": "host", "data": "1.1.1.1", "priority": 0, "ttl": 300},
                {"id": "t", "type": "TXT", "name": "host", "data": "\"keep\"", "priority": 0, "ttl": 300},
                {"id": "m", "type": "MX", "name": "host", "data": "mail.example.com", "priority": 10, "ttl": 300}
            ]),
        );
        let del_a = mock_delete(&mut server, "a");
        let _no_other_delete = server
            .mock("DELETE", format!("/domains/{DOMAIN}/records/t").as_str())
            .expect(0)
            .create();
        let _no_mx_delete = server
            .mock("DELETE", format!("/domains/{DOMAIN}/records/m").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        del_a.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "txt1", "type": "TXT", "name": "shared", "data": "\"keep\"", "priority": 0, "ttl": 300}
            ]),
        );
        let _no_delete_txt = server
            .mock("DELETE", format!("/domains/{DOMAIN}/records/txt1").as_str())
            .expect(0)
            .create();
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "shared",
                "type": "A",
                "data": "1.1.1.1",
                "ttl": 300,
            }),
        );

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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "101", "type": "TXT", "name": "_acme", "data": "\"existing\"", "priority": 0, "ttl": 60}
            ]),
        );
        let create_new = mock_post_match(
            &mut server,
            json!({
                "name": "_acme",
                "type": "TXT",
                "data": "\"new-token\"",
                "ttl": 60,
            }),
        );

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
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

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
    }

    #[tokio::test]
    async fn test_add_to_rrset_full_noop_when_everything_present() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "x", "type": "A", "name": "test", "data": "1.1.1.1", "priority": 0, "ttl": 300},
                {"id": "y", "type": "A", "name": "test", "data": "8.8.8.8", "priority": 0, "ttl": 300}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "200", "type": "TXT", "name": "_acme", "data": "\"keep-me\"", "priority": 0, "ttl": 60},
                {"id": "201", "type": "TXT", "name": "_acme", "data": "\"drop-me\"", "priority": 0, "ttl": 60}
            ]),
        );
        let delete = mock_delete(&mut server, "201");

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
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "300", "type": "A", "name": "test", "data": "1.1.1.1", "priority": 0, "ttl": 300}
            ]),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/domains/{DOMAIN}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
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
    async fn test_add_to_rrset_type_mismatch_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_rejected() {
        let mut server = mockito::Server::new_async().await;
        let _no_list = mock_list(&mut server, json!([]));
        let _no_post = server
            .mock("POST", format!("/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                })],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("TLSA")));
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_priority_field() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "",
                "type": "MX",
                "data": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            }),
        );

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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_matches_existing_with_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "mx1", "type": "MX", "name": "", "data": "mail.example.com", "priority": 10, "ttl": 3600},
                {"id": "mx2", "type": "MX", "name": "", "data": "mail.example.com", "priority": 20, "ttl": 3600}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();
        let del_mx2 = mock_delete(&mut server, "mx2");

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
        list.assert();
        del_mx2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_data_is_three_tokens() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "_imaps._tcp",
                "type": "SRV",
                "data": "5 993 mail.example.com",
                "ttl": 3600,
                "priority": 10,
            }),
        );

        let provider = setup_provider(server.url());
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_bind_string() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "",
                "type": "CAA",
                "data": "0 issue \"letsencrypt.org\"",
                "ttl": 3600,
            }),
        );

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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_txt_short_value_single_chunk() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "_dmarc",
                "type": "TXT",
                "data": "\"v=DMARC1; p=none\"",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_dmarc.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("v=DMARC1; p=none".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_txt_long_value_is_chunked() {
        let mut server = mockito::Server::new_async().await;
        let long = "a".repeat(600);
        let mut expected = String::new();
        crate::utils::txt_chunks_to_text(&mut expected, &long, " ");
        assert!(
            expected.contains("\" \""),
            "expected chunked TXT, got {expected}"
        );

        let list = mock_list(&mut server, json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "long",
                "type": "TXT",
                "data": expected,
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "long.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long)],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_and_converts() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "a1", "type": "A", "name": "host", "data": "1.1.1.1", "priority": 0, "ttl": 300},
                {"id": "a2", "type": "A", "name": "host", "data": "2.2.2.2", "priority": 0, "ttl": 300},
                {"id": "a3", "type": "A", "name": "other", "data": "9.9.9.9", "priority": 0, "ttl": 300},
                {"id": "t1", "type": "TXT", "name": "host", "data": "\"keep\"", "priority": 0, "ttl": 300}
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        for r in &records {
            assert_eq!(r.as_type(), DnsRecordType::A);
        }
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_paginates_via_next_cursor() {
        let mut server = mockito::Server::new_async().await;
        let next_cursor = "abc123";

        let mut page1_records: Vec<serde_json::Value> = Vec::new();
        for i in 0..2u32 {
            page1_records.push(json!({
                "id": format!("p1-{i}"),
                "type": "A",
                "name": "host",
                "data": format!("10.0.0.{i}"),
                "priority": 0,
                "ttl": 300,
            }));
        }

        let page1 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![Matcher::UrlEncoded(
                "per_page".into(),
                "500".into(),
            )]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "records": page1_records,
                    "meta": {"total": 3, "links": {"next": next_cursor, "prev": ""}}
                }))
                .unwrap(),
            )
            .expect(1)
            .create();

        let page2 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("per_page".into(), "500".into()),
                Matcher::UrlEncoded("cursor".into(), next_cursor.into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "records": [
                        {"id": "p2-0", "type": "A", "name": "host", "data": "10.0.1.0", "priority": 0, "ttl": 300}
                    ],
                    "meta": {"total": 3, "links": {"next": "", "prev": ""}}
                }))
                .unwrap(),
            )
            .expect(1)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 3);
        page1.assert();
        page2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_finds_record_past_first_page() {
        let mut server = mockito::Server::new_async().await;
        let next_cursor = "page2cursor";

        let page1 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![Matcher::UrlEncoded(
                "per_page".into(),
                "500".into(),
            )]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "records": [
                        {"id": "p1", "type": "TXT", "name": "other", "data": "\"x\"", "priority": 0, "ttl": 300}
                    ],
                    "meta": {"total": 2, "links": {"next": next_cursor, "prev": ""}}
                }))
                .unwrap(),
            )
            .expect(1)
            .create();

        let page2 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("per_page".into(), "500".into()),
                Matcher::UrlEncoded("cursor".into(), next_cursor.into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "records": [
                        {"id": "target", "type": "A", "name": "needle", "data": "1.2.3.4", "priority": 0, "ttl": 300}
                    ],
                    "meta": {"total": 2, "links": {"next": "", "prev": ""}}
                }))
                .unwrap(),
            )
            .expect(1)
            .create();

        let delete = mock_delete(&mut server, "target");

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "needle.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        page1.assert();
        page2.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_apex_uses_empty_string_name() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id": "a1", "type": "A", "name": "", "data": "1.1.1.1", "priority": 0, "ttl": 300}
            ]),
        );
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "",
                "type": "A",
                "data": "2.2.2.2",
                "ttl": 300,
            }),
        );
        let delete = mock_delete(&mut server, "a1");

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::Any)
            .with_status(401)
            .with_body(r#"{"error":"Invalid API token"}"#)
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
    #[ignore = "Requires Vultr API key, domain, and FQDN"]
    async fn integration_test() {
        let key = std::env::var("VULTR_API_KEY").unwrap_or_default();
        let origin = std::env::var("VULTR_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("VULTR_FQDN").unwrap_or_default();

        assert!(!key.is_empty(), "Set VULTR_API_KEY to run this test");
        assert!(!origin.is_empty(), "Set VULTR_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set VULTR_FQDN to run this test");

        let updater = DnsUpdater::new_vultr(key, Some(Duration::from_secs(30))).unwrap();

        let set_result = updater
            .set_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A([1, 1, 1, 1].into()),
                    DnsRecord::A([2, 2, 2, 2].into()),
                ],
                &origin,
            )
            .await;
        assert!(set_result.is_ok(), "set_rrset failed: {set_result:?}");

        let add_result = updater
            .add_to_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([3, 3, 3, 3].into())],
                &origin,
            )
            .await;
        assert!(add_result.is_ok(), "add_to_rrset failed: {add_result:?}");

        let remove_result = updater
            .remove_from_rrset(
                &fqdn,
                DnsRecordType::A,
                vec![DnsRecord::A([1, 1, 1, 1].into())],
                &origin,
            )
            .await;
        assert!(
            remove_result.is_ok(),
            "remove_from_rrset failed: {remove_result:?}"
        );

        let cleanup = updater
            .set_rrset(&fqdn, DnsRecordType::A, 300, vec![], &origin)
            .await;
        assert!(cleanup.is_ok(), "cleanup failed: {cleanup:?}");
    }
}
