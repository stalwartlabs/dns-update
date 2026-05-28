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
        providers::linode::LinodeProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN_ID: i64 = 1234;

    fn setup_provider(endpoint: String) -> LinodeProvider {
        LinodeProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_domain_lookup(server: &mut ServerGuard, domain: &str) -> Mock {
        server
            .mock("GET", "/domains")
            .match_header("authorization", "Bearer test_token")
            .match_header("x-filter", format!(r#"{{"domain":"{domain}"}}"#).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"data":[{{"id":{DOMAIN_ID},"domain":"{domain}"}}],"page":1,"pages":1,"results":1}}"#
            ))
            .create()
    }

    fn mock_list(server: &mut ServerGuard, rtype: &str, records: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("page_size".into(), "500".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .match_header("x-filter", format!(r#"{{"type":"{rtype}"}}"#).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "data": records,
                    "page": 1,
                    "pages": 1,
                    "results": 0,
                }))
                .unwrap(),
            )
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_empty() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "A", json!([]));

        let create = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "target": "1.1.1.1",
                "ttl_sec": 300,
            })))
            .with_status(200)
            .with_body(r#"{"id":11}"#)
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
        domain.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_noop_when_matches() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "A",
            json!([
                {"id": 11, "name": "host", "type": "A", "target": "1.1.1.1"},
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
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
        domain.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "A",
            json!([
                {"id": 11, "name": "host", "type": "A", "target": "1.1.1.1"},
                {"id": 22, "name": "host", "type": "A", "target": "9.9.9.9"},
            ]),
        );

        let delete_stale = server
            .mock(
                "DELETE",
                format!("/domains/{DOMAIN_ID}/records/22").as_str(),
            )
            .with_status(200)
            .with_body("{}")
            .create();

        let create_new = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "target": "8.8.8.8",
                "ttl_sec": 300,
            })))
            .with_status(200)
            .with_body(r#"{"id":33}"#)
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
        domain.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_of_same_type_only() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "A",
            json!([
                {"id": 11, "name": "gone", "type": "A", "target": "1.2.3.4"},
                {"id": 22, "name": "gone", "type": "A", "target": "5.6.7.8"},
            ]),
        );

        let delete_a = server
            .mock(
                "DELETE",
                format!("/domains/{DOMAIN_ID}/records/11").as_str(),
            )
            .with_status(200)
            .with_body("{}")
            .create();
        let delete_b = server
            .mock(
                "DELETE",
                format!("/domains/{DOMAIN_ID}/records/22").as_str(),
            )
            .with_status(200)
            .with_body("{}")
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
        domain.assert();
        list.assert();
        delete_a.assert();
        delete_b.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_isolates_other_types_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");

        let list_a = server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_query(Matcher::Any)
            .match_header("x-filter", r#"{"type":"A"}"#)
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [],
                    "page": 1,
                    "pages": 1,
                    "results": 0,
                }))
                .unwrap(),
            )
            .create();

        let _txt_list_must_not_fire = server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_query(Matcher::Any)
            .match_header("x-filter", r#"{"type":"TXT"}"#)
            .with_status(500)
            .expect(0)
            .create();

        let create = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::PartialJson(json!({
                "name": "shared",
                "type": "A",
                "target": "1.1.1.1",
            })))
            .with_status(200)
            .with_body(r#"{"id":1}"#)
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
        domain.assert();
        list_a.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "TXT",
            json!([
                {"id": 11, "name": "_acme", "type": "TXT", "target": "existing"},
            ]),
        );

        let create = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "name": "_acme",
                "type": "TXT",
                "target": "new-token",
                "ttl_sec": 60,
            })))
            .with_status(200)
            .with_body(r#"{"id":12}"#)
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
        domain.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
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
    async fn test_remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "TXT",
            json!([
                {"id": 11, "name": "_acme", "type": "TXT", "target": "keep-me"},
                {"id": 22, "name": "_acme", "type": "TXT", "target": "drop-me"},
            ]),
        );

        let delete = server
            .mock(
                "DELETE",
                format!("/domains/{DOMAIN_ID}/records/22").as_str(),
            )
            .with_status(200)
            .with_body("{}")
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
        domain.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
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
    async fn test_set_rrset_rejects_type_mismatch() {
        let mut server = mockito::Server::new_async().await;
        let _ = mock_domain_lookup(&mut server, "example.com");
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("wrong".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_is_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_mx_compares_priority() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "MX",
            json!([
                {"id": 1, "name": "", "type": "MX", "target": "mx1.example.com", "priority": 10},
                {"id": 2, "name": "", "type": "MX", "target": "mx2.example.com", "priority": 20},
            ]),
        );

        let create_new = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "MX",
                "target": "mx3.example.com",
                "ttl_sec": 3600,
                "priority": 30,
            })))
            .with_status(200)
            .with_body(r#"{"id":3}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mx1.example.com".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx2.example.com".to_string(),
                        priority: 20,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx3.example.com".to_string(),
                        priority: 30,
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain.assert();
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_lists_by_published_name_and_creates_one() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");

        let list = server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_query(Matcher::Any)
            .match_header("x-filter", r#"{"type":"SRV"}"#)
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [
                        {
                            "id": 7,
                            "name": "",
                            "type": "SRV",
                            "target": "old.example.com",
                            "priority": 10,
                            "weight": 5,
                            "port": 5060,
                            "service": "_sip",
                            "protocol": "_tcp",
                        }
                    ],
                    "page": 1,
                    "pages": 1,
                    "results": 1,
                }))
                .unwrap(),
            )
            .create();

        let delete_old = server
            .mock("DELETE", format!("/domains/{DOMAIN_ID}/records/7").as_str())
            .with_status(200)
            .with_body("{}")
            .create();

        let create = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "SRV",
                "target": "new.example.com",
                "ttl_sec": 300,
                "priority": 10,
                "weight": 5,
                "port": 5060,
                "service": "_sip",
                "protocol": "_tcp",
            })))
            .with_status(200)
            .with_body(r#"{"id":8}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 5060,
                    target: "new.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain.assert();
        list.assert();
        delete_old.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_via_tag_and_target() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "CAA", json!([]));

        let create = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "CAA",
                "target": "letsencrypt.org",
                "ttl_sec": 3600,
                "tag": "issue",
            })))
            .with_status(200)
            .with_body(r#"{"id":99}"#)
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
        domain.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_walks_pages_until_last() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");

        let page1 = server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("page_size".into(), "500".into()),
            ]))
            .match_header("x-filter", r#"{"type":"A"}"#)
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [
                        {"id": 1, "name": "other", "type": "A", "target": "1.0.0.1"},
                    ],
                    "page": 1,
                    "pages": 2,
                    "results": 2,
                }))
                .unwrap(),
            )
            .create();

        let page2 = server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "2".into()),
                Matcher::UrlEncoded("page_size".into(), "500".into()),
            ]))
            .match_header("x-filter", r#"{"type":"A"}"#)
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [
                        {"id": 2, "name": "host", "type": "A", "target": "1.1.1.1"},
                    ],
                    "page": 2,
                    "pages": 2,
                    "results": 2,
                }))
                .unwrap(),
            )
            .create();

        let _no_post = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
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
        domain.assert();
        page1.assert();
        page2.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "A",
            json!([
                {"id": 11, "name": "host", "type": "A", "target": "1.1.1.1"},
                {"id": 22, "name": "host", "type": "A", "target": "2.2.2.2"},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        domain.assert();
        list.assert();
    }
}
