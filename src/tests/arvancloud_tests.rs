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
    use crate::providers::arvancloud::ArvanCloudProvider;
    use crate::{
        DnsRecord, DnsRecordType, Error, MXRecord, TLSARecord, TlsaCertUsage, TlsaMatching,
        TlsaSelector,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> ArvanCloudProvider {
        ArvanCloudProvider::new(
            "Apikey 12345678-1234-1234-1234-123456789abc",
            Some(Duration::from_secs(2)),
        )
        .with_endpoint(endpoint)
    }

    fn auth_header() -> &'static str {
        "Apikey 12345678-1234-1234-1234-123456789abc"
    }

    fn paged(items: serde_json::Value) -> serde_json::Value {
        let count = items.as_array().map(|a| a.len()).unwrap_or(0) as u64;
        json!({
            "data": items,
            "meta": {
                "current_page": 1,
                "from": if count == 0 { 0 } else { 1 },
                "last_page": 1,
                "per_page": 300,
                "to": count,
                "total": count,
            }
        })
    }

    fn mock_list(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("GET", "/cdn/4.0/domains/example.com/dns-records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("per_page".into(), "300".into()),
            ]))
            .match_header("authorization", auth_header())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, paged(json!([])));
        let create = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::Json(json!({
                "type": "a",
                "name": "www",
                "value": [{"ip": "1.2.3.4", "port": null, "weight": 100, "country": ""}],
                "ttl": 300,
                "upstream_https": "default",
                "ip_filter_mode": {"count":"single","order":"none","geo_filter":"none"}
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"new-1","name":"www","type":"a"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "rec-1",
                    "name": "www",
                    "type": "a",
                    "value": [{"ip": "1.2.3.4", "port": null, "weight": 100, "country": ""}],
                    "can_delete": true,
                }
            ])),
        );
        let _no_post = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("/cdn/4.0/domains/example.com/dns-records/.+".into()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "keep",
                    "name": "host",
                    "type": "a",
                    "value": [{"ip": "1.1.1.1", "port": null, "weight": 100, "country": ""}],
                    "can_delete": true,
                },
                {
                    "id": "stale",
                    "name": "host",
                    "type": "a",
                    "value": [{"ip": "9.9.9.9", "port": null, "weight": 100, "country": ""}],
                    "can_delete": true,
                }
            ])),
        );

        let delete_stale = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/stale")
            .with_status(200)
            .with_body(r#"{"message":"deleted"}"#)
            .create();

        let create_new = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::PartialJson(json!({
                "type": "a",
                "name": "host",
                "value": [{"ip": "8.8.8.8", "port": null, "weight": 100, "country": ""}],
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"new","name":"host","type":"a"}}"#)
            .create();

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

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "a-1",
                    "name": "gone",
                    "type": "a",
                    "value": [{"ip": "1.2.3.4", "port": null, "weight": 100, "country": ""}],
                    "can_delete": true,
                },
                {
                    "id": "a-2",
                    "name": "gone",
                    "type": "a",
                    "value": [{"ip": "5.6.7.8", "port": null, "weight": 100, "country": ""}],
                    "can_delete": true,
                }
            ])),
        );

        let delete_a1 = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/a-1")
            .with_status(200)
            .with_body(r#"{"message":"deleted"}"#)
            .create();
        let delete_a2 = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/a-2")
            .with_status(200)
            .with_body(r#"{"message":"deleted"}"#)
            .create();

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

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        delete_a1.assert();
        delete_a2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_skips_can_delete_false_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "managed",
                    "name": "@",
                    "type": "ns",
                    "value": {"host": "ns1.ns.arvancdn.com."},
                    "can_delete": false,
                },
                {
                    "id": "user-ns",
                    "name": "@",
                    "type": "ns",
                    "value": {"host": "old.example.net."},
                    "can_delete": true,
                }
            ])),
        );

        let _no_delete_managed = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/managed")
            .expect(0)
            .create();
        let delete_user = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/user-ns")
            .with_status(200)
            .with_body(r#"{"message":"deleted"}"#)
            .create();
        let create_new = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::PartialJson(json!({
                "type": "ns",
                "name": "@",
                "value": {"host": "new.example.net"},
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"new","name":"@","type":"ns"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::NS,
                3600,
                vec![DnsRecord::NS("new.example.net".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        delete_user.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_ignores_other_types_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "txt-1",
                    "name": "shared",
                    "type": "txt",
                    "value": {"text": "untouched"},
                    "can_delete": true,
                },
                {
                    "id": "a-1",
                    "name": "shared",
                    "type": "a",
                    "value": [{"ip": "1.1.1.1", "port": null, "weight": 100, "country": ""}],
                    "can_delete": true,
                }
            ])),
        );

        let _no_delete_txt = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/txt-1")
            .expect(0)
            .create();
        let _no_post = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .expect(0)
            .create();

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

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-a".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, paged(json!([])));

        let create_ee = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::PartialJson(json!({
                "type": "tlsa",
                "name": "_443._tcp.www",
                "value": {
                    "usage": 3,
                    "selector": 1,
                    "matching_type": 1,
                    "certificate": "aa"
                }
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"ee","name":"_443._tcp.www","type":"tlsa"}}"#)
            .create();
        let create_ta = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::PartialJson(json!({
                "type": "tlsa",
                "name": "_443._tcp.www",
                "value": {
                    "usage": 2,
                    "selector": 1,
                    "matching_type": 1,
                    "certificate": "bb"
                }
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"ta","name":"_443._tcp.www","type":"tlsa"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.www.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xaa],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xbb],
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        create_ee.assert();
        create_ta.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "rec-old",
                    "name": "_acme",
                    "type": "txt",
                    "value": {"text": "existing"},
                    "can_delete": true,
                }
            ])),
        );

        let create_new = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::PartialJson(json!({
                "type": "txt",
                "name": "_acme",
                "value": {"text": "new-token"}
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"new","name":"_acme","type":"txt"}}"#)
            .create();

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

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "keep",
                    "name": "_acme",
                    "type": "txt",
                    "value": {"text": "keep-me"},
                    "can_delete": true,
                },
                {
                    "id": "drop",
                    "name": "_acme",
                    "type": "txt",
                    "value": {"text": "drop-me"},
                    "can_delete": true,
                }
            ])),
        );

        let delete = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/drop")
            .with_status(200)
            .with_body(r#"{"message":"deleted"}"#)
            .create();
        let _no_delete_keep = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/keep")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn test_remove_from_rrset_errors_on_can_delete_false() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "managed",
                    "name": "@",
                    "type": "ns",
                    "value": {"host": "ns1.ns.arvancdn.com."},
                    "can_delete": false,
                }
            ])),
        );
        let _no_delete = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/managed")
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "example.com",
                DnsRecordType::NS,
                vec![DnsRecord::NS("ns1.ns.arvancdn.com".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("can_delete=false")),
            "expected can_delete error, got {result:?}"
        );
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_typed_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "mx-1",
                    "name": "@",
                    "type": "mx",
                    "value": {"host": "mail.example.com.", "priority": 10},
                    "can_delete": true,
                },
                {
                    "id": "txt-1",
                    "name": "@",
                    "type": "txt",
                    "value": {"text": "ignored"},
                    "can_delete": true,
                }
            ])),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();

        list.assert();
        assert_eq!(result.len(), 1);
        match &result[0] {
            DnsRecord::MX(mx) => {
                assert_eq!(mx.exchange, "mail.example.com");
                assert_eq!(mx.priority, 10);
            }
            other => panic!("expected MX, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_paginates_when_meta_indicates_multiple_pages() {
        let mut server = mockito::Server::new_async().await;
        let page1 = server
            .mock("GET", "/cdn/4.0/domains/example.com/dns-records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("per_page".into(), "300".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [
                        {
                            "id": "p1",
                            "name": "other",
                            "type": "a",
                            "value": [{"ip": "1.0.0.0", "port": null, "weight": 100, "country": ""}],
                            "can_delete": true,
                        }
                    ],
                    "meta": {"current_page": 1, "last_page": 2, "per_page": 300, "from": 1, "to": 1, "total": 2}
                }))
                .unwrap(),
            )
            .create();
        let page2 = server
            .mock("GET", "/cdn/4.0/domains/example.com/dns-records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "2".into()),
                Matcher::UrlEncoded("per_page".into(), "300".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [
                        {
                            "id": "want",
                            "name": "needle",
                            "type": "a",
                            "value": [{"ip": "9.9.9.9", "port": null, "weight": 100, "country": ""}],
                            "can_delete": true,
                        }
                    ],
                    "meta": {"current_page": 2, "last_page": 2, "per_page": 300, "from": 2, "to": 2, "total": 2}
                }))
                .unwrap(),
            )
            .create();

        let delete = server
            .mock("DELETE", "/cdn/4.0/domains/example.com/dns-records/want")
            .with_status(200)
            .with_body(r#"{"message":"deleted"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "needle.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        page1.assert();
        page2.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_apex() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, paged(json!([])));
        let create = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .match_body(Matcher::PartialJson(json!({
                "type": "mx",
                "name": "@",
                "value": {"host": "mail.example.com", "priority": 10}
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":"mx1","name":"@","type":"mx"}}"#)
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

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_trailing_dot_normalisation_treats_as_match() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            paged(json!([
                {
                    "id": "cname-1",
                    "name": "blog",
                    "type": "cname",
                    "value": {"host": "target.example.net."},
                    "can_delete": true,
                }
            ])),
        );
        let _no_post = server
            .mock("POST", "/cdn/4.0/domains/example.com/dns-records")
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex("/cdn/4.0/domains/example.com/dns-records/.+".into()),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "blog.example.com",
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME("target.example.net".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        list.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_maps_to_error() {
        let mut server = mockito::Server::new_async().await;
        let _list = server
            .mock("GET", "/cdn/4.0/domains/example.com/dns-records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("page".into(), "1".into()),
                Matcher::UrlEncoded("per_page".into(), "300".into()),
            ]))
            .with_status(401)
            .with_body(r#"{"message":"invalid api key"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)), "{:?}", result);
    }

    #[tokio::test]
    #[ignore = "Requires ArvanCloud API key"]
    async fn integration_test() {
        let api_key = "";
        let origin = "";
        let name = "";

        assert!(!api_key.is_empty(), "Set ARVANCLOUD_API_KEY");
        assert!(!origin.is_empty(), "Set origin");
        assert!(!name.is_empty(), "Set name");

        let provider = ArvanCloudProvider::new(api_key, Some(Duration::from_secs(30)));
        provider
            .set_rrset(
                name,
                DnsRecordType::TXT,
                600,
                vec![DnsRecord::TXT("integration-test".to_string())],
                origin,
            )
            .await
            .unwrap();
        provider
            .set_rrset(name, DnsRecordType::TXT, 600, vec![], origin)
            .await
            .unwrap();
    }
}
