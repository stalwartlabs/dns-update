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
        DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::vercel::VercelProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN: &str = "example.com";

    fn setup_provider(endpoint: String) -> VercelProvider {
        VercelProvider::new("test_token", None::<&str>, Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn list_path() -> String {
        format!("/v5/domains/{DOMAIN}/records")
    }

    fn mock_list(server: &mut ServerGuard, records: serde_json::Value) -> Mock {
        server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::UrlEncoded("limit".into(), "100".into()))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "records": records,
                    "pagination": {"count": 0, "next": null, "prev": null}
                }))
                .unwrap(),
            )
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, id: &str) -> Mock {
        server
            .mock(
                "DELETE",
                format!("/v2/domains/{DOMAIN}/records/{id}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create()
    }

    fn mock_post(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"uid":"rec_new"}"#)
            .create()
    }

    fn mock_post_partial(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::PartialJson(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"uid":"rec_new"}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "name": "www",
                "type": "A",
                "value": "1.1.1.1",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
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
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([{"id":"rec-1","name":"www","type":"A","value":"1.1.1.1"}]),
        );
        let _no_post = server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/v2/domains/{DOMAIN}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
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
                {"id":"rec-keep","name":"host","type":"A","value":"1.1.1.1"},
                {"id":"rec-stale","name":"host","type":"A","value":"9.9.9.9"},
            ]),
        );
        let delete_stale = mock_delete(&mut server, "rec-stale");
        let create_new = mock_post(
            &mut server,
            json!({
                "name": "host",
                "type": "A",
                "value": "8.8.8.8",
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
                {"id":"rec-x","name":"gone","type":"A","value":"1.2.3.4"},
                {"id":"rec-y","name":"gone","type":"A","value":"5.6.7.8"},
            ]),
        );
        let delete_x = mock_delete(&mut server, "rec-x");
        let delete_y = mock_delete(&mut server, "rec-y");

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
        delete_x.assert();
        delete_y.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_preserves_other_types_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id":"a-rec","name":"shared","type":"A","value":"1.1.1.1"},
                {"id":"txt-rec","name":"shared","type":"TXT","value":"keep-me"},
            ]),
        );
        let delete_a = mock_delete(&mut server, "a-rec");
        let _no_txt_delete = server
            .mock(
                "DELETE",
                format!("/v2/domains/{DOMAIN}/records/txt-rec").as_str(),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete_a.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_short_circuit() {
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
    async fn test_add_to_rrset_skips_existing_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([{"id":"rec-old","name":"_acme","type":"TXT","value":"existing"}]),
        );
        let create_new = mock_post(
            &mut server,
            json!({
                "name": "_acme",
                "type": "TXT",
                "value": "new-token",
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
    async fn test_remove_from_rrset_empty_is_short_circuit() {
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
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id":"rec-keep","name":"_acme","type":"TXT","value":"keep-me"},
                {"id":"rec-drop","name":"_acme","type":"TXT","value":"drop-me"},
            ]),
        );
        let delete = mock_delete(&mut server, "rec-drop");
        let _no_keep_delete = server
            .mock(
                "DELETE",
                format!("/v2/domains/{DOMAIN}/records/rec-keep").as_str(),
            )
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
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([{"id":"rec-1","name":"_acme","type":"TXT","value":"present"}]),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/v2/domains/{DOMAIN}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("absent".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let server = mockito::Server::new_async().await;
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
    async fn test_set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xaa],
                })],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_empty_name() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = mock_post(
            &mut server,
            json!({
                "name": "",
                "type": "MX",
                "value": "mail.example.com",
                "ttl": 3600,
                "mxPriority": 10,
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
    async fn test_set_rrset_srv_uses_only_nested_object_no_top_level_value() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let create = server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::AllOf(vec![Matcher::Json(json!({
                "name": "_sip._tcp",
                "type": "SRV",
                "ttl": 300,
                "srv": {
                    "priority": 10,
                    "weight": 60,
                    "port": 5060,
                    "target": "sipserver.example.net",
                },
            }))]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"uid":"rec_srv"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 60,
                    port: 5060,
                    target: "sipserver.example.net".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id":"rec-1","name":"www","type":"A","value":"1.2.3.4"},
                {"id":"rec-2","name":"www","type":"A","value":"5.6.7.8"},
                {"id":"rec-3","name":"www","type":"TXT","value":"unrelated"},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.2.3.4".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("5.6.7.8".parse().unwrap())));
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_paginates() {
        let mut server = mockito::Server::new_async().await;
        let page_1 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "100".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"records":[{"id":"rec-1","name":"www","type":"A","value":"1.1.1.1"}],"pagination":{"count":1,"next":1700000000000,"prev":null}}"#,
            )
            .create();

        let page_2 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "100".into()),
                Matcher::UrlEncoded("until".into(), "1700000000000".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"records":[{"id":"rec-2","name":"www","type":"A","value":"2.2.2.2"}],"pagination":{"count":1,"next":null,"prev":null}}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        page_1.assert();
        page_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_with_two_priorities() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, json!([]));
        let primary = mock_post_partial(
            &mut server,
            json!({"name": "", "type": "MX", "value": "mx1.example.com", "mxPriority": 10}),
        );
        let backup = mock_post_partial(
            &mut server,
            json!({"name": "", "type": "MX", "value": "mx2.example.com", "mxPriority": 20}),
        );

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
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        primary.assert();
        backup.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_diff_uses_mxpriority_for_identity() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {"id":"rec-mx","name":"","type":"MX","value":"mail.example.com","mxPriority":10}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .expect(0)
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
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_diff_uses_nested_srv_object() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            json!([
                {
                    "id":"rec-srv",
                    "name":"_sip._tcp",
                    "type":"SRV",
                    "srv": {
                        "priority": 10,
                        "weight": 60,
                        "port": 5060,
                        "target": "sipserver.example.net"
                    }
                }
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/v2/domains/{DOMAIN}/records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 60,
                    port: 5060,
                    target: "sipserver.example.net".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }
}
