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
    use crate::providers::safedns::SafeDnsProvider;
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE: &str = "example.com";

    fn setup_provider(endpoint: &str) -> SafeDnsProvider {
        SafeDnsProvider::new("auth_token", Some(Duration::from_secs(2))).with_endpoint(endpoint)
    }

    fn list_path() -> String {
        format!("/zones/{ZONE}/records")
    }

    fn mock_list(
        server: &mut ServerGuard,
        name: &str,
        record_type: &str,
        records: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name:eq".into(), name.into()),
                Matcher::UrlEncoded("type:eq".into(), record_type.into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .match_header("authorization", "auth_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&json!({
                    "data": records,
                    "meta": {"pagination": {"total_pages": 1}}
                }))
                .unwrap(),
            )
            .create()
    }

    fn mock_delete(server: &mut ServerGuard, id: i64) -> Mock {
        server
            .mock("DELETE", format!("/zones/{ZONE}/records/{id}").as_str())
            .match_header("authorization", "auth_token")
            .with_status(204)
            .create()
    }

    fn mock_post_match(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("POST", format!("/zones/{ZONE}/records").as_str())
            .match_header("authorization", "auth_token")
            .match_body(Matcher::Json(body))
            .with_status(201)
            .with_body(r#"{"data":{"id":1,"name":"x","type":"A"}}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "host.example.com", "A", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "host.example.com",
                "type": "A",
                "content": "1.2.3.4",
                "ttl": 300,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
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
            "host.example.com",
            "A",
            json!([
                {"id": 1, "name": "host.example.com", "type": "A", "content": "1.2.3.4"}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/zones/{ZONE}/records").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock("DELETE", Matcher::Regex(format!("^/zones/{ZONE}/records/")))
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
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
            "host.example.com",
            "A",
            json!([
                {"id": 11, "name": "host.example.com", "type": "A", "content": "1.1.1.1"},
                {"id": 22, "name": "host.example.com", "type": "A", "content": "9.9.9.9"}
            ]),
        );
        let delete_stale = mock_delete(&mut server, 22);
        let create_new = mock_post_match(
            &mut server,
            json!({
                "name": "host.example.com",
                "type": "A",
                "content": "8.8.8.8",
                "ttl": 300,
            }),
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
            "gone.example.com",
            "A",
            json!([
                {"id": 33, "name": "gone.example.com", "type": "A", "content": "1.2.3.4"},
                {"id": 44, "name": "gone.example.com", "type": "A", "content": "5.6.7.8"}
            ]),
        );
        let del33 = mock_delete(&mut server, 33);
        let del44 = mock_delete(&mut server, 44);

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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        del33.assert();
        del44.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "_acme.example.com",
            "TXT",
            json!([
                {"id": 101, "name": "_acme.example.com", "type": "TXT", "content": "\"existing\""}
            ]),
        );
        let create_new = mock_post_match(
            &mut server,
            json!({
                "name": "_acme.example.com",
                "type": "TXT",
                "content": "\"new-token\"",
                "ttl": 60,
            }),
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

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

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

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_full_noop_when_all_present() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "test.example.com",
            "A",
            json!([
                {"id": 70, "name": "test.example.com", "type": "A", "content": "1.1.1.1"},
                {"id": 71, "name": "test.example.com", "type": "A", "content": "8.8.8.8"}
            ]),
        );
        let _no_post = server
            .mock("POST", format!("/zones/{ZONE}/records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
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
            "_acme.example.com",
            "TXT",
            json!([
                {"id": 200, "name": "_acme.example.com", "type": "TXT", "content": "\"keep-me\""},
                {"id": 201, "name": "_acme.example.com", "type": "TXT", "content": "\"drop-me\""}
            ]),
        );
        let delete = mock_delete(&mut server, 201);

        let provider = setup_provider(server.url().as_str());
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
            "test.example.com",
            "A",
            json!([
                {"id": 300, "name": "test.example.com", "type": "A", "content": "1.1.1.1"}
            ]),
        );
        let _no_delete = server
            .mock("DELETE", Matcher::Regex(format!("^/zones/{ZONE}/records/")))
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

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_is_short_circuit() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

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
    async fn test_set_rrset_tlsa_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_post = server
            .mock("POST", format!("/zones/{ZONE}/records").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                })],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unsupported(ref m)) if m.contains("TLSA")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_filters_by_type_for_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name:eq".into(), "shared.example.com".into()),
                Matcher::UrlEncoded("type:eq".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [],
                    "meta": {"pagination": {"total_pages": 1}}
                }))
                .unwrap(),
            )
            .expect(1)
            .create();

        let _txt_must_not_fire = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::UrlEncoded("type:eq".into(), "TXT".into()))
            .with_status(500)
            .expect(0)
            .create();

        let create = mock_post_match(
            &mut server,
            json!({
                "name": "shared.example.com",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 300,
            }),
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_sends_priority_as_separate_field() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "example.com", "MX", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "example.com",
                "type": "MX",
                "content": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            }),
        );

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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_content_excludes_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "_imaps._tcp.example.com", "SRV", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "_imaps._tcp.example.com",
                "type": "SRV",
                "content": "5 993 mail.example.com",
                "ttl": 3600,
                "priority": 10,
            }),
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_decomposed_fields() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "example.com", "CAA", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "example.com",
                "type": "CAA",
                "content": "0 issue \"letsencrypt.org\"",
                "ttl": 3600,
            }),
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_txt_escapes_embedded_quote() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "_acme.example.com", "TXT", json!([]));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "_acme.example.com",
                "type": "TXT",
                "content": "\"value with \\\"quote\\\" inside\"",
                "ttl": 60,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT(r#"value with "quote" inside"#.to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_txt_chunks_long_values_at_255_bytes() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(&mut server, "_acme.example.com", "TXT", json!([]));
        let long = "a".repeat(300);
        let expected = format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(45));
        let create = mock_post_match(
            &mut server,
            json!({
                "name": "_acme.example.com",
                "type": "TXT",
                "content": expected,
                "ttl": 60,
            }),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT(long)],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_paginates() {
        let mut server = mockito::Server::new_async().await;

        let mut page1_records: Vec<serde_json::Value> = Vec::new();
        for i in 0..200u32 {
            page1_records.push(json!({
                "id": i as i64,
                "name": "host.example.com",
                "type": "A",
                "content": format!("10.0.{}.{}", i / 256, i % 256),
            }));
        }
        let page1 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name:eq".into(), "host.example.com".into()),
                Matcher::UrlEncoded("type:eq".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": page1_records,
                    "meta": {"pagination": {"total_pages": 2}}
                }))
                .unwrap(),
            )
            .create();

        let page2 = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name:eq".into(), "host.example.com".into()),
                Matcher::UrlEncoded("type:eq".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "200".into()),
                Matcher::UrlEncoded("page".into(), "2".into()),
            ]))
            .with_status(200)
            .with_body(
                serde_json::to_string(&json!({
                    "data": [
                        {"id": 999, "name": "host.example.com", "type": "A", "content": "10.99.0.1"}
                    ],
                    "meta": {"pagination": {"total_pages": 2}}
                }))
                .unwrap(),
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 201);
        for r in &records {
            assert_eq!(r.as_type(), DnsRecordType::A);
        }
        page1.assert();
        page2.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_ignores_off_name_or_off_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": 1, "name": "host.example.com", "type": "A", "content": "1.1.1.1"},
                {"id": 2, "name": "other.example.com", "type": "A", "content": "9.9.9.9"}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        match &records[0] {
            DnsRecord::A(addr) => assert_eq!(addr.to_string(), "1.1.1.1"),
            other => panic!("expected A, got {other:?}"),
        }
        list.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", list_path().as_str())
            .match_query(Matcher::Any)
            .with_status(401)
            .with_body(r#"{"message":"Unauthorized"}"#)
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
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    #[ignore = "Requires SafeDNS auth token"]
    async fn integration_test() {
        let token = std::env::var("SAFEDNS_AUTH_TOKEN").unwrap_or_default();
        let origin = std::env::var("SAFEDNS_ORIGIN").unwrap_or_default();
        let name = std::env::var("SAFEDNS_NAME").unwrap_or_default();

        assert!(
            !token.is_empty() && !origin.is_empty() && !name.is_empty(),
            "Set SAFEDNS_AUTH_TOKEN, SAFEDNS_ORIGIN and SAFEDNS_NAME env vars"
        );

        let provider = SafeDnsProvider::new(&token, Some(Duration::from_secs(30)));
        assert!(
            provider
                .set_rrset(
                    &name,
                    DnsRecordType::A,
                    300,
                    vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                    &origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .set_rrset(&name, DnsRecordType::A, 300, vec![], &origin)
                .await
                .is_ok()
        );
    }
}
