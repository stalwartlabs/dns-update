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
        DnsRecord, DnsRecordType, Error, MXRecord, providers::dnsmadeeasy::DnsMadeEasyProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> DnsMadeEasyProvider {
        DnsMadeEasyProvider::new("api_key", "api_secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_domain_lookup(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("GET", "/dns/managed/name")
            .match_query(Matcher::UrlEncoded(
                "domainname".into(),
                "example.com".into(),
            ))
            .match_header("x-dnsme-apiKey", "api_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":12345,"name":"example.com"}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_empty_creates_via_bulk() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[]}"#)
            .create();

        let create_multi = server
            .mock("POST", "/dns/managed/12345/records/createMulti")
            .match_header("x-dnsme-apiKey", "api_key")
            .match_body(Matcher::Json(json!([
                {"type": "A", "name": "test", "value": "1.2.3.4", "ttl": 300, "gtdLocation": "DEFAULT"},
                {"type": "A", "name": "test", "value": "5.6.7.8", "ttl": 300, "gtdLocation": "DEFAULT"}
            ])))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":101},{"id":102}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        create_multi.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_no_changes() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":1,"type":"A","value":"1.2.3.4","ttl":300},{"id":2,"type":"A","value":"5.6.7.8","ttl":300}]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diff_add_and_remove() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":10,"type":"A","value":"1.2.3.4","ttl":300},{"id":11,"type":"A","value":"9.9.9.9","ttl":300}]}"#)
            .create();

        let bulk_delete = server
            .mock("DELETE", "/dns/managed/12345/records")
            .match_query(Matcher::UrlEncoded("ids".into(), "11".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let bulk_create = server
            .mock("POST", "/dns/managed/12345/records/createMulti")
            .match_body(Matcher::Json(json!([
                {"type": "A", "name": "test", "value": "8.8.8.8", "ttl": 300, "gtdLocation": "DEFAULT"}
            ])))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":20}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        bulk_delete.assert();
        bulk_create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_vec_deletes_all() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":1,"type":"A","value":"1.2.3.4","ttl":300},{"id":2,"type":"A","value":"5.6.7.8","ttl":300}]}"#)
            .create();

        let bulk_delete = server
            .mock("DELETE", "/dns/managed/12345/records")
            .match_query(Matcher::Regex("ids=1&ids=2".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        bulk_delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_vec_no_existing_no_calls() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[]}"#)
            .create();

        let create_multi = server
            .mock("POST", "/dns/managed/12345/records/createMulti")
            .match_body(Matcher::Json(json!([
                {"type": "A", "name": "test", "value": "1.2.3.4", "ttl": 300, "gtdLocation": "DEFAULT"}
            ])))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":101}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        create_multi.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_validation() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".into())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "expected Api(type mismatch), got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref m)) if m.contains("TLSA")),
            "expected Unsupported(TLSA), got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_noop() {
        let server = mockito::Server::new_async().await;
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
    async fn test_add_to_rrset_filters_missing() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":5,"type":"A","value":"1.2.3.4","ttl":300}]}"#)
            .create();

        let create_multi = server
            .mock("POST", "/dns/managed/12345/records/createMulti")
            .match_body(Matcher::Json(json!([
                {"type": "A", "name": "test", "value": "5.6.7.8", "ttl": 300, "gtdLocation": "DEFAULT"}
            ])))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":6}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        create_multi.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_all_already_present_no_post() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":5,"type":"A","value":"1.2.3.4","ttl":300}]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_present_bulk_delete() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":50,"type":"A","value":"1.2.3.4","ttl":300},{"id":51,"type":"A","value":"5.6.7.8","ttl":300}]}"#)
            .create();

        let bulk_delete = server
            .mock("DELETE", "/dns/managed/12345/records")
            .match_query(Matcher::Regex("ids=50&ids=51".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        bulk_delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_none_present_no_delete() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":50,"type":"A","value":"1.2.3.4","ttl":300}]}"#)
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
        domain_lookup.assert();
        record_lookup.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_mx_parses_mxlevel() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "@".into()),
                Matcher::UrlEncoded("type".into(), "MX".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":1,"type":"MX","value":"mail.example.com.","ttl":3600,"mxLevel":10},{"id":2,"type":"MX","value":"mail2.example.com.","ttl":3600,"mxLevel":20}]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await;
        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            exchange: "mail.example.com.".into(),
            priority: 10
        })));
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            exchange: "mail2.example.com.".into(),
            priority: 20
        })));
        domain_lookup.assert();
        record_lookup.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_uses_mxlevel_field() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = mock_domain_lookup(&mut server);

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "@".into()),
                Matcher::UrlEncoded("type".into(), "MX".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[]}"#)
            .create();

        let create_multi = server
            .mock("POST", "/dns/managed/12345/records/createMulti")
            .match_body(Matcher::Json(json!([
                {"type": "MX", "name": "@", "value": "mail.example.com.", "ttl": 3600, "mxLevel": 10, "gtdLocation": "DEFAULT"}
            ])))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":42}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com.".into(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        create_multi.assert();
    }
}
