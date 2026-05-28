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
        DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, providers::ipv64::Ipv64Provider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    const DOMAIN: &str = "example.com";

    fn setup_provider(endpoint: String) -> Ipv64Provider {
        Ipv64Provider::new("test_key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_get_domains(server: &mut ServerGuard, body: Value) -> Mock {
        server
            .mock("GET", "/")
            .match_query(Matcher::UrlEncoded("get_domains".into(), "".into()))
            .match_header("authorization", "Bearer test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn mock_add_record(
        server: &mut ServerGuard,
        prefix: &str,
        record_type: &str,
        content: &str,
    ) -> Mock {
        let body = format!(
            "add_record={DOMAIN}&praefix={}&type={record_type}&content={}",
            urlencoding(prefix),
            urlencoding(content),
        );
        server
            .mock("POST", "/")
            .match_header("authorization", "Bearer test_key")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(Matcher::Exact(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"info":"success","status":"201 Created"}"#)
            .create()
    }

    fn mock_del_record_by_id(server: &mut ServerGuard, id: &str) -> Mock {
        let body = format!("del_record={id}");
        server
            .mock("DELETE", "/")
            .match_header("authorization", "Bearer test_key")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(Matcher::Exact(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"info":"success","status":"200 OK"}"#)
            .create()
    }

    fn urlencoding(s: &str) -> String {
        serde_urlencoded::to_string([("k", s)]).unwrap()[2..].to_string()
    }

    fn get_domains_response(records: Value) -> Value {
        json!({
            "info": "success",
            "status": "200 OK",
            "subdomains": {
                DOMAIN: {
                    "updates": 0,
                    "wildcard": 0,
                    "records": records,
                }
            }
        })
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(&mut server, get_domains_response(json!([])));
        let create = mock_add_record(&mut server, "_acme-challenge", "TXT", "challenge-1");

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("challenge-1".to_string())],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 1001, "praefix": "host", "type": "A", "content": "1.1.1.1", "ttl": 60},
            ])),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 2001, "praefix": "host", "type": "A", "content": "1.1.1.1", "ttl": 60},
                {"record_id": 2002, "praefix": "host", "type": "A", "content": "9.9.9.9", "ttl": 60},
                {"record_id": 2003, "praefix": "host", "type": "AAAA", "content": "::1", "ttl": 60},
            ])),
        );
        let delete_stale = mock_del_record_by_id(&mut server, "2002");
        let create_new = mock_add_record(&mut server, "host", "A", "8.8.8.8");

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
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 3001, "praefix": "gone", "type": "A", "content": "1.2.3.4", "ttl": 60},
                {"record_id": 3002, "praefix": "gone", "type": "A", "content": "5.6.7.8", "ttl": 60},
                {"record_id": 3003, "praefix": "gone", "type": "AAAA", "content": "::1", "ttl": 60},
                {"record_id": 3004, "praefix": "other", "type": "A", "content": "8.8.8.8", "ttl": 60},
            ])),
        );
        let delete_a1 = mock_del_record_by_id(&mut server, "3001");
        let delete_a2 = mock_del_record_by_id(&mut server, "3002");

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset("gone.example.com", DnsRecordType::A, 300, vec![], DOMAIN)
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        delete_a1.assert();
        delete_a2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 4001, "praefix": "mix", "type": "TXT", "content": "leave-alone", "ttl": 60},
                {"record_id": 4002, "praefix": "mix", "type": "AAAA", "content": "::1", "ttl": 60},
            ])),
        );
        let create_a = mock_add_record(&mut server, "mix", "A", "1.1.1.1");

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "mix.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create_a.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 5001, "praefix": "_acme-challenge", "type": "TXT", "content": "existing", "ttl": 60},
            ])),
        );
        let create_new = mock_add_record(&mut server, "_acme-challenge", "TXT", "new-token");

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _list = server.mock("GET", "/").expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                vec![],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 6001, "praefix": "_acme-challenge", "type": "TXT", "content": "keep-me", "ttl": 60},
                {"record_id": 6002, "praefix": "_acme-challenge", "type": "TXT", "content": "drop-me", "ttl": 60},
            ])),
        );
        let delete = mock_del_record_by_id(&mut server, "6002");

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _list = server.mock("GET", "/").expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_is_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 7001, "praefix": "host", "type": "A", "content": "1.1.1.1", "ttl": 60},
            ])),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let provider = setup_provider("http://unused.invalid".into());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                DOMAIN,
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_tlsa() {
        let provider = setup_provider("http://unused.invalid".into());
        let result = provider
            .set_rrset("test.example.com", DnsRecordType::TLSA, 300, vec![], DOMAIN)
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("not supported")),
            "expected Error::Unsupported, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_caa() {
        let provider = setup_provider("http://unused.invalid".into());
        let result = provider
            .set_rrset("test.example.com", DnsRecordType::CAA, 300, vec![], DOMAIN)
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("not supported")),
            "expected Error::Unsupported, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_mx_uses_priority_in_content() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(&mut server, get_domains_response(json!([])));
        let create = mock_add_record(&mut server, "", "MX", "10 mail.example.com");

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                DOMAIN,
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_inlines_all_fields_in_content() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(&mut server, get_domains_response(json!([])));
        let create = mock_add_record(
            &mut server,
            "_sip._tcp",
            "SRV",
            "10 5 443 target.example.com",
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 443,
                    target: "target.example.com".to_string(),
                })],
                DOMAIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_matching_records() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_get_domains(
            &mut server,
            get_domains_response(json!([
                {"record_id": 8001, "praefix": "host", "type": "A", "content": "1.1.1.1", "ttl": 60},
                {"record_id": 8002, "praefix": "host", "type": "A", "content": "2.2.2.2", "ttl": 60},
                {"record_id": 8003, "praefix": "host", "type": "AAAA", "content": "::1", "ttl": 60},
                {"record_id": 8004, "praefix": "other", "type": "A", "content": "3.3.3.3", "ttl": 60},
            ])),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, DOMAIN)
            .await
            .expect("list_rrset failed");

        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_double_call_only_acts_once() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/")
            .match_query(Matcher::UrlEncoded("get_domains".into(), "".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_string(&get_domains_response(json!([
                    {"record_id": 11001, "praefix": "host", "type": "A", "content": "1.1.1.1", "ttl": 60},
                ])))
                .unwrap(),
            )
            .expect(2)
            .create();

        let provider = setup_provider(server.url());
        for _ in 0..2 {
            let result = provider
                .set_rrset(
                    "host.example.com",
                    DnsRecordType::A,
                    300,
                    vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                    DOMAIN,
                )
                .await;
            assert!(result.is_ok(), "set_rrset returned: {result:?}");
        }
        list.assert();
    }
}
