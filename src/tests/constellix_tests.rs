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
        DnsRecord, DnsRecordType, Error, MXRecord, providers::constellix::ConstellixProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN_ID: i64 = 12345;

    fn setup_provider(endpoint: String) -> ConstellixProvider {
        ConstellixProvider::new("api_key", "secret_key", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_domain_search(server: &mut ServerGuard, zone: &str) -> Mock {
        server
            .mock("GET", "/v1/domains/search")
            .match_query(Matcher::UrlEncoded("exact".into(), zone.into()))
            .match_header(
                "x-cns-security-token",
                Matcher::Regex("^api_key:[^:]+:[0-9]+$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(r#"[{{"id":{DOMAIN_ID},"name":"{zone}"}}]"#))
            .create()
    }

    fn mock_record_search(
        server: &mut ServerGuard,
        type_segment: &str,
        subdomain: &str,
        body: serde_json::Value,
    ) -> Mock {
        server
            .mock(
                "GET",
                format!("/v1/domains/{DOMAIN_ID}/records/{type_segment}/search").as_str(),
            )
            .match_query(Matcher::UrlEncoded("exact".into(), subdomain.into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_uses_bulk_delete_plus_add() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");

        let bulk = server
            .mock("POST", "/v1/domains/12345/records")
            .match_body(Matcher::Json(json!([
                {
                    "type": "a",
                    "delete": true,
                    "filter": {"field": "name", "op": "eq", "value": "host"},
                },
                {
                    "type": "a",
                    "add": true,
                    "set": {
                        "name": "host",
                        "ttl": 300,
                        "roundRobin": [
                            {"value": "1.1.1.1"},
                            {"value": "2.2.2.2"},
                        ],
                    },
                },
            ])))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
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
        domain_search.assert();
        bulk.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_only() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");

        let bulk = server
            .mock("POST", "/v1/domains/12345/records")
            .match_body(Matcher::Json(json!([
                {
                    "type": "txt",
                    "delete": true,
                    "filter": {"field": "name", "op": "eq", "value": "_acme-challenge"},
                },
            ])))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                60,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_search.assert();
        bulk.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".into())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("type mismatch")),
            "expected type mismatch error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::TLSA,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_mx_uses_level() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");

        let bulk = server
            .mock("POST", "/v1/domains/12345/records")
            .match_body(Matcher::Json(json!([
                {
                    "type": "mx",
                    "delete": true,
                    "filter": {"field": "name", "op": "eq", "value": ""},
                },
                {
                    "type": "mx",
                    "add": true,
                    "set": {
                        "name": "",
                        "ttl": 3600,
                        "roundRobin": [
                            {"value": "mail1.example.com.", "level": 10},
                            {"value": "mail2.example.com.", "level": 20},
                        ],
                    },
                },
            ])))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mail1.example.com.".into(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mail2.example.com.".into(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        domain_search.assert();
        bulk.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_when_missing() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(&mut server, "a", "host", json!([]));
        let create = server
            .mock("POST", "/v1/domains/12345/records/a")
            .match_body(Matcher::Json(json!({
                "name": "host",
                "ttl": 300,
                "roundRobin": [{"value": "1.1.1.1"}],
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":7}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domain_search.assert();
        record_search.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_merges_into_existing() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "a",
            "host",
            json!([{"id":42, "ttl":300, "roundRobin":[{"value":"1.1.1.1"}]}]),
        );
        let update = server
            .mock("PUT", "/v1/domains/12345/records/a/42")
            .match_body(Matcher::Json(json!({
                "name": "host",
                "ttl": 300,
                "roundRobin": [
                    {"value": "1.1.1.1"},
                    {"value": "2.2.2.2"},
                ],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
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
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domain_search.assert();
        record_search.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_is_idempotent_when_all_present() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "a",
            "host",
            json!([{"id":42, "ttl":300, "roundRobin":[{"value":"1.1.1.1"}]}]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        domain_search.assert();
        record_search.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_drops_one_keeps_others() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "a",
            "host",
            json!([{"id":42, "ttl":300, "roundRobin":[
                {"value":"1.1.1.1"},
                {"value":"2.2.2.2"},
            ]}]),
        );
        let update = server
            .mock("PUT", "/v1/domains/12345/records/a/42")
            .match_body(Matcher::Json(json!({
                "name": "host",
                "ttl": 300,
                "roundRobin": [
                    {"value": "1.1.1.1"},
                ],
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domain_search.assert();
        record_search.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_record_when_emptied() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "a",
            "host",
            json!([{"id":42, "ttl":300, "roundRobin":[
                {"value":"1.1.1.1"},
            ]}]),
        );
        let delete = server
            .mock("DELETE", "/v1/domains/12345/records/a/42")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        domain_search.assert();
        record_search.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "a",
            "host",
            json!([{"id":42, "ttl":300, "roundRobin":[
                {"value":"1.1.1.1"},
            ]}]),
        );

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
        domain_search.assert();
        record_search.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "a",
            "host",
            json!([{"id":42, "ttl":300, "roundRobin":[
                {"value":"1.1.1.1"},
                {"value":"2.2.2.2"},
            ]}]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
        domain_search.assert();
        record_search.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_when_no_record() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(&mut server, "txt", "missing", json!([]));

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::TXT, "example.com")
            .await
            .unwrap();
        assert!(result.is_empty(), "list_rrset returned: {result:?}");
        domain_search.assert();
        record_search.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_txt_unquotes_value() {
        let mut server = mockito::Server::new_async().await;
        let domain_search = mock_domain_search(&mut server, "example.com");
        let record_search = mock_record_search(
            &mut server,
            "txt",
            "_acme-challenge",
            json!([{"id":1, "ttl":60, "roundRobin":[
                {"value":"\"hello world\""},
            ]}]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await
            .unwrap();
        assert_eq!(result, vec![DnsRecord::TXT("hello world".into())]);
        domain_search.assert();
        record_search.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_rejects_tlsa() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::TLSA, "example.com")
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires CONSTELLIX_API_KEY, CONSTELLIX_SECRET_KEY, CONSTELLIX_DOMAIN env vars"]
    async fn test_live_constellix_roundtrip() {
        let api_key = std::env::var("CONSTELLIX_API_KEY").expect("CONSTELLIX_API_KEY");
        let secret_key = std::env::var("CONSTELLIX_SECRET_KEY").expect("CONSTELLIX_SECRET_KEY");
        let domain = std::env::var("CONSTELLIX_DOMAIN").expect("CONSTELLIX_DOMAIN");
        let provider =
            ConstellixProvider::new(api_key, secret_key, Some(Duration::from_secs(30))).unwrap();
        provider
            .set_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("hello".into())],
                &domain,
            )
            .await
            .unwrap();
        let listed = provider
            .list_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                &domain,
            )
            .await
            .unwrap();
        assert_eq!(listed, vec![DnsRecord::TXT("hello".into())]);
        provider
            .set_rrset(
                format!("dns-update-test.{domain}"),
                DnsRecordType::TXT,
                60,
                Vec::new(),
                &domain,
            )
            .await
            .unwrap();
    }
}
