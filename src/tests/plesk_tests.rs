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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::plesk::PleskProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const SITE_ID: i64 = 42;

    fn setup_provider(endpoint: &str) -> PleskProvider {
        PleskProvider::new(endpoint, "test_api_key", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn mock_domain(server: &mut ServerGuard, zone: &str) -> Mock {
        server
            .mock("GET", "/api/v2/domains")
            .match_query(Matcher::UrlEncoded("name".into(), zone.into()))
            .match_header("x-api-key", "test_api_key")
            .with_status(200)
            .with_body(format!(r#"[{{"id": {SITE_ID}, "name": "{zone}"}}]"#))
            .expect_at_least(1)
            .create()
    }

    fn mock_list_records(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("GET", "/api/v2/dns/records")
            .match_query(Matcher::UrlEncoded("site_id".into(), SITE_ID.to_string()))
            .match_header("x-api-key", "test_api_key")
            .with_status(200)
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_plesk(
            "https://plesk.example.com:8443",
            "test_api_key",
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Plesk(..))));
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(&mut server, json!([]));

        let create_a = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "A",
                "host": "www",
                "value": "1.1.1.1",
                "ttl": 300
            })))
            .with_status(200)
            .with_body(r#"{"id": 5001}"#)
            .create();

        let create_b = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "A",
                "host": "www",
                "value": "2.2.2.2",
                "ttl": 300
            })))
            .with_status(200)
            .with_body(r#"{"id": 5002}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
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
        create_a.assert();
        create_b.assert();
    }

    #[tokio::test]
    async fn set_rrset_is_noop_when_matching() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 7001, "type": "A", "host": "host.example.com.", "value": "1.1.1.1", "opt": ""}
            ]),
        );

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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn set_rrset_deletes_extras_and_adds_missing() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 8001, "type": "A", "host": "host.example.com.", "value": "1.1.1.1", "opt": ""},
                {"id": 8002, "type": "A", "host": "host.example.com.", "value": "9.9.9.9", "opt": ""}
            ]),
        );

        let delete_stale = server
            .mock("DELETE", "/api/v2/dns/records/8002")
            .with_status(204)
            .create();
        let create_new = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "A",
                "host": "host",
                "value": "8.8.8.8",
                "ttl": 300
            })))
            .with_status(200)
            .with_body(r#"{"id": 8003}"#)
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_all_of_type_only() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 9001, "type": "A", "host": "host.example.com.", "value": "1.1.1.1", "opt": ""},
                {"id": 9002, "type": "A", "host": "host.example.com.", "value": "2.2.2.2", "opt": ""},
                {"id": 9003, "type": "TXT", "host": "host.example.com.", "value": "keep", "opt": ""},
                {"id": 9004, "type": "AAAA", "host": "host.example.com.", "value": "::1", "opt": ""}
            ]),
        );

        let delete_a1 = server
            .mock("DELETE", "/api/v2/dns/records/9001")
            .with_status(204)
            .create();
        let delete_a2 = server
            .mock("DELETE", "/api/v2/dns/records/9002")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
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
        delete_a1.assert();
        delete_a2.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing_and_adds_new() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 10001, "type": "TXT", "host": "_acme.example.com.", "value": "existing", "opt": ""}
            ]),
        );

        let create_mock = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "TXT",
                "host": "_acme",
                "value": "new-token",
                "ttl": 60
            })))
            .with_status(200)
            .with_body(r#"{"id": 10002}"#)
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

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        create_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_vec_is_noop() {
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
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 11001, "type": "TXT", "host": "_acme.example.com.", "value": "keep-me", "opt": ""},
                {"id": 11002, "type": "TXT", "host": "_acme.example.com.", "value": "drop-me", "opt": ""}
            ]),
        );

        let delete_mock = server
            .mock("DELETE", "/api/v2/dns/records/11002")
            .with_status(204)
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

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        delete_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_empty_vec_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn set_rrset_tlsa_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0x00],
                })],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn set_rrset_txt_chunks_long_value() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(&mut server, json!([]));

        let long_value: String = "a".repeat(300);
        let first_chunk: String = "a".repeat(255);
        let second_chunk: String = "a".repeat(45);

        let create_first = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "TXT",
                "host": "long",
                "value": first_chunk,
                "ttl": 300
            })))
            .with_status(200)
            .with_body(r#"{"id": 12001}"#)
            .create();

        let create_second = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "TXT",
                "host": "long",
                "value": second_chunk,
                "ttl": 300
            })))
            .with_status(200)
            .with_body(r#"{"id": 12002}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "long.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long_value)],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create_first.assert();
        create_second.assert();
    }

    #[tokio::test]
    async fn set_rrset_mx_with_priority() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(&mut server, json!([]));

        let create_mock = server
            .mock("POST", "/api/v2/dns/records")
            .match_body(Matcher::Json(json!({
                "site_id": SITE_ID,
                "type": "MX",
                "host": "",
                "value": "mail.example.com",
                "opt": "10",
                "ttl": 3600
            })))
            .with_status(200)
            .with_body(r#"{"id": 13001}"#)
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

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        create_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_filtered_records() {
        let mut server = mockito::Server::new_async().await;
        let _domain_mock = mock_domain(&mut server, "example.com");
        let _list_mock = mock_list_records(
            &mut server,
            json!([
                {"id": 14001, "type": "A", "host": "host.example.com.", "value": "1.1.1.1", "opt": ""},
                {"id": 14002, "type": "A", "host": "host.example.com.", "value": "2.2.2.2", "opt": ""},
                {"id": 14003, "type": "TXT", "host": "host.example.com.", "value": "skip", "opt": ""},
                {"id": 14004, "type": "A", "host": "other.example.com.", "value": "3.3.3.3", "opt": ""}
            ]),
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }
}
