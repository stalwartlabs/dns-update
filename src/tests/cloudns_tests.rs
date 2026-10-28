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
        TlsaMatching, TlsaSelector, providers::cloudns::ClouDnsProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> ClouDnsProvider {
        ClouDnsProvider::new(
            Some("auth_user"),
            None::<&str>,
            "pw",
            Some(Duration::from_secs(5)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    #[test]
    fn test_provider_requires_auth() {
        let result = ClouDnsProvider::new(None::<&str>, None::<&str>, "pw", None);
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "www", "record": "1.1.1.1"},
                    "2": {"id": "2", "type": "A", "host": "www", "record": "2.2.2.2"}
                }"#,
            )
            .create();

        let del1 = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "1".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .expect_at_least(1)
            .create();
        let del2 = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "2".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .expect_at_least(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset(empty) failed: {result:?}");
        lookup.assert();
        del1.assert();
        del2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_on_empty_rrset_noop() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset(empty) failed: {result:?}");
        lookup.assert();
    }

    #[tokio::test]
    async fn test_in_body_rate_limit_is_retried() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body("[]")
            .create();

        let add_throttled = server
            .mock("POST", "/add-record.json")
            .with_status(200)
            .with_body(
                r#"{"status":"Failed","statusDescription":"Request blocked, 1.2.3.4 is sending more than 20 requests per second."}"#,
            )
            .expect(1)
            .create();

        let add_ok = server
            .mock("POST", "/add-record.json")
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .expect(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(
            result.is_ok(),
            "add_to_rrset should retry throttle: {result:?}"
        );
        lookup.assert();
        add_throttled.assert();
        add_ok.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diff_adds_and_deletes() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "www", "record": "1.1.1.1"},
                    "2": {"id": "2", "type": "A", "host": "www", "record": "2.2.2.2"}
                }"#,
            )
            .create();

        let delete_stale = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "2".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .create();

        let add_new = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("host".into(), "www".into()),
                mockito::Matcher::UrlEncoded("record-type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("record".into(), "3.3.3.3".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("3.3.3.3".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        lookup.assert();
        delete_stale.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_no_writes() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "www", "record": "1.1.1.1"}
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        lookup.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "www", "record": "1.1.1.1"}
                }"#,
            )
            .create();

        let add_new = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::UrlEncoded(
                "record".into(),
                "2.2.2.2".into(),
            ))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
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

        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        lookup.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset(empty) failed: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_matching() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "www", "record": "1.1.1.1"},
                    "2": {"id": "2", "type": "A", "host": "www", "record": "2.2.2.2"}
                }"#,
            )
            .create();

        let delete = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "1".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        lookup.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(
            result.is_ok(),
            "remove_from_rrset(empty) failed: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "www", "record": "1.1.1.1"},
                    "2": {"id": "2", "type": "A", "host": "www", "record": "2.2.2.2"}
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        lookup.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_empty() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert!(result.is_empty());
        lookup.assert();
    }

    #[tokio::test]
    async fn test_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))));
    }

    fn dane_ee_spki_sha256(cert_data: Vec<u8>) -> DnsRecord {
        DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data,
        })
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_adds_with_tlsa_fields() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("host".into(), "_25._tcp.mail".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TLSA".into()),
            ]))
            .with_status(200)
            .with_body("[]")
            .create();

        let add = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("host".into(), "_25._tcp.mail".into()),
                mockito::Matcher::UrlEncoded("record-type".into(), "TLSA".into()),
                mockito::Matcher::UrlEncoded("record".into(), "0aff10".into()),
                mockito::Matcher::UrlEncoded("tlsa_usage".into(), "3".into()),
                mockito::Matcher::UrlEncoded("tlsa_selector".into(), "1".into()),
                mockito::Matcher::UrlEncoded("tlsa_matching_type".into(), "1".into()),
                mockito::Matcher::UrlEncoded("ttl".into(), "3600".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![dane_ee_spki_sha256(vec![0x0a, 0xff, 0x10])],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        lookup.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_idempotent_ignores_hex_case() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "7": {"id": "7", "type": "TLSA", "host": "_25._tcp.mail", "record": "0AFF10",
                          "tlsa_usage": "3", "tlsa_selector": "1", "tlsa_matching_type": "1"}
                }"#,
            )
            .create();
        let no_writes = server
            .mock("POST", mockito::Matcher::Any)
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![dane_ee_spki_sha256(vec![0x0a, 0xff, 0x10])],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        lookup.assert();
        no_writes.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_replaces_stale_record() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "7": {"id": "7", "type": "TLSA", "host": "_25._tcp.mail", "record": "0aff10",
                          "tlsa_usage": "3", "tlsa_selector": "1", "tlsa_matching_type": "1"},
                    "8": {"id": "8", "type": "TLSA", "host": "_25._tcp.mail", "record": "0aff10",
                          "tlsa_usage": "2", "tlsa_selector": "1", "tlsa_matching_type": "1"}
                }"#,
            )
            .create();

        let delete_stale = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "8".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .create();

        let add_new = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("record".into(), "beef".into()),
                mockito::Matcher::UrlEncoded("tlsa_usage".into(), "3".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![
                    dane_ee_spki_sha256(vec![0x0a, 0xff, 0x10]),
                    dane_ee_spki_sha256(vec![0xbe, 0xef]),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        lookup.assert();
        delete_stale.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "7": {"id": "7", "type": "TLSA", "host": "_25._tcp.mail", "record": "0AFF10",
                          "tlsa_usage": "3", "tlsa_selector": "1", "tlsa_matching_type": "1"}
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await
            .unwrap();
        assert_eq!(result, vec![dane_ee_spki_sha256(vec![0x0a, 0xff, 0x10])]);
        lookup.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_tlsa_missing_field_is_parse_error() {
        let mut server = mockito::Server::new_async().await;
        let _lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "7": {"id": "7", "type": "TLSA", "host": "_25._tcp.mail", "record": "0aff10",
                          "tlsa_selector": "1", "tlsa_matching_type": "1"}
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Parse(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_normalizes_trailing_dot_on_cname() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body("[]")
            .create();

        let add_new = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("record-type".into(), "CNAME".into()),
                mockito::Matcher::UrlEncoded("record".into(), "target.example.org".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME("target.example.org.".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset(cname) failed: {result:?}");
        lookup.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_normalizes_trailing_dot_on_mx_exchange() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body("[]")
            .create();

        let add_new = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("record-type".into(), "MX".into()),
                mockito::Matcher::UrlEncoded("record".into(), "mail.example.org".into()),
                mockito::Matcher::UrlEncoded("priority".into(), "10".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                300,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.org.".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset(mx) failed: {result:?}");
        lookup.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_multi_record_diff_for_widened_finder() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(
                r#"{
                    "1": {"id": "1", "type": "A", "host": "multi", "record": "1.1.1.1"},
                    "2": {"id": "2", "type": "A", "host": "multi", "record": "2.2.2.2"},
                    "3": {"id": "3", "type": "A", "host": "multi", "record": "3.3.3.3"}
                }"#,
            )
            .create();

        let del2 = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "2".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .create();
        let del3 = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "3".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "multi.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        lookup.assert();
        del2.assert();
        del3.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_empty_host() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("host".into(), "".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body("[]")
            .create();

        let add = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("host".into(), "".into()),
                mockito::Matcher::UrlEncoded("record-type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "apex set_rrset failed: {result:?}");
        lookup.assert();
        add.assert();
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_cloudns(
            Some("user"),
            None::<&str>,
            "pw",
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::ClouDns(..))));
    }

    fn live_provider() -> (ClouDnsProvider, String, String) {
        let auth_id = std::env::var("CLOUDNS_AUTH_ID").ok();
        let sub_auth_id = std::env::var("CLOUDNS_SUB_AUTH_ID").ok();
        let password = std::env::var("CLOUDNS_AUTH_PASSWORD").unwrap();
        let zone = std::env::var("CLOUDNS_ZONE").unwrap();
        let name = format!("_25._tcp.dns-update-test.{zone}");
        let provider = ClouDnsProvider::new(
            auth_id,
            sub_auth_id,
            password,
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        (provider, zone, name)
    }

    fn live_records() -> Vec<DnsRecord> {
        vec![
            dane_ee_spki_sha256((0u8..32).collect()),
            DnsRecord::TLSA(TLSARecord {
                cert_usage: TlsaCertUsage::DaneTa,
                selector: TlsaSelector::Spki,
                matching: TlsaMatching::Sha256,
                cert_data: (32u8..64).collect(),
            }),
        ]
    }

    async fn live_list(provider: &ClouDnsProvider, name: &str, zone: &str) -> Vec<DnsRecord> {
        let listed = provider
            .list_rrset(name, DnsRecordType::TLSA, zone)
            .await
            .unwrap();
        eprintln!("list_rrset {name} TLSA -> {} record(s)", listed.len());
        for record in &listed {
            eprintln!("  {record}");
        }
        listed
    }

    #[tokio::test]
    #[ignore = "Requires CLOUDNS_AUTH_ID or CLOUDNS_SUB_AUTH_ID, CLOUDNS_AUTH_PASSWORD and CLOUDNS_ZONE"]
    async fn integration_tlsa_publish() {
        let (provider, zone, name) = live_provider();
        let records = live_records();

        eprintln!("step 1: set_rrset {name} TLSA (zone {zone})");
        for record in &records {
            eprintln!("  {record}");
        }
        provider
            .set_rrset(&name, DnsRecordType::TLSA, 300, records.clone(), &zone)
            .await
            .unwrap();

        eprintln!("step 2: read back");
        let listed = live_list(&provider, &name, &zone).await;
        assert_eq!(listed.len(), records.len());
        for record in &records {
            assert!(listed.contains(record), "missing {record}");
        }

        eprintln!("step 3: set_rrset again with the same records (expect no change)");
        provider
            .set_rrset(&name, DnsRecordType::TLSA, 300, records.clone(), &zone)
            .await
            .unwrap();
        assert_eq!(
            live_list(&provider, &name, &zone).await.len(),
            records.len()
        );

        eprintln!("step 4: set_rrset with only the 3 1 1 record (expect the 2 1 1 record removed)");
        provider
            .set_rrset(
                &name,
                DnsRecordType::TLSA,
                300,
                vec![records[0].clone()],
                &zone,
            )
            .await
            .unwrap();
        assert_eq!(
            live_list(&provider, &name, &zone).await,
            vec![records[0].clone()]
        );

        eprintln!("step 5: add_to_rrset the 2 1 1 record back (expect 2 records)");
        provider
            .add_to_rrset(
                &name,
                DnsRecordType::TLSA,
                300,
                vec![records[1].clone()],
                &zone,
            )
            .await
            .unwrap();
        assert_eq!(live_list(&provider, &name, &zone).await.len(), 2);
        eprintln!("PUBLISH OK: both records left in place for external checks");
    }

    #[tokio::test]
    #[ignore = "Requires CLOUDNS_AUTH_ID or CLOUDNS_SUB_AUTH_ID, CLOUDNS_AUTH_PASSWORD and CLOUDNS_ZONE"]
    async fn integration_tlsa_cleanup() {
        let (provider, zone, name) = live_provider();

        eprintln!("step 6: remove_from_rrset the 2 1 1 record (expect 1 record)");
        provider
            .remove_from_rrset(
                &name,
                DnsRecordType::TLSA,
                vec![live_records()[1].clone()],
                &zone,
            )
            .await
            .unwrap();
        assert_eq!(live_list(&provider, &name, &zone).await.len(), 1);

        eprintln!("step 7: set_rrset with no records (expect the RRSet deleted)");
        provider
            .set_rrset(&name, DnsRecordType::TLSA, 300, Vec::new(), &zone)
            .await
            .unwrap();
        assert!(live_list(&provider, &name, &zone).await.is_empty());
        eprintln!("CLEANUP OK");
    }
}
