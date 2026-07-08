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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, KeyValue, MXRecord, SRVRecord,
        providers::glesys::GlesysProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> GlesysProvider {
        GlesysProvider::new("api_user", "api_key", Some(Duration::from_secs(5)))
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .match_body(mockito::Matcher::Json(json!({"domainname": "example.com"})))
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "A", "host": "www", "data": "1.1.1.1"},
                    {"recordid": 2, "type": "A", "host": "www", "data": "2.2.2.2"},
                    {"recordid": 3, "type": "TXT", "host": "www", "data": "keep"},
                    {"recordid": 4, "type": "A", "host": "other", "data": "9.9.9.9"}
                ]}}"#,
            )
            .create();
        let del1 = server
            .mock("POST", "/domain/deleterecord")
            .match_body(mockito::Matcher::Json(json!({"recordid": 1})))
            .with_status(200)
            .with_body(r#"{"response": {"status": {"code": 200}}}"#)
            .create();
        let del2 = server
            .mock("POST", "/domain/deleterecord")
            .match_body(mockito::Matcher::Json(json!({"recordid": 2})))
            .with_status(200)
            .with_body(r#"{"response": {"status": {"code": 200}}}"#)
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

        assert!(result.is_ok(), "set_rrset empty failed: {result:?}");
        list_mock.assert();
        del1.assert();
        del2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diff_adds_and_deletes() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "A", "host": "www", "data": "1.1.1.1"},
                    {"recordid": 2, "type": "A", "host": "www", "data": "2.2.2.2"},
                    {"recordid": 3, "type": "TXT", "host": "www", "data": "untouched"}
                ]}}"#,
            )
            .create();
        let del_old = server
            .mock("POST", "/domain/deleterecord")
            .match_body(mockito::Matcher::Json(json!({"recordid": 2})))
            .with_status(200)
            .with_body(r#"{"response": {"status": {"code": 200}}}"#)
            .create();
        let add_new = server
            .mock("POST", "/domain/addrecord")
            .match_body(mockito::Matcher::Json(json!({
                "domainname": "example.com",
                "host": "www",
                "type": "A",
                "data": "3.3.3.3",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(r#"{"response": {"record": {"recordid": 10}}}"#)
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

        assert!(result.is_ok(), "set_rrset diff failed: {result:?}");
        list_mock.assert();
        del_old.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_no_calls() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "A", "host": "www", "data": "1.1.1.1"}
                ]}}"#,
            )
            .create();
        let add = server
            .mock("POST", "/domain/addrecord")
            .with_status(500)
            .expect(0)
            .create();
        let del = server
            .mock("POST", "/domain/deleterecord")
            .with_status(500)
            .expect(0)
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

        assert!(result.is_ok(), "set_rrset idempotent failed: {result:?}");
        list_mock.assert();
        add.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_uses_data_priority() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(r#"{"response": {"records": []}}"#)
            .create();
        let add = server
            .mock("POST", "/domain/addrecord")
            .match_body(mockito::Matcher::Json(json!({
                "domainname": "example.com",
                "host": "@",
                "type": "MX",
                "data": "20 backup.example.com.",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_body(r#"{"response": {"record": {"recordid": 11}}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "backup.example.com.".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset MX failed: {result:?}");
        list_mock.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_short_circuits() {
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
        assert!(result.is_ok(), "add empty failed: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "A", "host": "www", "data": "1.1.1.1"}
                ]}}"#,
            )
            .create();
        let add = server
            .mock("POST", "/domain/addrecord")
            .match_body(mockito::Matcher::Json(json!({
                "domainname": "example.com",
                "host": "www",
                "type": "A",
                "data": "2.2.2.2",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(r#"{"response": {"record": {"recordid": 12}}}"#)
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
        list_mock.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_short_circuits() {
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
        assert!(result.is_ok(), "remove empty failed: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_ignores_absent() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "A", "host": "www", "data": "1.1.1.1"}
                ]}}"#,
            )
            .create();
        let del = server
            .mock("POST", "/domain/deleterecord")
            .match_body(mockito::Matcher::Json(json!({"recordid": 1})))
            .with_status(200)
            .with_body(r#"{"response": {"status": {"code": 200}}}"#)
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
        list_mock.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "A", "host": "www", "data": "1.1.1.1"},
                    {"recordid": 2, "type": "AAAA", "host": "www", "data": "2001:db8::1"},
                    {"recordid": 3, "type": "A", "host": "other", "data": "9.9.9.9"},
                    {"recordid": 4, "type": "A", "host": "www", "data": "2.2.2.2"}
                ]}}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        list_mock.assert();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn test_list_rrset_parses_mx_srv_caa() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "MX", "host": "@", "data": "10 mail.example.com."}
                ]}}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset MX failed");
        list_mock.assert();
        assert_eq!(
            result,
            vec![DnsRecord::MX(MXRecord {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            })]
        );

        let mut server2 = mockito::Server::new_async().await;
        let list_mock2 = server2
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "SRV", "host": "_sip._tcp", "data": "10 20 5060 sip.example.com."}
                ]}}"#,
            )
            .create();
        let provider2 = setup_provider(server2.url().as_str());
        let result2 = provider2
            .list_rrset("_sip._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await
            .expect("list_rrset SRV failed");
        list_mock2.assert();
        assert_eq!(
            result2,
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 20,
                port: 5060,
                target: "sip.example.com".to_string(),
            })]
        );

        let mut server3 = mockito::Server::new_async().await;
        let list_mock3 = server3
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 1, "type": "CAA", "host": "@", "data": "0 issue \"letsencrypt.org\""}
                ]}}"#,
            )
            .create();
        let provider3 = setup_provider(server3.url().as_str());
        let result3 = provider3
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .expect("list_rrset CAA failed");
        list_mock3.assert();
        assert_eq!(
            result3,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: Vec::<KeyValue>::new(),
            })]
        );
    }

    #[tokio::test]
    async fn test_set_rrset_caa_encodes_bind_style() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(r#"{"response": {"records": []}}"#)
            .create();
        let add = server
            .mock("POST", "/domain/addrecord")
            .match_body(mockito::Matcher::Json(json!({
                "domainname": "example.com",
                "host": "@",
                "type": "CAA",
                "data": "0 issue \"letsencrypt.org\"",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_body(r#"{"response": {"record": {"recordid": 1}}}"#)
            .create();

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

        assert!(result.is_ok(), "set_rrset CAA failed: {result:?}");
        list_mock.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_type_validation_rejects_wrong_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result:?}"
        );

        let result_add = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result_add, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result_add:?}"
        );

        let result_remove = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result_remove, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result_remove:?}"
        );
    }

    #[tokio::test]
    async fn test_tlsa_refused() {
        use crate::{TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector};

        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0u8; 32],
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
    #[ignore = "Requires GleSYS credentials, zone, and FQDN"]
    async fn integration_test() {
        let user = std::env::var("GLESYS_API_USER").unwrap_or_default();
        let key = std::env::var("GLESYS_API_KEY").unwrap_or_default();
        let origin = std::env::var("GLESYS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("GLESYS_FQDN").unwrap_or_default();

        assert!(!user.is_empty() && !key.is_empty());
        assert!(!origin.is_empty() && !fqdn.is_empty());

        let updater = DnsUpdater::new_glesys(user, key, Some(Duration::from_secs(30))).unwrap();
        let set = updater
            .set_rrset(
                &fqdn,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A([1, 1, 1, 1].into())],
                &origin,
            )
            .await;
        assert!(set.is_ok(), "set_rrset failed: {set:?}");
        let clear = updater
            .set_rrset(&fqdn, DnsRecordType::A, 300, Vec::new(), &origin)
            .await;
        assert!(clear.is_ok(), "clear failed: {clear:?}");
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_glesys("u", "k", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::Glesys(..))));
    }
}
