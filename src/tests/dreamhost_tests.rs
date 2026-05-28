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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::dreamhost::DreamhostProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> DreamhostProvider {
        DreamhostProvider::new("test_key", Some(Duration::from_secs(5))).with_endpoint(endpoint)
    }

    fn list_body(records: &[(&str, &str, &str)]) -> String {
        let entries: Vec<String> = records
            .iter()
            .map(|(name, ty, value)| {
                format!(r#"{{"record":"{name}","type":"{ty}","value":"{value}","editable":"1"}}"#)
            })
            .collect();
        format!(r#"{{"result":"success","data":[{}]}}"#, entries.join(","))
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_all_of_type() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[
                ("test.example.com", "A", "1.1.1.1"),
                ("test.example.com", "A", "2.2.2.2"),
                ("test.example.com", "TXT", "keep-me"),
                ("other.example.com", "A", "9.9.9.9"),
            ]))
            .create();
        let remove_1 = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("value".into(), "1.1.1.1".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();
        let remove_2 = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("value".into(), "2.2.2.2".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset empty failed: {result:?}");
        remove_1.assert();
        remove_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diff_adds_and_removes() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[
                ("test.example.com", "A", "1.1.1.1"),
                ("test.example.com", "A", "2.2.2.2"),
            ]))
            .create();
        let remove_old = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "2.2.2.2".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();
        let add_new = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-add_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "3.3.3.3".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
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
        remove_old.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[("test.example.com", "A", "1.1.1.1")]))
            .create();
        let add_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-add_record".into(),
            ))
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_added"}"#)
            .create();
        let remove_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-remove_record".into(),
            ))
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset idempotent failed: {result:?}");
        add_mock.assert();
        remove_mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[
                ("test.example.com", "A", "1.1.1.1"),
                ("test.example.com", "TXT", "must-stay"),
            ]))
            .create();
        let no_txt_remove = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();
        let remove_a = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
                mockito::Matcher::UrlEncoded("value".into(), "1.1.1.1".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "cross-type isolation failed: {result:?}");
        remove_a.assert();
        no_txt_remove.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_no_op() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[]}"#)
            .create();
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
        assert!(result.is_ok());
        list_mock.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_present_values() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[("test.example.com", "A", "1.1.1.1")]))
            .create();
        let add_existing = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-add_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "1.1.1.1".into()),
            ]))
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_added"}"#)
            .create();
        let add_new = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-add_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "2.2.2.2".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
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
        add_existing.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_no_op() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[]}"#)
            .create();
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok());
        list_mock.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_skips_absent_values() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[("test.example.com", "A", "1.1.1.1")]))
            .create();
        let remove_present = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "1.1.1.1".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();
        let remove_absent = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "9.9.9.9".into()),
            ]))
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":"record_removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        remove_present.assert();
        remove_absent.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(list_body(&[
                ("test.example.com", "A", "1.1.1.1"),
                ("test.example.com", "A", "2.2.2.2"),
                ("test.example.com", "TXT", "skip"),
                ("other.example.com", "A", "9.9.9.9"),
            ]))
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await;
        let records = result.expect("list_rrset failed");
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
    }

    #[tokio::test]
    async fn test_caa_rejected_at_client() {
        let mut server = mockito::Server::new_async().await;
        let no_calls = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let caa = DnsRecord::CAA(CAARecord::Issue {
            issuer_critical: false,
            name: Some("letsencrypt.org".to_string()),
            options: vec![],
        });
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::CAA,
                300,
                vec![caa.clone()],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("CAA")),
            "expected CAA rejection, got {result:?}"
        );

        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::CAA,
                300,
                vec![caa.clone()],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("CAA")),
            "expected CAA rejection on add_to_rrset, got {result:?}"
        );

        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::CAA,
                vec![caa],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("CAA")),
            "expected CAA rejection on remove_from_rrset, got {result:?}"
        );

        no_calls.assert();
    }

    #[tokio::test]
    async fn test_tlsa_rejected_at_client() {
        let mut server = mockito::Server::new_async().await;
        let no_calls = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
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
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
        no_calls.assert();
    }

    #[tokio::test]
    async fn test_type_mismatch_rejected() {
        let mut server = mockito::Server::new_async().await;
        let no_calls = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("mismatch")),
            "expected type mismatch, got {result:?}"
        );
        no_calls.assert();
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_dreamhost("k", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::Dreamhost(..))));
    }
}
