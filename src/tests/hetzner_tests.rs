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
        DnsRecord, DnsRecordType, Error, MXRecord, TLSARecord, TlsaCertUsage, TlsaMatching,
        TlsaSelector, providers::hetzner::HetznerProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> HetznerProvider {
        HetznerProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn ok_action() -> &'static str {
        r#"{"action":{"id":1,"status":"success"}}"#
    }

    #[tokio::test]
    async fn test_set_rrset_calls_set_records_then_change_ttl() {
        let mut server = mockito::Server::new_async().await;
        let set_records = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/set_records",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "records": [{"value": "1.1.1.1"}, {"value": "2.2.2.2"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let change_ttl = server
            .mock("POST", "/zones/example.com/rrsets/www/A/actions/change_ttl")
            .match_body(Matcher::Json(json!({"ttl": 300})))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
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
        set_records.assert();
        change_ttl.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_set_records_returns_404() {
        let mut server = mockito::Server::new_async().await;
        let set_records = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/set_records",
            )
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"rrset not found"}}"#)
            .create();

        let add_records = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/add_records",
            )
            .match_body(Matcher::Json(json!({
                "records": [{"value": "1.1.1.1"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let change_ttl = server
            .mock("POST", "/zones/example.com/rrsets/www/A/actions/change_ttl")
            .match_body(Matcher::Json(json!({"ttl": 300})))
            .with_status(200)
            .with_body(ok_action())
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
        set_records.assert();
        add_records.assert();
        change_ttl.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_this_type() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/zones/example.com/rrsets/www/A")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/zones/example.com/rrsets/www/A")
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"rrset not found"}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("foo".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("RRSet record type mismatch")),
            "expected mismatch error, got {result:?}"
        );
    }

    fn tlsa_dane_ee() -> DnsRecord {
        DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xab, 0xcd],
        })
    }

    fn tlsa_dane_ta() -> DnsRecord {
        DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneTa,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0x12, 0x34, 0x56, 0x78],
        })
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let set_records = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_25._tcp.mail/TLSA/actions/set_records",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "records": [{"value": "3 1 1 abcd"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let change_ttl = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_25._tcp.mail/TLSA/actions/change_ttl",
            )
            .match_body(Matcher::Json(json!({"ttl": 300})))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![tlsa_dane_ee()],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        set_records.assert();
        change_ttl.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_multiple() {
        let mut server = mockito::Server::new_async().await;
        let set_records = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_25._tcp.mail/TLSA/actions/set_records",
            )
            .match_body(Matcher::Json(json!({
                "records": [
                    {"value": "3 1 1 abcd"},
                    {"value": "2 1 1 12345678"},
                ],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let change_ttl = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_25._tcp.mail/TLSA/actions/change_ttl",
            )
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![tlsa_dane_ee(), tlsa_dane_ta()],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        set_records.assert();
        change_ttl.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_posts_add_records_then_change_ttl() {
        let mut server = mockito::Server::new_async().await;
        let add = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/add_records",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "records": [{"value": "3.3.3.3"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let change_ttl = server
            .mock("POST", "/zones/example.com/rrsets/www/A/actions/change_ttl")
            .match_body(Matcher::Json(json!({"ttl": 600})))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        add.assert();
        change_ttl.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_falls_back_to_set_records_when_add_records_returns_404() {
        let mut server = mockito::Server::new_async().await;
        let add = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/add_records",
            )
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"rrset not found"}}"#)
            .create();

        let set_records = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/set_records",
            )
            .match_body(Matcher::Json(json!({
                "records": [{"value": "3.3.3.3"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let change_ttl = server
            .mock("POST", "/zones/example.com/rrsets/www/A/actions/change_ttl")
            .match_body(Matcher::Json(json!({"ttl": 600})))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("3.3.3.3".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        add.assert();
        set_records.assert();
        change_ttl.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_posts_remove_records() {
        let mut server = mockito::Server::new_async().await;
        let remove = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/remove_records",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "records": [{"value": "1.1.1.1"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        remove.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let remove = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/remove_records",
            )
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"rrset not found"}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        remove.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let remove = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_25._tcp.mail/TLSA/actions/remove_records",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "records": [{"value": "3 1 1 abcd"}],
            })))
            .with_status(200)
            .with_body(ok_action())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                vec![tlsa_dane_ee()],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        remove.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/example.com/rrsets")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "www".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "50".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"rrsets":[{"id":"www/A","name":"www","type":"A","ttl":300,"records":[{"value":"1.1.1.1"},{"value":"2.2.2.2"}]}],"meta":{}}"#,
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
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_on_404() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/example.com/rrsets")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "missing".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "50".into()),
            ]))
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"zone not found"}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert!(result.unwrap().is_empty());
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_when_no_rrsets() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/example.com/rrsets")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "www".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
                Matcher::UrlEncoded("per_page".into(), "50".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"rrsets":[],"meta":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert!(result.unwrap().is_empty());
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_tlsa() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/example.com/rrsets")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "_25._tcp.mail".into()),
                Matcher::UrlEncoded("type".into(), "TLSA".into()),
                Matcher::UrlEncoded("per_page".into(), "50".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"rrsets":[{"id":"_25._tcp.mail/TLSA","name":"_25._tcp.mail","type":"TLSA","ttl":300,"records":[{"value":"3 1 1 abcd"},{"value":"2 1 1 12345678"}]}],"meta":{}}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert_eq!(result.unwrap(), vec![tlsa_dane_ee(), tlsa_dane_ta()]);
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_mx() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/example.com/rrsets")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "@".into()),
                Matcher::UrlEncoded("type".into(), "MX".into()),
                Matcher::UrlEncoded("per_page".into(), "50".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"rrsets":[{"id":"@/MX","name":"@","type":"MX","ttl":300,"records":[{"value":"10 mail.example.com."}]}],"meta":{}}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let records = result.unwrap();
        assert_eq!(
            records,
            vec![DnsRecord::MX(MXRecord {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            })]
        );
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_txt_with_quotes() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/example.com/rrsets")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), "_acme-challenge".into()),
                Matcher::UrlEncoded("type".into(), "TXT".into()),
                Matcher::UrlEncoded("per_page".into(), "50".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"rrsets":[{"id":"_acme-challenge/TXT","name":"_acme-challenge","type":"TXT","ttl":300,"records":[{"value":"\"hello world\""}]}],"meta":{}}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        assert_eq!(
            result.unwrap(),
            vec![DnsRecord::TXT("hello world".to_string())]
        );
        list.assert();
    }

    #[tokio::test]
    async fn test_retry_on_429() {
        let mut server = mockito::Server::new_async().await;
        let rate_limited = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/set_records",
            )
            .with_status(429)
            .with_header("retry-after", "0")
            .with_body(r#"{"error":{"code":"rate_limit_exceeded"}}"#)
            .expect(1)
            .create();

        let success = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/www/A/actions/set_records",
            )
            .with_status(200)
            .with_body(ok_action())
            .expect(1)
            .create();

        let change_ttl = server
            .mock("POST", "/zones/example.com/rrsets/www/A/actions/change_ttl")
            .with_status(200)
            .with_body(ok_action())
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
        rate_limited.assert();
        success.assert();
        change_ttl.assert();
    }
}
