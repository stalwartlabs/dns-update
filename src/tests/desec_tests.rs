#[cfg(test)]
mod tests {
    use crate::providers::desec::DesecDnsRecordRepresentation;
    use crate::{
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::desec::DesecProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> DesecProvider {
        DesecProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[test]
    fn test_into_desec_record() {
        let record = DnsRecord::A("1.1.1.1".parse().unwrap());
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "1.1.1.1");
        assert_eq!(desec_record.record_type, "A");

        let record = DnsRecord::AAAA("2001:db8::1".parse().unwrap());
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "2001:db8::1");
        assert_eq!(desec_record.record_type, "AAAA");

        let record = DnsRecord::TXT("test".to_string());
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "\"test\"");
        assert_eq!(desec_record.record_type, "TXT");

        let record = DnsRecord::MX(MXRecord {
            exchange: "mail.example.com".to_string(),
            priority: 10,
        });
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "10 mail.example.com.");
        assert_eq!(desec_record.record_type, "MX");

        let record = DnsRecord::SRV(SRVRecord {
            target: "sip.example.com".to_string(),
            priority: 10,
            weight: 20,
            port: 443,
        });
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "10 20 443 sip.example.com.");
        assert_eq!(desec_record.record_type, "SRV");

        let record = DnsRecord::TLSA(TLSARecord {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching: TlsaMatching::Sha256,
            cert_data: vec![0xde, 0xad, 0xbe, 0xef],
        });
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "3 1 1 deadbeef");
        assert_eq!(desec_record.record_type, "TLSA");

        let record = DnsRecord::CAA(CAARecord::Issue {
            issuer_critical: false,
            name: Some("letsencrypt.org".to_string()),
            options: vec![],
        });
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "0 issue \"letsencrypt.org\"");
        assert_eq!(desec_record.record_type, "CAA");

        let record = DnsRecord::CAA(CAARecord::IssueWild {
            issuer_critical: true,
            name: Some("letsencrypt.org".to_string()),
            options: vec![],
        });
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "128 issuewild \"letsencrypt.org\"");
        assert_eq!(desec_record.record_type, "CAA");

        let record = DnsRecord::CAA(CAARecord::Iodef {
            issuer_critical: false,
            url: "mailto:admin@example.com".to_string(),
        });
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "0 iodef \"mailto:admin@example.com\"");
        assert_eq!(desec_record.record_type, "CAA");
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_existing() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!([{
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1", "2.2.2.2"],
        }]);
        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/")
            .with_status(200)
            .match_header("authorization", "Token test_token")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"[{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1", "2.2.2.2"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }]"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_absent() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!([{
            "subname": "test",
            "type": "TXT",
            "ttl": 3600,
            "records": ["\"v=DKIM1; p=abc\""],
        }]);
        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/")
            .with_status(200)
            .match_header("authorization", "Token test_token")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"[{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["\"v=DKIM1; p=abc\""],
                    "ttl": 3600,
                    "type": "TXT",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }]"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::TXT,
                3600,
                vec![DnsRecord::TXT("v=DKIM1; p=abc".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_at_apex_uses_empty_subname() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!([{
            "subname": "",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        }]);
        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/")
            .with_status(200)
            .match_header("authorization", "Token test_token")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"[{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "",
                    "name": "example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }]"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/domains/example.com/rrsets/test/A/")
            .with_status(204)
            .match_header("authorization", "Token test_token")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_at_apex_deletes_with_at_url() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/domains/example.com/rrsets/@/TXT/")
            .with_status(204)
            .match_header("authorization", "Token test_token")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::TXT,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_not_found_is_ok() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/domains/example.com/rrsets/test/A/")
            .with_status(404)
            .with_body(r#"{ "detail": "Not found." }"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(ref m)) if m.contains("mismatch")));
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_to_rrset_creates_when_absent() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(404)
            .create();
        let expected_request = json!({
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        });
        let post_mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
        post_mock.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_merges_with_existing() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();
        let expected_request = json!({
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1", "2.2.2.2"],
        });
        let put_mock = server
            .mock("PUT", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1", "2.2.2.2"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("2.2.2.2".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_idempotent_when_present() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();
        let put_mock = server
            .mock("PUT", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .expect(0)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_at_apex() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/@/A/")
            .with_status(404)
            .create();
        let expected_request = json!({
            "subname": "",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        });
        let post_mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "",
                    "name": "example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
        post_mock.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("test.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_and_puts() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1", "2.2.2.2"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();
        let expected_request = json!({
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["2.2.2.2"],
        });
        let put_mock = server
            .mock("PUT", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["2.2.2.2"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
        put_mock.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_when_filtered_empty() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();
        let delete_mock = server
            .mock("DELETE", "/domains/example.com/rrsets/test/A/")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();
        let put_mock = server
            .mock("PUT", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .expect(0)
            .create();
        let delete_mock = server
            .mock("DELETE", "/domains/example.com/rrsets/test/A/")
            .with_status(204)
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

        assert!(result.is_ok());
        get_mock.assert();
        put_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_not_found_is_ok() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(404)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        get_mock.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_records() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["1.1.1.1", "2.2.2.2"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                DnsRecord::A("2.2.2.2".parse().unwrap()),
            ]
        );
        get_mock.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_txt_unquotes() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/_acme-challenge/TXT/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "_acme-challenge",
                    "name": "_acme-challenge.example.com.",
                    "records": ["\"token-a\"", "\"token-b\""],
                    "ttl": 3600,
                    "type": "TXT",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::TXT("token-a".to_string()),
                DnsRecord::TXT("token-b".to_string()),
            ]
        );
        get_mock.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_mx() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/@/MX/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "",
                    "name": "example.com.",
                    "records": ["10 mail.example.com.", "20 mail2.example.com."],
                    "ttl": 3600,
                    "type": "MX",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .unwrap();
        assert_eq!(
            result,
            vec![
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".to_string(),
                }),
                DnsRecord::MX(MXRecord {
                    priority: 20,
                    exchange: "mail2.example.com".to_string(),
                }),
            ]
        );
        get_mock.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_404_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let get_mock = server
            .mock("GET", "/domains/example.com/rrsets/test/A/")
            .with_status(404)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("test.example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap();
        assert!(result.is_empty());
        get_mock.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(ref m)) if m.contains("mismatch")));
    }
}
