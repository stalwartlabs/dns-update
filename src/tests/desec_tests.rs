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

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Token test_token")
            .match_header("content-type", "application/json")
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
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_mx_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "MX",
            "ttl": 3600,
            "records": ["10 mail.example.com."],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Token test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["10 mail.example.com."],
                    "ttl": 3600,
                    "type": "MX",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(401)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Token test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(r#"{ "detail": "Invalid token." }"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "AAAA",
            "ttl": 3600,
            "records": ["2001:db8::1"],
        });

        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/test/AAAA/")
            .with_status(200)
            .match_body(mockito::Matcher::Json(expected_request))
            .match_header("authorization", "Token test_token")
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["2001:db8::1"],
                    "ttl": 3600,
                    "type": "AAAA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test",
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/domains/example.com/rrsets/test/TXT/")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_tlsa_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "_443._tcp.test",
            "type": "TLSA",
            "ttl": 3600,
            "records": ["3 1 1 e3b0c442"],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Token test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "_443._tcp.test",
                    "name": "_443._tcp.test.example.com.",
                    "records": ["3 1 1 e3b0c442"],
                    "ttl": 3600,
                    "type": "TLSA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_443._tcp.test.example.com",
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xe3, 0xb0, 0xc4, 0x42],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_tlsa_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "_443._tcp.test",
            "type": "TLSA",
            "ttl": 3600,
            "records": ["2 0 2 abcdef01"],
        });

        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/_443._tcp.test/TLSA/")
            .with_status(200)
            .match_body(mockito::Matcher::Json(expected_request))
            .match_header("authorization", "Token test_token")
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "_443._tcp.test",
                    "name": "_443._tcp.test.example.com.",
                    "records": ["2 0 2 abcdef01"],
                    "ttl": 3600,
                    "type": "TLSA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "_443._tcp.test",
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneTa,
                    selector: TlsaSelector::Full,
                    matching: TlsaMatching::Sha512,
                    cert_data: vec![0xab, 0xcd, 0xef, 0x01],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_caa_issue_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "CAA",
            "ttl": 3600,
            "records": ["0 issue \"letsencrypt.org\""],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Token test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["0 issue \"letsencrypt.org\""],
                    "ttl": 3600,
                    "type": "CAA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_caa_issuewild_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "CAA",
            "ttl": 3600,
            "records": ["128 issuewild \"letsencrypt.org\""],
        });

        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/test/CAA/")
            .with_status(200)
            .match_body(mockito::Matcher::Json(expected_request))
            .match_header("authorization", "Token test_token")
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["128 issuewild \"letsencrypt.org\""],
                    "ttl": 3600,
                    "type": "CAA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test",
                DnsRecord::CAA(CAARecord::IssueWild {
                    issuer_critical: true,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_caa_iodef_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "CAA",
            "ttl": 3600,
            "records": ["0 iodef \"mailto:admin@example.com\""],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Token test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(expected_request))
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": ["0 iodef \"mailto:admin@example.com\""],
                    "ttl": 3600,
                    "type": "CAA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::CAA(CAARecord::Iodef {
                    issuer_critical: false,
                    url: "mailto:admin@example.com".to_string(),
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_lowercases_subname_and_domain() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "mail",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .match_body(mockito::Matcher::Json(expected_request))
            .match_header("authorization", "Token test_token")
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "mail",
                    "name": "mail.example.com.",
                    "records": ["1.1.1.1"],
                    "ttl": 3600,
                    "type": "A",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "Mail.Example.COM",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "Example.COM",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_clamps_ttl_below_minimum() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "test",
            "type": "A",
            "ttl": 3600,
            "records": ["1.1.1.1"],
        });

        let mock = server
            .mock("POST", "/domains/example.com/rrsets/")
            .with_status(201)
            .match_body(mockito::Matcher::Json(expected_request))
            .match_header("authorization", "Token test_token")
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
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_lowercases_path_and_clamps_ttl() {
        let mut server = mockito::Server::new_async().await;
        let expected_request = json!({
            "subname": "mail",
            "type": "AAAA",
            "ttl": 3600,
            "records": ["2001:db8::1"],
        });

        let mock = server
            .mock("PUT", "/domains/example.com/rrsets/mail/AAAA/")
            .with_status(200)
            .match_body(mockito::Matcher::Json(expected_request))
            .match_header("authorization", "Token test_token")
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "mail",
                    "name": "mail.example.com.",
                    "records": ["2001:db8::1"],
                    "ttl": 3600,
                    "type": "AAAA",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "MAIL",
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
                300,
                "Example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_lowercases_path() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/domains/example.com/rrsets/mail/TXT/")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("Mail.Example.com", "Example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires desec API Token and domain configuration"]
    async fn integration_test() {
        let token = ""; // <-- Fill in your deSEC API token here
        let origin = ""; // <-- Fill in your domain (e.g., "example.com")
        let domain = ""; // <-- Fill in your test subdomain (e.g., "test.example.com")

        assert!(
            !token.is_empty(),
            "Please configure your deSEC API token in the integration test"
        );
        assert!(
            !origin.is_empty(),
            "Please configure your domain in the integration test"
        );
        assert!(
            !domain.is_empty(),
            "Please configure your test subdomain in the integration test"
        );

        let provider = DesecProvider::new(token, Some(Duration::from_secs(30)));
        let cname_sub = format!("cname-test.{origin}");
        let srv_sub = format!("_sip._tcp.{origin}");
        let tlsa_sub = format!("_443._tcp.{origin}");

        // --- Create & update all record types ---

        // A record
        assert!(
            provider
                .create(
                    domain,
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    domain,
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // AAAA record
        assert!(
            provider
                .create(
                    domain,
                    DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    domain,
                    DnsRecord::AAAA("2001:db8::2".parse().unwrap()),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // TXT record
        assert!(
            provider
                .create(
                    domain,
                    DnsRecord::TXT("v=spf1 -all".to_string()),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    domain,
                    DnsRecord::TXT("v=spf1 ~all".to_string()),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // MX record
        assert!(
            provider
                .create(
                    domain,
                    DnsRecord::MX(MXRecord {
                        exchange: format!("mail.{origin}"),
                        priority: 10
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    domain,
                    DnsRecord::MX(MXRecord {
                        exchange: format!("mail2.{origin}"),
                        priority: 20
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // CNAME record (dedicated subdomain — cannot coexist with other record types)
        assert!(
            provider
                .create(
                    &cname_sub,
                    DnsRecord::CNAME(format!("target.{origin}")),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    &cname_sub,
                    DnsRecord::CNAME(format!("target2.{origin}")),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // SRV record
        assert!(
            provider
                .create(
                    &srv_sub,
                    DnsRecord::SRV(SRVRecord {
                        priority: 10,
                        weight: 20,
                        port: 5060,
                        target: format!("sip.{origin}")
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    &srv_sub,
                    DnsRecord::SRV(SRVRecord {
                        priority: 20,
                        weight: 10,
                        port: 5060,
                        target: format!("sip2.{origin}")
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // TLSA record
        assert!(
            provider
                .create(
                    &tlsa_sub,
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xe3, 0xb0, 0xc4, 0x42]
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    &tlsa_sub,
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xab, 0xcd, 0xef, 0x01]
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // CAA record
        assert!(
            provider
                .create(
                    domain,
                    DnsRecord::CAA(CAARecord::Issue {
                        issuer_critical: false,
                        name: Some("letsencrypt.org".to_string()),
                        options: vec![]
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );
        assert!(
            provider
                .update(
                    domain,
                    DnsRecord::CAA(CAARecord::Issue {
                        issuer_critical: false,
                        name: Some("sectigo.com".to_string()),
                        options: vec![]
                    }),
                    3600,
                    origin
                )
                .await
                .is_ok()
        );

        // Set DESEC_NO_CLEANUP=1 to skip deletion (e.g. to inspect records in the web UI).
        if std::env::var("DESEC_NO_CLEANUP")
            .unwrap_or_default()
            .is_empty()
        {
            assert!(
                provider
                    .delete(domain, origin, DnsRecordType::A)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(domain, origin, DnsRecordType::AAAA)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(domain, origin, DnsRecordType::TXT)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(domain, origin, DnsRecordType::MX)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(&cname_sub, origin, DnsRecordType::CNAME)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(&srv_sub, origin, DnsRecordType::SRV)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(&tlsa_sub, origin, DnsRecordType::TLSA)
                    .await
                    .is_ok()
            );
            assert!(
                provider
                    .delete(domain, origin, DnsRecordType::CAA)
                    .await
                    .is_ok()
            );
        }
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
}
