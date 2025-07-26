#[cfg(test)]
mod tests {
    use crate::{providers::desec::DesecProvider, DnsRecord, DnsRecordType, Error};
    use std::time::Duration;
    use serde_json::json;
    use crate::providers::desec::DesecDnsRecordRepresentation;

    fn setup_provider(endpoint: &str) -> DesecProvider {
        DesecProvider::new("test_token", Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
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

        let mock = server.mock("POST", "/domains/example.com/rrsets/")
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
                }"#
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A { content: "1.1.1.1".parse().unwrap() },
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
            "records": ["10 mail.example.com"],
        });

        let mock = server.mock("POST", "/domains/example.com/rrsets/")
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
                    "records": ["10 mail.example.com"],
                    "ttl": 3600,
                    "type": "MX",
                    "touched": "2025-07-25T19:18:37.292390Z"
                }"#
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::MX { priority: 10, content: "mail.example.com".to_string() },
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

        let mock = server.mock("POST", "/domains/example.com/rrsets/")
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
                DnsRecord::A { content: "1.1.1.1".parse().unwrap() },
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

        let mock = server.mock("PUT", "/domains/example.com/rrsets/test/AAAA/")
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
                }"#
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test",
                DnsRecord::AAAA { content: "2001:db8::1".parse().unwrap() },
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
        let mock = server.mock("DELETE", "/domains/example.com/rrsets/test/TXT/")
            .with_status(204)
            .create();
    
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete(
                "test",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;
    
        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires desec API Token and domain configuration"]
    async fn integration_test() {
        let token = "";        // <-- Fill in your deSEC API token here
        let origin = "";       // <-- Fill in your domain (e.g., "example.com")
        let domain = "";       // <-- Fill in your test subdomain (e.g., "test.example.com")

        assert!(!token.is_empty(), "Please configure your deSEC API token in the integration test");
        assert!(!origin.is_empty(), "Please configure your domain in the integration test");
        assert!(!domain.is_empty(), "Please configure your test subdomain in the integration test");


        let provider = DesecProvider::new(token, Some(Duration::from_secs(30)));

        // check creation
        let creation_result = provider
            .create(
                domain,
                DnsRecord::A { content: "1.1.1.1".parse().unwrap() },
                3600,
                origin
            )
            .await;

        assert!(creation_result.is_ok());

       // check modification
        let update_result = provider
            .update(
                domain,
                DnsRecord::A { content: "2.2.2.2".parse().unwrap() },
                3600,
                origin
            )
            .await;

        assert!(update_result.is_ok());

        // check deletion
        let deletion_result = provider
            .delete(
                domain,
                origin,
                DnsRecordType::A,
            )
            .await;

        assert!(deletion_result.is_ok());
    }

    #[test]
    fn test_into_desec_record() {
        let record = DnsRecord::A {
            content: "1.1.1.1".parse().unwrap(),
        };
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "1.1.1.1");
        assert_eq!(desec_record.record_type, "A");

        let record = DnsRecord::AAAA {
            content: "2001:db8::1".parse().unwrap(),
        };
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "2001:db8::1");
        assert_eq!(desec_record.record_type, "AAAA");

        let record = DnsRecord::TXT {
            content: "test".to_string(),
        };
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "test");
        assert_eq!(desec_record.record_type, "TXT");

        let record = DnsRecord::MX {
            priority: 10,
            content: "mail.example.com".to_string(),
        };
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "10 mail.example.com");
        assert_eq!(desec_record.record_type, "MX");

        let record = DnsRecord::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            content: "sip.example.com".to_string(),
        };
        let desec_record: DesecDnsRecordRepresentation = record.into();
        assert_eq!(desec_record.content, "10 20 443 sip.example.com");
        assert_eq!(desec_record.record_type, "SRV");
    }
}