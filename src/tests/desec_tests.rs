#[cfg(test)]
mod tests {
    use crate::{providers::desec::DesecProvider, DnsRecord, DnsRecordType, Error};
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> DesecProvider {
        DesecProvider::new("test_token", Some(endpoint),  Some(Duration::from_secs(1)))
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server.mock("POST", "/domains/example.com/rrsets/test/A/")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_header("authorization", "Token test_token")
            .with_body(
            r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": [
                        "1.1.1.1"
                    ],
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
    async fn test_create_record_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server.mock("POST", "/domains/example.com/rrsets/test/A/")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_header("authorization", "Token test_token")
            .with_body(r#"{ "detail": "Invalid token." }"#
            )
            .create();


        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test",
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
        let mock = server.mock("PUT", "/domains/example.com/rrsets/test/AAAA/")
            .with_status(200)
            .with_body(
                r#"{
                    "created": "2025-07-25T19:18:37.286381Z",
                    "domain": "example.com",
                    "subname": "test",
                    "name": "test.example.com.",
                    "records": [
                        "2001:db8::1"
                    ],
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

    /*
#[test]
fn test_convert_record() {
use super::convert_record;

// Test A record
let record = DnsRecord::A { content: "192.0.2.1".parse().unwrap() };
assert_eq!(convert_record(record).unwrap(), "192.0.2.1");

// Test MX record
let record = DnsRecord::MX {
    content: "mail.example.com".to_string(),
    priority: 10,
};
assert_eq!(convert_record(record).unwrap(), "10 mail.example.com");

// Test SRV record
let record = DnsRecord::SRV {
    content: "sip.example.com".to_string(),
    priority: 10,
    weight: 20,
    port: 5060,
};
assert_eq!(convert_record(record).unwrap(), "10 20 5060 sip.example.com");
}*/
}