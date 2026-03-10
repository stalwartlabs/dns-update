#[cfg(test)]
mod tests {
    use crate::{
        providers::dnsimple::DNSimpleProvider,
        DnsRecord, DnsRecordType, DnsUpdater,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> DNSimpleProvider {
        DNSimpleProvider::new(
            "test_bearer_token",
            "1010",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_dnsimple(
            "test_token",
            "1010",
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());
        assert!(
            matches!(updater, Ok(DnsUpdater::DNSimple(..))),
            "Expected DNSimple updater to provide a DNSimple provider"
        );
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/1010/zones/example.com/records")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "name": "test",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 3600,
            })))
            .with_status(201)
            .with_body(r#"{"data":{"id":1,"zone_id":"example.com","name":"test","content":"1.1.1.1","ttl":3600,"type":"A","priority":null}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A {
                    content: "1.1.1.1".parse().unwrap(),
                },
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_mock = server
            .mock("GET", "/1010/zones/example.com/records")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("name".into(), "www".into()),
                mockito::Matcher::UrlEncoded("type".into(), "AAAA".into()),
            ]))
            .with_body(r#"{"data":[{"id":42,"zone_id":"example.com","parent_id":null,"name":"www","content":"2001:db8::1","ttl":3600,"priority":null,"type":"AAAA","regions":["global"],"system_record":false}]}"#)
            .create();

        let patch_mock = server
            .mock("PATCH", "/1010/zones/example.com/records/42")
            .match_header("Authorization", "Bearer test_bearer_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "content": "2001:db8::2",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_body(r#"{"data":{"id":42,"zone_id":"example.com","name":"www","content":"2001:db8::2","ttl":3600,"type":"AAAA","priority":null}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA {
                    content: "2001:db8::2".parse().unwrap(),
                },
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        patch_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_mock = server
            .mock("GET", "/1010/zones/example.com/records")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"data":[{"id":99,"zone_id":"example.com","parent_id":null,"name":"test","content":"hello","ttl":3600,"priority":null,"type":"TXT","regions":["global"],"system_record":false}]}"#)
            .create();

        let delete_mock = server
            .mock("DELETE", "/1010/zones/example.com/records/99")
            .match_header("Authorization", "Bearer test_bearer_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        list_mock.assert();
        delete_mock.assert();
    }
}
