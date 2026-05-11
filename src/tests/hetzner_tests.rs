#[cfg(test)]
mod tests {
    use crate::{
        DnsRecord, DnsRecordType, DnsUpdater, MXRecord, providers::hetzner::HetznerProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> HetznerProvider {
        HetznerProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_hetzner("test_token", Some(Duration::from_secs(30)));

        assert!(updater.is_ok());
        assert!(
            matches!(updater, Ok(DnsUpdater::Hetzner(..))),
            "Expected Hetzner updater to provide a Hetzner provider"
        );
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let add_records_mock = server
            .mock("POST", "/zones/example.com/rrsets/test/A/actions/add_records")
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "records": [{"value": "1.1.1.1"}],
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":1,"status":"success"}}"#)
            .create();

        let change_ttl_mock = server
            .mock("POST", "/zones/example.com/rrsets/test/A/actions/change_ttl")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({"ttl": 3600})))
            .with_status(201)
            .with_body(r#"{"action":{"id":2,"status":"success"}}"#)
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
        add_records_mock.assert();
        change_ttl_mock.assert();
    }

    #[tokio::test]
    async fn create_apex_record_uses_at_sign() {
        let mut server = mockito::Server::new_async().await;

        let add_records_mock = server
            .mock("POST", "/zones/example.com/rrsets/@/A/actions/add_records")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "records": [{"value": "1.2.3.4"}],
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":1,"status":"success"}}"#)
            .create();

        let change_ttl_mock = server
            .mock("POST", "/zones/example.com/rrsets/@/A/actions/change_ttl")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({"ttl": 3600})))
            .with_status(201)
            .with_body(r#"{"action":{"id":2,"status":"success"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        add_records_mock.assert();
        change_ttl_mock.assert();
    }

    #[tokio::test]
    async fn create_mx_record_serializes_priority_in_value() {
        let mut server = mockito::Server::new_async().await;

        let add_records_mock = server
            .mock("POST", "/zones/example.com/rrsets/test/MX/actions/add_records")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "records": [{"value": "10 mail.example.com."}],
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":1,"status":"success"}}"#)
            .create();

        let change_ttl_mock = server
            .mock("POST", "/zones/example.com/rrsets/test/MX/actions/change_ttl")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({"ttl": 3600})))
            .with_status(201)
            .with_body(r#"{"action":{"id":2,"status":"success"}}"#)
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
        add_records_mock.assert();
        change_ttl_mock.assert();
    }

    #[tokio::test]
    async fn create_txt_record_quotes_value() {
        let mut server = mockito::Server::new_async().await;

        let add_records_mock = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_acme-challenge/TXT/actions/add_records",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "records": [{"value": "\"challenge-value\""}],
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":1,"status":"success"}}"#)
            .create();

        let change_ttl_mock = server
            .mock(
                "POST",
                "/zones/example.com/rrsets/_acme-challenge/TXT/actions/change_ttl",
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({"ttl": 60})))
            .with_status(201)
            .with_body(r#"{"action":{"id":2,"status":"success"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("challenge-value".to_string()),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        add_records_mock.assert();
        change_ttl_mock.assert();
    }

    #[tokio::test]
    async fn create_long_txt_record_splits_into_255_byte_chunks() {
        let mut server = mockito::Server::new_async().await;
        let long = "a".repeat(400);
        let expected_value = format!("\"{}\" \"{}\"", "a".repeat(255), "a".repeat(145));

        let add_records_mock = server
            .mock("POST", "/zones/example.com/rrsets/long/TXT/actions/add_records")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({
                "records": [{"value": expected_value}],
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":1,"status":"success"}}"#)
            .create();

        let change_ttl_mock = server
            .mock("POST", "/zones/example.com/rrsets/long/TXT/actions/change_ttl")
            .match_header("authorization", "Bearer test_token")
            .match_body(mockito::Matcher::Json(json!({"ttl": 60})))
            .with_status(201)
            .with_body(r#"{"action":{"id":2,"status":"success"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "long.example.com",
                DnsRecord::TXT(long),
                60,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "{:?}", result);
        add_records_mock.assert();
        change_ttl_mock.assert();
    }

    #[tokio::test]
    async fn update_record_calls_set_records_and_change_ttl() {
        let mut server = mockito::Server::new_async().await;

        let set_records_mock = server
            .mock("POST", "/zones/example.com/rrsets/www/AAAA/actions/set_records")
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "records": [{"value": "2001:db8::2"}],
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":1,"status":"success"}}"#)
            .create();

        let change_ttl_mock = server
            .mock("POST", "/zones/example.com/rrsets/www/AAAA/actions/change_ttl")
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "ttl": 7200,
            })))
            .with_status(201)
            .with_body(r#"{"action":{"id":2,"status":"success"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA("2001:db8::2".parse().unwrap()),
                7200,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        set_records_mock.assert();
        change_ttl_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("DELETE", "/zones/example.com/rrsets/test/TXT")
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn delete_apex_record_uses_at_sign() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("DELETE", "/zones/example.com/rrsets/@/A")
            .match_header("authorization", "Bearer test_token")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok());
        mock.assert();
    }
}
