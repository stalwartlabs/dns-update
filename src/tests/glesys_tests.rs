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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::glesys::GlesysProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> GlesysProvider {
        GlesysProvider::new("api_user", "api_key", Some(Duration::from_secs(5)))
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected = json!({
            "domainname": "example.com",
            "host": "test",
            "type": "A",
            "data": "1.1.1.1",
            "ttl": 300,
        });
        let mock = server
            .mock("POST", "/domain/addrecord")
            .match_header("authorization", mockito::Matcher::Regex("^Basic ".into()))
            .match_body(mockito::Matcher::Json(expected))
            .with_status(200)
            .with_body(r#"{"response": {"record": {"recordid": 99}}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .match_body(mockito::Matcher::Json(json!({"domainname": "example.com"})))
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 7, "type": "TXT", "host": "test"},
                    {"recordid": 8, "type": "A", "host": "test"}
                ]}}"#,
            )
            .create();
        let update_mock = server
            .mock("POST", "/domain/updaterecord")
            .match_body(mockito::Matcher::Json(json!({
                "recordid": 8,
                "data": "9.9.9.9",
                "ttl": 600,
            })))
            .with_status(200)
            .with_body(r#"{"response": {"status": {"code": 200}}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update failed: {result:?}");
        list_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("POST", "/domain/listrecords")
            .with_status(200)
            .with_body(
                r#"{"response": {"records": [
                    {"recordid": 7, "type": "TXT", "host": "test"}
                ]}}"#,
            )
            .create();
        let delete_mock = server
            .mock("POST", "/domain/deleterecord")
            .match_body(mockito::Matcher::Json(json!({"recordid": 7})))
            .with_status(200)
            .with_body(r#"{"response": {"status": {"code": 200}}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/domain/addrecord")
            .with_status(401)
            .with_body(r#"{"message": "Unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
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

        let updater =
            DnsUpdater::new_glesys(user, key, Some(Duration::from_secs(30))).unwrap();
        let create = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create.is_ok(), "create failed: {create:?}");
        let delete = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete.is_ok(), "delete failed: {delete:?}");
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_glesys("u", "k", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::Glesys(..))));
    }
}
