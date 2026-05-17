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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::dreamhost::DreamhostProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> DreamhostProvider {
        DreamhostProvider::new("test_key", Some(Duration::from_secs(5))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("key".into(), "test_key".into()),
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-add_record".into()),
                mockito::Matcher::UrlEncoded("record".into(), "test.example.com".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
                mockito::Matcher::UrlEncoded("value".into(), "hello".into()),
                mockito::Matcher::UrlEncoded("format".into(), "json".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result": "success", "data": "record_added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("hello".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_error_result() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"result": "error", "data": "record_already_exists_remove_first"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("hello".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(
                r#"{"result": "success", "data": [
                    {"record": "test.example.com", "type": "A", "value": "1.1.1.1"}
                ]}"#,
            )
            .create();
        let remove_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-remove_record".into(),
            ))
            .with_status(200)
            .with_body(r#"{"result": "success", "data": "record_removed"}"#)
            .create();
        let add_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-add_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "8.8.8.8".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result": "success", "data": "record_added"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update failed: {result:?}");
        list_mock.assert();
        remove_mock.assert();
        add_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let _list_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::UrlEncoded(
                "cmd".into(),
                "dns-list_records".into(),
            ))
            .with_status(200)
            .with_body(
                r#"{"result": "success", "data": [
                    {"record": "test.example.com", "type": "TXT", "value": "hello"}
                ]}"#,
            )
            .create();
        let remove_mock = server
            .mock("GET", mockito::Matcher::Any)
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("cmd".into(), "dns-remove_record".into()),
                mockito::Matcher::UrlEncoded("value".into(), "hello".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"result": "success", "data": "record_removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        remove_mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Dreamhost API key and FQDN"]
    async fn integration_test() {
        let api_key = std::env::var("DREAMHOST_API_KEY").unwrap_or_default();
        let fqdn = std::env::var("DREAMHOST_FQDN").unwrap_or_default();
        let origin = std::env::var("DREAMHOST_ORIGIN").unwrap_or_default();

        assert!(!api_key.is_empty());
        assert!(!fqdn.is_empty());

        let updater =
            DnsUpdater::new_dreamhost(api_key, Some(Duration::from_secs(30))).unwrap();
        let create = updater
            .create(&fqdn, DnsRecord::TXT("test".into()), 0, &origin)
            .await;
        assert!(create.is_ok(), "create failed: {create:?}");
        let delete = updater.delete(&fqdn, &origin, DnsRecordType::TXT).await;
        assert!(delete.is_ok(), "delete failed: {delete:?}");
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_dreamhost("k", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::Dreamhost(..))));
    }
}
