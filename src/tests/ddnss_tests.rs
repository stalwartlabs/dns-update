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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::ddnss::DdnssProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> DdnssProvider {
        DdnssProvider::new("test_key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn ok_body() -> &'static str {
        "<html><body>Updated 1 hostname.</body></html>"
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("key".into(), "test_key".into()),
                Matcher::UrlEncoded("host".into(), "host.example.com".into()),
                Matcher::UrlEncoded("txt".into(), "challenge".into()),
                Matcher::UrlEncoded("txtm".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::TXT("challenge".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_uses_txtm_2() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("key".into(), "test_key".into()),
                Matcher::UrlEncoded("host".into(), "host.example.com".into()),
                Matcher::UrlEncoded("txtm".into(), "2".into()),
            ]))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_creates_again() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("txt".into(), "second".into()),
                Matcher::UrlEncoded("txtm".into(), "1".into()),
            ]))
            .with_status(200)
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::TXT("second".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_failure_response_maps_to_api_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("<html><body>Authorization failed.</body></html>")
            .create();
        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::TXT("x".into()),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        mock.assert();
    }

    #[tokio::test]
    async fn test_non_txt_record_rejected() {
        let provider = DdnssProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires DDNSS_KEY and DDNSS_HOST env vars"]
    async fn integration_test() {
        let key = std::env::var("DDNSS_KEY").unwrap_or_default();
        let host = std::env::var("DDNSS_HOST").unwrap_or_default();
        assert!(!key.is_empty(), "Set DDNSS_KEY");
        assert!(!host.is_empty(), "Set DDNSS_HOST");

        let updater = DnsUpdater::new_ddnss(key, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&host, DnsRecord::TXT("test".into()), 300, &host)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");
        let delete_result = updater.delete(&host, &host, DnsRecordType::TXT).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
