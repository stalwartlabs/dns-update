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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::duckdns::DuckDnsProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> DuckDnsProvider {
        DuckDnsProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("domains".into(), "host.duckdns.org".into()),
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("clear".into(), "false".into()),
                Matcher::UrlEncoded("txt".into(), "challenge-value".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.host.duckdns.org",
                DnsRecord::TXT("challenge-value".to_string()),
                300,
                "host.duckdns.org",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_txt_record_sends_same_request() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("domains".into(), "host.duckdns.org".into()),
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("clear".into(), "false".into()),
                Matcher::UrlEncoded("txt".into(), "new-value".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "_acme-challenge.host.duckdns.org",
                DnsRecord::TXT("new-value".to_string()),
                300,
                "host.duckdns.org",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_clears_txt_record() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("domains".into(), "host.duckdns.org".into()),
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("clear".into(), "true".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete(
                "_acme-challenge.host.duckdns.org",
                "host.duckdns.org",
                DnsRecordType::TXT,
            )
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_non_ok_response_is_api_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("KO")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.duckdns.org",
                DnsRecord::TXT("v".to_string()),
                300,
                "host.duckdns.org",
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
        let provider =
            DuckDnsProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .create(
                "host.duckdns.org",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "host.duckdns.org",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires DUCKDNS_TOKEN and DUCKDNS_DOMAIN env vars"]
    async fn integration_test() {
        let token = std::env::var("DUCKDNS_TOKEN").unwrap_or_default();
        let domain = std::env::var("DUCKDNS_DOMAIN").unwrap_or_default();

        assert!(!token.is_empty(), "Set DUCKDNS_TOKEN to run this test");
        assert!(
            !domain.is_empty(),
            "Set DUCKDNS_DOMAIN to run this test (e.g. host.duckdns.org)"
        );

        let updater = DnsUpdater::new_duckdns(token, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(&domain, DnsRecord::TXT("test-value".into()), 300, &domain)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&domain, DnsRecord::TXT("test-value-2".into()), 300, &domain)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&domain, &domain, DnsRecordType::TXT).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
