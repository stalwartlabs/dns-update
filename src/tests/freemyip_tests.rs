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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::freemyip::FreeMyIpProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> FreeMyIpProvider {
        FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("domain".into(), "host.freemyip.com".into()),
                Matcher::UrlEncoded("txt".into(), "challenge-value".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.freemyip.com",
                DnsRecord::TXT("challenge-value".to_string()),
                300,
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_uses_same_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("domain".into(), "host.freemyip.com".into()),
                Matcher::UrlEncoded("txt".into(), "v2".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "host.freemyip.com",
                DnsRecord::TXT("v2".to_string()),
                300,
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_clears_txt() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("domain".into(), "host.freemyip.com".into()),
                Matcher::UrlEncoded("txt".into(), "".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("host.freemyip.com", "host.freemyip.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_non_ok_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("ERROR")
            .create();
        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.freemyip.com",
                DnsRecord::TXT("v".into()),
                300,
                "host.freemyip.com",
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
            FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .create(
                "host.freemyip.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "host.freemyip.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires FREEMYIP_TOKEN and FREEMYIP_DOMAIN env vars"]
    async fn integration_test() {
        let token = std::env::var("FREEMYIP_TOKEN").unwrap_or_default();
        let domain = std::env::var("FREEMYIP_DOMAIN").unwrap_or_default();
        assert!(!token.is_empty(), "Set FREEMYIP_TOKEN");
        assert!(!domain.is_empty(), "Set FREEMYIP_DOMAIN");

        let updater = DnsUpdater::new_freemyip(token, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&domain, DnsRecord::TXT("test".into()), 300, &domain)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");
        let delete_result = updater.delete(&domain, &domain, DnsRecordType::TXT).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
