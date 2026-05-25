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
    async fn test_set_rrset_single_txt_overwrites() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("domain".into(), "host.freemyip.com".into()),
                Matcher::UrlEncoded("txt".into(), "new-value".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("new-value".into())],
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_clears_slot_without_delete_yes() {
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

        let forbidden = server
            .mock("GET", "/")
            .match_query(Matcher::UrlEncoded("delete".into(), "yes".into()))
            .with_status(200)
            .with_body("OK")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        mock.assert();
        forbidden.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_multiple_values_rejected() {
        let provider = FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .set_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("v1".into()), DnsRecord::TXT("v2".into())],
                "host.freemyip.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => assert!(
                msg.contains("one TXT record"),
                "unexpected error message: {msg}"
            ),
            other => panic!("expected Error::Api, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_set_rrset_non_txt_rejected() {
        let provider = FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .set_rrset(
                "host.freemyip.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "host.freemyip.com",
            )
            .await;
        match result {
            Err(Error::Api(msg)) => {
                assert!(msg.contains("Only TXT"), "unexpected error message: {msg}")
            }
            other => panic!("expected Error::Api, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let provider = FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .add_to_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "expected Ok for empty add, got {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_blind_sets_txt() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("domain".into(), "host.freemyip.com".into()),
                Matcher::UrlEncoded("txt".into(), "value-1".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("value-1".into())],
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let provider = FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .remove_from_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                vec![],
                "host.freemyip.com",
            )
            .await;
        assert!(
            result.is_ok(),
            "expected Ok for empty remove, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_clears_slot() {
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
            .remove_from_rrset(
                "host.freemyip.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("any".into())],
                "host.freemyip.com",
            )
            .await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_rejected() {
        let provider = FreeMyIpProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .list_rrset("host.freemyip.com", DnsRecordType::TXT, "host.freemyip.com")
            .await;
        match result {
            Err(Error::Api(msg)) => {
                assert!(msg.contains("listing"), "unexpected error message: {msg}")
            }
            other => panic!("expected Error::Api, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "Requires FREEMYIP_TOKEN and FREEMYIP_DOMAIN env vars"]
    async fn integration_test() {
        let token = std::env::var("FREEMYIP_TOKEN").unwrap_or_default();
        let domain = std::env::var("FREEMYIP_DOMAIN").unwrap_or_default();
        assert!(!token.is_empty(), "Set FREEMYIP_TOKEN");
        assert!(!domain.is_empty(), "Set FREEMYIP_DOMAIN");

        let updater = DnsUpdater::new_freemyip(token, Some(Duration::from_secs(30))).unwrap();
        let set_result = updater
            .set_rrset(
                &domain,
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("test".into())],
                &domain,
            )
            .await;
        assert!(set_result.is_ok(), "set_rrset failed: {set_result:?}");
        let clear_result = updater
            .set_rrset(&domain, DnsRecordType::TXT, 300, vec![], &domain)
            .await;
        assert!(clear_result.is_ok(), "clear failed: {clear_result:?}");
    }
}
