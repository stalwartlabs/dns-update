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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, Error, providers::ddnss::DdnssProvider};
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
    async fn test_set_rrset_empty_clears_via_txtm_2() {
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
            .set_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset empty returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_single_txt_overwrites_via_txtm_1() {
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
            .set_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("challenge".into())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset single returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_multi_txt_rejected() {
        let provider = DdnssProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("a".into()), DnsRecord::TXT("b".into())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("one TXT record")),
            "expected Error::Api about one TXT record, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_non_txt_type_rejected() {
        let provider = DdnssProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("Only TXT")),
            "expected Error::Api about TXT only, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_rejected() {
        let provider = DdnssProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("x".into())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("add_to_rrset")),
            "expected Error::Unsupported about add_to_rrset, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_rejected() {
        let provider = DdnssProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("x".into())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("remove_from_rrset")),
            "expected Error::Unsupported about remove_from_rrset, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_list_rrset_rejected() {
        let provider = DdnssProvider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::TXT, "example.com")
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("listing")),
            "expected Error::Unsupported about listing, got {result:?}"
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
        let set_result = updater
            .set_rrset(
                &host,
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("test".into())],
                &host,
            )
            .await;
        assert!(set_result.is_ok(), "set_rrset failed: {set_result:?}");
        let clear_result = updater
            .set_rrset(&host, DnsRecordType::TXT, 300, Vec::new(), &host)
            .await;
        assert!(clear_result.is_ok(), "clear failed: {clear_result:?}");
    }
}
