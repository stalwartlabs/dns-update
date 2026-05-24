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
    use crate::{DnsRecord, DnsRecordType, Error, providers::duckdns::DuckDnsProvider};
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> DuckDnsProvider {
        DuckDnsProvider::new("test_token", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_set_rrset_single_txt_overwrites() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("domains".into(), "host.duckdns.org".into()),
                Matcher::UrlEncoded("token".into(), "test_token".into()),
                Matcher::UrlEncoded("clear".into(), "false".into()),
                Matcher::UrlEncoded("txt".into(), "single-value".into()),
            ]))
            .with_status(200)
            .with_body("OK")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.host.duckdns.org",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("single-value".to_string())],
                "host.duckdns.org",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_clears() {
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
            .set_rrset(
                "_acme-challenge.host.duckdns.org",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "host.duckdns.org",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_multiple_records_rejected() {
        let provider = DuckDnsProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .set_rrset(
                "host.duckdns.org",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("first".to_string()),
                    DnsRecord::TXT("second".to_string()),
                ],
                "host.duckdns.org",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("only supports one TXT record")),
            "expected Error::Api about single TXT, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_non_txt_type_rejected() {
        let provider = DuckDnsProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .set_rrset(
                "host.duckdns.org",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "host.duckdns.org",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("Only TXT records are supported")),
            "expected Error::Api about TXT only, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_rejected() {
        let provider = DuckDnsProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .add_to_rrset(
                "host.duckdns.org",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("value".to_string())],
                "host.duckdns.org",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("add_to_rrset")),
            "expected Error::Api about add_to_rrset, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_remove_from_rrset_rejected() {
        let provider = DuckDnsProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .remove_from_rrset(
                "host.duckdns.org",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("value".to_string())],
                "host.duckdns.org",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("remove_from_rrset")),
            "expected Error::Api about remove_from_rrset, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_list_rrset_rejected() {
        let provider = DuckDnsProvider::new("test_token", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .list_rrset("host.duckdns.org", DnsRecordType::TXT, "host.duckdns.org")
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("listing")),
            "expected Error::Api about listing, got {result:?}"
        );
    }
}
