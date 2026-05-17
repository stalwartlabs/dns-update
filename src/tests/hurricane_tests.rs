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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::hurricane::HurricaneProvider,
    };
    use std::collections::HashMap;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> HurricaneProvider {
        let mut creds = HashMap::new();
        creds.insert("example.com".to_string(), "secret-token".to_string());
        HurricaneProvider::new(creds, Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let mut creds = HashMap::new();
        creds.insert("example.com".to_string(), "tok".to_string());
        let updater = DnsUpdater::new_hurricane(creds, Some(Duration::from_secs(30)));

        assert!(updater.is_ok());
        assert!(matches!(updater, Ok(DnsUpdater::Hurricane(..))));
    }

    #[tokio::test]
    async fn create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "hostname".into(),
                    "_acme-challenge.example.com".into(),
                ),
                mockito::Matcher::UrlEncoded("password".into(), "secret-token".into()),
                mockito::Matcher::UrlEncoded("txt".into(), "token-value".into()),
            ]))
            .with_status(200)
            .with_body("good 1.2.3.4")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("token-value".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn create_non_txt_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("Hurricane Electric")));
    }

    #[tokio::test]
    async fn create_unknown_zone_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "host.unknown.example",
                DnsRecord::TXT("v".to_string()),
                300,
                "unknown.example",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("not found")));
    }

    #[tokio::test]
    async fn create_badauth_returns_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_body("badauth")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "host.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    async fn delete_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "hostname".into(),
                    "_acme-challenge.example.com".into(),
                ),
                mockito::Matcher::UrlEncoded("txt".into(), ".".into()),
            ]))
            .with_status(200)
            .with_body("good")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn delete_non_txt_returns_error() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("host.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(matches!(result, Err(Error::Api(msg)) if msg.contains("Hurricane Electric")));
    }

    #[tokio::test]
    #[ignore = "Requires Hurricane Electric account with TXT record password"]
    async fn integration_test() {
        let zone = "";
        let hostname = "";
        let password = "";

        assert!(!zone.is_empty(), "Configure zone in the integration test");
        assert!(
            !hostname.is_empty(),
            "Configure hostname in the integration test"
        );
        assert!(
            !password.is_empty(),
            "Configure password in the integration test"
        );

        let mut creds = HashMap::new();
        creds.insert(zone.to_string(), password.to_string());
        let provider = HurricaneProvider::new(creds, Some(Duration::from_secs(30))).unwrap();

        assert!(
            provider
                .create(
                    hostname,
                    DnsRecord::TXT("integration-test-value".to_string()),
                    300,
                    zone
                )
                .await
                .is_ok()
        );

        assert!(
            provider
                .delete(hostname, zone, DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
