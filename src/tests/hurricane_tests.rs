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
    async fn set_rrset_empty_clears_txt() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "hostname".into(),
                    "_acme-challenge.example.com".into(),
                ),
                mockito::Matcher::UrlEncoded("password".into(), "secret-token".into()),
                mockito::Matcher::UrlEncoded("txt".into(), ".".into()),
            ]))
            .with_status(200)
            .with_body("good")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_single_txt_overwrites() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded(
                    "hostname".into(),
                    "_acme-challenge.example.com".into(),
                ),
                mockito::Matcher::UrlEncoded("password".into(), "secret-token".into()),
                mockito::Matcher::UrlEncoded("txt".into(), "new-value".into()),
            ]))
            .with_status(200)
            .with_body("good 1.2.3.4")
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("new-value".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_multiple_txt_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("first".to_string()),
                    DnsRecord::TXT("second".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(msg)) if msg.contains("only supports one TXT record per host"))
        );
    }

    #[tokio::test]
    async fn set_rrset_non_txt_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

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
            matches!(result, Err(Error::Api(msg)) if msg.contains("Only TXT records are supported by Hurricane Electric"))
        );
    }

    #[tokio::test]
    async fn add_to_rrset_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .add_to_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("value".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unsupported(msg)) if msg.contains("does not support add_to_rrset"))
        );
    }

    #[tokio::test]
    async fn remove_from_rrset_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .remove_from_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("value".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unsupported(msg)) if msg.contains("does not support remove_from_rrset"))
        );
    }

    #[tokio::test]
    async fn list_rrset_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());

        let result = provider
            .list_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unsupported(msg)) if msg.contains("does not support listing records"))
        );
    }

    #[tokio::test]
    #[ignore = "Requires Hurricane Electric account with TXT record password"]
    async fn integration_test() {
        let zone = std::env::var("HURRICANE_ZONE").unwrap_or_default();
        let hostname = std::env::var("HURRICANE_HOSTNAME").unwrap_or_default();
        let password = std::env::var("HURRICANE_PASSWORD").unwrap_or_default();

        assert!(!zone.is_empty(), "Set HURRICANE_ZONE env var");
        assert!(!hostname.is_empty(), "Set HURRICANE_HOSTNAME env var");
        assert!(!password.is_empty(), "Set HURRICANE_PASSWORD env var");

        let mut creds = HashMap::new();
        creds.insert(zone.to_string(), password.to_string());
        let provider = HurricaneProvider::new(creds, Some(Duration::from_secs(30))).unwrap();

        assert!(
            provider
                .set_rrset(
                    &hostname,
                    DnsRecordType::TXT,
                    300,
                    vec![DnsRecord::TXT("integration-test-value".to_string())],
                    &zone,
                )
                .await
                .is_ok()
        );

        assert!(
            provider
                .set_rrset(&hostname, DnsRecordType::TXT, 300, Vec::new(), &zone)
                .await
                .is_ok()
        );
    }
}
