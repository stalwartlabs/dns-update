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
        DnsRecord, DnsRecordType, DnsUpdater, providers::technitium::TechnitiumProvider,
    };
    use std::time::Duration;

    fn setup(endpoint: &str) -> TechnitiumProvider {
        TechnitiumProvider::new("http://placeholder", "tok", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn add_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/api/zones/records/add")
            .with_status(200)
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("token".into(), "tok".into()),
                mockito::Matcher::UrlEncoded(
                    "domain".into(),
                    "_acme-challenge.example.com".into(),
                ),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
                mockito::Matcher::UrlEncoded("ttl".into(), "300".into()),
                mockito::Matcher::UrlEncoded("text".into(), "challenge-value".into()),
            ]))
            .with_body(r#"{"status":"ok"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("challenge-value".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn add_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/api/zones/records/add")
            .with_status(200)
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("ipAddress".into(), "1.2.3.4".into()),
                mockito::Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_body(r#"{"status":"ok"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/api/zones/records/delete")
            .with_status(200)
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("token".into(), "tok".into()),
                mockito::Matcher::UrlEncoded("domain".into(), "test.example.com".into()),
                mockito::Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .with_body(r#"{"status":"ok"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn error_status_returns_api_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/api/zones/records/add")
            .with_status(200)
            .with_body(r#"{"status":"error","errorMessage":"bad"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(crate::Error::Api(_))));
        mock.assert();
    }

    #[test]
    fn rejects_empty_token() {
        let result = TechnitiumProvider::new("http://localhost", "", None);
        assert!(matches!(result, Err(crate::Error::Api(_))));
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_technitium(
            "http://localhost",
            "tok",
            Some(Duration::from_secs(5)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Technitium(..))));
    }

    #[tokio::test]
    #[ignore = "Requires a Technitium server, token, and zone"]
    async fn integration_test() {
        let endpoint = std::env::var("TECHNITIUM_SERVER_BASE_URL").unwrap_or_default();
        let token = std::env::var("TECHNITIUM_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("TECHNITIUM_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("TECHNITIUM_FQDN").unwrap_or_default();
        assert!(!endpoint.is_empty());
        assert!(!token.is_empty());
        assert!(!origin.is_empty());
        assert!(!fqdn.is_empty());

        let updater =
            DnsUpdater::new_technitium(endpoint, token, Some(Duration::from_secs(30))).unwrap();
        assert!(
            updater
                .create(
                    &fqdn,
                    DnsRecord::TXT("integration".to_string()),
                    300,
                    &origin
                )
                .await
                .is_ok()
        );
        assert!(
            updater
                .delete(&fqdn, &origin, DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
