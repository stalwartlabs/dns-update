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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, providers::bindman::BindmanProvider};
    use serde_json::json;
    use std::time::Duration;

    fn setup(endpoint: &str) -> BindmanProvider {
        BindmanProvider::new(
            "http://placeholder",
            None::<(&str, &str)>,
            Some(Duration::from_secs(1)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected = json!({
            "name": "_acme-challenge.example.com.",
            "value": "challenge-value",
            "type": "TXT"
        });

        let mock = server
            .mock("POST", "/records")
            .with_status(204)
            .match_body(mockito::Matcher::Json(expected))
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
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/records/_acme-challenge.example.com./TXT")
            .with_status(204)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn create_record_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/records")
            .with_status(400)
            .with_body(r#"{"message":"bad"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(crate::Error::Api(_))));
        mock.assert();
    }

    #[test]
    fn rejects_empty_url() {
        let result =
            BindmanProvider::new("", None::<(&str, &str)>, Some(Duration::from_secs(1)));
        assert!(matches!(result, Err(crate::Error::Api(_))));
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_bindman(
            "http://localhost",
            None::<(&str, &str)>,
            Some(Duration::from_secs(5)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Bindman(..))));
    }

    #[tokio::test]
    #[ignore = "Requires a Bindman manager URL and zone configuration"]
    async fn integration_test() {
        let url = std::env::var("BINDMAN_MANAGER_ADDRESS").unwrap_or_default();
        let fqdn = std::env::var("BINDMAN_FQDN").unwrap_or_default();
        assert!(!url.is_empty());
        assert!(!fqdn.is_empty());
        let updater =
            DnsUpdater::new_bindman(url, None::<(&str, &str)>, Some(Duration::from_secs(30)))
                .unwrap();
        assert!(
            updater
                .create(
                    &fqdn,
                    DnsRecord::TXT("integration".to_string()),
                    300,
                    "example.com"
                )
                .await
                .is_ok()
        );
        assert!(
            updater
                .delete(&fqdn, "example.com", DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
