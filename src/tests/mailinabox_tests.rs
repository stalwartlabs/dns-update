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
        DnsRecord, DnsRecordType, DnsUpdater, providers::mailinabox::MailinaboxProvider,
    };
    use std::time::Duration;

    fn setup(endpoint: &str) -> MailinaboxProvider {
        MailinaboxProvider::new(
            "http://placeholder",
            "user@example.com",
            "secret",
            Some(Duration::from_secs(1)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/admin/dns/custom/_acme-challenge.example.com/TXT",
            )
            .with_status(200)
            .match_header(
                "authorization",
                "Basic dXNlckBleGFtcGxlLmNvbTpzZWNyZXQ=",
            )
            .match_body("challenge-value")
            .with_body("updated DNS")
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
    async fn update_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/admin/dns/custom/test.example.com/A")
            .with_status(200)
            .match_body("1.2.3.4")
            .with_body("updated DNS")
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("DELETE", "/admin/dns/custom/test.example.com/TXT")
            .with_status(200)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn unauthorized_propagates() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/admin/dns/custom/test.example.com/TXT")
            .with_status(401)
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
        assert!(matches!(result, Err(crate::Error::Unauthorized)));
        mock.assert();
    }

    #[test]
    fn rejects_empty_credentials() {
        let result = MailinaboxProvider::new("http://x", "", "", None);
        assert!(matches!(result, Err(crate::Error::Api(_))));
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_mailinabox(
            "http://localhost",
            "a@b.com",
            "p",
            Some(Duration::from_secs(5)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Mailinabox(..))));
    }

    #[tokio::test]
    #[ignore = "Requires Mail-in-a-Box credentials, base URL, and target FQDN"]
    async fn integration_test() {
        let url = std::env::var("MAILINABOX_BASE_URL").unwrap_or_default();
        let email = std::env::var("MAILINABOX_EMAIL").unwrap_or_default();
        let password = std::env::var("MAILINABOX_PASSWORD").unwrap_or_default();
        let origin = std::env::var("MAILINABOX_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("MAILINABOX_FQDN").unwrap_or_default();
        assert!(!url.is_empty());
        assert!(!email.is_empty());
        assert!(!password.is_empty());
        assert!(!origin.is_empty());
        assert!(!fqdn.is_empty());

        let updater =
            DnsUpdater::new_mailinabox(url, email, password, Some(Duration::from_secs(30)))
                .unwrap();
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
