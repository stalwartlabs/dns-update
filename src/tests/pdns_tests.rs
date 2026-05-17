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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, providers::pdns::PdnsProvider};
    use serde_json::json;
    use std::time::Duration;

    fn setup(endpoint: &str) -> PdnsProvider {
        PdnsProvider::new(
            "api-key",
            None::<&str>,
            Some("localhost"),
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let expected = json!({
            "rrsets": [{
                "name": "test.example.com.",
                "type": "A",
                "changetype": "REPLACE",
                "ttl": 300,
                "records": [{
                    "content": "1.2.3.4",
                    "disabled": false
                }]
            }]
        });

        let mock = server
            .mock("PATCH", "/api/v1/servers/localhost/zones/example.com.")
            .with_status(204)
            .match_header("x-api-key", "api-key")
            .match_body(mockito::Matcher::Json(expected))
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
        let expected = json!({
            "rrsets": [{
                "name": "test.example.com.",
                "type": "TXT",
                "changetype": "DELETE"
            }]
        });

        let mock = server
            .mock("PATCH", "/api/v1/servers/localhost/zones/example.com.")
            .with_status(204)
            .match_header("x-api-key", "api-key")
            .match_body(mockito::Matcher::Json(expected))
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn unauthorized_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PATCH", "/api/v1/servers/localhost/zones/example.com.")
            .with_status(401)
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
        assert!(matches!(result, Err(crate::Error::Unauthorized)));
        mock.assert();
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_pdns(
            "k",
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(5)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Pdns(..))));
    }

    #[tokio::test]
    #[ignore = "Requires a PowerDNS API endpoint, key, and zone"]
    async fn integration_test() {
        let endpoint = std::env::var("PDNS_API_URL").unwrap_or_default();
        let api_key = std::env::var("PDNS_API_KEY").unwrap_or_default();
        let origin = std::env::var("PDNS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("PDNS_FQDN").unwrap_or_default();
        assert!(!endpoint.is_empty(), "set PDNS_API_URL");
        assert!(!api_key.is_empty(), "set PDNS_API_KEY");
        assert!(!origin.is_empty(), "set PDNS_ORIGIN");
        assert!(!fqdn.is_empty(), "set PDNS_FQDN");

        let updater = DnsUpdater::new_pdns(
            api_key,
            Some(endpoint),
            None::<&str>,
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        assert!(
            updater
                .create(&fqdn, DnsRecord::A("1.2.3.4".parse().unwrap()), 300, &origin)
                .await
                .is_ok()
        );
        assert!(
            updater
                .delete(&fqdn, &origin, DnsRecordType::A)
                .await
                .is_ok()
        );
    }
}
