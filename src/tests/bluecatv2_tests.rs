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
        DnsRecord, DnsRecordType, DnsUpdater,
        providers::bluecatv2::{BluecatV2Config, BluecatV2Provider},
    };
    use std::time::Duration;

    fn config() -> BluecatV2Config {
        BluecatV2Config {
            server_url: "http://placeholder".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            config_name: "default".to_string(),
            view_name: "internal".to_string(),
            skip_deploy: true,
            request_timeout: Some(Duration::from_secs(1)),
        }
    }

    fn setup(endpoint: &str) -> BluecatV2Provider {
        BluecatV2Provider::new(config()).unwrap().with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let session = server
            .mock("POST", "/api/v2/sessions")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"basicAuthenticationCredentials":"AUTH"}"#)
            .create();

        let zone_lookup = server
            .mock("GET", mockito::Matcher::Regex("/api/v2/zones\\?.*".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"count":1,"totalCount":1,"data":[{"id":42,"absoluteName":"example.com"}]}"#,
            )
            .create();

        let create_rec = server
            .mock("POST", "/api/v2/zones/42/resourceRecords")
            .with_status(201)
            .match_header("authorization", "Basic AUTH")
            .with_body(r#"{"id":7}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("challenge".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create failed: {result:?}");
        session.assert();
        zone_lookup.assert();
        create_rec.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let session = server
            .mock("POST", "/api/v2/sessions")
            .with_status(200)
            .with_body(r#"{"basicAuthenticationCredentials":"AUTH"}"#)
            .create();

        let zone_lookup = server
            .mock("GET", mockito::Matcher::Regex("/api/v2/zones\\?.*".into()))
            .with_status(200)
            .with_body(
                r#"{"count":1,"totalCount":1,"data":[{"id":42,"absoluteName":"example.com"}]}"#,
            )
            .create();

        let find_rec = server
            .mock(
                "GET",
                mockito::Matcher::Regex("/api/v2/zones/42/resourceRecords\\?.*".into()),
            )
            .with_status(200)
            .with_body(
                r#"{"count":1,"totalCount":1,"data":[{"id":9,"absoluteName":"test.example.com","recordType":"TXT"}]}"#,
            )
            .create();

        let delete_rec = server
            .mock("DELETE", "/api/v2/resourceRecords/9")
            .with_status(204)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete failed: {result:?}");
        session.assert();
        zone_lookup.assert();
        find_rec.assert();
        delete_rec.assert();
    }

    #[tokio::test]
    async fn missing_zone_returns_error() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/api/v2/sessions")
            .with_status(200)
            .with_body(r#"{"basicAuthenticationCredentials":"AUTH"}"#)
            .create();
        server
            .mock("GET", mockito::Matcher::Regex("/api/v2/zones\\?.*".into()))
            .with_status(200)
            .with_body(r#"{"count":0,"totalCount":0,"data":[]}"#)
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
    }

    #[test]
    fn rejects_missing_credentials() {
        let mut cfg = config();
        cfg.username.clear();
        assert!(matches!(
            BluecatV2Provider::new(cfg),
            Err(crate::Error::Api(_))
        ));
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_bluecatv2(config());
        assert!(matches!(updater, Ok(DnsUpdater::BluecatV2(..))));
    }

    #[tokio::test]
    #[ignore = "Requires Bluecat Address Manager v2 access"]
    async fn integration_test() {
        let cfg = BluecatV2Config {
            server_url: std::env::var("BLUECATV2_SERVER_URL").unwrap_or_default(),
            username: std::env::var("BLUECATV2_USERNAME").unwrap_or_default(),
            password: std::env::var("BLUECATV2_PASSWORD").unwrap_or_default(),
            config_name: std::env::var("BLUECATV2_CONFIG_NAME").unwrap_or_default(),
            view_name: std::env::var("BLUECATV2_VIEW_NAME").unwrap_or_default(),
            skip_deploy: true,
            request_timeout: Some(Duration::from_secs(30)),
        };
        let origin = std::env::var("BLUECATV2_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("BLUECATV2_FQDN").unwrap_or_default();
        assert!(!cfg.server_url.is_empty());
        assert!(!cfg.username.is_empty());
        assert!(!origin.is_empty());
        assert!(!fqdn.is_empty());

        let updater = DnsUpdater::new_bluecatv2(cfg).unwrap();
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
