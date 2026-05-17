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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::cpanel::CpanelProvider,
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> CpanelProvider {
        CpanelProvider::new(
            endpoint,
            "test_user",
            "test_token",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    fn b64(value: &str) -> String {
        BASE64.encode(value.as_bytes())
    }

    fn zone_fixture_with_record(record_type: &str, host: &str, value: &str) -> String {
        let domain_b64 = b64("example.com");
        let ns_b64 = b64("ns1.example.com.");
        let admin_b64 = b64("admin.example.com.");
        let serial_b64 = b64("2024010100");
        let host_b64 = b64(host);
        let value_b64 = b64(value);

        format!(
            r#"{{"status":1,"data":[
                {{"line_index":1,"type":"record","record_type":"SOA","dname_b64":"{domain}",
                  "data_b64":["{ns}","{admin}","{serial}","3600","1800","1209600","300"],"ttl":3600}},
                {{"line_index":5,"type":"record","record_type":"{rt}","dname_b64":"{host}",
                  "data_b64":["{val}"],"ttl":3600}}
            ]}}"#,
            domain = domain_b64,
            ns = ns_b64,
            admin = admin_b64,
            serial = serial_b64,
            rt = record_type,
            host = host_b64,
            val = value_b64,
        )
    }

    fn zone_fixture_no_record() -> String {
        let domain_b64 = b64("example.com");
        let ns_b64 = b64("ns1.example.com.");
        let admin_b64 = b64("admin.example.com.");
        let serial_b64 = b64("2024010100");
        format!(
            r#"{{"status":1,"data":[
                {{"line_index":1,"type":"record","record_type":"SOA","dname_b64":"{domain}",
                  "data_b64":["{ns}","{admin}","{serial}","3600","1800","1209600","300"],"ttl":3600}}
            ]}}"#,
            domain = domain_b64,
            ns = ns_b64,
            admin = admin_b64,
            serial = serial_b64,
        )
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_cpanel(
            "https://cpanel.example.com:2083",
            "test_user",
            "test_token",
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Cpanel(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(mockito::Matcher::UrlEncoded(
                "zone".into(),
                "example.com".into(),
            ))
            .match_header("authorization", "cpanel test_user:test_token")
            .with_status(200)
            .with_body(zone_fixture_no_record())
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("zone".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                mockito::Matcher::Regex("add=".into()),
            ]))
            .match_header("authorization", "cpanel test_user:test_token")
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("challenge-value".into()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(mockito::Matcher::UrlEncoded(
                "zone".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_body(zone_fixture_with_record(
                "TXT",
                "_acme-challenge.example.com",
                "old-value",
            ))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("zone".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                mockito::Matcher::Regex("edit=".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010102"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "_acme-challenge.example.com",
                DnsRecord::TXT("new-value".into()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(mockito::Matcher::UrlEncoded(
                "zone".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_body(zone_fixture_with_record(
                "TXT",
                "_acme-challenge.example.com",
                "old-value",
            ))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("zone".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                mockito::Matcher::UrlEncoded("remove".into(), "5".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010103"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_not_found() {
        let mut server = mockito::Server::new_async().await;

        let _zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(mockito::Matcher::UrlEncoded(
                "zone".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_body(zone_fixture_no_record())
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("missing.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(matches!(result, Err(Error::NotFound)));
    }

    #[tokio::test]
    async fn create_record_api_error() {
        let mut server = mockito::Server::new_async().await;

        let _zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(mockito::Matcher::UrlEncoded(
                "zone".into(),
                "example.com".into(),
            ))
            .with_status(200)
            .with_body(r#"{"status":0,"errors":["Invalid zone"],"messages":[]}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("v".into()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    #[ignore = "Requires cPanel server URL, username and API token"]
    async fn integration_test() {
        let base_url = std::env::var("CPANEL_BASE_URL").unwrap_or_default();
        let username = std::env::var("CPANEL_USERNAME").unwrap_or_default();
        let token = std::env::var("CPANEL_TOKEN").unwrap_or_default();
        let origin = std::env::var("CPANEL_ORIGIN").unwrap_or_default();
        let domain = std::env::var("CPANEL_DOMAIN").unwrap_or_default();

        assert!(!base_url.is_empty(), "Please configure CPANEL_BASE_URL");
        assert!(!username.is_empty(), "Please configure CPANEL_USERNAME");
        assert!(!token.is_empty(), "Please configure CPANEL_TOKEN");
        assert!(!origin.is_empty(), "Please configure CPANEL_ORIGIN");
        assert!(!domain.is_empty(), "Please configure CPANEL_DOMAIN");

        let updater = DnsUpdater::new_cpanel(
            base_url,
            username,
            token,
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        assert!(
            updater
                .create(
                    &domain,
                    DnsRecord::TXT("integration-test".into()),
                    300,
                    &origin
                )
                .await
                .is_ok()
        );
        assert!(
            updater
                .update(
                    &domain,
                    DnsRecord::TXT("integration-test-2".into()),
                    300,
                    &origin
                )
                .await
                .is_ok()
        );
        assert!(
            updater
                .delete(&domain, &origin, DnsRecordType::TXT)
                .await
                .is_ok()
        );
    }
}
