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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::cloudns::ClouDnsProvider,
    };
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> ClouDnsProvider {
        ClouDnsProvider::new(
            Some("auth_user"),
            None::<&str>,
            "pw",
            Some(Duration::from_secs(5)),
        )
        .unwrap()
        .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/add-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("auth-id".into(), "auth_user".into()),
                mockito::Matcher::UrlEncoded("auth-password".into(), "pw".into()),
                mockito::Matcher::UrlEncoded("domain-name".into(), "example.com".into()),
                mockito::Matcher::UrlEncoded("host".into(), "test".into()),
                mockito::Matcher::UrlEncoded("record-type".into(), "TXT".into()),
                mockito::Matcher::UrlEncoded("record".into(), "hello".into()),
                mockito::Matcher::UrlEncoded("ttl".into(), "300".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"The record was added successfully."}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("hello".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create failed: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_failure_status() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/add-record.json")
            .with_status(200)
            .with_body(r#"{"status":"Failed","statusDescription":"Invalid record."}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("hello".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(r#"{"100": {"id": "100", "type": "A", "host": "test"}}"#)
            .create();

        let modify = server
            .mock("POST", "/mod-record.json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("record-id".into(), "100".into()),
                mockito::Matcher::UrlEncoded("host".into(), "test".into()),
                mockito::Matcher::UrlEncoded("record".into(), "9.9.9.9".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"updated"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update failed: {result:?}");
        lookup.assert();
        modify.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let lookup = server
            .mock("GET", mockito::Matcher::Regex("^/records.json".into()))
            .with_status(200)
            .with_body(r#"{"7": {"id": "7", "type": "TXT", "host": "test"}}"#)
            .create();

        let delete = server
            .mock("POST", "/delete-record.json")
            .match_body(mockito::Matcher::UrlEncoded("record-id".into(), "7".into()))
            .with_status(200)
            .with_body(r#"{"status":"Success","statusDescription":"removed"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete failed: {result:?}");
        lookup.assert();
        delete.assert();
    }

    #[test]
    fn test_provider_requires_auth() {
        let result = ClouDnsProvider::new(None::<&str>, None::<&str>, "pw", None);
        assert!(matches!(result, Err(Error::Api(_))));
    }

    #[tokio::test]
    #[ignore = "Requires ClouDNS credentials, zone and FQDN"]
    async fn integration_test() {
        let auth_id = std::env::var("CLOUDNS_AUTH_ID").ok();
        let sub_auth_id = std::env::var("CLOUDNS_SUB_AUTH_ID").ok();
        let password = std::env::var("CLOUDNS_AUTH_PASSWORD").unwrap_or_default();
        let origin = std::env::var("CLOUDNS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("CLOUDNS_FQDN").unwrap_or_default();

        assert!(!password.is_empty());
        assert!(!origin.is_empty() && !fqdn.is_empty());

        let updater = DnsUpdater::new_cloudns(
            auth_id,
            sub_auth_id,
            password,
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        let create = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create.is_ok(), "create failed: {create:?}");
        let delete = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete.is_ok(), "delete failed: {delete:?}");
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_cloudns(
            Some("user"),
            None::<&str>,
            "pw",
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::ClouDns(..))));
    }
}
