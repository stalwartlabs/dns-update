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
        DnsRecord, DnsRecordType, Error, providers::exoscale::ExoscaleProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> ExoscaleProvider {
        ExoscaleProvider::new("api_key", "api_secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn auth_match() -> Matcher {
        Matcher::Regex("^EXO2-HMAC-SHA256 credential=api_key,expires=[0-9]+,signature=.+$".into())
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let zones = server
            .mock("GET", "/dns-domain")
            .match_header("authorization", auth_match())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"dns-domains":[{"id":"zone-1","unicode-name":"example.com"}]}"#)
            .create();

        let create = server
            .mock("POST", "/dns-domain/zone-1/record")
            .match_header("authorization", auth_match())
            .match_body(Matcher::Json(json!({
                "name": "_acme-challenge",
                "type": "TXT",
                "content": "\"hello\"",
                "ttl": 60
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"r-1"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("hello".into()),
                60,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        zones.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_a_record() {
        let mut server = mockito::Server::new_async().await;

        let zones = server
            .mock("GET", "/dns-domain")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"dns-domains":[{"id":"zone-1","unicode-name":"example.com"}]}"#)
            .create();

        let record_list = server
            .mock("GET", "/dns-domain/zone-1/record")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"dns-domain-records":[{"id":"r-99","name":"host","type":"A"}]}"#)
            .create();

        let update = server
            .mock("PUT", "/dns-domain/zone-1/record/r-99")
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "content": "5.6.7.8",
                "ttl": 60
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"r-99"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                60,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        zones.assert();
        record_list.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;

        let zones = server
            .mock("GET", "/dns-domain")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"dns-domains":[{"id":"zone-1","unicode-name":"example.com"}]}"#)
            .create();

        let record_list = server
            .mock("GET", "/dns-domain/zone-1/record")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"dns-domain-records":[{"id":"r-11","name":"_acme-challenge","type":"TXT"}]}"#)
            .create();

        let delete = server
            .mock("DELETE", "/dns-domain/zone-1/record/r-11")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete(
                "_acme-challenge.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        zones.assert();
        record_list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_auth_error_propagates() {
        let mut server = mockito::Server::new_async().await;

        let zones = server
            .mock("GET", "/dns-domain")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                60,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        zones.assert();
    }

    #[tokio::test]
    #[ignore = "requires EXOSCALE_API_KEY, EXOSCALE_API_SECRET, EXOSCALE_DOMAIN env vars"]
    async fn test_live_exoscale_roundtrip() {
        let api_key = std::env::var("EXOSCALE_API_KEY").expect("EXOSCALE_API_KEY");
        let api_secret = std::env::var("EXOSCALE_API_SECRET").expect("EXOSCALE_API_SECRET");
        let domain = std::env::var("EXOSCALE_DOMAIN").expect("EXOSCALE_DOMAIN");
        let provider =
            ExoscaleProvider::new(api_key, api_secret, Some(Duration::from_secs(30))).unwrap();
        provider
            .create(
                format!("dns-update-test.{domain}"),
                DnsRecord::TXT("hello".into()),
                60,
                &domain,
            )
            .await
            .unwrap();
        provider
            .delete(
                format!("dns-update-test.{domain}"),
                &domain,
                DnsRecordType::TXT,
            )
            .await
            .unwrap();
    }
}
