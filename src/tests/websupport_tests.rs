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
        DnsRecord, DnsRecordType, Error, providers::websupport::WebSupportProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> WebSupportProvider {
        WebSupportProvider::new("api_key", "secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn services_body() -> &'static str {
        r#"{"items":[{"id":111,"serviceName":"domain","name":"example.com"}]}"#
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let services = server
            .mock("GET", "/v1/user/self/service")
            .match_header("authorization", Matcher::Regex("^Basic .+$".into()))
            .match_header("date", Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(services_body())
            .create();

        let create = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "TXT",
                "name": "_acme-challenge",
                "content": "hello",
                "ttl": 600
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"id":42}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("hello".into()),
                600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        services.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_a_record_replaces() {
        let mut server = mockito::Server::new_async().await;

        let services = server
            .mock("GET", "/v1/user/self/service")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(services_body())
            .expect_at_least(1)
            .create();

        let record_list = server
            .mock("GET", "/v2/service/111/dns/record")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":7,"type":"A","name":"host"}]}"#)
            .create();

        let delete_old = server
            .mock("DELETE", "/v2/service/111/dns/record/7")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let create_new = server
            .mock("POST", "/v2/service/111/dns/record")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "host",
                "content": "9.9.9.9",
                "ttl": 600
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"id":99}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::A("9.9.9.9".parse().unwrap()),
                600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        services.assert();
        record_list.assert();
        delete_old.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;

        let services = server
            .mock("GET", "/v1/user/self/service")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(services_body())
            .create();

        let record_list = server
            .mock("GET", "/v2/service/111/dns/record")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":33,"type":"TXT","name":"_acme-challenge"}]}"#)
            .create();

        let delete = server
            .mock("DELETE", "/v2/service/111/dns/record/33")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
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
        services.assert();
        record_list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_auth_error_propagates() {
        let mut server = mockito::Server::new_async().await;

        let services = server
            .mock("GET", "/v1/user/self/service")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                600,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        services.assert();
    }

    #[tokio::test]
    #[ignore = "requires WEBSUPPORT_API_KEY, WEBSUPPORT_SECRET, WEBSUPPORT_DOMAIN env vars"]
    async fn test_live_websupport_roundtrip() {
        let api_key = std::env::var("WEBSUPPORT_API_KEY").expect("WEBSUPPORT_API_KEY");
        let secret = std::env::var("WEBSUPPORT_SECRET").expect("WEBSUPPORT_SECRET");
        let domain = std::env::var("WEBSUPPORT_DOMAIN").expect("WEBSUPPORT_DOMAIN");
        let provider =
            WebSupportProvider::new(api_key, secret, Some(Duration::from_secs(30))).unwrap();
        provider
            .create(
                format!("dns-update-test.{domain}"),
                DnsRecord::TXT("hello".into()),
                600,
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
