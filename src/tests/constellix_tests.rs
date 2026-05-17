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
        DnsRecord, DnsRecordType, Error, providers::constellix::ConstellixProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> ConstellixProvider {
        ConstellixProvider::new("api_key", "secret_key", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;

        let domain_search = server
            .mock("GET", "/v1/domains/search")
            .match_query(Matcher::UrlEncoded("exact".into(), "example.com".into()))
            .match_header(
                "x-cns-security-token",
                Matcher::Regex("^api_key:[^:]+:[0-9]+$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":12345,"name":"example.com"}]"#)
            .create();

        let create = server
            .mock("POST", "/v1/domains/12345/records/txt")
            .match_body(Matcher::Json(json!({
                "name": "_acme-challenge",
                "ttl": 60,
                "roundRobin": [{"value": "\"abc\""}]
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":99}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("abc".into()),
                60,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        domain_search.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_a_record() {
        let mut server = mockito::Server::new_async().await;

        let domain_search = server
            .mock("GET", "/v1/domains/search")
            .match_query(Matcher::UrlEncoded("exact".into(), "example.com".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":12345,"name":"example.com"}]"#)
            .create();

        let record_search = server
            .mock("GET", "/v1/domains/12345/records/a/search")
            .match_query(Matcher::UrlEncoded("exact".into(), "host".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":42}]"#)
            .create();

        let update = server
            .mock("PUT", "/v1/domains/12345/records/a/42")
            .match_body(Matcher::Json(json!({
                "name": "host",
                "ttl": 120,
                "roundRobin": [{"value": "10.0.0.1"}]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "host.example.com",
                DnsRecord::A("10.0.0.1".parse().unwrap()),
                120,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        domain_search.assert();
        record_search.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;

        let domain_search = server
            .mock("GET", "/v1/domains/search")
            .match_query(Matcher::UrlEncoded("exact".into(), "example.com".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":12345}]"#)
            .create();

        let record_search = server
            .mock("GET", "/v1/domains/12345/records/txt/search")
            .match_query(Matcher::UrlEncoded("exact".into(), "_acme-challenge".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"id":55}]"#)
            .create();

        let delete = server
            .mock("DELETE", "/v1/domains/12345/records/txt/55")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"success":"deleted"}"#)
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
        domain_search.assert();
        record_search.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_auth_error_propagates() {
        let mut server = mockito::Server::new_async().await;

        let domain_search = server
            .mock("GET", "/v1/domains/search")
            .match_query(Matcher::Any)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errors":["unauthorized"]}"#)
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
        domain_search.assert();
    }

    #[tokio::test]
    #[ignore = "requires CONSTELLIX_API_KEY, CONSTELLIX_SECRET_KEY, CONSTELLIX_DOMAIN env vars"]
    async fn test_live_constellix_roundtrip() {
        let api_key = std::env::var("CONSTELLIX_API_KEY").expect("CONSTELLIX_API_KEY");
        let secret_key = std::env::var("CONSTELLIX_SECRET_KEY").expect("CONSTELLIX_SECRET_KEY");
        let domain = std::env::var("CONSTELLIX_DOMAIN").expect("CONSTELLIX_DOMAIN");
        let provider =
            ConstellixProvider::new(api_key, secret_key, Some(Duration::from_secs(30))).unwrap();
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
