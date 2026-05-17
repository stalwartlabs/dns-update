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
        DnsRecord, DnsRecordType, Error, providers::dnsmadeeasy::DnsMadeEasyProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> DnsMadeEasyProvider {
        DnsMadeEasyProvider::new("api_key", "api_secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = server
            .mock("GET", "/dns/managed/name")
            .match_query(Matcher::UrlEncoded("domainname".into(), "example.com".into()))
            .match_header("x-dnsme-apiKey", "api_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":12345,"name":"example.com"}"#)
            .create();

        let create = server
            .mock("POST", "/dns/managed/12345/records")
            .match_header("x-dnsme-apiKey", "api_key")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "test",
                "value": "1.2.3.4",
                "ttl": 300
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":99,"name":"test","type":"A","value":"1.2.3.4","ttl":300,"sourceId":12345}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        domain_lookup.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_record_replaces_existing() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = server
            .mock("GET", "/dns/managed/name")
            .match_query(Matcher::UrlEncoded("domainname".into(), "example.com".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":12345,"name":"example.com"}"#)
            .create();

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "A".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":555}]}"#)
            .create();

        let delete_old = server
            .mock("DELETE", "/dns/managed/12345/records/555")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let create = server
            .mock("POST", "/dns/managed/12345/records")
            .match_body(Matcher::Json(json!({
                "type": "A",
                "name": "test",
                "value": "5.6.7.8",
                "ttl": 300
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":600}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        delete_old.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_delete_record() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = server
            .mock("GET", "/dns/managed/name")
            .match_query(Matcher::UrlEncoded("domainname".into(), "example.com".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":12345,"name":"example.com"}"#)
            .create();

        let record_lookup = server
            .mock("GET", "/dns/managed/12345/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), "test".into()),
                Matcher::UrlEncoded("type".into(), "TXT".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[{"id":777}]}"#)
            .create();

        let delete = server
            .mock("DELETE", "/dns/managed/12345/records/777")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        domain_lookup.assert();
        record_lookup.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_auth_error_propagates() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = server
            .mock("GET", "/dns/managed/name")
            .match_query(Matcher::Any)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":["unauthorized"]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        domain_lookup.assert();
    }

    #[tokio::test]
    #[ignore = "requires DNSMADEEASY_API_KEY, DNSMADEEASY_API_SECRET, DNSMADEEASY_DOMAIN env vars"]
    async fn test_live_dnsmadeeasy_roundtrip() {
        let api_key = std::env::var("DNSMADEEASY_API_KEY").expect("DNSMADEEASY_API_KEY");
        let api_secret = std::env::var("DNSMADEEASY_API_SECRET").expect("DNSMADEEASY_API_SECRET");
        let domain = std::env::var("DNSMADEEASY_DOMAIN").expect("DNSMADEEASY_DOMAIN");
        let provider =
            DnsMadeEasyProvider::new(api_key, api_secret, Some(Duration::from_secs(30))).unwrap();
        provider
            .create(
                format!("dns-update-test.{domain}"),
                DnsRecord::TXT("hello".into()),
                300,
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
