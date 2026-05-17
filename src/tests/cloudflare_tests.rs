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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord,
        providers::cloudflare::CloudflareProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE_ID: &str = "abc123zoneid";
    const RECORD_ID: &str = "def456recordid";

    fn setup_provider(endpoint: String) -> CloudflareProvider {
        CloudflareProvider::new("test_token", None::<&str>, Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_zone_lookup(server: &mut ServerGuard, zone_name: &str) -> Mock {
        server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), zone_name.into()))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"errors":[],"success":true,"result":[{{"id":"{ZONE_ID}","name":"{zone_name}"}}]}}"#
            ))
            .create()
    }

    fn mock_record_lookup(server: &mut ServerGuard, record_name: &str, record_type: &str) -> Mock {
        server
            .mock("GET", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), record_name.into()),
                Matcher::UrlEncoded("type".into(), record_type.into()),
                Matcher::UrlEncoded("match".into(), "all".into()),
            ]))
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"errors":[],"success":true,"result":[{{"id":"{RECORD_ID}","name":"{record_name}"}}]}}"#
            ))
            .create()
    }

    fn ok_body() -> &'static str {
        r#"{"errors":[],"success":true,"result":{}}"#
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "proxied": false,
                "name": "test.example.com",
                "type": "A",
                "content": "1.1.1.1",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_resolves_record_id_before_patch() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let record_lookup = mock_record_lookup(&mut server, "test.example.com", "A");

        let patch = server
            .mock(
                "PATCH",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "name": "test.example.com",
                "type": "A",
                "content": "8.8.8.8",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned: {result:?}");
        zone.assert();
        record_lookup.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn test_update_returns_api_error_when_record_missing() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let empty_lookup = server
            .mock("GET", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errors":[],"success":true,"result":[]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "missing.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        zone.assert();
        empty_lookup.assert();
    }

    #[tokio::test]
    async fn test_delete_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let record_lookup = mock_record_lookup(&mut server, "test.example.com", "TXT");

        let delete = server
            .mock(
                "DELETE",
                format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        zone.assert();
        record_lookup.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_obtain_zone_id_walks_up_to_parent_zone() {
        let mut server = mockito::Server::new_async().await;

        let zone_miss = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), "sub.example.com".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errors":[],"success":true,"result":[]}"#)
            .create();

        let zone_hit = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "host.sub.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                3600,
                "sub.example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone_miss.assert();
        zone_hit.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_create_txt_record_wraps_content_in_quotes() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 300,
                "proxied": false,
                "name": "test.example.com",
                "type": "TXT",
                "content": "\"v=spf1 -all\"",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::TXT("v=spf1 -all".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_create_mx_record_sends_priority() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "proxied": false,
                "priority": 10,
                "name": "example.com",
                "type": "MX",
                "content": "mail.example.com",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_create_caa_record_sends_data_struct() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_body(Matcher::Json(json!({
                "ttl": 3600,
                "proxied": false,
                "name": "example.com",
                "type": "CAA",
                "data": {
                    "flags": 0,
                    "tag": "issue",
                    "value": "letsencrypt.org",
                },
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "example.com",
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), "example.com".into()))
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"errors":[{"code":10000,"message":"Unauthorized"}],"success":false,"result":[]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    async fn test_api_success_false_surfaces_as_api_error() {
        let mut server = mockito::Server::new_async().await;
        let failure = server
            .mock("GET", "/zones")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"errors":[{"code":1003,"message":"Invalid zone identifier"}],"success":false,"result":[]}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
        failure.assert();
    }

    #[tokio::test]
    async fn test_email_and_key_auth_uses_x_auth_headers() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("GET", "/zones")
            .match_query(Matcher::UrlEncoded("name".into(), "example.com".into()))
            .match_header("x-auth-email", "user@example.com")
            .match_header("x-auth-key", "the-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"errors":[],"success":true,"result":[{{"id":"{ZONE_ID}","name":"example.com"}}]}}"#
            ))
            .create();

        let create = server
            .mock("POST", format!("/zones/{ZONE_ID}/dns_records").as_str())
            .match_header("x-auth-email", "user@example.com")
            .match_header("x-auth-key", "the-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(ok_body())
            .create();

        let provider = CloudflareProvider::new(
            "the-key",
            Some("user@example.com"),
            Some(Duration::from_secs(1)),
        )
        .unwrap()
        .with_endpoint(server.url());

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Cloudflare API token, zone, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("CLOUDFLARE_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("CLOUDFLARE_FQDN").unwrap_or_default();

        assert!(
            !token.is_empty(),
            "Set CLOUDFLARE_API_TOKEN to run this test"
        );
        assert!(
            !origin.is_empty(),
            "Set CLOUDFLARE_ORIGIN to run this test (e.g. example.com)"
        );
        assert!(
            !fqdn.is_empty(),
            "Set CLOUDFLARE_FQDN to run this test (e.g. test.example.com)"
        );

        let updater =
            DnsUpdater::new_cloudflare(token, None::<&str>, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
