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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::linode::LinodeProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const DOMAIN_ID: i64 = 1234;
    const RECORD_ID: i64 = 5678;

    fn setup_provider(endpoint: String) -> LinodeProvider {
        LinodeProvider::new("test_token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_domain_lookup(server: &mut ServerGuard, domain: &str) -> Mock {
        server
            .mock("GET", "/domains")
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"data":[{{"id":{DOMAIN_ID},"domain":"{domain}"}}],"page":1,"pages":1,"results":1}}"#
            ))
            .create()
    }

    fn mock_record_lookup(server: &mut ServerGuard, sub: &str, rtype: &str) -> Mock {
        server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"data":[{{"id":{RECORD_ID},"name":"{sub}","type":"{rtype}"}}],"page":1,"pages":1,"results":1}}"#
            ))
            .create()
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");

        let create = server
            .mock("POST", format!("/domains/{DOMAIN_ID}/records").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "name": "test",
                "type": "A",
                "target": "1.1.1.1",
                "ttl_sec": 3600,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":5678}"#)
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
        domain.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_update_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let record = mock_record_lookup(&mut server, "test", "A");

        let update = server
            .mock(
                "PUT",
                format!("/domains/{DOMAIN_ID}/records/{RECORD_ID}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "name": "test",
                "type": "A",
                "target": "8.8.8.8",
                "ttl_sec": 3600,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":5678}"#)
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
        domain.assert();
        record.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let record = mock_record_lookup(&mut server, "test", "TXT");

        let delete = server
            .mock(
                "DELETE",
                format!("/domains/{DOMAIN_ID}/records/{RECORD_ID}").as_str(),
            )
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        domain.assert();
        record.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/domains")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errors":[{"reason":"Invalid token"}]}"#)
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
    async fn test_update_returns_api_error_when_record_missing() {
        let mut server = mockito::Server::new_async().await;
        let domain = mock_domain_lookup(&mut server, "example.com");
        let empty = server
            .mock("GET", format!("/domains/{DOMAIN_ID}/records").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":[],"page":1,"pages":1,"results":0}"#)
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
        domain.assert();
        empty.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Linode API token, domain, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("LINODE_TOKEN").unwrap_or_default();
        let origin = std::env::var("LINODE_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("LINODE_FQDN").unwrap_or_default();

        assert!(!token.is_empty(), "Set LINODE_TOKEN to run this test");
        assert!(!origin.is_empty(), "Set LINODE_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set LINODE_FQDN to run this test");

        let updater = DnsUpdater::new_linode(token, Some(Duration::from_secs(30))).unwrap();

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
