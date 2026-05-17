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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::vercel::VercelProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const RECORD_ID: &str = "rec_abc";

    fn setup_provider(endpoint: String) -> VercelProvider {
        VercelProvider::new("test_token", None::<&str>, Some(Duration::from_secs(1)))
            .with_endpoint(endpoint)
    }

    fn mock_records_list(server: &mut ServerGuard, sub: &str, rtype: &str) -> Mock {
        server
            .mock("GET", "/v4/domains/example.com/records")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"records":[{{"id":"{RECORD_ID}","name":"{sub}","type":"{rtype}","value":"x"}}]}}"#
            ))
            .create()
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;
        let create = server
            .mock("POST", "/v2/domains/example.com/records")
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "name": "test",
                "type": "A",
                "value": "1.1.1.1",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"uid":"rec_abc"}"#)
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
        create.assert();
    }

    #[tokio::test]
    async fn test_update_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_records_list(&mut server, "test", "A");
        let update = server
            .mock("PATCH", format!("/v1/domains/records/{RECORD_ID}").as_str())
            .match_header("authorization", "Bearer test_token")
            .match_body(Matcher::Json(json!({
                "name": "test",
                "type": "A",
                "value": "8.8.8.8",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
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
        list.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_resolves_record_id() {
        let mut server = mockito::Server::new_async().await;
        let list = mock_records_list(&mut server, "test", "TXT");
        let delete = server
            .mock(
                "DELETE",
                format!("/v2/domains/example.com/records/{RECORD_ID}").as_str(),
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
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("POST", "/v2/domains/example.com/records")
            .with_status(401)
            .with_body(r#"{"error":{"code":"forbidden","message":"forbidden"}}"#)
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
    async fn test_team_id_is_appended_as_query_string() {
        let mut server = mockito::Server::new_async().await;
        let create = server
            .mock("POST", "/v2/domains/example.com/records?teamId=team_123")
            .match_header("authorization", "Bearer test_token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"uid":"rec_abc"}"#)
            .create();

        let provider = VercelProvider::new(
            "test_token",
            Some("team_123"),
            Some(Duration::from_secs(1)),
        )
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
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Vercel API token, domain, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("VERCEL_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("VERCEL_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("VERCEL_FQDN").unwrap_or_default();
        let team_id = std::env::var("VERCEL_TEAM_ID").ok();

        assert!(!token.is_empty(), "Set VERCEL_API_TOKEN to run this test");
        assert!(!origin.is_empty(), "Set VERCEL_ORIGIN to run this test");
        assert!(!fqdn.is_empty(), "Set VERCEL_FQDN to run this test");

        let updater = DnsUpdater::new_vercel(token, team_id, Some(Duration::from_secs(30))).unwrap();

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
