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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, providers::vercel::VercelProvider};
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> VercelProvider {
        VercelProvider::new(
            "test_token",
            Some("test_team".to_string()),
            None,
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_vercel(
            "test_token",
            Some("test_team".to_string()),
            None,
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());
        assert!(
            matches!(updater, Ok(DnsUpdater::Vercel(..))),
            "Expected Vercel updater to provide a Vercel provider"
        );
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/domains/example.com/records")
            .match_query(mockito::Matcher::UrlEncoded("teamId".into(), "test_team".into()))
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "type": "A",
                "name": "test",
                "value": "1.1.1.1",
                "ttl": 3600,
                "comment": "Managed by Stalwart"
            })))
            .with_status(200)
            .with_body(json!({"uid": "rec_123"}).to_string())
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        result.expect("Failed to create record");
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;
        
        // Mock list to find record ID
        let list_mock = server
            .mock("GET", "/v5/domains/example.com/records")
            .match_query(mockito::Matcher::UrlEncoded("teamId".into(), "test_team".into()))
            .with_status(200)
            .with_body(json!({
                "records": [
                    {
                        "id": "rec_123",
                        "name": "test",
                        "type": "A"
                    }
                ],
                "pagination": {"count": 1, "next": null}
            }).to_string())
            .create();

        let update_mock = server
            .mock("PATCH", "/v1/domains/records/rec_123")
            .match_query(mockito::Matcher::UrlEncoded("teamId".into(), "test_team".into()))
            .match_body(mockito::Matcher::Json(json!({
                "type": "A",
                "name": "test",
                "value": "8.8.8.8",
                "ttl": 3600,
                "comment": "Managed by Stalwart"
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("8.8.8.8".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        result.expect("Failed to update record");
        list_mock.assert();
        update_mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let list_mock = server
            .mock("GET", "/v5/domains/example.com/records")
            .match_query(mockito::Matcher::UrlEncoded("teamId".into(), "test_team".into()))
            .with_status(200)
            .with_body(json!({
                "records": [
                    {
                        "id": "rec_123",
                        "name": "test",
                        "type": "TXT"
                    }
                ],
                "pagination": {"count": 1, "next": null}
            }).to_string())
            .create();

        let delete_mock = server
            .mock("DELETE", "/v2/domains/example.com/records/rec_123")
            .match_query(mockito::Matcher::UrlEncoded("teamId".into(), "test_team".into()))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .delete(
                "test.example.com",
                "example.com",
                DnsRecordType::TXT,
            )
            .await;

        result.expect("Failed to delete record");
        list_mock.assert();
        delete_mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Vercel API keys and domain configuration"]
    async fn vercel_integration_test() {
        let token = std::env::var("VERCEL_TOKEN").unwrap_or_default();
        let domain = std::env::var("VERCEL_DOMAIN").unwrap_or_default();
        let origin = std::env::var("VERCEL_ORIGIN").unwrap_or_default();
        let team_id = std::env::var("VERCEL_TEAM_ID").ok();
        let slug = std::env::var("VERCEL_SLUG").ok();

        assert!(
            !token.is_empty(),
            "Please configure your Vercel token in the integration test"
        );
        assert!(
            !domain.is_empty(),
            "Please configure your domain in the integration test"
        );
        assert!(
            !origin.is_empty(),
            "Please configure your origin in the integration test"
        );

        let updater = DnsUpdater::new_vercel(token, team_id, slug, Some(Duration::from_secs(30))).unwrap();

        let create_result = updater
            .create(&domain, DnsRecord::A([1, 1, 1, 1].into()), 60, &origin)
            .await;
        assert!(create_result.is_ok());

        let update_result = updater
            .update(&domain, DnsRecord::A([8, 8, 8, 8].into()), 60, &origin)
            .await;
        assert!(update_result.is_ok());

        let delete_result = updater
            .delete(&domain, &origin, crate::DnsRecordType::A)
            .await;
        assert!(delete_result.is_ok());
    }
}
