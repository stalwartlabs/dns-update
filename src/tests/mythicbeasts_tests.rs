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
        DnsRecord, DnsRecordType, DnsUpdater, Error,
        providers::mythicbeasts::MythicBeastsProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn provider(endpoint: String) -> MythicBeastsProvider {
        MythicBeastsProvider::new("user", "pass", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_obtains_token_then_posts() {
        let mut server = mockito::Server::new_async().await;
        let token = server
            .mock("POST", "/auth/login")
            .match_header("authorization", "Basic dXNlcjpwYXNz")
            .with_status(200)
            .with_body(
                r#"{"access_token":"abc123","expires_in":3600,"token_type":"bearer"}"#,
            )
            .create();

        let post = server
            .mock(
                "POST",
                "/dns/v2/zones/example.com/records/_acme/TXT",
            )
            .match_header("authorization", "Bearer abc123")
            .match_body(Matcher::PartialJsonString(
                r#"{"records":[{"host":"_acme","ttl":300,"type":"TXT","data":"value"}]}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"records_added":1,"records_removed":0,"message":""}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("value".to_string()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned {result:?}");
        token.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_delete_calls_delete_with_subdomain_and_type() {
        let mut server = mockito::Server::new_async().await;
        let token = server
            .mock("POST", "/auth/login")
            .with_status(200)
            .with_body(
                r#"{"access_token":"tok","expires_in":3600,"token_type":"bearer"}"#,
            )
            .create();

        let del = server
            .mock("DELETE", "/dns/v2/zones/example.com/records/www/A")
            .match_header("authorization", "Bearer tok")
            .with_status(200)
            .with_body(r#"{"records_removed":1}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "delete returned {result:?}");
        token.assert();
        del.assert();
    }

    #[tokio::test]
    async fn test_auth_failure_returns_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let token = server
            .mock("POST", "/auth/login")
            .with_status(401)
            .with_body(r#"{"error":"invalid_client","error_description":"bad"}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "_acme.example.com",
                DnsRecord::TXT("v".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)), "got {result:?}");
        token.assert();
    }

    #[tokio::test]
    #[ignore = "Requires MYTHICBEASTS_USERNAME, MYTHICBEASTS_PASSWORD, MYTHICBEASTS_ORIGIN, MYTHICBEASTS_FQDN"]
    async fn integration_test() {
        let user = std::env::var("MYTHICBEASTS_USERNAME").unwrap_or_default();
        let pass = std::env::var("MYTHICBEASTS_PASSWORD").unwrap_or_default();
        let origin = std::env::var("MYTHICBEASTS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("MYTHICBEASTS_FQDN").unwrap_or_default();
        assert!(!user.is_empty() && !pass.is_empty() && !origin.is_empty() && !fqdn.is_empty());

        let updater =
            DnsUpdater::new_mythicbeasts(user, pass, Some(Duration::from_secs(30))).unwrap();
        updater
            .create(&fqdn, DnsRecord::TXT("x".to_string()), 300, &origin)
            .await
            .unwrap();
        updater
            .delete(&fqdn, &origin, DnsRecordType::TXT)
            .await
            .unwrap();
    }
}
