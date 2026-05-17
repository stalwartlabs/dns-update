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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord,
        providers::ultradns::UltraDnsProvider,
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup(server_url: &str) -> UltraDnsProvider {
        UltraDnsProvider::new(
            "user",
            "pass",
            Some(server_url.to_string()),
            Some(Duration::from_secs(2)),
        )
        .expect("provider")
        .with_endpoint(server_url)
        .with_cached_token("cached-token")
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_ultradns(
            "user",
            "pass",
            None,
            Some(Duration::from_secs(1)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::UltraDns(..))));
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/v3/zones/example.com./rrsets/A/test.example.com.",
            )
            .match_header("authorization", "Bearer cached-token")
            .match_body(mockito::Matcher::Json(json!({
                "ttl": 300,
                "rdata": ["1.1.1.1"],
            })))
            .with_status(201)
            .with_body(r#"{"message":"created"}"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn create_record_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/v3/zones/example.com./rrsets/A/test.example.com.",
            )
            .with_status(401)
            .with_body(r#"[{"errorCode":60001,"errorMessage":"invalid token"}]"#)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)));
        mock.assert();
    }

    #[tokio::test]
    async fn update_mx_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("PUT", "/v3/zones/example.com./rrsets/MX/example.com.")
            .match_header("authorization", "Bearer cached-token")
            .match_body(mockito::Matcher::Json(json!({
                "ttl": 3600,
                "rdata": ["10 mail.example.com."],
            })))
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .update(
                "example.com",
                DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".into(),
                    priority: 10,
                }),
                3600,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "DELETE",
                "/v3/zones/example.com./rrsets/TXT/test.example.com.",
            )
            .match_header("authorization", "Bearer cached-token")
            .with_status(204)
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn token_acquired_via_password_grant() {
        let mut server = mockito::Server::new_async().await;
        let token_mock = server
            .mock("POST", "/v2/authorization/token")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("grant_type=password".into()),
                mockito::Matcher::Regex("username=user".into()),
                mockito::Matcher::Regex("password=pass".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"accessToken":"fresh-token","refreshToken":"r-token","expiresIn":"3600","tokenType":"Bearer"}"#,
            )
            .create();
        let create_mock = server
            .mock(
                "POST",
                "/v3/zones/example.com./rrsets/A/test.example.com.",
            )
            .match_header("authorization", "Bearer fresh-token")
            .with_status(201)
            .with_body("{}")
            .create();

        let provider = UltraDnsProvider::new(
            "user",
            "pass",
            Some(server.url().clone()),
            Some(Duration::from_secs(2)),
        )
        .expect("provider")
        .with_endpoint(server.url().as_str());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        token_mock.assert();
        create_mock.assert();
    }

    #[tokio::test]
    async fn create_srv_uses_rdata_format() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/v3/zones/example.com./rrsets/SRV/_sip._tcp.example.com.",
            )
            .match_body(mockito::Matcher::Json(json!({
                "ttl": 300,
                "rdata": ["10 20 5060 sip.example.com."],
            })))
            .with_status(201)
            .with_body("{}")
            .create();

        let provider = setup(server.url().as_str());
        let result = provider
            .create(
                "_sip._tcp.example.com",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "sip.example.com".into(),
                }),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "{result:?}");
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires UltraDNS account credentials and a managed zone"]
    async fn integration_test() {
        let username = ""; // <-- UltraDNS username
        let password = ""; // <-- UltraDNS password
        let zone = ""; // <-- zone (e.g. "example.com")
        assert!(!username.is_empty() && !password.is_empty() && !zone.is_empty());
        let provider = UltraDnsProvider::new(
            username,
            password,
            None,
            Some(Duration::from_secs(30)),
        )
        .expect("provider");
        let owner = format!("test.{zone}");
        provider
            .create(
                owner.as_str(),
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                zone,
            )
            .await
            .expect("create");
        provider
            .delete(owner.as_str(), zone, DnsRecordType::A)
            .await
            .expect("delete");
    }
}
