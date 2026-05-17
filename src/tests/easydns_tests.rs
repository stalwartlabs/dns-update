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
        providers::easydns::EasyDnsProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn provider(endpoint: String) -> EasyDnsProvider {
        EasyDnsProvider::new("token", "key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_puts_zone_record() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/zones/records/add/example.com/TXT?format=json")
            .match_header("authorization", "Basic dG9rZW46a2V5")
            .match_body(Matcher::PartialJsonString(
                r#"{"domain":"example.com","host":"_acme","type":"TXT","rdata":"value","ttl":"300","prio":"0"}"#
                    .to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"msg":"OK","status":201,"data":{"id":"abc"}}"#)
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
        put.assert();
    }

    #[tokio::test]
    async fn test_update_resolves_id_then_posts() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/records/all/example.com?format=json")
            .with_status(200)
            .with_body(
                r#"{"data":[{"id":"42","host":"www","type":"A","rdata":"1.2.3.4","ttl":"300"}]}"#,
            )
            .create();

        let post = server
            .mock("POST", "/zones/records/example.com/42?format=json")
            .with_status(200)
            .with_body(r#"{"data":{"id":"42"}}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .update(
                "www.example.com",
                DnsRecord::A("5.6.7.8".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "update returned {result:?}");
        list.assert();
        post.assert();
    }

    #[tokio::test]
    async fn test_delete_finds_id_then_deletes() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/zones/records/all/example.com?format=json")
            .with_status(200)
            .with_body(
                r#"{"data":[{"id":"99","host":"www","type":"A","rdata":"1.2.3.4","ttl":"300"}]}"#,
            )
            .create();

        let delete = server
            .mock("DELETE", "/zones/records/example.com/99?format=json")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = provider(server.url());
        let result = provider
            .delete("www.example.com", "example.com", DnsRecordType::A)
            .await;
        assert!(result.is_ok(), "delete returned {result:?}");
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_maps_error() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("PUT", "/zones/records/add/example.com/A?format=json")
            .with_status(401)
            .with_body("Unauthorized")
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unauthorized)), "got {result:?}");
        m.assert();
    }

    #[tokio::test]
    async fn test_api_error_body_maps_to_api_error() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("PUT", "/zones/records/add/example.com/A?format=json")
            .with_status(200)
            .with_body(r#"{"error":{"code":42,"message":"nope"}}"#)
            .create();

        let provider = provider(server.url());
        let result = provider
            .create(
                "www.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
        m.assert();
    }

    #[tokio::test]
    #[ignore = "Requires EASYDNS_TOKEN, EASYDNS_KEY, EASYDNS_ORIGIN, EASYDNS_FQDN"]
    async fn integration_test() {
        let token = std::env::var("EASYDNS_TOKEN").unwrap_or_default();
        let key = std::env::var("EASYDNS_KEY").unwrap_or_default();
        let origin = std::env::var("EASYDNS_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("EASYDNS_FQDN").unwrap_or_default();
        assert!(!token.is_empty() && !key.is_empty() && !origin.is_empty() && !fqdn.is_empty());

        let updater = DnsUpdater::new_easydns(token, key, Some(Duration::from_secs(30))).unwrap();
        updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await
            .unwrap();
        updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
            .await
            .unwrap();
        updater
            .delete(&fqdn, &origin, DnsRecordType::A)
            .await
            .unwrap();
    }
}
