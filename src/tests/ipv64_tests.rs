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
        DnsRecord, DnsRecordType, DnsUpdater, Error, providers::ipv64::Ipv64Provider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> Ipv64Provider {
        Ipv64Provider::new("test_key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_txt_record_success() {
        let mut server = mockito::Server::new_async().await;
        let body = "add_record=example.com&praefix=_acme-challenge&type=TXT&content=challenge".to_string();
        let mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer test_key")
            .match_body(Matcher::Exact(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"200","info":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("challenge".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        mock.assert();
    }

    #[tokio::test]
    async fn test_delete_sends_del_record() {
        let mut server = mockito::Server::new_async().await;
        let body = "del_record=example.com&praefix=_acme-challenge&type=TXT&content=".to_string();
        let mock = server
            .mock("DELETE", "/")
            .match_header("authorization", "Bearer test_key")
            .match_body(Matcher::Exact(body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"200","info":"ok"}"#)
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
        mock.assert();
    }

    #[tokio::test]
    async fn test_update_sends_delete_then_add() {
        let mut server = mockito::Server::new_async().await;
        let del = server
            .mock("DELETE", "/")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"200","info":"ok"}"#)
            .create();
        let add = server
            .mock("POST", "/")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"200","info":"ok"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .update(
                "_acme-challenge.example.com",
                DnsRecord::TXT("new".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "update returned: {result:?}");
        del.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(401)
            .with_body(r#"{"status":"401","info":"unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::TXT("x".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        mock.assert();
    }

    #[tokio::test]
    async fn test_non_txt_record_rejected() {
        let provider = Ipv64Provider::new("test_key", Some(Duration::from_secs(1))).unwrap();
        let result = provider
            .create(
                "_acme-challenge.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(_))),
            "expected Error::Api, got {result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "Requires IPV64_API_KEY, IPV64_ORIGIN, IPV64_FQDN env vars"]
    async fn integration_test() {
        let key = std::env::var("IPV64_API_KEY").unwrap_or_default();
        let origin = std::env::var("IPV64_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("IPV64_FQDN").unwrap_or_default();
        assert!(!key.is_empty(), "Set IPV64_API_KEY");
        assert!(!origin.is_empty(), "Set IPV64_ORIGIN");
        assert!(!fqdn.is_empty(), "Set IPV64_FQDN");

        let updater = DnsUpdater::new_ipv64(key, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&fqdn, DnsRecord::TXT("test".into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");
        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::TXT).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
