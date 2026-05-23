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
        DnsRecord, DnsRecordType, DnsUpdater, Error, SRVRecord,
        providers::infomaniak::InfomaniakProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> InfomaniakProvider {
        InfomaniakProvider::new("test-token", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let domain_lookup = server
            .mock("GET", "/1/product")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("service_name".into(), "domain".into()),
                Matcher::UrlEncoded("customer_name".into(), "example.com".into()),
            ]))
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#,
            )
            .create();

        let create = server
            .mock("POST", "/1/domain/42/dns/record")
            .match_header("authorization", "Bearer test-token")
            .match_body(Matcher::Json(json!({
                "source": "test",
                "target": "1.2.3.4",
                "type": "A",
                "ttl": 300
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":"success","data":"rec-1"}"#)
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
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;
        let domain_lookup = server
            .mock("GET", "/1/product")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#,
            )
            .create();

        let list = server
            .mock("GET", "/1/domain/42/dns/record")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"result":"success","data":[{"id":"rec-9","source":"test","type":"TXT","target":"\"abc\""}]}"#,
            )
            .create();

        let delete = server
            .mock("DELETE", "/1/domain/42/dns/record/rec-9")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"result":"success"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;
        assert!(result.is_ok(), "delete returned: {result:?}");
        domain_lookup.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_response_maps_to_error_api() {
        let mut server = mockito::Server::new_async().await;
        let _domain_lookup = server
            .mock("GET", "/1/product")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"result":"error","error":{"code":"unauthorized","description":"bad token"}}"#,
            )
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
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_dkim_txt_includes_dkim_type_rsa() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/1/product")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#)
            .create();

        let create = server
            .mock("POST", "/1/domain/42/dns/record")
            .match_body(Matcher::Json(json!({
                "source": "selector._domainkey",
                "target": "\"v=DKIM1;k=rsa;p=AAAA\"",
                "type": "TXT",
                "ttl": 300,
                "dkim_type": "rsa"
            })))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"rec-d"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "selector._domainkey.example.com",
                DnsRecord::TXT("v=DKIM1;k=rsa;p=AAAA".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_dkim_retries_with_ed25519_when_rsa_rejected() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/1/product")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#)
            .create();

        let rsa_attempt = server
            .mock("POST", "/1/domain/42/dns/record")
            .match_body(Matcher::PartialJson(
                json!({"dkim_type": "rsa"}),
            ))
            .with_status(400)
            .with_body(
                r#"{"result":"error","error":{"code":"choose_dkim_type","description":"Please choose DKIM Type"}}"#,
            )
            .create();

        let ed25519_attempt = server
            .mock("POST", "/1/domain/42/dns/record")
            .match_body(Matcher::PartialJson(
                json!({"dkim_type": "ed25519"}),
            ))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"rec-d"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "selector._domainkey.example.com",
                DnsRecord::TXT("v=DKIM1;k=ed25519;p=AAAA".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        rsa_attempt.assert();
        ed25519_attempt.assert();
    }

    #[tokio::test]
    async fn test_non_dkim_txt_omits_dkim_type() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/1/product")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#)
            .create();

        let create = server
            .mock("POST", "/1/domain/42/dns/record")
            .match_body(Matcher::Json(json!({
                "source": "_dmarc",
                "target": "\"v=DMARC1; p=none\"",
                "type": "TXT",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"rec-x"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_dmarc.example.com",
                DnsRecord::TXT("v=DMARC1; p=none".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    async fn test_spf_singleton_falls_back_to_replace_existing() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/1/product")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#)
            .create();

        let initial_post = server
            .mock("POST", "/1/domain/42/dns/record")
            .with_status(400)
            .with_body(
                r#"{"result":"error","error":{"code":"you_can_only_add_one_spf_save_for_each_dns_zone","description":"singleton"}}"#,
            )
            .create();

        let list = server
            .mock("GET", "/1/domain/42/dns/record")
            .with_status(200)
            .with_body(
                r#"{"result":"success","data":[
                    {"id":"rec-spf","source":"","type":"TXT","target":"\"v=spf1 -all\""},
                    {"id":"rec-other","source":"","type":"TXT","target":"\"unrelated\""}
                ]}"#,
            )
            .create();

        let put = server
            .mock("PUT", "/1/domain/42/dns/record/rec-spf")
            .match_body(Matcher::Json(json!({
                "source": "",
                "target": "\"v=spf1 include:_spf.example.net ~all\"",
                "type": "TXT",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"rec-spf"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "example.com",
                DnsRecord::TXT("v=spf1 include:_spf.example.net ~all".to_string()),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        initial_post.assert();
        list.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_srv_target_gets_trailing_dot() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/1/product")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"result":"success","data":[{"id":42,"customer_name":"example.com"}]}"#)
            .create();

        let create = server
            .mock("POST", "/1/domain/42/dns/record")
            .match_body(Matcher::Json(json!({
                "source": "_imaps._tcp",
                "target": "10 5 993 mail.example.com.",
                "type": "SRV",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(r#"{"result":"success","data":"rec-s"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_imaps._tcp.example.com",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".to_string(),
                }),
                300,
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "create returned: {result:?}");
        create.assert();
    }

    #[tokio::test]
    #[ignore = "Requires INFOMANIAK_ACCESS_TOKEN, INFOMANIAK_ORIGIN, INFOMANIAK_FQDN env vars"]
    async fn integration_test() {
        let token = std::env::var("INFOMANIAK_ACCESS_TOKEN").unwrap_or_default();
        let origin = std::env::var("INFOMANIAK_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("INFOMANIAK_FQDN").unwrap_or_default();
        assert!(!token.is_empty(), "Set INFOMANIAK_ACCESS_TOKEN");
        assert!(!origin.is_empty(), "Set INFOMANIAK_ORIGIN");
        assert!(!fqdn.is_empty(), "Set INFOMANIAK_FQDN");

        let updater = DnsUpdater::new_infomaniak(token, Some(Duration::from_secs(30))).unwrap();
        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
