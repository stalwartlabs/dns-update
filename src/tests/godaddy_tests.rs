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
        DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, providers::godaddy::GodaddyProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> GodaddyProvider {
        GodaddyProvider::new("test_key", "test_secret", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_with_full_array() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .match_header("authorization", "sso-key test_key:test_secret")
            .match_body(Matcher::Json(json!([
                {"data": "1.2.3.4", "ttl": 600},
                {"data": "5.6.7.8", "ttl": 600},
            ])))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![
                    DnsRecord::A("1.2.3.4".parse().unwrap()),
                    DnsRecord::A("5.6.7.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        put.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_the_rrset() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock(
                "DELETE",
                "/v1/domains/example.com/records/TXT/_acme-challenge",
            )
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_acme-challenge.example.com",
                DnsRecordType::TXT,
                0,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_treats_404_as_success() {
        let mut server = mockito::Server::new_async().await;
        let delete = server
            .mock("DELETE", "/v1/domains/example.com/records/A/missing")
            .with_status(404)
            .with_body(r#"{"code":"NOT_FOUND"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "missing.example.com",
                DnsRecordType::A,
                0,
                Vec::new(),
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        delete.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_mismatched_record_type() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "expected type mismatch error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_mx_includes_priority_in_each_item() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/MX/@")
            .match_body(Matcher::Json(json!([
                {"data": "mail1.example.com", "ttl": 3600, "priority": 10},
                {"data": "mail2.example.com", "ttl": 3600, "priority": 20},
            ])))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mail1.example.com".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mail2.example.com".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_a_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_merges_with_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(200)
            .with_body(r#"[{"data":"1.2.3.4","ttl":600}]"#)
            .create();
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .match_body(Matcher::Json(json!([
                {"data": "1.2.3.4", "ttl": 600},
                {"data": "5.6.7.8", "ttl": 600},
            ])))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("5.6.7.8".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(200)
            .with_body(r#"[{"data":"1.2.3.4","ttl":600}]"#)
            .create();
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_on_missing_rrset_creates_it() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(404)
            .with_body(r#"{"code":"NOT_FOUND"}"#)
            .create();
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .match_body(Matcher::Json(json!([{
                "data": "5.6.7.8",
                "ttl": 600,
            }])))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("5.6.7.8".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_a_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_then_puts() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(200)
            .with_body(r#"[{"data":"1.2.3.4","ttl":600},{"data":"5.6.7.8","ttl":600}]"#)
            .create();
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .match_body(Matcher::Json(json!([{
                "data": "5.6.7.8",
                "ttl": 600,
            }])))
            .with_status(200)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_when_filtered_empty() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(200)
            .with_body(r#"[{"data":"1.2.3.4","ttl":600}]"#)
            .create();
        let delete = server
            .mock("DELETE", "/v1/domains/example.com/records/A/www")
            .with_status(204)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_a_noop() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(200)
            .with_body(r#"[{"data":"1.2.3.4","ttl":600}]"#)
            .create();
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
        put.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_missing_rrset_is_a_noop() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .with_status(404)
            .with_body(r#"{"code":"NOT_FOUND"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_records() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/www")
            .match_header("authorization", "sso-key test_key:test_secret")
            .with_status(200)
            .with_body(r#"[{"data":"1.2.3.4","ttl":600},{"data":"5.6.7.8","ttl":600}]"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(
            result,
            vec![
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                DnsRecord::A("5.6.7.8".parse().unwrap()),
            ]
        );
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_empty_on_404() {
        let mut server = mockito::Server::new_async().await;
        let get = server
            .mock("GET", "/v1/domains/example.com/records/A/missing")
            .with_status(404)
            .with_body(r#"{"code":"NOT_FOUND"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("missing.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        assert!(result.is_empty(), "expected empty list, got {result:?}");
        get.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_decodes_mx_and_srv() {
        let mut server = mockito::Server::new_async().await;
        let mx_get = server
            .mock("GET", "/v1/domains/example.com/records/MX/@")
            .with_status(200)
            .with_body(r#"[{"data":"mail.example.com","ttl":3600,"priority":10}]"#)
            .create();
        let srv_get = server
            .mock("GET", "/v1/domains/example.com/records/SRV/_sip._tcp")
            .with_status(200)
            .with_body(
                r#"[{"data":"sip.example.com","ttl":3600,"priority":10,"weight":60,"port":5060}]"#,
            )
            .create();

        let provider = setup_provider(server.url());

        let mx = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("MX list failed");
        assert_eq!(
            mx,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 10,
            })]
        );

        let srv = provider
            .list_rrset("_sip._tcp.example.com", DnsRecordType::SRV, "example.com")
            .await
            .expect("SRV list failed");
        assert_eq!(
            srv,
            vec![DnsRecord::SRV(SRVRecord {
                priority: 10,
                weight: 60,
                port: 5060,
                target: "sip.example.com".to_string(),
            })]
        );

        mx_get.assert();
        srv_get.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_does_not_touch_other_types_at_same_name() {
        let mut server = mockito::Server::new_async().await;
        let put = server
            .mock("PUT", "/v1/domains/example.com/records/A/www")
            .match_body(Matcher::Json(json!([{"data":"1.2.3.4","ttl":600}])))
            .with_status(200)
            .with_body("[]")
            .create();
        let untouched = server
            .mock("PUT", "/v1/domains/example.com/records/AAAA/www")
            .expect(0)
            .create();
        let untouched_delete = server
            .mock("DELETE", "/v1/domains/example.com/records/AAAA/www")
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        put.assert();
        untouched.assert();
        untouched_delete.assert();
    }
}
