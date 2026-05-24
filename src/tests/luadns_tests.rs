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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, providers::luadns::LuaDnsProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const BASIC: &str = "Basic dXNlckBleGFtcGxlLmNvbTpzZWNyZXRfdG9rZW4=";

    fn setup_provider(endpoint: &str) -> LuaDnsProvider {
        LuaDnsProvider::new(
            "user@example.com",
            "secret_token",
            Some(Duration::from_secs(5)),
        )
        .with_endpoint(endpoint)
    }

    fn mock_zone_lookup(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/v1/zones")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "500".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .match_header("authorization", BASIC)
            .with_status(200)
            .with_body(r#"[{"id":1,"name":"example.com"},{"id":2,"name":"example.net"}]"#)
            .create()
    }

    fn mock_list_records(server: &mut ServerGuard, body: &str) -> Mock {
        server
            .mock("GET", "/v1/zones/1/records")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("limit".into(), "500".into()),
                Matcher::UrlEncoded("page".into(), "1".into()),
            ]))
            .match_header("authorization", BASIC)
            .with_status(200)
            .with_body(body)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_matching_type() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":10,"name":"www.example.com.","type":"A","content":"1.2.3.4","ttl":300,"zone_id":1},
                {"id":11,"name":"www.example.com.","type":"A","content":"5.6.7.8","ttl":300,"zone_id":1},
                {"id":12,"name":"www.example.com.","type":"AAAA","content":"::1","ttl":300,"zone_id":1},
                {"id":13,"name":"other.example.com.","type":"A","content":"9.9.9.9","ttl":300,"zone_id":1}
            ]"#,
        );

        let del10 = server
            .mock("DELETE", "/v1/zones/1/records/10")
            .with_status(200)
            .with_body("{}")
            .create();
        let del11 = server
            .mock("DELETE", "/v1/zones/1/records/11")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        del10.assert();
        del11.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_diffs_add_and_remove() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":21,"name":"mx.example.com.","type":"MX","content":"10 mail1.example.com.","ttl":300,"zone_id":1},
                {"id":22,"name":"mx.example.com.","type":"MX","content":"20 mail2.example.com.","ttl":300,"zone_id":1},
                {"id":23,"name":"mx.example.com.","type":"TXT","content":"\"keep\"","ttl":300,"zone_id":1}
            ]"#,
        );

        let del22 = server
            .mock("DELETE", "/v1/zones/1/records/22")
            .with_status(200)
            .with_body("{}")
            .create();
        let create_30 = server
            .mock("POST", "/v1/zones/1/records")
            .match_body(Matcher::Json(json!({
                "name": "mx.example.com.",
                "type": "MX",
                "content": "30 mail3.example.com.",
                "ttl": 600,
            })))
            .with_status(200)
            .with_body(
                r#"{"id":33,"name":"mx.example.com.","type":"MX","content":"30 mail3.example.com.","ttl":600,"zone_id":1}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "mx.example.com",
                DnsRecordType::MX,
                600,
                vec![
                    DnsRecord::MX(MXRecord {
                        priority: 10,
                        exchange: "mail1.example.com".to_string(),
                    }),
                    DnsRecord::MX(MXRecord {
                        priority: 30,
                        exchange: "mail3.example.com".to_string(),
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
        del22.assert();
        create_30.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_idempotent_no_changes() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":40,"name":"www.example.com.","type":"A","content":"1.1.1.1","ttl":300,"zone_id":1}
            ]"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset failed: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":51,"name":"www.example.com.","type":"A","content":"1.1.1.1","ttl":300,"zone_id":1}
            ]"#,
        );

        let create_new = server
            .mock("POST", "/v1/zones/1/records")
            .match_body(Matcher::Json(json!({
                "name": "www.example.com.",
                "type": "A",
                "content": "2.2.2.2",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(
                r#"{"id":52,"name":"www.example.com.","type":"A","content":"2.2.2.2","ttl":300,"zone_id":1}"#,
            )
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset failed: {result:?}");
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset empty failed: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_only_targeted() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":60,"name":"www.example.com.","type":"A","content":"1.1.1.1","ttl":300,"zone_id":1},
                {"id":61,"name":"www.example.com.","type":"A","content":"2.2.2.2","ttl":300,"zone_id":1}
            ]"#,
        );

        let del60 = server
            .mock("DELETE", "/v1/zones/1/records/60")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset failed: {result:?}");
        del60.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset empty failed: {result:?}");
    }

    #[tokio::test]
    async fn test_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref m)) if m.contains("RRSet record type mismatch"))
        );
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_type() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":70,"name":"www.example.com.","type":"A","content":"1.1.1.1","ttl":300,"zone_id":1},
                {"id":71,"name":"www.example.com.","type":"A","content":"2.2.2.2","ttl":300,"zone_id":1},
                {"id":72,"name":"www.example.com.","type":"TXT","content":"\"ignore\"","ttl":300,"zone_id":1},
                {"id":73,"name":"other.example.com.","type":"A","content":"9.9.9.9","ttl":300,"zone_id":1}
            ]"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        let mut got: Vec<String> = result
            .into_iter()
            .map(|r| match r {
                DnsRecord::A(a) => a.to_string(),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        got.sort();
        assert_eq!(got, vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()]);
    }

    #[tokio::test]
    async fn test_list_rrset_txt_unquotes() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(
            &mut server,
            r#"[
                {"id":80,"name":"_acme.example.com.","type":"TXT","content":"\"hello world\"","ttl":60,"zone_id":1}
            ]"#,
        );

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("_acme.example.com", DnsRecordType::TXT, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result, vec![DnsRecord::TXT("hello world".to_string())]);
    }

    #[tokio::test]
    async fn test_zone_match_case_insensitive() {
        let mut server = mockito::Server::new_async().await;
        let _zones = mock_zone_lookup(&mut server);
        let _list = mock_list_records(&mut server, "[]");

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .list_rrset("www.EXAMPLE.com", DnsRecordType::A, "Example.COM")
            .await;
        assert!(result.is_ok(), "list_rrset failed: {result:?}");
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_luadns("user", "token", Some(Duration::from_secs(30)));
        assert!(matches!(updater, Ok(DnsUpdater::LuaDns(..))));
    }
}
