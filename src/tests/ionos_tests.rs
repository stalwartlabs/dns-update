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
    use crate::{DnsRecord, DnsRecordType, Error, MXRecord, providers::ionos::IonosProvider};
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE_ID: &str = "zone-1";

    fn setup_provider(endpoint: String) -> IonosProvider {
        IonosProvider::new("test_key", Some(Duration::from_secs(1))).with_endpoint(endpoint)
    }

    fn mock_zone_lookup(server: &mut ServerGuard, zone_name: &str) -> Mock {
        server
            .mock("GET", "/v1/zones")
            .match_header("x-api-key", "test_key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"[{{"id":"{ZONE_ID}","name":"{zone_name}","type":"NATIVE"}}]"#
            ))
            .create()
    }

    fn mock_list(
        server: &mut ServerGuard,
        name: &str,
        record_type: &str,
        records: serde_json::Value,
    ) -> Mock {
        server
            .mock("GET", format!("/v1/zones/{ZONE_ID}").as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("recordName".into(), name.into()),
                Matcher::UrlEncoded("recordType".into(), record_type.into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({"id": ZONE_ID, "name": "example.com", "records": records}).to_string(),
            )
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "host.example.com", "A", json!([]));

        let create = server
            .mock("POST", "/v1/zones/zone-1/records")
            .match_body(Matcher::Json(json!([
                {"name": "host.example.com", "content": "1.1.1.1", "ttl": 300, "type": "A", "prio": 0},
                {"name": "host.example.com", "content": "2.2.2.2", "ttl": 300, "type": "A", "prio": 0},
            ])))
            .with_status(201)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([{
                "id": "rec-1",
                "name": "host.example.com",
                "content": "1.1.1.1",
                "ttl": 300,
                "type": "A",
            }]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": "rec-keep", "name": "host.example.com", "content": "1.1.1.1", "ttl": 300, "type": "A"},
                {"id": "rec-stale", "name": "host.example.com", "content": "9.9.9.9", "ttl": 300, "type": "A"},
            ]),
        );

        let delete_stale = server
            .mock("DELETE", "/v1/zones/zone-1/records/rec-stale")
            .with_status(200)
            .with_body("{}")
            .create();

        let create_new = server
            .mock("POST", "/v1/zones/zone-1/records")
            .match_body(Matcher::Json(json!([
                {"name": "host.example.com", "content": "2.2.2.2", "ttl": 300, "type": "A", "prio": 0},
            ])))
            .with_status(201)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_vec_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": "rec-1", "name": "host.example.com", "content": "1.1.1.1", "ttl": 300, "type": "A"},
                {"id": "rec-2", "name": "host.example.com", "content": "2.2.2.2", "ttl": 300, "type": "A"},
            ]),
        );

        let delete_1 = server
            .mock("DELETE", "/v1/zones/zone-1/records/rec-1")
            .with_status(200)
            .with_body("{}")
            .create();

        let delete_2 = server
            .mock("DELETE", "/v1/zones/zone-1/records/rec-2")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete_1.assert();
        delete_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(&mut server, "host.example.com", "A", json!([]));

        let create = server
            .mock("POST", "/v1/zones/zone-1/records")
            .match_body(Matcher::Json(json!([
                {"name": "host.example.com", "content": "1.1.1.1", "ttl": 300, "type": "A", "prio": 0},
            ])))
            .with_status(201)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("oops".to_string())],
                "example.com",
            )
            .await;

        assert!(
            matches!(&result, Err(Error::Api(msg)) if msg.contains("mismatch")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([{
                "id": "rec-1",
                "name": "host.example.com",
                "content": "1.1.1.1",
                "ttl": 300,
                "type": "A",
            }]),
        );

        let create = server
            .mock("POST", "/v1/zones/zone-1/records")
            .match_body(Matcher::Json(json!([
                {"name": "host.example.com", "content": "2.2.2.2", "ttl": 300, "type": "A", "prio": 0},
            ])))
            .with_status(201)
            .with_body("[]")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_idempotent_when_all_present() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([{
                "id": "rec-1",
                "name": "host.example.com",
                "content": "1.1.1.1",
                "ttl": 300,
                "type": "A",
            }]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());

        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_matching() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "host.example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([
                {"id": "rec-1", "name": "host.example.com", "content": "1.1.1.1", "ttl": 300, "type": "A"},
                {"id": "rec-2", "name": "host.example.com", "content": "2.2.2.2", "ttl": 300, "type": "A"},
            ]),
        );

        let delete = server
            .mock("DELETE", "/v1/zones/zone-1/records/rec-1")
            .with_status(200)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "host.example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_skips_absent() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "host.example.com",
            "A",
            json!([{
                "id": "rec-1",
                "name": "host.example.com",
                "content": "1.1.1.1",
                "ttl": 300,
                "type": "A",
            }]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("9.9.9.9".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com");
        let list = mock_list(
            &mut server,
            "mail.example.com",
            "MX",
            json!([
                {"id": "rec-1", "name": "mail.example.com", "content": "mx1.example.com", "ttl": 3600, "type": "MX", "prio": 10},
                {"id": "rec-2", "name": "mail.example.com", "content": "mx2.example.com", "ttl": 3600, "type": "MX", "prio": 20},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::MX, "example.com")
            .await;

        assert!(result.is_ok(), "list_rrset returned: {result:?}");
        let listed = result.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&DnsRecord::MX(MXRecord {
            exchange: "mx1.example.com".to_string(),
            priority: 10,
        })));
        assert!(listed.contains(&DnsRecord::MX(MXRecord {
            exchange: "mx2.example.com".to_string(),
            priority: 20,
        })));
        zone.assert();
        list.assert();
    }
}
