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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, KeyValue, MXRecord, SRVRecord,
        TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    const API_KEY: &str = "test_api_key";
    const OWNER: &str = "www.example.com.";
    const ORIGIN: &str = "example.com.";
    const DEFAULT_SERVER: &str = "localhost";

    fn updater(endpoint: &str, server_name: Option<&str>) -> DnsUpdater {
        DnsUpdater::new_pdns(
            API_KEY,
            Some(endpoint),
            server_name,
            Some(Duration::from_secs(1)),
        )
        .unwrap()
    }

    fn zone_path(server_name: &str) -> String {
        format!("/api/v1/servers/{server_name}/zones/{ORIGIN}")
    }

    fn mock_list(
        server: &mut ServerGuard,
        server_name: &str,
        record_type: &str,
        body: Value,
    ) -> Mock {
        mock_filtered_list(server, server_name, record_type, false, body)
    }

    fn mock_filtered_list(
        server: &mut ServerGuard,
        server_name: &str,
        record_type: &str,
        include_disabled: bool,
        body: Value,
    ) -> Mock {
        server
            .mock("GET", zone_path(server_name).as_str())
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrset_name".into(), OWNER.into()),
                Matcher::UrlEncoded("rrset_type".into(), record_type.into()),
                Matcher::UrlEncoded("include_disabled".into(), include_disabled.to_string()),
            ]))
            .match_header("x-api-key", API_KEY)
            .match_header("accept", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create()
    }

    fn mock_preservation_read(server: &mut ServerGuard, server_name: &str, body: Value) -> Mock {
        server
            .mock("GET", zone_path(server_name).as_str())
            .match_query(Matcher::Missing)
            .match_header("x-api-key", API_KEY)
            .match_header("accept", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create()
    }

    fn mock_patch(server: &mut ServerGuard, server_name: &str, body: Value) -> Mock {
        server
            .mock("PATCH", zone_path(server_name).as_str())
            .match_header("x-api-key", API_KEY)
            .match_header("accept", "application/json")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(body))
            .with_status(204)
            .create()
    }

    fn zone_with_rrset(record_type: &str, ttl: u32, records: Value) -> Value {
        json!({
            "rrsets": [{
                "name": OWNER,
                "type": record_type,
                "ttl": ttl,
                "records": records
            }]
        })
    }

    fn replace_body(record_type: &str, ttl: u32, records: Value) -> Value {
        json!({
            "rrsets": [{
                "name": OWNER,
                "type": record_type,
                "changetype": "REPLACE",
                "ttl": ttl,
                "records": records
            }]
        })
    }

    fn delete_body(record_type: &str) -> Value {
        json!({
            "rrsets": [{
                "name": OWNER,
                "type": record_type,
                "changetype": "DELETE"
            }]
        })
    }

    #[test]
    fn constructor_builds_pdns_updater_with_defaults() {
        let updater = DnsUpdater::new_pdns(
            API_KEY,
            None::<&str>,
            None::<&str>,
            Some(Duration::from_secs(30)),
        );

        assert!(matches!(updater, Ok(DnsUpdater::Pdns(..))));
    }

    #[tokio::test]
    async fn endpoint_is_normalized_and_default_server_is_used() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_list(&mut server, DEFAULT_SERVER, "A", json!({"rrsets": []}));
        let endpoint = format!("{}/api/v1///", server.url());

        let result = updater(&endpoint, None)
            .list_rrset(OWNER, DnsRecordType::A, ORIGIN)
            .await;

        assert_eq!(result.unwrap(), Vec::<DnsRecord>::new());
        get.assert();
    }

    #[tokio::test]
    async fn zone_and_server_path_segments_are_encoded() {
        let mut server = mockito::Server::new_async().await;
        let patch = server
            .mock(
                "PATCH",
                "/api/v1/servers/primary%2Fone/zones/example=5Ftest.com.",
            )
            .match_header("x-api-key", API_KEY)
            .match_body(Matcher::Json(replace_body(
                "A",
                300,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            )))
            .with_status(204)
            .create();
        let updater = updater(&server.url(), Some("primary/one"));

        let result = updater
            .set_rrset(
                OWNER,
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example_test.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        patch.assert();

        let root_patch = server
            .mock("PATCH", "/api/v1/servers/primary%2Fone/zones/=2E")
            .match_body(Matcher::Json(json!({
                "rrsets": [{
                    "name": ".",
                    "type": "A",
                    "changetype": "REPLACE",
                    "ttl": 300,
                    "records": [{"content": "192.0.2.2", "disabled": false}]
                }]
            })))
            .with_status(204)
            .create();
        let result = updater
            .set_rrset(
                ".",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("192.0.2.2".parse().unwrap())],
                ".",
            )
            .await;

        assert!(result.is_ok(), "root set_rrset returned {result:?}");
        root_patch.assert();
    }

    #[tokio::test]
    async fn set_rrset_sends_exact_replace_to_custom_server() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(
            &mut server,
            "primary",
            replace_body(
                "A",
                300,
                json!([
                    {"content": "192.0.2.1", "disabled": false},
                    {"content": "192.0.2.2", "disabled": false}
                ]),
            ),
        );
        let endpoint = format!("{}/", server.url());
        let updater = updater(&endpoint, Some("primary"));

        let result = updater
            .set_rrset(
                OWNER,
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("192.0.2.1".parse().unwrap()),
                    DnsRecord::A("192.0.2.2".parse().unwrap()),
                ],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_sends_exact_delete() {
        let mut server = mockito::Server::new_async().await;
        let patch = mock_patch(&mut server, DEFAULT_SERVER, delete_body("AAAA"));
        let updater = updater(&server.url(), None);

        let result = updater
            .set_rrset(OWNER, DnsRecordType::AAAA, 86400, vec![], ORIGIN)
            .await;

        assert!(result.is_ok(), "set_rrset returned {result:?}");
        patch.assert();
    }

    #[tokio::test]
    async fn set_rrset_renders_powerdns_record_formats() {
        let mut server = mockito::Server::new_async().await;
        let updater = updater(&server.url(), None);
        let cases = vec![
            (
                DnsRecordType::CNAME,
                DnsRecord::CNAME("alias.example.com".into()),
                "alias.example.com.",
            ),
            (
                DnsRecordType::NS,
                DnsRecord::NS("ns1.example.com".into()),
                "ns1.example.com.",
            ),
            (
                DnsRecordType::MX,
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".into(),
                }),
                "10 mail.example.com.",
            ),
            (
                DnsRecordType::TXT,
                DnsRecord::TXT("hello \"PowerDNS\"".into()),
                r#""hello \"PowerDNS\"""#,
            ),
            (
                DnsRecordType::SRV,
                DnsRecord::SRV(SRVRecord {
                    priority: 1,
                    weight: 2,
                    port: 443,
                    target: "service.example.com".into(),
                }),
                "1 2 443 service.example.com.",
            ),
            (
                DnsRecordType::TLSA,
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xde, 0xad, 0xbe, 0xef],
                }),
                "3 1 1 deadbeef",
            ),
            (
                DnsRecordType::CAA,
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: true,
                    name: Some("letsencrypt.org".into()),
                    options: vec![KeyValue {
                        key: "validationmethods".into(),
                        value: "dns-01".into(),
                    }],
                }),
                r#"128 issue "letsencrypt.org; validationmethods=dns-01""#,
            ),
        ];

        for (record_type, record, content) in cases {
            let patch = mock_patch(
                &mut server,
                DEFAULT_SERVER,
                replace_body(
                    record_type.as_str(),
                    600,
                    json!([{"content": content, "disabled": false}]),
                ),
            );
            let result = updater
                .set_rrset(OWNER, record_type, 600, vec![record], ORIGIN)
                .await;
            assert!(
                result.is_ok(),
                "{} set_rrset returned {result:?}",
                record_type.as_str()
            );
            patch.assert();
        }
    }

    #[tokio::test]
    async fn add_reads_full_zone_and_preserves_ttl_and_disabled_records() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "A",
                900,
                json!([
                    {"content": "192.0.2.1", "disabled": false},
                    {"content": "192.0.2.2", "disabled": true},
                    {"content": "192.0.2.9", "disabled": true}
                ]),
            ),
        );
        let patch = mock_patch(
            &mut server,
            DEFAULT_SERVER,
            replace_body(
                "A",
                900,
                json!([
                    {"content": "192.0.2.1", "disabled": false},
                    {"content": "192.0.2.2", "disabled": false},
                    {"content": "192.0.2.9", "disabled": true},
                    {"content": "192.0.2.3", "disabled": false}
                ]),
            ),
        );
        let updater = updater(&server.url(), None);

        let result = updater
            .add_to_rrset(
                OWNER,
                DnsRecordType::A,
                60,
                vec![
                    DnsRecord::A("192.0.2.1".parse().unwrap()),
                    DnsRecord::A("192.0.2.2".parse().unwrap()),
                    DnsRecord::A("192.0.2.3".parse().unwrap()),
                ],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        get.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn remove_reads_full_zone_and_preserves_ttl_and_disabled_records() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "A",
                1200,
                json!([
                    {"content": "192.0.2.1", "disabled": false},
                    {"content": "192.0.2.2", "disabled": false},
                    {"content": "192.0.2.1", "disabled": true}
                ]),
            ),
        );
        let patch = mock_patch(
            &mut server,
            DEFAULT_SERVER,
            replace_body(
                "A",
                1200,
                json!([
                    {"content": "192.0.2.2", "disabled": false},
                    {"content": "192.0.2.1", "disabled": true}
                ]),
            ),
        );
        let updater = updater(&server.url(), None);

        let result = updater
            .remove_from_rrset(
                OWNER,
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        get.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn add_falls_back_to_filtered_lookup_when_full_zone_rrset_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let full_zone = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            json!({
                "rrsets": [{
                    "name": OWNER,
                    "type": "A",
                    "ttl": 0,
                    "records": [],
                    "comments": [{"content": "managed externally"}]
                }]
            }),
        );
        let filtered = mock_filtered_list(
            &mut server,
            DEFAULT_SERVER,
            "A",
            true,
            zone_with_rrset(
                "A",
                900,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            ),
        );
        let patch = mock_patch(
            &mut server,
            DEFAULT_SERVER,
            replace_body(
                "A",
                900,
                json!([
                    {"content": "192.0.2.1", "disabled": false},
                    {"content": "192.0.2.2", "disabled": false}
                ]),
            ),
        );
        let updater = updater(&server.url(), None);

        let result = updater
            .add_to_rrset(
                OWNER,
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("192.0.2.2".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        full_zone.assert();
        filtered.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn add_uses_requested_ttl_for_comment_only_rrset() {
        let mut server = mockito::Server::new_async().await;
        let comment_only = json!({
            "rrsets": [{
                "name": OWNER,
                "type": "A",
                "ttl": 0,
                "records": [],
                "comments": [{"content": "managed externally"}]
            }]
        });
        let full_zone = mock_preservation_read(&mut server, DEFAULT_SERVER, comment_only.clone());
        let filtered = mock_filtered_list(&mut server, DEFAULT_SERVER, "A", true, comment_only);
        let patch = mock_patch(
            &mut server,
            DEFAULT_SERVER,
            replace_body(
                "A",
                600,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            ),
        );
        let updater = updater(&server.url(), None);

        let result = updater
            .add_to_rrset(
                OWNER,
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        full_zone.assert();
        filtered.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn add_creates_missing_rrset_with_requested_ttl() {
        let mut server = mockito::Server::new_async().await;
        let full_zone = mock_preservation_read(&mut server, DEFAULT_SERVER, json!({"rrsets": []}));
        let filtered = mock_filtered_list(
            &mut server,
            DEFAULT_SERVER,
            "A",
            true,
            json!({"rrsets": []}),
        );
        let patch = mock_patch(
            &mut server,
            DEFAULT_SERVER,
            replace_body(
                "A",
                600,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            ),
        );
        let updater = updater(&server.url(), None);

        let result = updater
            .add_to_rrset(
                OWNER,
                DnsRecordType::A,
                600,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        full_zone.assert();
        filtered.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn remove_falls_back_to_filtered_lookup_when_full_zone_has_no_rrsets() {
        let mut server = mockito::Server::new_async().await;
        let full_zone = mock_preservation_read(&mut server, DEFAULT_SERVER, json!({"rrsets": []}));
        let filtered = mock_filtered_list(
            &mut server,
            DEFAULT_SERVER,
            "A",
            true,
            zone_with_rrset(
                "A",
                900,
                json!([
                    {"content": "192.0.2.1", "disabled": false},
                    {"content": "192.0.2.2", "disabled": false}
                ]),
            ),
        );
        let patch = mock_patch(
            &mut server,
            DEFAULT_SERVER,
            replace_body(
                "A",
                900,
                json!([{"content": "192.0.2.2", "disabled": false}]),
            ),
        );
        let updater = updater(&server.url(), None);

        let result = updater
            .remove_from_rrset(
                OWNER,
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        full_zone.assert();
        filtered.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn remove_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let full_zone = mock_preservation_read(&mut server, DEFAULT_SERVER, json!({"rrsets": []}));
        let filtered = mock_filtered_list(
            &mut server,
            DEFAULT_SERVER,
            "A",
            true,
            json!({"rrsets": []}),
        );
        let no_patch = server.mock("PATCH", Matcher::Any).expect(0).create();
        let updater = updater(&server.url(), None);

        let result = updater
            .remove_from_rrset(
                OWNER,
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        full_zone.assert();
        filtered.assert();
        no_patch.assert();
    }

    #[tokio::test]
    async fn remove_last_record_deletes_rrset() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "A",
                300,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            ),
        );
        let patch = mock_patch(&mut server, DEFAULT_SERVER, delete_body("A"));
        let updater = updater(&server.url(), None);

        let result = updater
            .remove_from_rrset(
                OWNER,
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        get.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn empty_add_and_remove_are_noops() {
        let mut server = mockito::Server::new_async().await;
        let no_get = server.mock("GET", Matcher::Any).expect(0).create();
        let no_patch = server.mock("PATCH", Matcher::Any).expect(0).create();
        let updater = updater(&server.url(), None);

        let add = updater
            .add_to_rrset(OWNER, DnsRecordType::A, 300, vec![], ORIGIN)
            .await;
        let remove = updater
            .remove_from_rrset(OWNER, DnsRecordType::A, vec![], ORIGIN)
            .await;

        assert!(add.is_ok(), "empty add returned {add:?}");
        assert!(remove.is_ok(), "empty remove returned {remove:?}");
        no_get.assert();
        no_patch.assert();
    }

    #[tokio::test]
    async fn add_existing_enabled_record_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "A",
                300,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            ),
        );
        let no_patch = server.mock("PATCH", Matcher::Any).expect(0).create();
        let updater = updater(&server.url(), None);

        let result = updater
            .add_to_rrset(
                OWNER,
                DnsRecordType::A,
                60,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        get.assert();
        no_patch.assert();
    }

    #[tokio::test]
    async fn add_matches_equivalent_powerdns_record_content() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "TXT",
                300,
                json!([{"content": r#""hello" "world""#, "disabled": false}]),
            ),
        );
        let no_patch = server.mock("PATCH", Matcher::Any).expect(0).create();
        let updater = updater(&server.url(), None);

        let result = updater
            .add_to_rrset(
                OWNER,
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("helloworld".into())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        get.assert();
        no_patch.assert();
    }

    #[tokio::test]
    async fn remove_matches_equivalent_powerdns_record_content() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "TXT",
                300,
                json!([{"content": r#""hello" "world""#, "disabled": false}]),
            ),
        );
        let patch = mock_patch(&mut server, DEFAULT_SERVER, delete_body("TXT"));
        let updater = updater(&server.url(), None);

        let result = updater
            .remove_from_rrset(
                OWNER,
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("helloworld".into())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        get.assert();
        patch.assert();
    }

    #[tokio::test]
    async fn remove_absent_record_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_preservation_read(
            &mut server,
            DEFAULT_SERVER,
            zone_with_rrset(
                "A",
                300,
                json!([{"content": "192.0.2.1", "disabled": false}]),
            ),
        );
        let no_patch = server.mock("PATCH", Matcher::Any).expect(0).create();
        let updater = updater(&server.url(), None);

        let result = updater
            .remove_from_rrset(
                OWNER,
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.99".parse().unwrap())],
                ORIGIN,
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        get.assert();
        no_patch.assert();
    }

    #[tokio::test]
    async fn list_parses_all_supported_formats_and_ignores_disabled_records() {
        let mut server = mockito::Server::new_async().await;
        let updater = updater(&server.url(), None);
        let cases = vec![
            (
                DnsRecordType::A,
                json!([
                    {"content": "192.0.2.1"},
                    {"content": "192.0.2.2", "disabled": true}
                ]),
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
            ),
            (
                DnsRecordType::AAAA,
                json!([{"content": "2001:db8::1"}]),
                vec![DnsRecord::AAAA("2001:db8::1".parse().unwrap())],
            ),
            (
                DnsRecordType::CNAME,
                json!([{"content": "alias.example.com."}]),
                vec![DnsRecord::CNAME("alias.example.com".into())],
            ),
            (
                DnsRecordType::NS,
                json!([{"content": "ns1.example.com."}]),
                vec![DnsRecord::NS("ns1.example.com".into())],
            ),
            (
                DnsRecordType::MX,
                json!([{"content": "10 mail.example.com."}]),
                vec![DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".into(),
                })],
            ),
            (
                DnsRecordType::TXT,
                json!([{"content": r#""hello \"PowerDNS\"""#}]),
                vec![DnsRecord::TXT("hello \"PowerDNS\"".into())],
            ),
            (
                DnsRecordType::SRV,
                json!([{"content": "1 2 443 service.example.com."}]),
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 1,
                    weight: 2,
                    port: 443,
                    target: "service.example.com".into(),
                })],
            ),
            (
                DnsRecordType::TLSA,
                json!([{"content": "3 1 1 deadbeef"}]),
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xde, 0xad, 0xbe, 0xef],
                })],
            ),
            (
                DnsRecordType::CAA,
                json!([{"content": r#"128 ISSUE "letsencrypt.org; validationmethods=dns-01""#}]),
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: true,
                    name: Some("letsencrypt.org".into()),
                    options: vec![KeyValue {
                        key: "validationmethods".into(),
                        value: "dns-01".into(),
                    }],
                })],
            ),
        ];

        for (record_type, records, expected) in cases {
            let get = mock_list(
                &mut server,
                DEFAULT_SERVER,
                record_type.as_str(),
                zone_with_rrset(record_type.as_str(), 300, records),
            );
            let result = updater.list_rrset(OWNER, record_type, ORIGIN).await;
            assert_eq!(
                result.unwrap(),
                expected,
                "failed to parse {} records",
                record_type.as_str()
            );
            get.assert();
        }
    }

    #[tokio::test]
    async fn list_returns_empty_when_filtered_rrset_is_missing() {
        let mut server = mockito::Server::new_async().await;
        let get = mock_list(
            &mut server,
            DEFAULT_SERVER,
            "A",
            zone_with_rrset(
                "AAAA",
                300,
                json!([{"content": "2001:db8::1", "disabled": false}]),
            ),
        );

        let result = updater(&server.url(), None)
            .list_rrset(OWNER, DnsRecordType::A, ORIGIN)
            .await;

        assert_eq!(result.unwrap(), Vec::<DnsRecord>::new());
        get.assert();
    }

    #[tokio::test]
    async fn type_mismatch_fails_before_request() {
        let mut server = mockito::Server::new_async().await;
        let no_patch = server.mock("PATCH", Matcher::Any).expect(0).create();

        let result = updater(&server.url(), None)
            .set_rrset(
                OWNER,
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not an address".into())],
                ORIGIN,
            )
            .await;

        assert!(
            matches!(result, Err(Error::Api(ref message)) if message.contains("RRSet record type mismatch")),
            "expected type mismatch, got {result:?}"
        );
        no_patch.assert();
    }

    #[tokio::test]
    async fn unauthorized_response_maps_to_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", zone_path(DEFAULT_SERVER).as_str())
            .match_query(Matcher::Any)
            .match_header("x-api-key", API_KEY)
            .with_status(401)
            .with_body(r#"{"error":"Unauthorized"}"#)
            .create();

        let result = updater(&server.url(), None)
            .list_rrset(OWNER, DnsRecordType::A, ORIGIN)
            .await;

        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    #[ignore = "Requires PDNS_API_KEY and PDNS_ORIGIN"]
    async fn integration_test() {
        let api_key = std::env::var("PDNS_API_KEY").unwrap_or_default();
        let origin = std::env::var("PDNS_ORIGIN").unwrap_or_default();
        let endpoint = std::env::var("PDNS_ENDPOINT").ok();
        let server_name = std::env::var("PDNS_SERVER").ok();
        assert!(!api_key.is_empty(), "Set PDNS_API_KEY");
        assert!(!origin.is_empty(), "Set PDNS_ORIGIN");

        let updater = DnsUpdater::new_pdns(
            api_key,
            endpoint.as_deref(),
            server_name.as_deref(),
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        let run_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let owner = format!("dns-update-{run_id}.{origin}");
        let first = DnsRecord::TXT("powerdns-integration-one".into());
        let second = DnsRecord::TXT("powerdns-integration-two".into());

        updater
            .set_rrset(&owner, DnsRecordType::TXT, 60, vec![first.clone()], &origin)
            .await
            .expect("set_rrset");
        updater
            .add_to_rrset(
                &owner,
                DnsRecordType::TXT,
                60,
                vec![second.clone()],
                &origin,
            )
            .await
            .expect("add_to_rrset");
        let mut listed = updater
            .list_rrset(&owner, DnsRecordType::TXT, &origin)
            .await
            .expect("list_rrset");
        listed.sort_by_key(ToString::to_string);
        let mut expected = vec![first.clone(), second];
        expected.sort_by_key(ToString::to_string);
        assert_eq!(listed, expected);
        updater
            .remove_from_rrset(&owner, DnsRecordType::TXT, vec![first], &origin)
            .await
            .expect("remove_from_rrset");
        updater
            .set_rrset(&owner, DnsRecordType::TXT, 60, vec![], &origin)
            .await
            .expect("cleanup");
    }
}
