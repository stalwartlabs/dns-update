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
        CAARecord, DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, SRVRecord, TLSARecord,
        TlsaCertUsage, TlsaMatching, TlsaSelector, providers::bunny::BunnyProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE_ID: u32 = 12345;

    fn setup_provider(endpoint: String) -> BunnyProvider {
        BunnyProvider::new("bunny-mock-api-key", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn mock_zone_lookup(
        server: &mut ServerGuard,
        zone_name: &str,
        records: serde_json::Value,
    ) -> Mock {
        let body = json!({
            "Items": [{
                "Id": ZONE_ID,
                "Domain": zone_name,
                "Records": records,
            }],
            "CurrentPage": 1,
            "TotalItems": 1,
            "HasMoreItems": false,
        });
        server
            .mock("GET", "/dnszone")
            .match_query(Matcher::UrlEncoded("search".into(), zone_name.into()))
            .match_header("accesskey", "bunny-mock-api-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com", json!([]));

        let create = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "www",
                "Ttl": 300,
                "Type": 0,
                "Value": "1.2.3.4",
            })))
            .with_status(201)
            .with_body(r#"{"Id":1,"Name":"www","Type":0,"Value":"1.2.3.4","Ttl":300}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 1, "Name": "www", "Type": 0, "Value": "1.2.3.4", "Ttl": 300},
            ]),
        );
        let _no_put = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dnszone/{ZONE_ID}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_new() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 11, "Name": "host", "Type": 0, "Value": "1.1.1.1", "Ttl": 300},
                {"Id": 22, "Name": "host", "Type": 0, "Value": "9.9.9.9", "Ttl": 300},
            ]),
        );

        let delete_stale = server
            .mock("DELETE", format!("/dnszone/{ZONE_ID}/records/22").as_str())
            .with_status(204)
            .create();

        let create_new = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "host",
                "Ttl": 300,
                "Type": 0,
                "Value": "8.8.8.8",
            })))
            .with_status(201)
            .with_body(r#"{"Id":33,"Name":"host","Type":0,"Value":"8.8.8.8","Ttl":300}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("8.8.8.8".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all_of_type() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 41, "Name": "gone", "Type": 0, "Value": "1.2.3.4", "Ttl": 300},
                {"Id": 42, "Name": "gone", "Type": 0, "Value": "5.6.7.8", "Ttl": 300},
                {"Id": 43, "Name": "gone", "Type": 3, "Value": "keep-me", "Ttl": 300},
            ]),
        );

        let del_a1 = server
            .mock("DELETE", format!("/dnszone/{ZONE_ID}/records/41").as_str())
            .with_status(204)
            .create();
        let del_a2 = server
            .mock("DELETE", format!("/dnszone/{ZONE_ID}/records/42").as_str())
            .with_status(204)
            .create();
        let _no_delete_txt = server
            .mock("DELETE", format!("/dnszone/{ZONE_ID}/records/43").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "gone.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        del_a1.assert();
        del_a2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 50, "Name": "shared", "Type": 3, "Value": "do-not-touch", "Ttl": 300},
            ]),
        );

        let create = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "shared",
                "Ttl": 300,
                "Type": 0,
                "Value": "1.1.1.1",
            })))
            .with_status(201)
            .with_body(r#"{"Id":51,"Name":"shared","Type":0,"Value":"1.1.1.1","Ttl":300}"#)
            .create();

        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dnszone/{ZONE_ID}/records/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone_lookup(&mut server, "example.com", json!([]));

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com", json!([]));

        let put_ee = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "_25._tcp.mail",
                "Ttl": 300,
                "Type": 15,
                "Value": "3 1 1 aa",
            })))
            .with_status(201)
            .with_body(r#"{"Id":71,"Name":"_25._tcp.mail","Type":15,"Value":"3 1 1 aa","Ttl":300}"#)
            .create();
        let put_ta = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "_25._tcp.mail",
                "Ttl": 300,
                "Type": 15,
                "Value": "2 1 1 bb",
            })))
            .with_status(201)
            .with_body(r#"{"Id":72,"Name":"_25._tcp.mail","Type":15,"Value":"2 1 1 bb","Ttl":300}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneEe,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xaa],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xbb],
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        put_ee.assert();
        put_ta.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_mx_emits_priority() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com", json!([]));

        let create = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "",
                "Ttl": 3600,
                "Type": 4,
                "Value": "mail.example.com",
                "Priority": 10,
            })))
            .with_status(201)
            .with_body(
                r#"{"Id":81,"Name":"","Type":4,"Value":"mail.example.com","Priority":10,"Ttl":3600}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![DnsRecord::MX(MXRecord {
                    exchange: "mail.example.com".to_string(),
                    priority: 10,
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_emits_all_fields() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com", json!([]));

        let create = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "_imaps._tcp",
                "Ttl": 3600,
                "Type": 8,
                "Value": "mail.example.com",
                "Priority": 10,
                "Weight": 5,
                "Port": 993,
            })))
            .with_status(201)
            .with_body(
                r#"{"Id":91,"Name":"_imaps._tcp","Type":8,"Value":"mail.example.com","Priority":10,"Weight":5,"Port":993,"Ttl":3600}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_imaps._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_separate_fields() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server, "example.com", json!([]));

        let create = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "",
                "Ttl": 3600,
                "Type": 9,
                "Value": "letsencrypt.org",
                "Tag": "issue",
            })))
            .with_status(201)
            .with_body(
                r#"{"Id":101,"Name":"","Type":9,"Value":"letsencrypt.org","Flags":0,"Tag":"issue","Ttl":3600}"#,
            )
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                3600,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 110, "Name": "_acme", "Type": 3, "Value": "existing", "Ttl": 60},
            ]),
        );

        let create = server
            .mock("PUT", format!("/dnszone/{ZONE_ID}/records").as_str())
            .match_body(Matcher::Json(json!({
                "Name": "_acme",
                "Ttl": 60,
                "Type": 3,
                "Value": "new-token",
            })))
            .with_status(201)
            .with_body(r#"{"Id":111,"Name":"_acme","Type":3,"Value":"new-token","Ttl":60}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("new-token".to_string()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_input_short_circuits() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_put = server.mock("PUT", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 120, "Name": "_acme", "Type": 3, "Value": "keep-me", "Ttl": 60},
                {"Id": 121, "Name": "_acme", "Type": 3, "Value": "drop-me", "Ttl": 60},
            ]),
        );

        let delete = server
            .mock("DELETE", format!("/dnszone/{ZONE_ID}/records/121").as_str())
            .with_status(204)
            .create();
        let _no_keep_delete = server
            .mock("DELETE", format!("/dnszone/{ZONE_ID}/records/120").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop-me".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        delete.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 130, "Name": "www", "Type": 0, "Value": "1.1.1.1", "Ttl": 300},
            ]),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dnszone/{ZONE_ID}/records/")),
            )
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
        zone.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_input_short_circuits() {
        let mut server = mockito::Server::new_async().await;
        let _no_call = server.mock("GET", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("www.example.com", DnsRecordType::A, vec![], "example.com")
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_list_rrset_returns_filtered_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 140, "Name": "host", "Type": 0, "Value": "1.1.1.1", "Ttl": 300},
                {"Id": 141, "Name": "host", "Type": 0, "Value": "2.2.2.2", "Ttl": 300},
                {"Id": 142, "Name": "host", "Type": 3, "Value": "ignored-txt", "Ttl": 300},
                {"Id": 143, "Name": "other", "Type": 0, "Value": "9.9.9.9", "Ttl": 300},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(result.len(), 2, "expected 2 A records, got {result:?}");
        assert!(result.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(result.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        zone.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_integer_type_field_from_response() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(
            &mut server,
            "example.com",
            json!([
                {"Id": 150, "Name": "mail", "Type": 4, "Value": "mx1.example.com", "Priority": 10, "Ttl": 3600},
            ]),
        );

        let provider = setup_provider(server.url());
        let result = provider
            .list_rrset("mail.example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(
            result,
            vec![DnsRecord::MX(MXRecord {
                exchange: "mx1.example.com".to_string(),
                priority: 10,
            })]
        );
        zone.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_zone_lookup_maps_to_error() {
        let mut server = mockito::Server::new_async().await;
        let unauth = server
            .mock("GET", "/dnszone")
            .match_query(Matcher::UrlEncoded("search".into(), "example.com".into()))
            .with_status(401)
            .with_body("{}")
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauth.assert();
    }

    #[test]
    fn provider_creation() {
        let provider = BunnyProvider::new("bunny-mock-api-key", Some(Duration::from_secs(1)));

        assert!(provider.is_ok());
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_bunny("bunny-mock-api-key", Some(Duration::from_secs(30)));

        assert!(
            matches!(updater, Ok(DnsUpdater::Bunny(..))),
            "Expected Bunny updater to provide a Bunny provider"
        );
    }
}
