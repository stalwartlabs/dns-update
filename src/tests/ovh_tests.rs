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
        TlsaCertUsage, TlsaMatching, TlsaSelector,
        providers::ovh::{OvhEndpoint, OvhProvider, OvhRecordFormat},
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider() -> OvhProvider {
        OvhProvider::new(
            "test_app_key",
            "test_app_secret",
            "test_consumer_key",
            OvhEndpoint::OvhEu,
            Some(Duration::from_secs(1)),
        )
        .unwrap()
    }

    #[test]
    fn test_ovh_endpoint_parsing() {
        assert!(matches!(
            "ovh-eu".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::OvhEu
        ));
        assert!(matches!(
            "ovh-us".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::OvhUs
        ));
        assert!(matches!(
            "ovh-ca".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::OvhCa
        ));
        assert!(matches!(
            "kimsufi-eu".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::KimsufiEu
        ));
        assert!(matches!(
            "kimsufi-ca".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::KimsufiCa
        ));
        assert!(matches!(
            "soyoustart-eu".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::SoyoustartEu
        ));
        assert!(matches!(
            "soyoustart-ca".parse::<OvhEndpoint>().unwrap(),
            OvhEndpoint::SoyoustartCa
        ));

        assert!("invalid-endpoint".parse::<OvhEndpoint>().is_err());
    }

    #[test]
    fn test_ovh_provider_creation() {
        let provider = OvhProvider::new(
            "test_app_key",
            "test_app_secret",
            "test_consumer_key",
            OvhEndpoint::OvhEu,
            Some(Duration::from_secs(30)),
        );

        assert!(provider.is_ok());
    }

    #[test]
    fn test_dns_updater_ovh_creation() {
        let updater = DnsUpdater::new_ovh(
            "test_app_key",
            "test_app_secret",
            "test_consumer_key",
            OvhEndpoint::OvhEu,
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());

        match updater.unwrap() {
            DnsUpdater::Ovh(_) => (),
            _ => panic!("Expected OVH provider"),
        }
    }

    #[test]
    fn test_ovh_record_format_from_dns_record() {
        let record = DnsRecord::A("1.1.1.1".parse().unwrap());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "A");
        assert_eq!(ovh_record.target, "1.1.1.1");

        let record = DnsRecord::AAAA("2001:db8::1".parse().unwrap());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "AAAA");
        assert_eq!(ovh_record.target, "2001:db8::1");

        let record = DnsRecord::CNAME("alias.example.com".to_string());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "CNAME");
        assert_eq!(ovh_record.target, "alias.example.com.");

        let record = DnsRecord::CNAME("alias.example.com.".to_string());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "CNAME");
        assert_eq!(ovh_record.target, "alias.example.com.");

        let record = DnsRecord::MX(MXRecord {
            exchange: "mail.example.com".to_string(),
            priority: 10,
        });
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "MX");
        assert_eq!(ovh_record.target, "10 mail.example.com.");

        let record = DnsRecord::TXT("v=spf1 include:_spf.example.com ~all".to_string());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "TXT");
        assert_eq!(ovh_record.target, "v=spf1 include:_spf.example.com ~all");

        let record = DnsRecord::SRV(SRVRecord {
            target: "sip.example.com".to_string(),
            priority: 10,
            weight: 20,
            port: 443,
        });
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "SRV");
        assert_eq!(ovh_record.target, "10 20 443 sip.example.com.");

        let record = DnsRecord::NS("ns1.example.com".to_string());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "NS");
        assert_eq!(ovh_record.target, "ns1.example.com.");

        let record = DnsRecord::NS("ns1.example.com.".to_string());
        let ovh_record: OvhRecordFormat = (&record).into();
        assert_eq!(ovh_record.field_type, "NS");
        assert_eq!(ovh_record.target, "ns1.example.com.");
    }

    fn mock_zone(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("GET", "/domain/zone/example.com")
            .with_status(200)
            .with_body(r#"{"name": "example.com"}"#)
            .create()
    }

    fn mock_list(
        server: &mut mockito::ServerGuard,
        field_type: &str,
        sub_domain: &str,
        body: serde_json::Value,
    ) -> mockito::Mock {
        let path = format!(
            "/domain/zone/example.com/record?fieldType={}&subDomain={}",
            field_type, sub_domain
        );
        server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn mock_get_record(
        server: &mut mockito::ServerGuard,
        id: u64,
        body: serde_json::Value,
    ) -> mockito::Mock {
        let path = format!("/domain/zone/example.com/record/{}", id);
        server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn mock_delete_record(server: &mut mockito::ServerGuard, id: u64) -> mockito::Mock {
        let path = format!("/domain/zone/example.com/record/{}", id);
        server
            .mock("DELETE", path.as_str())
            .with_status(200)
            .with_body("")
            .create()
    }

    fn mock_refresh(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/domain/zone/example.com/refresh")
            .with_status(200)
            .with_body("")
            .create()
    }

    fn mock_post_record(
        server: &mut mockito::ServerGuard,
        body_match: serde_json::Value,
    ) -> mockito::Mock {
        server
            .mock("POST", "/domain/zone/example.com/record")
            .match_body(mockito::Matcher::Json(body_match))
            .with_status(200)
            .with_body(r#"{"id": 999999}"#)
            .create()
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "A", "www", json!([]));
        let create_a = mock_post_record(
            &mut server,
            json!({
                "fieldType": "A",
                "subDomain": "www",
                "target": "1.1.1.1",
                "ttl": 300
            }),
        );
        let refresh = mock_refresh(&mut server);

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create_a.assert();
        refresh.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "A", "www", json!([111]));
        let fetch = mock_get_record(
            &mut server,
            111,
            json!({
                "id": 111,
                "zone": "example.com",
                "subDomain": "www",
                "fieldType": "A",
                "target": "1.1.1.1",
                "ttl": 300
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        fetch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "A", "host", json!([200, 201]));
        let fetch_keep = mock_get_record(
            &mut server,
            200,
            json!({
                "id": 200,
                "zone": "example.com",
                "subDomain": "host",
                "fieldType": "A",
                "target": "1.1.1.1",
                "ttl": 300
            }),
        );
        let fetch_stale = mock_get_record(
            &mut server,
            201,
            json!({
                "id": 201,
                "zone": "example.com",
                "subDomain": "host",
                "fieldType": "A",
                "target": "9.9.9.9",
                "ttl": 300
            }),
        );
        let delete_stale = mock_delete_record(&mut server, 201);
        let create_new = mock_post_record(
            &mut server,
            json!({
                "fieldType": "A",
                "subDomain": "host",
                "target": "8.8.8.8",
                "ttl": 300
            }),
        );
        let refresh = mock_refresh(&mut server);

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
        list.assert();
        fetch_keep.assert();
        fetch_stale.assert();
        delete_stale.assert();
        create_new.assert();
        refresh.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "A", "gone", json!([300, 301]));
        let fetch_x = mock_get_record(
            &mut server,
            300,
            json!({
                "id": 300,
                "zone": "example.com",
                "subDomain": "gone",
                "fieldType": "A",
                "target": "1.2.3.4",
                "ttl": 300
            }),
        );
        let fetch_y = mock_get_record(
            &mut server,
            301,
            json!({
                "id": 301,
                "zone": "example.com",
                "subDomain": "gone",
                "fieldType": "A",
                "target": "5.6.7.8",
                "ttl": 300
            }),
        );
        let delete_x = mock_delete_record(&mut server, 300);
        let delete_y = mock_delete_record(&mut server, 301);
        let refresh = mock_refresh(&mut server);

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
        list.assert();
        fetch_x.assert();
        fetch_y.assert();
        delete_x.assert();
        delete_y.assert();
        refresh.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
        let provider = setup_provider();
        let result = provider
            .set_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_is_noop() {
        let provider = setup_provider();
        let result = provider
            .add_to_rrset(
                "x.example.com",
                DnsRecordType::A,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "TXT", "_acme", json!([400]));
        let fetch_existing = mock_get_record(
            &mut server,
            400,
            json!({
                "id": 400,
                "zone": "example.com",
                "subDomain": "_acme",
                "fieldType": "TXT",
                "target": "existing",
                "ttl": 60
            }),
        );
        let create_new = mock_post_record(
            &mut server,
            json!({
                "fieldType": "TXT",
                "subDomain": "_acme",
                "target": "new-token",
                "ttl": 60
            }),
        );
        let refresh = mock_refresh(&mut server);

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
        list.assert();
        fetch_existing.assert();
        create_new.assert();
        refresh.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_all_present_is_full_noop() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "TXT", "_acme", json!([500]));
        let fetch = mock_get_record(
            &mut server,
            500,
            json!({
                "id": 500,
                "zone": "example.com",
                "subDomain": "_acme",
                "fieldType": "TXT",
                "target": "already-here",
                "ttl": 60
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .add_to_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                60,
                vec![DnsRecord::TXT("already-here".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        fetch.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_is_noop() {
        let provider = setup_provider();
        let result = provider
            .remove_from_rrset("x.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "TXT", "_acme", json!([600, 601]));
        let fetch_keep = mock_get_record(
            &mut server,
            600,
            json!({
                "id": 600,
                "zone": "example.com",
                "subDomain": "_acme",
                "fieldType": "TXT",
                "target": "keep-me",
                "ttl": 60
            }),
        );
        let fetch_drop = mock_get_record(
            &mut server,
            601,
            json!({
                "id": 601,
                "zone": "example.com",
                "subDomain": "_acme",
                "fieldType": "TXT",
                "target": "drop-me",
                "ttl": 60
            }),
        );
        let delete = mock_delete_record(&mut server, 601);
        let refresh = mock_refresh(&mut server);

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
        list.assert();
        fetch_keep.assert();
        fetch_drop.assert();
        delete.assert();
        refresh.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_value_is_noop_no_mutation() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "TXT", "_acme", json!([700]));
        let fetch = mock_get_record(
            &mut server,
            700,
            json!({
                "id": 700,
                "zone": "example.com",
                "subDomain": "_acme",
                "fieldType": "TXT",
                "target": "present",
                "ttl": 60
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .remove_from_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("not-there".to_string())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        fetch.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_returns_parsed_records() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "MX", "", json!([800, 801]));
        let fetch_a = mock_get_record(
            &mut server,
            800,
            json!({
                "id": 800,
                "zone": "example.com",
                "subDomain": "",
                "fieldType": "MX",
                "target": "10 mail1.example.com.",
                "ttl": 3600
            }),
        );
        let fetch_b = mock_get_record(
            &mut server,
            801,
            json!({
                "id": 801,
                "zone": "example.com",
                "subDomain": "",
                "fieldType": "MX",
                "target": "20 mail2.example.com.",
                "ttl": 3600
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await;

        let records = result.expect("list_rrset returned err");
        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            priority: 10,
            exchange: "mail1.example.com.".to_string()
        })));
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            priority: 20,
            exchange: "mail2.example.com.".to_string()
        })));
        zone.assert();
        list.assert();
        fetch_a.assert();
        fetch_b.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_two_tlsa_at_same_owner() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "TLSA", "_25._tcp.mail", json!([900, 901]));
        let fetch_old_ee = mock_get_record(
            &mut server,
            900,
            json!({
                "id": 900,
                "zone": "example.com",
                "subDomain": "_25._tcp.mail",
                "fieldType": "TLSA",
                "target": "3 1 1 aa",
                "ttl": 300
            }),
        );
        let fetch_old_ta = mock_get_record(
            &mut server,
            901,
            json!({
                "id": 901,
                "zone": "example.com",
                "subDomain": "_25._tcp.mail",
                "fieldType": "TLSA",
                "target": "2 1 1 bb",
                "ttl": 300
            }),
        );
        let delete_ee = mock_delete_record(&mut server, 900);
        let delete_ta = mock_delete_record(&mut server, 901);
        let create_ee = mock_post_record(
            &mut server,
            json!({
                "fieldType": "TLSA",
                "subDomain": "_25._tcp.mail",
                "target": "3 1 1 cc",
                "ttl": 300
            }),
        );
        let create_ta = mock_post_record(
            &mut server,
            json!({
                "fieldType": "TLSA",
                "subDomain": "_25._tcp.mail",
                "target": "2 1 1 dd",
                "ttl": 300
            }),
        );
        let refresh = mock_refresh(&mut server);

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
                        cert_data: vec![0xcc],
                    }),
                    DnsRecord::TLSA(TLSARecord {
                        cert_usage: TlsaCertUsage::DaneTa,
                        selector: TlsaSelector::Spki,
                        matching: TlsaMatching::Sha256,
                        cert_data: vec![0xdd],
                    }),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        fetch_old_ee.assert();
        fetch_old_ta.assert();
        delete_ee.assert();
        delete_ta.assert();
        create_ee.assert();
        create_ta.assert();
        refresh.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_round_trips_via_display_form() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "CAA", "", json!([1100]));
        let fetch = mock_get_record(
            &mut server,
            1100,
            json!({
                "id": 1100,
                "zone": "example.com",
                "subDomain": "",
                "fieldType": "CAA",
                "target": "0 issue \"letsencrypt.org\"",
                "ttl": 3600
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
        list.assert();
        fetch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_round_trips() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "SRV", "_sip._tcp", json!([1200]));
        let fetch = mock_get_record(
            &mut server,
            1200,
            json!({
                "id": 1200,
                "zone": "example.com",
                "subDomain": "_sip._tcp",
                "fieldType": "SRV",
                "target": "10 20 443 sip.example.com.",
                "ttl": 300
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 443,
                    target: "sip.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        fetch.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_does_not_touch_other_types_at_same_name() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone(&mut server);
        let list = mock_list(&mut server, "A", "host", json!([1300]));
        let fetch = mock_get_record(
            &mut server,
            1300,
            json!({
                "id": 1300,
                "zone": "example.com",
                "subDomain": "host",
                "fieldType": "A",
                "target": "1.1.1.1",
                "ttl": 300
            }),
        );

        let mut provider = setup_provider();
        provider.endpoint = server.url();

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
        fetch.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_records_must_match_declared_type() {
        let provider = setup_provider();
        let result = provider
            .add_to_rrset(
                "test.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_records_must_match_declared_type() {
        let provider = setup_provider();
        let result = provider
            .remove_from_rrset(
                "test.example.com",
                DnsRecordType::A,
                vec![DnsRecord::TXT("nope".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }
}
