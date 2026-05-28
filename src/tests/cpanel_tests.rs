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
        DnsRecord, DnsRecordType, DnsUpdater, Error, MXRecord, providers::cpanel::CpanelProvider,
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: &str) -> CpanelProvider {
        CpanelProvider::new(
            endpoint,
            "test_user",
            "test_token",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    fn b64(value: &str) -> String {
        BASE64.encode(value.as_bytes())
    }

    fn soa_row(serial: &str) -> String {
        let domain_b64 = b64("example.com.");
        let ns_b64 = b64("ns1.example.com.");
        let admin_b64 = b64("admin.example.com.");
        let serial_b64 = b64(serial);
        format!(
            r#"{{"line_index":1,"type":"record","record_type":"SOA","dname_b64":"{domain}",
                "data_b64":["{ns}","{admin}","{serial}","3600","1800","1209600","300"],"ttl":3600}}"#,
            domain = domain_b64,
            ns = ns_b64,
            admin = admin_b64,
            serial = serial_b64,
        )
    }

    fn record_row(line: i64, rt: &str, host: &str, fields: &[&str], ttl: u32) -> String {
        let host_b64 = b64(host);
        let data: Vec<String> = fields.iter().map(|f| format!("\"{}\"", b64(f))).collect();
        format!(
            r#"{{"line_index":{line},"type":"record","record_type":"{rt}","dname_b64":"{host}",
                "data_b64":[{data}],"ttl":{ttl}}}"#,
            line = line,
            rt = rt,
            host = host_b64,
            data = data.join(","),
            ttl = ttl,
        )
    }

    fn zone_response(rows: &[String]) -> String {
        format!(r#"{{"status":1,"data":[{}]}}"#, rows.join(","))
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_cpanel(
            "https://cpanel.example.com:2083",
            "test_user",
            "test_token",
            Some(Duration::from_secs(30)),
        );
        assert!(matches!(updater, Ok(DnsUpdater::Cpanel(..))));
    }

    #[tokio::test]
    async fn set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[soa_row("2024010100")]))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("zone".into(), "example.com".into()),
                Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                Matcher::Regex("add=".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_empty_deletes_all_matching_rows() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(10, "TXT", "_acme.example.com.", &["tok-a"], 300),
                record_row(11, "TXT", "_acme.example.com.", &["tok-b"], 300),
                record_row(12, "A", "_acme.example.com.", &["192.0.2.1"], 300),
            ]))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::Regex(r"zone=example.com".into()),
                Matcher::Regex(r"serial=2024010100".into()),
                Matcher::Regex(r"(^|&)remove=10($|&)".into()),
                Matcher::Regex(r"(^|&)remove=11($|&)".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_acme.example.com",
                DnsRecordType::TXT,
                300,
                vec![],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_idempotent_short_circuits() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(7, "A", "www.example.com.", &["192.0.2.1"], 3600),
            ]))
            .expect(1)
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .expect(0)
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(20, "A", "host.example.com.", &["192.0.2.1"], 3600),
                record_row(21, "AAAA", "host.example.com.", &["2001:db8::1"], 3600),
                record_row(22, "TXT", "host.example.com.", &["old-txt"], 3600),
            ]))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("zone".into(), "example.com".into()),
                Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                Matcher::Regex("edit=".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::TXT,
                3600,
                vec![DnsRecord::TXT("new-txt".into())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_txt_chunks_long_values() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[soa_row("2024010100")]))
            .create();

        let long_value: String = "x".repeat(400);
        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::Regex(
                "add=.*%5C%22%20%5C%22|add=.*%5C%22\\+%5C%22".into(),
            ))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_dkim.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long_value)],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_retries_on_serial_mismatch() {
        let mut server = mockito::Server::new_async().await;

        let zone_first = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[soa_row("2024010100")]))
            .expect(1)
            .create();

        let edit_first = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                Matcher::Regex("add=".into()),
            ]))
            .with_status(200)
            .with_body(
                r#"{"status":0,"errors":["The provided SOA serial number does not match the current SOA serial number for the zone."],"messages":[]}"#,
            )
            .expect(1)
            .create();

        let zone_second = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[soa_row("2024010199")]))
            .expect(1)
            .create();

        let edit_second = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("serial".into(), "2024010199".into()),
                Matcher::Regex("add=".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010200"}}"#)
            .expect(1)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::A("192.0.2.1".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_first.assert();
        edit_first.assert();
        zone_second.assert();
        edit_second.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_skips_existing() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(30, "A", "www.example.com.", &["192.0.2.1"], 3600),
            ]))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("zone".into(), "example.com".into()),
                Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                Matcher::Regex("add=".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![
                    DnsRecord::A("192.0.2.1".parse().unwrap()),
                    DnsRecord::A("192.0.2.2".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn add_to_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![],
                "example.com",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn remove_from_rrset_removes_matching_only() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(
                    40,
                    "MX",
                    "example.com.",
                    &["10", "mail1.example.com."],
                    3600,
                ),
                record_row(
                    41,
                    "MX",
                    "example.com.",
                    &["20", "mail2.example.com."],
                    3600,
                ),
            ]))
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("zone".into(), "example.com".into()),
                Matcher::UrlEncoded("serial".into(), "2024010100".into()),
                Matcher::UrlEncoded("remove".into(), "40".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"status":1,"data":{"new_serial":"2024010101"}}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "example.com",
                DnsRecordType::MX,
                vec![DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail1.example.com".into(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn remove_from_rrset_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[soa_row("2024010100")]))
            .expect(1)
            .create();

        let edit_mock = server
            .mock("GET", "/execute/DNS/mass_edit_zone")
            .expect(0)
            .with_status(200)
            .with_body(r#"{"status":1}"#)
            .create();

        let provider = setup_provider(server.url().as_str());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::A,
                vec![DnsRecord::A("192.0.2.99".parse().unwrap())],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        zone_mock.assert();
        edit_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_matching_records() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(50, "A", "host.example.com.", &["192.0.2.1"], 3600),
                record_row(51, "A", "host.example.com.", &["192.0.2.2"], 3600),
                record_row(52, "AAAA", "host.example.com.", &["2001:db8::1"], 3600),
            ]))
            .create();

        let provider = setup_provider(server.url().as_str());
        let records = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::A("192.0.2.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("192.0.2.2".parse().unwrap())));
        zone_mock.assert();
    }

    #[tokio::test]
    async fn list_rrset_returns_mx_with_priority() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("GET", "/execute/DNS/parse_zone")
            .match_query(Matcher::UrlEncoded("zone".into(), "example.com".into()))
            .with_status(200)
            .with_body(zone_response(&[
                soa_row("2024010100"),
                record_row(
                    60,
                    "MX",
                    "example.com.",
                    &["10", "mail1.example.com."],
                    3600,
                ),
                record_row(
                    61,
                    "MX",
                    "example.com.",
                    &["20", "mail2.example.com."],
                    3600,
                ),
            ]))
            .create();

        let provider = setup_provider(server.url().as_str());
        let records = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(records.len(), 2);
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            priority: 10,
            exchange: "mail1.example.com".into(),
        })));
        assert!(records.contains(&DnsRecord::MX(MXRecord {
            priority: 20,
            exchange: "mail2.example.com".into(),
        })));
        zone_mock.assert();
    }

    #[tokio::test]
    async fn set_rrset_rejects_type_mismatch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                3600,
                vec![DnsRecord::TXT("nope".into())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")));
    }

    #[tokio::test]
    async fn set_rrset_rejects_tlsa_before_fetch() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url().as_str());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                3600,
                vec![],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Unsupported(ref m)) if m.contains("TLSA")));
    }
}
