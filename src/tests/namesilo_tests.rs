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
        CAARecord, DnsRecord, DnsRecordType, Error, KeyValue, MXRecord, SRVRecord,
        providers::namesilo::NameSiloProvider,
    };
    use mockito::Matcher;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NameSiloProvider {
        NameSiloProvider::new("apikey", Some(Duration::from_secs(1)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn ok_reply(code: &str, detail: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><namesilo><request><operation>op</operation><ip>0.0.0.0</ip></request><reply><code>{code}</code><detail>{detail}</detail></reply></namesilo>"#
        )
    }

    fn list_reply(records: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><namesilo><request><operation>dnsListRecords</operation><ip>0.0.0.0</ip></request><reply><code>300</code><detail>success</detail>{records}</reply></namesilo>"#
        )
    }

    fn resource_record(
        id: &str,
        rtype: &str,
        host: &str,
        value: &str,
        ttl: &str,
        distance: &str,
    ) -> String {
        format!(
            "<resource_record><record_id>{id}</record_id><type>{rtype}</type><host>{host}</host><value>{value}</value><ttl>{ttl}</ttl><distance>{distance}</distance></resource_record>"
        )
    }

    #[tokio::test]
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(""))
            .create();

        let add_1 = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "A".into()),
                Matcher::UrlEncoded("rrhost".into(), "host".into()),
                Matcher::UrlEncoded("rrvalue".into(), "1.1.1.1".into()),
                Matcher::UrlEncoded("rrttl".into(), "300".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
            .create();

        let add_2 = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "A".into()),
                Matcher::UrlEncoded("rrhost".into(), "host".into()),
                Matcher::UrlEncoded("rrvalue".into(), "8.8.8.8".into()),
                Matcher::UrlEncoded("rrttl".into(), "300".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        add_1.assert();
        add_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&resource_record(
                "rec1",
                "A",
                "host.example.com",
                "1.1.1.1",
                "300",
                "0",
            )))
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
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_keeps_matching() {
        let mut server = mockito::Server::new_async().await;
        let records = format!(
            "{}{}",
            resource_record("rec-keep", "A", "host.example.com", "1.1.1.1", "300", "0"),
            resource_record("rec-stale", "A", "host.example.com", "9.9.9.9", "300", "0"),
        );
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&records))
            .create();

        let delete_stale = server
            .mock("GET", "/dnsDeleteRecord")
            .match_query(Matcher::UrlEncoded("rrid".into(), "rec-stale".into()))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
            .create();

        let add_new = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "A".into()),
                Matcher::UrlEncoded("rrhost".into(), "host".into()),
                Matcher::UrlEncoded("rrvalue".into(), "8.8.8.8".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        delete_stale.assert();
        add_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_records_deletes_all() {
        let mut server = mockito::Server::new_async().await;
        let records = format!(
            "{}{}{}",
            resource_record("rec-x", "A", "gone.example.com", "1.2.3.4", "300", "0"),
            resource_record("rec-y", "A", "gone.example.com", "5.6.7.8", "300", "0"),
            resource_record("rec-z", "TXT", "gone.example.com", "untouched", "300", "0"),
        );
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&records))
            .create();

        let delete_x = server
            .mock("GET", "/dnsDeleteRecord")
            .match_query(Matcher::UrlEncoded("rrid".into(), "rec-x".into()))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
            .create();

        let delete_y = server
            .mock("GET", "/dnsDeleteRecord")
            .match_query(Matcher::UrlEncoded("rrid".into(), "rec-y".into()))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        delete_x.assert();
        delete_y.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let records = format!(
            "{}{}",
            resource_record("rec-a", "A", "host.example.com", "1.1.1.1", "300", "0"),
            resource_record("rec-txt", "TXT", "host.example.com", "keep me", "300", "0"),
        );
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&records))
            .expect(1)
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
        list.assert();
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
    async fn test_add_to_rrset_skips_existing_values() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&resource_record(
                "rec-1",
                "A",
                "host.example.com",
                "1.1.1.1",
                "300",
                "0",
            )))
            .create();

        let add_new = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "A".into()),
                Matcher::UrlEncoded("rrvalue".into(), "2.2.2.2".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        add_new.assert();
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
    async fn test_remove_from_rrset_only_matching() {
        let mut server = mockito::Server::new_async().await;
        let records = format!(
            "{}{}",
            resource_record("rec-1", "A", "host.example.com", "1.1.1.1", "300", "0"),
            resource_record("rec-2", "A", "host.example.com", "2.2.2.2", "300", "0"),
        );
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&records))
            .create();

        let delete_1 = server
            .mock("GET", "/dnsDeleteRecord")
            .match_query(Matcher::UrlEncoded("rrid".into(), "rec-1".into()))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset(
                "host.example.com",
                DnsRecordType::A,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("9.9.9.9".parse().unwrap()),
                ],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
        list.assert();
        delete_1.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_records_must_match_declared_type() {
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
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("RRSet record type mismatch")),
            "expected type mismatch, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_ns() {
        let provider = setup_provider("http://unused".to_string());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::NS,
                300,
                vec![DnsRecord::NS("ns1.example.com".to_string())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("NS records are not supported")),
            "expected NS rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_rejects_tlsa() {
        let provider = setup_provider("http://unused".to_string());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Api(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_set_rrset_mx_uses_distance_for_priority() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(""))
            .create();

        let add = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "MX".into()),
                Matcher::UrlEncoded("rrhost".into(), "".into()),
                Matcher::UrlEncoded("rrvalue".into(), "mail.example.com".into()),
                Matcher::UrlEncoded("rrdistance".into(), "10".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_uses_colon_format() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(""))
            .create();

        let add = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "SRV".into()),
                Matcher::UrlEncoded("rrhost".into(), "_sip._tcp".into()),
                Matcher::UrlEncoded("rrvalue".into(), "20:5060:sip.example.com".into()),
                Matcher::UrlEncoded("rrdistance".into(), "10".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                3600,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "sip.example.com".to_string(),
                })],
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        list.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_uses_colon_format() {
        let mut server = mockito::Server::new_async().await;
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(""))
            .create();

        let add = server
            .mock("GET", "/dnsAddRecord")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("rrtype".into(), "CAA".into()),
                Matcher::UrlEncoded("rrvalue".into(), "0:issue:letsencrypt.org".into()),
            ]))
            .with_status(200)
            .with_body(ok_reply("300", "success"))
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
        list.assert();
        add.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_records() {
        let mut server = mockito::Server::new_async().await;
        let records = format!(
            "{}{}{}",
            resource_record("rec-a", "A", "host.example.com", "1.1.1.1", "300", "0"),
            resource_record("rec-b", "A", "host.example.com", "2.2.2.2", "300", "0"),
            resource_record("rec-txt", "TXT", "host.example.com", "ignore", "300", "0"),
        );
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&records))
            .create();

        let provider = setup_provider(server.url());
        let listed = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(listed.len(), 2, "expected only A records, got {listed:?}");
        assert!(listed.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(listed.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        list.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_parses_caa_back() {
        let mut server = mockito::Server::new_async().await;
        let records = resource_record(
            "rec-caa",
            "CAA",
            "example.com",
            "0:issue:letsencrypt.org",
            "300",
            "0",
        );
        let list = server
            .mock("GET", "/dnsListRecords")
            .match_query(Matcher::UrlEncoded("domain".into(), "example.com".into()))
            .with_status(200)
            .with_body(list_reply(&records))
            .create();

        let provider = setup_provider(server.url());
        let listed = provider
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .expect("list_rrset failed");

        assert_eq!(
            listed,
            vec![DnsRecord::CAA(CAARecord::Issue {
                issuer_critical: false,
                name: Some("letsencrypt.org".to_string()),
                options: vec![],
            })]
        );
        list.assert();
        let _ = KeyValue {
            key: String::new(),
            value: String::new(),
        };
    }
}
