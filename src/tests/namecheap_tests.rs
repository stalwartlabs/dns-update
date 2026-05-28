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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord,
        providers::namecheap::NamecheapProvider,
    };
    use mockito::Matcher;
    use std::{net::Ipv4Addr, time::Duration};

    fn provider(endpoint: String) -> NamecheapProvider {
        NamecheapProvider::new(
            "user",
            "key",
            "1.2.3.4",
            None::<&str>,
            Some(Duration::from_secs(1)),
        )
        .unwrap()
        .with_endpoint(format!("{endpoint}/xml.response"))
    }

    const SET_HOSTS_OK: &str = r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
  <Errors/>
  <CommandResponse>
    <DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/>
  </CommandResponse>
</ApiResponse>"#;

    fn get_hosts_xml(hosts: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<ApiResponse Status="OK">
  <Errors/>
  <CommandResponse>
    <DomainDNSGetHostsResult Domain="example.com">
{hosts}
    </DomainDNSGetHostsResult>
  </CommandResponse>
</ApiResponse>"#
        )
    }

    fn host_xml(name: &str, ty: &str, address: &str, mx_pref: &str, ttl: &str) -> String {
        format!(
            r#"      <host HostId="1" Name="{name}" Type="{ty}" Address="{address}" MXPref="{mx_pref}" TTL="{ttl}"/>"#
        )
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_existing_and_preserves_other_types() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&format!(
            "{}\n{}\n{}",
            host_xml("www", "A", "1.1.1.1", "10", "300"),
            host_xml("www", "TXT", "old", "10", "300"),
            host_xml("mail", "MX", "mx1.example.com", "5", "300"),
        ));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("Command".into(), "namecheap.domains.dns.setHosts".into()),
                Matcher::UrlEncoded("HostName1".into(), "www".into()),
                Matcher::UrlEncoded("RecordType1".into(), "A".into()),
                Matcher::UrlEncoded("Address1".into(), "1.1.1.1".into()),
                Matcher::UrlEncoded("HostName2".into(), "mail".into()),
                Matcher::UrlEncoded("RecordType2".into(), "MX".into()),
                Matcher::UrlEncoded("Address2".into(), "mx1.example.com".into()),
                Matcher::UrlEncoded("MXPref2".into(), "5".into()),
                Matcher::UrlEncoded("HostName3".into(), "www".into()),
                Matcher::UrlEncoded("RecordType3".into(), "TXT".into()),
                Matcher::UrlEncoded("Address3".into(), "new-a".into()),
                Matcher::UrlEncoded("HostName4".into(), "www".into()),
                Matcher::UrlEncoded("RecordType4".into(), "TXT".into()),
                Matcher::UrlEncoded("Address4".into(), "new-b".into()),
            ]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("new-a".to_string()),
                    DnsRecord::TXT("new-b".to_string()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_deletes_only_target_rrset() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&format!(
            "{}\n{}",
            host_xml("www", "A", "1.1.1.1", "10", "300"),
            host_xml("www", "TXT", "old", "10", "300"),
        ));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("Command".into(), "namecheap.domains.dns.setHosts".into()),
                Matcher::UrlEncoded("HostName1".into(), "www".into()),
                Matcher::UrlEncoded("RecordType1".into(), "A".into()),
                Matcher::UrlEncoded("Address1".into(), "1.1.1.1".into()),
            ]))
            .match_request(|req| {
                let body = req.utf8_lossy_body().unwrap_or_default();
                !body.contains("HostName2")
            })
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_on_missing_rrset_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&host_xml("www", "A", "1.1.1.1", "10", "300"));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_add_to_rrset_skips_duplicates() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&format!(
            "{}\n{}",
            host_xml("www", "TXT", "existing", "10", "300"),
            host_xml("www", "A", "1.1.1.1", "10", "300"),
        ));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("Command".into(), "namecheap.domains.dns.setHosts".into()),
                Matcher::UrlEncoded("HostName1".into(), "www".into()),
                Matcher::UrlEncoded("RecordType1".into(), "TXT".into()),
                Matcher::UrlEncoded("Address1".into(), "existing".into()),
                Matcher::UrlEncoded("HostName2".into(), "www".into()),
                Matcher::UrlEncoded("RecordType2".into(), "A".into()),
                Matcher::UrlEncoded("HostName3".into(), "www".into()),
                Matcher::UrlEncoded("RecordType3".into(), "TXT".into()),
                Matcher::UrlEncoded("Address3".into(), "fresh".into()),
            ]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                vec![
                    DnsRecord::TXT("existing".to_string()),
                    DnsRecord::TXT("fresh".to_string()),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_all_present_no_set_hosts() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&host_xml("www", "TXT", "existing", "10", "300"));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("existing".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "add_to_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_short_circuits() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                Vec::new(),
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_filters_specific_values() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&format!(
            "{}\n{}\n{}",
            host_xml("www", "TXT", "keep", "10", "300"),
            host_xml("www", "TXT", "drop", "10", "300"),
            host_xml("www", "A", "1.1.1.1", "10", "300"),
        ));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("Command".into(), "namecheap.domains.dns.setHosts".into()),
                Matcher::UrlEncoded("Address1".into(), "keep".into()),
                Matcher::UrlEncoded("Address2".into(), "1.1.1.1".into()),
            ]))
            .match_request(|req| {
                let body = req.utf8_lossy_body().unwrap_or_default();
                !body.contains("HostName3")
            })
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("drop".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_absent_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&host_xml("www", "TXT", "keep", "10", "300"));
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .expect(0)
            .create();

        let provider = provider(server.url());
        let result = provider
            .remove_from_rrset(
                "www.example.com",
                DnsRecordType::TXT,
                vec![DnsRecord::TXT("nothing-matches".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&format!(
            "{}\n{}\n{}\n{}",
            host_xml("www", "A", "1.1.1.1", "10", "300"),
            host_xml("www", "A", "2.2.2.2", "10", "300"),
            host_xml("www", "TXT", "value", "10", "300"),
            host_xml("mail", "A", "9.9.9.9", "10", "300"),
        ));
        let _get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let provider = provider(server.url());
        let result = provider
            .list_rrset("www.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&DnsRecord::A(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(result.contains(&DnsRecord::A(Ipv4Addr::new(2, 2, 2, 2))));
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
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
            matches!(result, Err(Error::Api(ref m)) if m.contains("type mismatch")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_tlsa_rejected_on_set_rrset() {
        use crate::{TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector};

        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "_443._tcp.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0u8; 32],
                })],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref m)) if m.contains("TLSA")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_srv_rejected_on_set_rrset() {
        use crate::SRVRecord;

        let server = mockito::Server::new_async().await;
        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "_sip._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "sip.example.com".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref m)) if m.contains("SRV")),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_txt_long_value_is_chunked() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml("");
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let long = "a".repeat(260);
        let chunk1 = "a".repeat(255);
        let chunk2 = "a".repeat(5);

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("RecordType1".into(), "TXT".into()),
                Matcher::UrlEncoded("Address1".into(), chunk1),
                Matcher::UrlEncoded("RecordType2".into(), "TXT".into()),
                Matcher::UrlEncoded("Address2".into(), chunk2),
            ]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "long.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT(long)],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_caa_uses_combined_address_string() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml("");
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let set = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("RecordType1".into(), "CAA".into()),
                Matcher::UrlEncoded("Address1".into(), "0 issue letsencrypt.org".into()),
            ]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::CAA,
                300,
                vec![DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: Vec::new(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned {result:?}");
        get.assert();
        set.assert();
    }

    #[tokio::test]
    async fn test_ttl_is_clamped_to_namecheap_range() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml("");
        let get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .expect_at_least(1)
            .create();

        let set_low = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![Matcher::UrlEncoded(
                "TTL1".into(),
                "60".into(),
            )]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let set_high = server
            .mock("POST", "/xml.response")
            .match_body(Matcher::AllOf(vec![Matcher::UrlEncoded(
                "TTL1".into(),
                "60000".into(),
            )]))
            .with_status(200)
            .with_body(SET_HOSTS_OK)
            .create();

        let provider = provider(server.url());

        provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                10,
                vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4))],
                "example.com",
            )
            .await
            .expect("low-ttl set_rrset");

        provider
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                999_999,
                vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4))],
                "example.com",
            )
            .await
            .expect("high-ttl set_rrset");

        get.assert();
        set_low.assert();
        set_high.assert();
    }

    #[tokio::test]
    async fn test_list_rrset_mx_parses_priority() {
        let mut server = mockito::Server::new_async().await;
        let body = get_hosts_xml(&host_xml("@", "MX", "mail.example.com", "20", "300"));
        let _get = server
            .mock("GET", "/xml.response")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create();

        let provider = provider(server.url());
        let result = provider
            .list_rrset("example.com", DnsRecordType::MX, "example.com")
            .await
            .expect("list_rrset failed");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            DnsRecord::MX(MXRecord {
                exchange: "mail.example.com".to_string(),
                priority: 20,
            })
        );
    }
}
