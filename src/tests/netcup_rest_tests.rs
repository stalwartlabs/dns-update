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
        CAARecord, DnsRecord, DnsRecordType, Error, MXRecord, SRVRecord, TLSARecord, TlsaCertUsage,
        TlsaMatching, TlsaSelector, providers::netcup_rest::NetcupRestProvider,
    };
    use mockito::{Matcher, Mock, ServerGuard};
    use serde_json::{Value, json};
    use std::time::Duration;

    const AUTH: &str = "Bearer rest-key";
    const REVISION: &str = "2b1c0f6e-7d3a-4c1e-9f0a-3e5b8d2c1a00";
    const OLD_REVISION: &str = "0a9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d00";

    fn provider(server: &ServerGuard) -> NetcupRestProvider {
        NetcupRestProvider::new("rest-key", Some(Duration::from_secs(5)))
            .with_endpoint(server.url())
    }

    fn ok(result: Value, last_page: u32) -> String {
        json!({
            "success": true,
            "errors": [],
            "messages": [],
            "meta": {"pagination": {"page": 1, "perPage": 100, "totalEntries": 1, "previousPage": 0, "nextPage": 0, "lastPage": last_page}},
            "result": result,
        })
        .to_string()
    }

    fn record(name: &str, rtype: &str, rdata: &str, ttl: u32) -> Value {
        json!({
            "identifier": format!("{name}-{rtype}-{rdata}"),
            "name": name,
            "type": rtype,
            "rdata": rdata,
            "ttl": ttl,
            "immutable": false,
        })
    }

    fn page_query(page: u32) -> Matcher {
        Matcher::AllOf(vec![
            Matcher::UrlEncoded("page".into(), page.to_string()),
            Matcher::UrlEncoded("perPage".into(), "100".into()),
        ])
    }

    fn mock_domain(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/domain")
            .match_query(Matcher::UrlEncoded("fqdn".into(), "example.com".into()))
            .match_header("authorization", AUTH)
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(ok(
                json!([{"id": 42, "fqdn": "example.com", "isDnsManaged": true}]),
                0,
            ))
            .create()
    }

    fn mock_revisions(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/domain/42/dns/revision")
            .match_query(page_query(1))
            .match_header("authorization", AUTH)
            .with_status(200)
            .with_body(ok(
                json!([
                    {"identifier": REVISION, "createdAt": "2026-11-02T09:45:00Z", "state": "committed", "serial": 2},
                    {"identifier": OLD_REVISION, "createdAt": "2026-11-02T10:30:00+02:00", "state": "committed", "serial": 1},
                ]),
                0,
            ))
            .create()
    }

    fn mock_records(server: &mut ServerGuard, records: Value) -> Mock {
        server
            .mock(
                "GET",
                format!("/domain/42/dns/revision/{REVISION}/record").as_str(),
            )
            .match_query(page_query(1))
            .match_header("authorization", AUTH)
            .with_status(200)
            .with_body(ok(records, 0))
            .create()
    }

    fn mock_zone(server: &mut ServerGuard, records: Value) -> [Mock; 3] {
        [
            mock_domain(server),
            mock_revisions(server),
            mock_records(server, records),
        ]
    }

    fn mock_changeset(server: &mut ServerGuard, create: Value, delete: Value) -> Mock {
        let mut body = json!({"autoCommit": true, "strict": true});
        if create != json!([]) {
            body["create"] = create;
        }
        if delete != json!([]) {
            body["delete"] = delete;
        }
        server
            .mock("POST", "/domain/42/changeset")
            .match_header("authorization", AUTH)
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(body))
            .with_status(200)
            .with_body(
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "meta": null,
                    "result": {"identifier": "new", "state": "committed"},
                })
                .to_string(),
            )
            .expect(1)
            .create()
    }

    fn mock_no_changeset(server: &mut ServerGuard) -> Mock {
        server
            .mock("POST", "/domain/42/changeset")
            .expect(0)
            .create()
    }

    fn input(name: &str, rtype: &str, rdata: &str, ttl: u32) -> Value {
        json!({"name": name, "type": rtype, "rdata": rdata, "ttl": ttl})
    }

    // Keeps matching records, deletes stale ones, creates missing ones, ignores immutable records.
    #[tokio::test]
    async fn set_rrset_replaces_stale_records() {
        let mut server = mockito::Server::new_async().await;
        let mut immutable = record("www", "A", "9.9.9.9", 300);
        immutable["immutable"] = json!(true);
        let _zone = mock_zone(
            &mut server,
            json!([
                record("www", "A", "1.1.1.1", 300),
                record("www", "A", "3.3.3.3", 300),
                record("www", "AAAA", "2001:db8::1", 300),
                record("api", "A", "3.3.3.3", 300),
                immutable,
            ]),
        );
        let changeset = mock_changeset(
            &mut server,
            json!([input("www", "A", "2.2.2.2", 300)]),
            json!([input("www", "A", "3.3.3.3", 300)]),
        );

        provider(&server)
            .set_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                    DnsRecord::A("2.2.2.2".parse().unwrap()),
                    DnsRecord::A("1.1.1.1".parse().unwrap()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        changeset.assert();
    }

    // An unchanged RRSet sends no changeset.
    #[tokio::test]
    async fn set_rrset_unchanged_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone(
            &mut server,
            json!([record("mail", "CNAME", "host.example.net.", 300)]),
        );
        let changeset = mock_no_changeset(&mut server);

        provider(&server)
            .set_rrset(
                "mail.example.com",
                DnsRecordType::CNAME,
                300,
                vec![DnsRecord::CNAME("host.example.net".into())],
                "example.com",
            )
            .await
            .unwrap();

        changeset.assert();
    }

    // A TTL change deletes the record with its listed TTL and recreates it.
    #[tokio::test]
    async fn set_rrset_ttl_change_recreates() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone(&mut server, json!([record("@", "A", "1.1.1.1", 3600)]));
        let changeset = mock_changeset(
            &mut server,
            json!([input("@", "A", "1.1.1.1", 300)]),
            json!([input("@", "A", "1.1.1.1", 3600)]),
        );

        provider(&server)
            .set_rrset(
                "example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await
            .unwrap();

        changeset.assert();
    }

    // Adds only records not already present, with zone-file encoded rdata.
    #[tokio::test]
    async fn add_to_rrset_encodes_rdata() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone(
            &mut server,
            json!([record("@", "TXT", "\"v=spf1 -all\"", 300)]),
        );
        let changeset = mock_changeset(
            &mut server,
            json!([input("@", "TXT", "\"say \\\"hi\\\"\"", 600)]),
            json!([]),
        );

        provider(&server)
            .add_to_rrset(
                "example.com",
                DnsRecordType::TXT,
                600,
                vec![
                    DnsRecord::TXT("v=spf1 -all".into()),
                    DnsRecord::TXT("say \"hi\"".into()),
                    DnsRecord::TXT("say \"hi\"".into()),
                ],
                "example.com",
            )
            .await
            .unwrap();

        changeset.assert();
    }

    // Each record type is sent in the presentation format netcup documents.
    #[tokio::test]
    async fn add_to_rrset_record_types() {
        let cases = [
            (
                "_sip._tcp",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 5060,
                    target: "sip.example.com".into(),
                }),
                "SRV",
                "10 5 5060 sip.example.com.",
            ),
            (
                "@",
                DnsRecord::MX(MXRecord {
                    priority: 10,
                    exchange: "mail.example.com".into(),
                }),
                "MX",
                "10 mail.example.com.",
            ),
            (
                "@",
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".into()),
                    options: vec![],
                }),
                "CAA",
                "0 issue \"letsencrypt.org\"",
            ),
            (
                "_25._tcp.mail",
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xab, 0xcd],
                }),
                "TLSA",
                "3 1 1 abcd",
            ),
        ];
        for (name, record, rtype, rdata) in cases {
            let mut server = mockito::Server::new_async().await;
            let _zone = mock_zone(&mut server, json!([]));
            let changeset = mock_changeset(
                &mut server,
                json!([input(name, rtype, rdata, 300)]),
                json!([]),
            );
            let fqdn = if name == "@" {
                "example.com".to_string()
            } else {
                format!("{name}.example.com")
            };

            provider(&server)
                .add_to_rrset(&fqdn, record.as_type(), 300, vec![record], "example.com")
                .await
                .unwrap();

            changeset.assert();
        }
    }

    // Removal deletes the listed record verbatim, including its TTL and rdata spelling.
    #[tokio::test]
    async fn remove_from_rrset_deletes_listed_record() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone(
            &mut server,
            json!([
                record("@", "MX", "10 mail.example.com.", 7200),
                record("@", "MX", "20 backup.example.com.", 7200),
            ]),
        );
        let changeset = mock_changeset(
            &mut server,
            json!([]),
            json!([input("@", "MX", "10 mail.example.com.", 7200)]),
        );

        provider(&server)
            .remove_from_rrset(
                "example.com",
                DnsRecordType::MX,
                vec![
                    DnsRecord::MX(MXRecord {
                        priority: 10,
                        exchange: "mail.example.com".into(),
                    }),
                    DnsRecord::MX(MXRecord {
                        priority: 30,
                        exchange: "absent.example.com".into(),
                    }),
                ],
                "example.com",
            )
            .await
            .unwrap();

        changeset.assert();
    }

    // Listing follows pagination and decodes rdata.
    #[tokio::test]
    async fn list_rrset_paginates_and_decodes() {
        let mut server = mockito::Server::new_async().await;
        let _domain = mock_domain(&mut server);
        let _revisions = mock_revisions(&mut server);
        let path = format!("/domain/42/dns/revision/{REVISION}/record");
        let _first = server
            .mock("GET", path.as_str())
            .match_query(page_query(1))
            .with_status(200)
            .with_body(ok(
                json!([
                    record("@", "CAA", "128 issue \"ca.example.net; account=1\"", 300),
                    record("www", "CAA", "0 iodef \"mailto:x@example.com\"", 300),
                ]),
                2,
            ))
            .create();
        let _second = server
            .mock("GET", path.as_str())
            .match_query(page_query(2))
            .with_status(200)
            .with_body(ok(json!([record("@", "CAA", "0 issuewild \";\"", 300)]), 2))
            .create();

        let records = provider(&server)
            .list_rrset("example.com", DnsRecordType::CAA, "example.com")
            .await
            .unwrap();

        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0],
            DnsRecord::CAA(CAARecord::Issue { issuer_critical: true, name: Some(name), options })
                if name == "ca.example.net" && options.len() == 1
        ));
        assert!(matches!(
            &records[1],
            DnsRecord::CAA(CAARecord::IssueWild {
                issuer_critical: false,
                name: None,
                ..
            })
        ));
    }

    // Split TXT strings are joined when listed.
    #[tokio::test]
    async fn list_rrset_joins_txt_chunks() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone(
            &mut server,
            json!([record(
                "sel._domainkey",
                "TXT",
                "\"v=DKIM1; p=abc\" \"def\"",
                300
            )]),
        );

        let records = provider(&server)
            .list_rrset(
                "sel._domainkey.example.com",
                DnsRecordType::TXT,
                "example.com",
            )
            .await
            .unwrap();

        assert_eq!(records, vec![DnsRecord::TXT("v=DKIM1; p=abcdef".into())]);
    }

    // A domain not on CloudDNS is rejected with a hint to use the CCP API.
    #[tokio::test]
    async fn domain_not_dns_managed() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/domain")
            .match_query(Matcher::UrlEncoded("fqdn".into(), "example.com".into()))
            .with_status(200)
            .with_body(ok(
                json!([{"id": 42, "fqdn": "example.com", "isDnsManaged": false}]),
                0,
            ))
            .create();

        let err = provider(&server)
            .list_rrset("example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::Api(msg) if msg.contains("CCP")));
    }

    // An unknown domain and an error envelope surface as API errors.
    #[tokio::test]
    async fn domain_lookup_errors() {
        let mut server = mockito::Server::new_async().await;
        let _domain = server
            .mock("GET", "/domain")
            .match_query(Matcher::UrlEncoded("fqdn".into(), "example.com".into()))
            .with_status(200)
            .with_body(
                json!({
                    "success": false,
                    "errors": [{"code": "resourceDoesNotExist", "message": "Resource does not exist."}],
                    "messages": [],
                    "meta": null,
                    "result": null,
                })
                .to_string(),
            )
            .create();
        let _other = server
            .mock("GET", "/domain")
            .match_query(Matcher::UrlEncoded("fqdn".into(), "example.org".into()))
            .with_status(200)
            .with_body(ok(json!([{"id": 7, "fqdn": "sub.example.org"}]), 0))
            .create();

        let err = provider(&server)
            .list_rrset("example.com", DnsRecordType::A, "example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Api(msg) if msg.contains("resourceDoesNotExist")));

        let err = provider(&server)
            .list_rrset("example.org", DnsRecordType::A, "example.org")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Api(msg) if msg.contains("not found")));
    }

    // A changeset rejected by netcup is reported with its error code.
    #[tokio::test]
    async fn changeset_error() {
        let mut server = mockito::Server::new_async().await;
        let _zone = mock_zone(&mut server, json!([]));
        let _changeset = server
            .mock("POST", "/domain/42/changeset")
            .with_status(422)
            .with_body(
                json!({
                    "success": false,
                    "errors": [{"code": "validationError", "message": "rdata invalid"}],
                    "messages": [],
                    "meta": null,
                    "result": null,
                })
                .to_string(),
            )
            .create();

        let err = provider(&server)
            .add_to_rrset(
                "www.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.1.1.1".parse().unwrap())],
                "example.com",
            )
            .await
            .unwrap_err();

        assert!(matches!(err, Error::Api(msg) if msg.contains("validationError")));
    }
}
