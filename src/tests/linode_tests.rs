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
    use crate::providers::linode::{LinodeProvider, UpdateLinodeRecord};
    use crate::{DnsRecord, DnsRecordType, Error};
    use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
    use hickory_resolver::{name_server::TokioConnectionProvider, Resolver};
    use mockito::{Matcher::PartialJson, Mock, Server, ServerGuard};
    use serde_json::{json, Value, Value::Null};
    use std::{
        collections::hash_map::RandomState,
        hash::{BuildHasher, Hasher},
        net::{IpAddr, Ipv4Addr},
        time::Duration,
        time::SystemTime,
    };

    const TIMEOUT: Option<Duration> = Some(Duration::new(1, 0));
    const BEARER: &str = "2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482";
    const TEST_IPV4: &str = "23.45.67.89";
    const INTEGRATION_TIMEOUT_MS: u64 = 180000; // millisecond timeout

    fn linode_api(s: &mut ServerGuard, m: &str, p: &str, b: &str, e: Value) -> Mock {
        let token = "Bearer ".to_owned() + BEARER;
        let mock = s.mock(m, p).expect(1).with_status(201).with_body(b);
        let mock = mock.with_header("content-type", "application/json");
        let mock = mock.match_header("authorization", token.as_str());
        let mock = mock.match_header("content-type", "application/json");
        if e == Null {
            return mock.create();
        };
        mock.match_body(PartialJson(e)).create()
    }

    type Lpmomo = (LinodeProvider, Mock, Mock);
    fn setup_linode_mock(server: &mut ServerGuard, bearer: &str) -> Lpmomo {
        let domains = linode_api(
            server,
            "GET",
            "/domains",
            r#"{
              "data": [
                {
                  "id": 3345977,
                  "type": "master",
                  "domain": "ci-cd.stalwart.dns-update.jaygiffin.com",
                  "tags": [],
                  "group": "",
                  "status": "active",
                  "errors": "",
                  "description": "",
                  "soa_email": "noreply@stalw.art",
                  "retry_sec": 0,
                  "master_ips": [],
                  "axfr_ips": [],
                  "expire_sec": 0,
                  "refresh_sec": 0,
                  "ttl_sec": 0,
                  "created": "2025-09-23T16:34:01",
                  "updated": "2025-09-23T16:34:01"
                }
              ],
              "page": 1,
              "pages": 1,
              "results": 1
            }"#,
            Null,
        );

        let records = linode_api(
            server,
            "GET",
            "/domains/3345977/records",
            r#"{
              "data": [
                {
                  "id": 41022342,
                  "type": "A",
                  "name": "www.test",
                  "target": "1.1.1.1",
                  "priority": 0,
                  "weight": 0,
                  "port": 0,
                  "service": null,
                  "protocol": null,
                  "ttl_sec": 0,
                  "tag": null,
                  "created": "2025-09-23T19:41:38",
                  "updated": "2025-09-23T19:41:38"
                },
                {
                  "id": 41022304,
                  "type": "TXT",
                  "name": "_acme-challenge",
                  "target": "1HQjYS6NlSne1RCeCxfTisFAwr8-9fEbGEQ4jWtzBnQ",
                  "priority": 0,
                  "weight": 0,
                  "port": 0,
                  "service": null,
                  "protocol": null,
                  "ttl_sec": 0,
                  "tag": null,
                  "created": "2025-09-23T19:33:45",
                  "updated": "2025-09-23T19:33:45"
                }
              ],
              "page": 1,
              "pages": 1,
              "results": 2
            }"#,
            Null,
        );

        let linode = LinodeProvider::new(bearer, TIMEOUT);
        let linode = linode.with_endpoint(server.url().as_str());
        (linode, records, domains)
    }

    async fn mock_create_records(server: &mut ServerGuard, provider: &LinodeProvider) -> Mock {
        let mock = linode_api(
            server,
            "POST",
            "/domains/3345977/records",
            r#"{
              "id": 41035719,
              "type": "A",
              "name": "www.test",
              "target": "1.2.3.4",
              "priority": 0,
              "weight": 0,
              "port": 0,
              "service": null,
              "protocol": null,
              "ttl_sec": 0,
              "tag": null,
              "created": "2025-09-24T16:56:58",
              "updated": "2025-09-24T16:56:58"
            }"#,
            json!({
                "type": "A",
                "name": "www.test",
                "target": "1.2.3.4"
            }),
        );

        let content = "1.2.3.4".parse().unwrap();
        let result = provider.create(
            "www.test.ci-cd.stalwart.dns-update.jaygiffin.com",
            DnsRecord::A { content },
            3600,
            "ci-cd.stalwart.dns-update.jaygiffin.com",
        );

        let result = result.await;
        assert!(result.is_ok(), "{:?}", result);
        mock
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = Server::new_async().await;
        let (provider, _rec, _dom) = setup_linode_mock(&mut server, BEARER);
        mock_create_records(&mut server, &provider).await.assert();
    }

    #[tokio::test]
    async fn test_create_mx_record_success() {
        let mut server = Server::new_async().await;
        let (provider, _rec, _dom) = setup_linode_mock(&mut server, BEARER);

        /*  curl -sS --request GET \
            --url 'https://cloud.linode.com/api/v4/domains/3345977/records' \
            --header 'accept: application/json' \
            --header "authorization: Bearer 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482" \
            --header 'content-type: application/json' \
            --data '{"type":"MX","name":"mail","priority":10,"target":"smtp.example.com"}'
             | jq

           {
             "id": 41106332,
             "type": "MX",
             "name": "mail",
             "target": "smtp.example.com",
             "priority": 10,
             "weight": 0,
             "port": 0,
             "service": null,
             "protocol": null,
             "ttl_sec": 0,
             "tag": null,
             "created": "2025-09-30T20:15:40",
             "updated": "2025-09-30T20:15:40"
           }
        */
        let mock = linode_api(
            &mut server,
            "POST",
            "/domains/3345977/records",
            r#"{
              "id": 41106332,
              "type": "MX",
              "name": "mail",
              "target": "smtp.example.com",
              "priority": 10,
              "weight": 0,
              "port": 0,
              "service": null,
              "protocol": null,
              "ttl_sec": 0,
              "tag": null,
              "created": "2025-09-30T20:15:40",
              "updated": "2025-09-30T20:15:40"
            }"#,
            json!({
                "type": "MX",
                "name": "mail",
                "priority": 10,
                "target": "smtp.example.com"
            }),
        );

        let result = provider.create(
            "mail.ci-cd.stalwart.dns-update.jaygiffin.com",
            DnsRecord::MX {
                priority: 10,
                content: "smtp.example.com".to_string(),
            },
            3600,
            "ci-cd.stalwart.dns-update.jaygiffin.com",
        );

        let result = result.await;
        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_unauthorized() {
        let mut server = Server::new_async().await;
        // Notice: provide a bad authorization token that fails:
        let bad = "bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0";
        let (provider, _rec, _dom) = setup_linode_mock(&mut server, bad);
        /*  curl -sS --request GET \
            --url https://api.linode.com/v4/domains \
            -w '%{stderr}Http status: %{http_code}\n%{stdout}\n' \
            --header 'accept: application/json' \
            --header "authorization: Bearer bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0" \
             | jq

            Http status: 401

        */
        let token = "Bearer ".to_owned() + bad;
        let mock = server.mock("GET", "/domains").with_status(401).with_body(
            r#"{
              "errors": [
                {
                  "reason": "Invalid Token"
                }
              ]
            }"#,
        );
        let mock = mock.with_header("content-type", "application/json");
        let mock = mock.match_header("authorization", token.as_str());
        let mock = mock.match_header("content-type", "application/json");
        let mock = mock.create();

        let content = "1.2.3.4".parse().unwrap();
        let result = provider.create(
            "www.test.ci-cd.stalwart.dns-update.jaygiffin.com",
            DnsRecord::A { content },
            3600,
            "ci-cd.stalwart.dns-update.jaygiffin.com",
        );

        let e = result
            .await
            .expect_err("Bad authorization token succeeded somehow!");
        assert!(matches!(e, Error::Unauthorized), "{:?}", e);
        mock.assert();
    }

    async fn mock_update_records(server: &mut ServerGuard, provider: &LinodeProvider) -> Mock {
        let mock = linode_api(
            server,
            "PUT",
            "/domains/3345977/records/41022342",
            r#"{
               "id": 41035719,
               "type": "A",
               "name": "www.test",
               "target": "87.65.43.210",
               "priority": 0,
               "weight": 0,
               "port": 0,
               "service": null,
               "protocol": null,
               "ttl_sec": 0,
               "tag": null,
               "created": "2025-09-24T16:56:58",
               "updated": "2025-09-24T17:10:20"
            }"#,
            json!({
                "type": "A",
                "name": "www.test",
                "target": "87.65.43.210"
            }),
        );

        let content = "87.65.43.210".parse().unwrap();
        let result = provider.update(
            "www.test.",
            DnsRecord::A { content },
            3600,
            "ci-cd.stalwart.dns-update.jaygiffin.com",
        );
        let result = result.await;
        assert!(result.is_ok(), "{:?}", result);
        mock
    }

    #[tokio::test]
    async fn test_update_record_sucess() {
        let mut server = Server::new_async().await;
        let (provider, _rec, _dom) = setup_linode_mock(&mut server, BEARER);
        mock_update_records(&mut server, &provider).await.assert();
    }

    #[tokio::test]
    async fn test_record_domain_cache() {
        let mut server = Server::new_async().await;
        let (provider, rec, dom) = setup_linode_mock(&mut server, BEARER);
        mock_update_records(&mut server, &provider).await.assert();
        mock_create_records(&mut server, &provider).await.assert();
        rec.assert();
        dom.assert();
    }

    #[tokio::test]
    async fn test_delete_record_sucess() {
        let mut server = Server::new_async().await;
        let (provider, _rec, _dom) = setup_linode_mock(&mut server, BEARER);
        let mock = linode_api(
            &mut server,
            "DELETE",
            "/domains/3345977/records/41022304",
            r#"{}"#,
            Null,
        );

        let result = provider.delete(
            "_acme-challenge.",
            "ci-cd.stalwart.dns-update.jaygiffin.com",
            DnsRecordType::TXT,
        );

        let result = result.await;
        assert!(result.is_ok(), "{:?}", result);
        mock.assert();
    }

    #[test]
    fn test_into_linode_record() {
        let record = DnsRecord::A {
            content: "1.1.1.1".parse().unwrap(),
        };
        let linode_record: UpdateLinodeRecord = record.into();
        assert_eq!(linode_record.target.as_str(), "1.1.1.1");
        assert_eq!(linode_record.rr_type, "A");

        let record = DnsRecord::AAAA {
            content: "2001:db8::1".parse().unwrap(),
        };
        let linode_record: UpdateLinodeRecord = record.into();
        assert_eq!(linode_record.target.as_str(), "2001:db8::1");
        assert_eq!(linode_record.rr_type, "AAAA");

        let record = DnsRecord::TXT {
            content: "test".to_string(),
        };
        let linode_record: UpdateLinodeRecord = record.into();
        assert_eq!(linode_record.target.as_str(), "test");
        assert_eq!(linode_record.rr_type, "TXT");

        let record = DnsRecord::MX {
            priority: 10,
            content: "mail.example.com".to_string(),
        };
        let linode_record: UpdateLinodeRecord = record.into();
        assert_eq!(linode_record.target.as_str(), "mail.example.com");
        assert_eq!(linode_record.priority, Some(10));
        assert_eq!(linode_record.rr_type, "MX");

        let record = DnsRecord::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            content: "sip.example.com".to_string(),
        };
        let linode_record: UpdateLinodeRecord = record.into();
        assert_eq!(linode_record.target.as_str(), "sip.example.com");
        assert_eq!(linode_record.priority, Some(10));
        assert_eq!(linode_record.weight, Some(20));
        assert_eq!(linode_record.port, Some(443));
        assert_eq!(linode_record.rr_type, "SRV");
    }

    async fn get_linode_nameservers() -> Vec<IpAddr> {
        let dnsrr = Resolver::builder_tokio().unwrap().build();
        let mut results = Vec::<IpAddr>::new();
        for i in 1..=5 {
            let fqdn = format!("ns{}.linode.com.", i);
            if let Ok(ns) = dnsrr.lookup_ip(fqdn).await {
                results.extend(ns);
            }
        }
        results
    }

    async fn query_ipv4_address(vv: &[IpAddr; 1], fqdn: &str) -> Vec<String> {
        let ns = NameServerConfigGroup::from_ips_clear(vv, 53, true);
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], ns),
            TokioConnectionProvider::default(),
        )
        .build();
        resolver.clear_cache(); // sanity check just to be sure
        let lookup4 = resolver.ipv4_lookup(fqdn);
        if let Ok(vv) = lookup4.await {
            vv.iter().map(|v| v.to_string()).collect()
        } else {
            Vec::<String>::default()
        }
    }

    #[tokio::test]
    #[ignore = "Takes up to a minute or two to see the updated DNS records"]
    async fn linode_integration_test() {
        /* ci-cd.stalwart.dns-update.jaygiffin.com Linode manager portal:

        URL:   login.linode.com/login
        Un:    ci-cd_stalwart_dns-update
        Pw:    ci-cd_stalwart_dns-update0!
        Log:   cloud.linode.com/domains/3345977
        Docs:  https://techdocs.akamai.com/linode-api/reference/get-domains
        OAuth: 2710cefeb00e975e51ed404e7060a4b6014eba99d333703a3e7dc930923b8482
        If you cant login, text/call my cell: (eig-fiv-nin)sev-six-zer zer-thr-zer-fou

        P.s. I'm not affiliated with Stalwart Labs LLC. FOSS is all about
         rando strangers helping rando strangers and I'm a rando stranger.
        P.s. The permissions are locked to only give access to thf/e Domains
         API of ci-cd.stalwart.dns-update.jaygiffin.com; I trust y'all not
         not to abuse. Many thanks and keep up the FOSS work ☺️🎉💻 */
        let token = std::env::var("LINODE_TOKEN").unwrap_or_else(|_v| BEARER.to_string());
        let fqdn = std::env::var("LINODE_FQDN").unwrap_or_else(|_v| {
            "integration.test.ci-cd.stalwart.dns-update.jaygiffin.com".to_string()
        });
        let zone = std::env::var("LINODE_ZONE")
            .unwrap_or_else(|_v| "ci-cd.stalwart.dns-update.jaygiffin.com".to_string());

        assert!(
            !token.is_empty(),
            "Empty Linode API token in Linode integration test"
        );
        assert!(!fqdn.is_empty(), "Empty fqdn in Linode integration test");
        assert!(!zone.is_empty(), "Empty zone in Linode integration test");

        let one_ip = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        let one_4x = query_ipv4_address(&one_ip, "one.one.one.one").await;
        let one_any = one_4x.iter().any(|x| x.as_str() == "1.1.1.1");
        assert!(one_any, "Test needs an internet connection: {:?}", one_4x);

        let linode_ns = get_linode_nameservers();
        let provider = LinodeProvider::new(&token, TIMEOUT);
        let content = TEST_IPV4.parse::<Ipv4Addr>().unwrap();
        let record = DnsRecord::A { content };

        let _ = provider
            .delete(fqdn.as_str(), zone.as_str(), DnsRecordType::A)
            .await; // just in case

        // check creation
        let result = provider.create(fqdn.as_str(), record, 3600, zone.as_str());
        let result = result.await;
        assert!(result.is_ok(), "{:?}", result);

        let linode_ns = linode_ns.await;
        println!("linode_ns: {:?}", linode_ns);
        assert!(1 < linode_ns.len(), "Test needs an internet connection");

        let to_dur = Duration::from_millis(INTEGRATION_TIMEOUT_MS);
        let timeout = SystemTime::now() + to_dur;
        tokio::time::sleep(Duration::new(5, 0)).await; // sleep 5s first
        let mut lku_any: bool;
        while {
            tokio::time::sleep(Duration::from_millis(498)).await;
            let p = RandomState::new().build_hasher().finish() as usize;
            let p = [*linode_ns.get(p % linode_ns.len()).unwrap()];
            let lku_res = query_ipv4_address(&p, fqdn.as_str()).await;
            println!("Progress: got {:?}", lku_res);
            lku_any = lku_res.iter().any(|x| x.as_str() == TEST_IPV4);
            !lku_any && SystemTime::now() < timeout
        } {}

        // check deletion
        let result = provider.delete(&fqdn, &zone, DnsRecordType::A);
        let result = result.await;
        assert!(result.is_ok(), "{:?}", result);

        assert!(lku_any, "Failed to see DNS record propagation on ns1.linode.com through ns5.linode.com within {} seconds", INTEGRATION_TIMEOUT_MS/1000);
    }
}
