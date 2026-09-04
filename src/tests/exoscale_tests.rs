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
        TlsaMatching, TlsaSelector,
        crypto::hmac_sha256,
        providers::exoscale::{ExoscaleProvider, signing_string},
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use mockito::{Matcher, Mock, Request, ServerGuard};
    use serde_json::json;
    use std::time::Duration;

    const ZONE_ID: &str = "zone-1";

    fn setup_provider(endpoint: String) -> ExoscaleProvider {
        ExoscaleProvider::new("api_key", "api_secret", Some(Duration::from_secs(2)))
            .unwrap()
            .with_endpoint(endpoint)
    }

    fn valid_signature(request: &Request) -> bool {
        let Some(header) = request
            .header("authorization")
            .first()
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let Some(rest) = header.strip_prefix("EXO2-HMAC-SHA256 credential=api_key,expires=") else {
            return false;
        };
        let Some((expires, signature)) = rest.split_once(",signature=") else {
            return false;
        };
        let (Ok(expires), Ok(body)) = (expires.parse::<i64>(), request.utf8_lossy_body()) else {
            return false;
        };
        let expected = format!(
            "{} {}\n{}\n\n\n{}",
            request.method(),
            request.path(),
            body,
            expires
        );
        signature == BASE64_STANDARD.encode(hmac_sha256(b"api_secret", expected.as_bytes()))
    }

    fn mock_zone_lookup(server: &mut ServerGuard) -> Mock {
        server
            .mock("GET", "/dns-domain")
            .match_request(valid_signature)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"dns-domains":[{{"id":"{ZONE_ID}","unicode-name":"example.com"}}]}}"#
            ))
            .create()
    }

    fn mock_list(server: &mut ServerGuard, body: serde_json::Value) -> Mock {
        server
            .mock("GET", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_request(valid_signature)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&body).unwrap())
            .create()
    }

    fn ok_op_body() -> &'static str {
        r#"{"id":"op-1","state":"success"}"#
    }

    #[test]
    fn test_signing_string_matches_documented_layout() {
        assert_eq!(
            signing_string(
                "GET",
                "/v2/resource/a02baf5a-a3e4-49a0-857b-8a08d276c1c0",
                "",
                1599140767
            ),
            "GET /v2/resource/a02baf5a-a3e4-49a0-857b-8a08d276c1c0\n\n\n\n1599140767"
        );
        assert_eq!(
            signing_string(
                "POST",
                "/v2/security-group",
                r#"{"name": "my-security-group"}"#,
                1599140767
            ),
            "POST /v2/security-group\n{\"name\": \"my-security-group\"}\n\n\n1599140767"
        );
    }

    #[tokio::test]
    async fn test_signature_covers_body_and_endpoint_path_prefix() {
        let mut server = mockito::Server::new_async().await;
        let zone = server
            .mock("GET", "/v2/dns-domain")
            .match_request(valid_signature)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"dns-domains":[{{"id":"{ZONE_ID}","unicode-name":"example.com"}}]}}"#
            ))
            .create();
        let list = server
            .mock("GET", format!("/v2/dns-domain/{ZONE_ID}/record").as_str())
            .match_request(valid_signature)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"dns-domain-records":[]}"#)
            .create();
        let create = server
            .mock("POST", format!("/v2/dns-domain/{ZONE_ID}/record").as_str())
            .match_request(valid_signature)
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_op_body())
            .create();

        let provider = setup_provider(format!("{}/v2", server.url()));
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
    async fn test_set_rrset_creates_when_owner_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(&mut server, json!({"dns-domain-records": []}));

        let create_1 = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_request(valid_signature)
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_op_body())
            .create();

        let create_2 = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "content": "2.2.2.2",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_op_body())
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
        create_1.assert();
        create_2.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_is_noop_when_already_matches() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "r-1", "name": "host", "type": "A", "content": "1.1.1.1", "ttl": 300}
            ]}),
        );
        let _no_post = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dns-domain/{ZONE_ID}/record/")),
            )
            .expect(0)
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
    }

    #[tokio::test]
    async fn test_set_rrset_deletes_extras_and_creates_missing() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "rec-keep", "name": "host", "type": "A", "content": "1.1.1.1", "ttl": 300},
                {"id": "rec-stale", "name": "host", "type": "A", "content": "9.9.9.9", "ttl": 300}
            ]}),
        );

        let delete_stale = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/rec-stale").as_str(),
            )
            .match_request(valid_signature)
            .with_status(200)
            .with_body(ok_op_body())
            .create();

        let create_new = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "host",
                "type": "A",
                "content": "8.8.8.8",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_op_body())
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
        list.assert();
        delete_stale.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_empty_vec_deletes_all_records_of_type() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "rec-x", "name": "gone", "type": "A", "content": "1.2.3.4", "ttl": 300},
                {"id": "rec-y", "name": "gone", "type": "A", "content": "5.6.7.8", "ttl": 300},
                {"id": "rec-z", "name": "gone", "type": "TXT", "content": "\"keepme\"", "ttl": 300}
            ]}),
        );

        let delete_x = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/rec-x").as_str(),
            )
            .with_status(200)
            .with_body(ok_op_body())
            .create();
        let delete_y = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/rec-y").as_str(),
            )
            .with_status(200)
            .with_body(ok_op_body())
            .create();
        let must_not_delete_txt = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/rec-z").as_str(),
            )
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
        list.assert();
        delete_x.assert();
        delete_y.assert();
        must_not_delete_txt.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_cross_type_isolation() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "txt-1", "name": "shared", "type": "TXT", "content": "\"do-not-touch\"", "ttl": 300}
            ]}),
        );
        let must_not_delete_txt = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/txt-1").as_str(),
            )
            .expect(0)
            .create();

        let create_a = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "shared",
                "type": "A",
                "content": "1.2.3.4",
                "ttl": 300,
            })))
            .with_status(200)
            .with_body(ok_op_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "shared.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create_a.assert();
        must_not_delete_txt.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_apex_uses_empty_string_name() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(&mut server, json!({"dns-domain-records": []}));

        let create = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "MX",
                "content": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            })))
            .with_status(200)
            .with_body(ok_op_body())
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_type_mismatch_is_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::TXT("not-an-A".to_string())],
                "example.com",
            )
            .await;
        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    async fn test_set_rrset_tlsa_is_rejected() {
        let server = mockito::Server::new_async().await;
        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_25._tcp.mail.example.com",
                DnsRecordType::TLSA,
                300,
                vec![DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![0xaa],
                })],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unsupported(ref msg)) if msg.contains("TLSA")),
            "expected TLSA rejection, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_add_to_rrset_empty_vec_short_circuits() {
        let mut server = mockito::Server::new_async().await;
        let _no_calls = server.mock("GET", Matcher::Any).expect(0).create();

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
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "r-old", "name": "_acme", "type": "TXT", "content": "\"existing\"", "ttl": 60}
            ]}),
        );

        let create_new = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "_acme",
                "type": "TXT",
                "content": "\"new-token\"",
                "ttl": 60,
            })))
            .with_status(200)
            .with_body(ok_op_body())
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
        list.assert();
        create_new.assert();
    }

    #[tokio::test]
    async fn test_add_to_rrset_full_noop_when_all_present() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "r-1", "name": "host", "type": "A", "content": "1.1.1.1", "ttl": 300},
                {"id": "r-2", "name": "host", "type": "A", "content": "8.8.8.8", "ttl": 300}
            ]}),
        );
        let _no_post = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .add_to_rrset(
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
        assert!(result.is_ok(), "add_to_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_empty_vec_short_circuits() {
        let mut server = mockito::Server::new_async().await;
        let _no_calls = server.mock("GET", Matcher::Any).expect(0).create();
        let _no_delete = server.mock("DELETE", Matcher::Any).expect(0).create();

        let provider = setup_provider(server.url());
        let result = provider
            .remove_from_rrset("host.example.com", DnsRecordType::A, vec![], "example.com")
            .await;
        assert!(result.is_ok(), "remove_from_rrset returned: {result:?}");
    }

    #[tokio::test]
    async fn test_remove_from_rrset_deletes_only_matching_values() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "rec-keep", "name": "_acme", "type": "TXT", "content": "\"keep-me\"", "ttl": 300},
                {"id": "rec-drop", "name": "_acme", "type": "TXT", "content": "\"drop-me\"", "ttl": 300}
            ]}),
        );

        let delete = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/rec-drop").as_str(),
            )
            .with_status(200)
            .with_body(ok_op_body())
            .create();
        let must_not_delete_keep = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/rec-keep").as_str(),
            )
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
        list.assert();
        delete.assert();
        must_not_delete_keep.assert();
    }

    #[tokio::test]
    async fn test_remove_from_rrset_noop_when_value_absent() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "rec-1", "name": "host", "type": "A", "content": "1.1.1.1", "ttl": 300}
            ]}),
        );
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dns-domain/{ZONE_ID}/record/")),
            )
            .expect(0)
            .create();

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
    async fn test_list_rrset_filters_by_name_and_type() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "rec-a1", "name": "host", "type": "A", "content": "1.1.1.1", "ttl": 300},
                {"id": "rec-a2", "name": "host", "type": "A", "content": "2.2.2.2", "ttl": 300},
                {"id": "rec-txt", "name": "host", "type": "TXT", "content": "\"hi\"", "ttl": 300},
                {"id": "rec-other", "name": "elsewhere", "type": "A", "content": "9.9.9.9", "ttl": 300}
            ]}),
        );

        let provider = setup_provider(server.url());
        let records = provider
            .list_rrset("host.example.com", DnsRecordType::A, "example.com")
            .await
            .expect("list_rrset");
        assert_eq!(records.len(), 2, "expected 2 A records, got {records:?}");
        assert!(records.contains(&DnsRecord::A("1.1.1.1".parse().unwrap())));
        assert!(records.contains(&DnsRecord::A("2.2.2.2".parse().unwrap())));
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_srv_uses_priority_and_packed_content() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(&mut server, json!({"dns-domain-records": []}));

        let create = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "_imaps._tcp",
                "type": "SRV",
                "content": "5 993 mail.example.com.",
                "ttl": 300,
                "priority": 10,
            })))
            .with_status(200)
            .with_body(ok_op_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_imaps._tcp.example.com",
                DnsRecordType::SRV,
                300,
                vec![DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com.".to_string(),
                })],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_caa_bind_one_liner() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(&mut server, json!({"dns-domain-records": []}));

        let create = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::Json(json!({
                "name": "",
                "type": "CAA",
                "content": "0 issue \"letsencrypt.org\"",
                "ttl": 3600,
            })))
            .with_status(200)
            .with_body(ok_op_body())
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
        list.assert();
        create.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_txt_roundtrip_via_diff_is_noop() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "rec-1", "name": "_dmarc", "type": "TXT", "content": "\"v=DMARC1; p=none\"", "ttl": 300}
            ]}),
        );
        let _no_post = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .expect(0)
            .create();
        let _no_delete = server
            .mock(
                "DELETE",
                Matcher::Regex(format!("^/dns-domain/{ZONE_ID}/record/")),
            )
            .expect(0)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "_dmarc.example.com",
                DnsRecordType::TXT,
                300,
                vec![DnsRecord::TXT("v=DMARC1; p=none".to_string())],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
    }

    #[tokio::test]
    async fn test_set_rrset_replaces_two_mx_with_different_priorities() {
        let mut server = mockito::Server::new_async().await;
        let zone = mock_zone_lookup(&mut server);
        let list = mock_list(
            &mut server,
            json!({"dns-domain-records": [
                {"id": "old-mx", "name": "", "type": "MX", "content": "old.example.com", "ttl": 300, "priority": 5}
            ]}),
        );

        let delete_old = server
            .mock(
                "DELETE",
                format!("/dns-domain/{ZONE_ID}/record/old-mx").as_str(),
            )
            .with_status(200)
            .with_body(ok_op_body())
            .create();
        let create_primary = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "type": "MX",
                "content": "mx1.example.com",
                "priority": 10,
            })))
            .with_status(200)
            .with_body(ok_op_body())
            .create();
        let create_backup = server
            .mock("POST", format!("/dns-domain/{ZONE_ID}/record").as_str())
            .match_body(Matcher::PartialJson(json!({
                "type": "MX",
                "content": "mx2.example.com",
                "priority": 20,
            })))
            .with_status(200)
            .with_body(ok_op_body())
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "example.com",
                DnsRecordType::MX,
                3600,
                vec![
                    DnsRecord::MX(MXRecord {
                        exchange: "mx1.example.com".to_string(),
                        priority: 10,
                    }),
                    DnsRecord::MX(MXRecord {
                        exchange: "mx2.example.com".to_string(),
                        priority: 20,
                    }),
                ],
                "example.com",
            )
            .await;
        assert!(result.is_ok(), "set_rrset returned: {result:?}");
        zone.assert();
        list.assert();
        delete_old.assert();
        create_primary.assert();
        create_backup.assert();
    }

    #[tokio::test]
    async fn test_unauthorized_propagates() {
        let mut server = mockito::Server::new_async().await;
        let unauthorized = server
            .mock("GET", "/dns-domain")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"unauthorized"}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .set_rrset(
                "host.example.com",
                DnsRecordType::A,
                300,
                vec![DnsRecord::A("1.2.3.4".parse().unwrap())],
                "example.com",
            )
            .await;
        assert!(
            matches!(result, Err(Error::Unauthorized)),
            "expected Unauthorized, got {result:?}"
        );
        unauthorized.assert();
    }

    #[tokio::test]
    #[ignore = "requires EXOSCALE_API_KEY, EXOSCALE_API_SECRET, EXOSCALE_DOMAIN env vars"]
    async fn test_live_exoscale_rrset_roundtrip() {
        let api_key = std::env::var("EXOSCALE_API_KEY").expect("EXOSCALE_API_KEY");
        let api_secret = std::env::var("EXOSCALE_API_SECRET").expect("EXOSCALE_API_SECRET");
        let domain = std::env::var("EXOSCALE_DOMAIN").expect("EXOSCALE_DOMAIN");
        let provider =
            ExoscaleProvider::new(api_key, api_secret, Some(Duration::from_secs(30))).unwrap();

        let label = format!("dns-update-rrset-test.{domain}");
        let records = vec![
            DnsRecord::A("1.1.1.1".parse().unwrap()),
            DnsRecord::A("2.2.2.2".parse().unwrap()),
        ];

        provider
            .set_rrset(
                label.as_str(),
                DnsRecordType::A,
                60,
                records.clone(),
                domain.as_str(),
            )
            .await
            .expect("set_rrset");
        provider
            .set_rrset(
                label.as_str(),
                DnsRecordType::A,
                60,
                records,
                domain.as_str(),
            )
            .await
            .expect("set_rrset idempotent");
        let listed = provider
            .list_rrset(label.as_str(), DnsRecordType::A, domain.as_str())
            .await
            .expect("list_rrset");
        assert_eq!(listed.len(), 2);
        provider
            .set_rrset(
                label.as_str(),
                DnsRecordType::A,
                60,
                vec![],
                domain.as_str(),
            )
            .await
            .expect("set_rrset empty");
    }
}
