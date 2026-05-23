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
        DnsRecord, DnsRecordType, DnsUpdater, Error, SRVRecord,
        providers::netcup::NetcupProvider,
    };
    use mockito::Matcher;
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider(endpoint: String) -> NetcupProvider {
        NetcupProvider::new(
            "12345",
            "key",
            "password",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    #[tokio::test]
    async fn test_create_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let login = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "login",
                "param": {"customernumber": "12345", "apikey": "key", "apipassword": "password"}
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{"apisessionid":"sess-1"}}"#)
            .create();

        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "domainname": "example.com",
                    "customernumber": "12345",
                    "apikey": "key",
                    "apisessionid": "sess-1",
                    "dnsrecordset": {
                        "dnsrecords": [{
                            "hostname": "test",
                            "type": "A",
                            "destination": "1.2.3.4"
                        }]
                    }
                }
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        login.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_delete_a_record_success() {
        let mut server = mockito::Server::new_async().await;

        let login = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"action": "login"})))
            .with_status(200)
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{"apisessionid":"sess-2"}}"#)
            .create();

        let info = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"action": "infoDnsRecords"})))
            .with_status(200)
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{"dnsrecords":[{"id":"99","hostname":"test","type":"A","destination":"1.2.3.4"}]}}"#)
            .create();

        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {"dnsrecordset": {"dnsrecords": [{"hostname": "test", "type": "A", "destination": "1.2.3.4", "deleterecord": true}]}}
            })))
            .with_status(200)
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::A)
            .await;

        assert!(result.is_ok(), "delete returned: {result:?}");
        login.assert();
        info.assert();
        update.assert();
    }

    #[tokio::test]
    async fn test_create_srv_record_uses_full_4_tuple_destination() {
        let mut server = mockito::Server::new_async().await;

        let _login = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({"action": "login"})))
            .with_status(200)
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{"apisessionid":"sess-3"}}"#)
            .create();

        let update = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "action": "updateDnsRecords",
                "param": {
                    "dnsrecordset": {
                        "dnsrecords": [{
                            "hostname": "_imaps._tcp",
                            "type": "SRV",
                            "destination": "10 5 993 mail.example.com.",
                        }]
                    }
                }
            })))
            .with_status(200)
            .with_body(r#"{"status":"success","statuscode":2000,"shortmessage":"ok","longmessage":"","responsedata":{}}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "_imaps._tcp.example.com",
                DnsRecord::SRV(SRVRecord {
                    priority: 10,
                    weight: 5,
                    port: 993,
                    target: "mail.example.com".to_string(),
                }),
                300,
                "example.com",
            )
            .await;

        assert!(result.is_ok(), "create returned: {result:?}");
        update.assert();
    }

    #[tokio::test]
    async fn test_login_failure_returns_error() {
        let mut server = mockito::Server::new_async().await;
        let _login = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"status":"error","statuscode":4001,"shortmessage":"bad credentials","longmessage":"check creds","responsedata":[]}"#)
            .create();

        let provider = setup_provider(server.url());
        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.2.3.4".parse().unwrap()),
                300,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))), "got {result:?}");
    }

    #[tokio::test]
    #[ignore = "Requires NETCUP_CUSTOMER_NUMBER, NETCUP_API_KEY, NETCUP_API_PASSWORD, NETCUP_ORIGIN, NETCUP_FQDN env vars"]
    async fn integration_test() {
        let customer = std::env::var("NETCUP_CUSTOMER_NUMBER").unwrap_or_default();
        let key = std::env::var("NETCUP_API_KEY").unwrap_or_default();
        let pass = std::env::var("NETCUP_API_PASSWORD").unwrap_or_default();
        let origin = std::env::var("NETCUP_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("NETCUP_FQDN").unwrap_or_default();
        assert!(!customer.is_empty(), "Set NETCUP_CUSTOMER_NUMBER");
        assert!(!key.is_empty(), "Set NETCUP_API_KEY");
        assert!(!pass.is_empty(), "Set NETCUP_API_PASSWORD");
        assert!(!origin.is_empty(), "Set NETCUP_ORIGIN");
        assert!(!fqdn.is_empty(), "Set NETCUP_FQDN");

        let updater = DnsUpdater::new_netcup(
            customer,
            key,
            pass,
            Some(Duration::from_secs(30)),
        )
        .unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }
}
