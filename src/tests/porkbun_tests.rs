// /*
//  * Copyright Stalwart Labs LLC See the COPYING
//  * file at the top-level directory of this distribution.
//  *
//  * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
//  * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
//  * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
//  * option. This file may not be copied, modified, or distributed
//  * except according to those terms.
//  */
#[cfg(test)]
mod tests {
    use crate::{
        DnsRecord, DnsRecordType, DnsUpdater, MXRecord, SRVRecord,
        providers::porkbun::{PorkBunProvider, RecordData},
    };
    use serde_json::json;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    fn setup_provider(endpoint: &str) -> PorkBunProvider {
        PorkBunProvider::new(
            "test_api_key",
            "test_secret_api_key",
            Some(Duration::from_secs(1)),
        )
        .with_endpoint(endpoint)
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_porkbun(
            "test_api_key-mock-api-key",
            "test_secret_api_key",
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());

        assert!(
            matches!(updater, Ok(DnsUpdater::Porkbun(..))),
            "Expected Porkbun updater to provide a Porkbun provider"
        );
    }

    #[test]
    fn record_data_from_dns_record() {
        let record = DnsRecord::A("1.1.1.1".parse().unwrap());

        let porkbun_record: RecordData = record.into();
        if let RecordData::A { content } = porkbun_record {
            assert_eq!(content, "1.1.1.1".parse::<Ipv4Addr>().unwrap());
        } else {
            panic!("Expected A type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "A");

        let record = DnsRecord::AAAA("2001:db8::1".parse().unwrap());
        let porkbun_record: RecordData = record.into();
        if let RecordData::AAAA { content } = porkbun_record {
            assert_eq!(content, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("Expected AAAA type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "AAAA");

        let record = DnsRecord::CNAME("alias.example.com".to_string());
        let porkbun_record: RecordData = record.into();
        if let RecordData::CNAME { ref content } = porkbun_record {
            assert_eq!(content, "alias.example.com");
        } else {
            panic!("Expected CNAME type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "CNAME");

        let record = DnsRecord::MX(MXRecord {
            exchange: "mail.example.com".to_string(),
            priority: 10,
        });
        let porkbun_record: RecordData = record.into();
        if let RecordData::MX { prio, ref content } = porkbun_record {
            assert_eq!(prio, 10);
            assert_eq!(content, "mail.example.com");
        } else {
            panic!("Expected MX type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "MX");

        let record = DnsRecord::TXT("v=spf1 include:_spf.example.com ~all".to_string());
        let porkbun_record: RecordData = record.into();
        if let RecordData::TXT { ref content } = porkbun_record {
            assert_eq!(content, "v=spf1 include:_spf.example.com ~all");
        } else {
            panic!("Expected TXT type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "TXT");

        let record = DnsRecord::SRV(SRVRecord {
            target: "sip.example.com".to_string(),
            priority: 10,
            weight: 20,
            port: 443,
        });
        let porkbun_record: RecordData = record.into();
        if let RecordData::SRV { prio, ref content } = porkbun_record {
            assert_eq!(prio, 10);
            assert_eq!(content, "20 443 sip.example.com");
        } else {
            panic!("Expected SRV type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "SRV");

        let record = DnsRecord::NS("ns1.example.com".to_string());
        let porkbun_record: RecordData = record.into();
        if let RecordData::NS { ref content } = porkbun_record {
            assert_eq!(content, "ns1.example.com");
        } else {
            panic!("Expected NS type record, got {:?}", porkbun_record);
        }
        assert_eq!(porkbun_record.variant_name(), "NS");
    }

    #[tokio::test]
    async fn create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/dns/create/example.com")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "name": "test",
                "type": "A",
                "content": "1.1.1.1",
                "ttl": 3600,
            })))
            .with_body(r#"{"status": "SUCCESS","id": "106926659"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/dns/editByNameType/example.com/AAAA/www")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
                "name": "www",
                "type": "AAAA",
                "content": "2001:db8::1",
                "ttl": 3600,
            })))
            .with_body(r#"{"status": "SUCCESS"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .update(
                "www.example.com",
                DnsRecord::AAAA("2001:db8::1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    async fn delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/dns/deleteByNameType/example.com/TXT/test")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "apikey": "test_api_key",
                "secretapikey": "test_secret_api_key",
            })))
            .with_body(r#"{"status": "SUCCESS"}"#)
            .create();

        let provider = setup_provider(server.url().as_str());

        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Porkbun API credentials and domain configuration"]
    async fn integration_test() {
        let api_key = std::env::var("PB_API_KEY").unwrap_or_default();
        let secret_api_key = std::env::var("PB_SECRET_API_KEY").unwrap_or_default();
        let origin = std::env::var("PB_ORIGIN").unwrap_or_default();
        let domain = std::env::var("PB_DOMAIN").unwrap_or_default();

        assert!(
            !api_key.is_empty(),
            "Please configure your Porkbun API key in the integration test"
        );
        assert!(
            !secret_api_key.is_empty(),
            "Please configure your Porkbun secret API key in the integration test"
        );
        assert!(
            !origin.is_empty(),
            "Please configure your domain in the integration test"
        );
        assert!(
            !domain.is_empty(),
            "Please configure your test domain in the integration test"
        );

        let updater =
            DnsUpdater::new_porkbun(api_key, secret_api_key, Some(Duration::from_secs(30)))
                .unwrap();

        let creation_result = updater
            .create(
                &domain,
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                &origin,
            )
            .await;

        assert!(creation_result.is_ok());

        let update_result = updater
            .update(
                &domain,
                DnsRecord::A("2.2.2.2".parse().unwrap()),
                3600,
                &origin,
            )
            .await;

        assert!(update_result.is_ok());

        let deletion_result = updater.delete(domain, origin, DnsRecordType::A).await;

        assert!(deletion_result.is_ok());
    }
}
