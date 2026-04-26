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
        providers::gandi::{GandiProvider, GandiRecordFormat},
    };
    use serde_json::json;
    use std::time::Duration;

    fn setup_provider() -> GandiProvider {
        GandiProvider::new(
            "test_token",
            Some(Duration::from_secs(1)),
        )
        .unwrap()
    }

    #[test]
    fn test_gandi_provider_creation() {
        let provider = GandiProvider::new(
            "test_token",
            Some(Duration::from_secs(30)),
        );

        assert!(provider.is_ok());
    }

    #[test]
    fn test_dns_updater_gandi_creation() {
        let updater = DnsUpdater::new_gandi(
            "test_token",
            Some(Duration::from_secs(30)),
        );

        assert!(updater.is_ok());

        match updater.unwrap() {
            DnsUpdater::Gandi(_) => (),
            _ => panic!("Expected Gandi provider"),
        }
    }

    #[test]
    fn test_gandi_record_format_from_dns_record() {
        let record = DnsRecord::A("1.1.1.1".parse().unwrap());
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "A");
        assert_eq!(gandi_record.value, "1.1.1.1");

        let record = DnsRecord::AAAA("2001:db8::1".parse().unwrap());
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "AAAA");
        assert_eq!(gandi_record.value, "2001:db8::1");

        let record = DnsRecord::CNAME("alias.example.com".to_string());
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "CNAME");
        assert_eq!(gandi_record.value, "alias.example.com");

        let record = DnsRecord::MX(MXRecord {
            exchange: "mail.example.com".to_string(),
            priority: 10,
        });
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "MX");
        assert_eq!(gandi_record.value, "10 mail.example.com");

        let record = DnsRecord::TXT("\"v=spf1 include:_spf.example.com ~all\"".to_string());
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "TXT");
        assert_eq!(gandi_record.value, "\"v=spf1 include:_spf.example.com ~all\"");

        let record = DnsRecord::TXT("v=spf1 include:_spf.example.com ~all".to_string());
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "TXT");
        assert_eq!(gandi_record.value, "v=spf1 include:_spf.example.com ~all");

        let record = DnsRecord::SRV(SRVRecord {
            target: "sip.example.com".to_string(),
            priority: 10,
            weight: 20,
            port: 443,
        });
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "SRV");
        assert_eq!(gandi_record.value, "10 20 443 sip.example.com");

        let record = DnsRecord::NS("ns1.example.com".to_string());
        let gandi_record: GandiRecordFormat = (&record).into();
        assert_eq!(gandi_record.kind, "NS");
        assert_eq!(gandi_record.value, "ns1.example.com");
    }

    #[tokio::test]
    async fn test_create_record_success() {
        let mut server = mockito::Server::new_async().await;

        let create_mock = server
            .mock("POST", "/domains/example.com/records/test/A")
            .with_status(200)
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "rrset_values": ["1.1.1.1"],
                "rrset_ttl": 3600
            })))
            .with_body(r#"{"message": "SUCCESS"}"#)
            .create();

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(result.is_ok());
        create_mock.assert();
    }

    #[tokio::test]
    async fn test_update_record_success() {
        let mut server = mockito::Server::new_async().await;

        let update_mock = server
            .mock("PUT", "/domains/example.com/records/test/A")
            .with_status(200)
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({
                "rrset_values": ["2.2.2.2"],
                "rrset_ttl": 3600
            })))
            .with_body(r#"{"message": "SUCCESS"}"#)
            .create();

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .update(
                "test.example.com",
                DnsRecord::A("2.2.2.2".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        dbg!(&result);
        assert!(result.is_ok());
        update_mock.assert();
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mut server = mockito::Server::new_async().await;

        let delete_mock = server
            .mock("DELETE", "/domains/example.com/records/test/TXT")
            .with_status(200)
            .match_header("authorization", "Bearer test_token")
            .match_header("content-type", "application/json")
            .with_body(r#"{"message": "SUCCESS"}"#)
            .create();

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .delete("test.example.com", "example.com", DnsRecordType::TXT)
            .await;

        assert!(result.is_ok());
        delete_mock.assert();
    }

    #[tokio::test]
    async fn test_create_record_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let zone_mock = server
            .mock("POST", "/domains/example.com/records/test/A")
            .with_status(401)
            .match_header("authorization", "Bearer test_token")
            .with_body(r#"{"message": "Invalid credentials"}"#)
            .create();

        let mut provider = setup_provider();
        provider.endpoint = server.url();

        let result = provider
            .create(
                "test.example.com",
                DnsRecord::A("1.1.1.1".parse().unwrap()),
                3600,
                "example.com",
            )
            .await;

        assert!(matches!(result, Err(Error::Api(_))));
        zone_mock.assert();
    }

    #[tokio::test]
    #[ignore = "Requires Gandi API credentials and domain configuration"]
    async fn integration_test() {
        let token = std::env::var("GANDIV5_PERSONAL_ACCESS_TOKEN").unwrap_or_default();
        let origin = std::env::var("GANDIV5_ORIGIN").unwrap_or_default();
        let domain = std::env::var("GANDIV5_DOMAIN").unwrap_or_default();

        assert!(
            !token.is_empty(),
            "Please configure your Gandi application key in the integration test"
        );
        assert!(
            !origin.is_empty(),
            "Please configure your domain in the integration test"
        );
        assert!(
            !domain.is_empty(),
            "Please configure your test subdomain in the integration test"
        );

        let updater = DnsUpdater::new_gandi(
            token,
            Some(Duration::from_secs(30)),
        )
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

        let deletion_result = updater.delete(&domain, &origin, DnsRecordType::A).await;

        assert!(deletion_result.is_ok());

        let tlsa_result = updater
            .create(
                &domain,
                DnsRecord::TLSA(TLSARecord {
                    cert_usage: TlsaCertUsage::DaneEe,
                    selector: TlsaSelector::Spki,
                    matching: TlsaMatching::Sha256,
                    cert_data: vec![
                        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
                        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                    ],
                }),
                3600,
                &origin,
            )
            .await;

        assert!(tlsa_result.is_ok());

        let tlsa_deletion_result = updater.delete(&domain, &origin, DnsRecordType::TLSA).await;

        assert!(tlsa_deletion_result.is_ok());

        let caa_result = updater
            .create(
                &domain,
                DnsRecord::CAA(CAARecord::Issue {
                    issuer_critical: false,
                    name: Some("letsencrypt.org".to_string()),
                    options: vec![],
                }),
                3600,
                &origin,
            )
            .await;

        assert!(caa_result.is_ok());

        let caa_deletion_result = updater.delete(&domain, &origin, DnsRecordType::CAA).await;

        assert!(caa_deletion_result.is_ok());
    }
}
