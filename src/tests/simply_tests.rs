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
        CAARecord, DnsRecord, MXRecord, SRVRecord,
        providers::simply::{ExistingDnsRecord, SimplyRecordContent},
    };

    #[test]
    fn test_content_from_mx_splits_priority() {
        let content = SimplyRecordContent::try_from(DnsRecord::MX(MXRecord {
            exchange: "mail.example.com.".to_string(),
            priority: 10,
        }))
        .unwrap();
        assert_eq!(content.record_type, "MX");
        assert_eq!(content.data, "mail.example.com");
        assert_eq!(content.priority, Some(10));
    }

    #[test]
    fn test_content_from_srv_packs_weight_port_target() {
        let content = SimplyRecordContent::try_from(DnsRecord::SRV(SRVRecord {
            priority: 10,
            weight: 5,
            port: 993,
            target: "mail.example.com.".to_string(),
        }))
        .unwrap();
        assert_eq!(content.record_type, "SRV");
        assert_eq!(content.data, "5 993 mail.example.com");
        assert_eq!(content.priority, Some(10));
    }

    #[test]
    fn test_content_from_caa_uses_bind_string() {
        let content = SimplyRecordContent::try_from(DnsRecord::CAA(CAARecord::Issue {
            issuer_critical: false,
            name: Some("letsencrypt.org".to_string()),
            options: vec![],
        }))
        .unwrap();
        assert_eq!(content.record_type, "CAA");
        assert_eq!(content.data, "0 issue \"letsencrypt.org\"");
        assert_eq!(content.priority, None);
    }

    #[test]
    fn test_content_from_tlsa_uses_display_string() {
        let record = crate::utils::parse_tlsa("3 1 1 0123af").unwrap();
        let content = SimplyRecordContent::try_from(record).unwrap();
        assert_eq!(content.record_type, "TLSA");
        assert_eq!(content.data, "3 1 1 0123af");
    }

    #[test]
    fn test_existing_srv_record_parses_back() {
        let record = DnsRecord::try_from(ExistingDnsRecord {
            record_id: 1,
            name: "_imaps._tcp".to_string(),
            record_type: "SRV".to_string(),
            data: "5 993 mail.example.com".to_string(),
            priority: Some(10),
        })
        .unwrap();
        match record {
            DnsRecord::SRV(srv) => {
                assert_eq!(srv.priority, 10);
                assert_eq!(srv.weight, 5);
                assert_eq!(srv.port, 993);
                assert_eq!(srv.target, "mail.example.com");
            }
            other => panic!("expected SRV, got {other:?}"),
        }
    }

    #[test]
    fn test_existing_caa_record_parses_back() {
        let record = DnsRecord::try_from(ExistingDnsRecord {
            record_id: 2,
            name: "@".to_string(),
            record_type: "CAA".to_string(),
            data: "0 issue \"letsencrypt.org\"".to_string(),
            priority: None,
        })
        .unwrap();
        match record {
            DnsRecord::CAA(CAARecord::Issue {
                issuer_critical,
                name,
                ..
            }) => {
                assert!(!issuer_critical);
                assert_eq!(name.as_deref(), Some("letsencrypt.org"));
            }
            other => panic!("expected CAA Issue, got {other:?}"),
        }
    }
}
