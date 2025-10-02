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
        strip_origin_from_name, ApiCacheFetcher, ApiCacheManager, DnsRecord, DnsRecordTrait,
    };
    use std::{
        hash::{Hash, Hasher},
        sync::Mutex,
    };

    #[test]
    fn test_strip_origin_from_name() {
        assert_eq!(
            strip_origin_from_name("www.example.com", "example.com"),
            "www"
        );
        assert_eq!(strip_origin_from_name("example.com", "example.com"), "@");
        assert_eq!(
            strip_origin_from_name("api.v1.example.com", "example.com"),
            "api.v1"
        );
        assert_eq!(
            strip_origin_from_name("example.com", "google.com"),
            "example.com"
        );
    }

    #[test]
    fn test_dns_record_trait() {
        let record = DnsRecord::A {
            content: "1.1.1.1".parse().unwrap(),
        };
        assert_eq!(record.get_content().as_str(), "1.1.1.1");
        assert_eq!(record.get_type(), "A");

        let record = DnsRecord::AAAA {
            content: "2001:db8::1".parse().unwrap(),
        };
        assert_eq!(record.get_content().as_str(), "2001:db8::1");
        assert_eq!(record.get_type(), "AAAA");

        let record = DnsRecord::TXT {
            content: "test".to_string(),
        };
        assert_eq!(record.get_content().as_str(), "test");
        assert_eq!(record.get_type(), "TXT");

        let record = DnsRecord::MX {
            priority: 10,
            content: "mail.example.com".to_string(),
        };
        assert_eq!(record.get_content().as_str(), "mail.example.com");
        assert_eq!(record.get_priority(), Some(10));
        assert_eq!(record.get_type(), "MX");

        let record = DnsRecord::SRV {
            priority: 10,
            weight: 20,
            port: 443,
            content: "sip.example.com".to_string(),
        };
        assert_eq!(record.get_content().as_str(), "sip.example.com");
        assert_eq!(record.get_priority(), Some(10));
        assert_eq!(record.get_weight(), Some(20));
        assert_eq!(record.get_port(), Some(443));
        assert_eq!(record.get_type(), "SRV");
    }

    static LIBTEST_PR_SEQ: Mutex<Vec<i64>> = Mutex::new(Vec::new());

    #[derive(Clone, Default)]
    pub struct LibTestProvider {
        cache: ApiCacheManager<i64>,
    }

    pub struct LibTestZoneFetcher<'a> {
        origin: &'a str,
    }

    impl<'a> ApiCacheFetcher<i64> for LibTestZoneFetcher<'a> {
        async fn fetch_api_response(&mut self) -> crate::Result<i64> {
            let fe = || crate::Error::Api("No more entries left in SEQ!".to_string());
            LIBTEST_PR_SEQ.lock().unwrap().pop().ok_or_else(fe)
        }
    }

    impl Hash for LibTestZoneFetcher<'_> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.origin.hash(state);
        }
    }

    #[tokio::test]
    async fn test_api_cache_manager() {
        let provider = LibTestProvider::default();
        let mut app = vec![3000000, 20000, 100];
        LIBTEST_PR_SEQ.lock().unwrap().append(&mut app);
        // `provider.create` returns the same random value from its API cache
        //  when passed the same key in successive calls. Observe:
        assert_eq!(provider.create("first-entry/").await, Ok(100));
        assert_eq!(provider.create("first-entry/").await, Ok(100));
        assert_eq!(provider.create("first-entry/").await, Ok(100));
        assert_eq!(provider.create("second-entry/").await, Ok(20000));
        assert_eq!(provider.create("second-entry/").await, Ok(20000));
        assert_eq!(provider.create("second-entry/").await, Ok(20000));
        assert_eq!(provider.create("third-entry/").await, Ok(3000000));
        assert_eq!(provider.create("third-entry/").await, Ok(3000000));
        assert_eq!(provider.create("third-entry/").await, Ok(3000000));
    }

    impl LibTestProvider {
        pub(crate) async fn create(&self, origin: &str) -> crate::Result<i64> {
            let mut fet = LibTestZoneFetcher { origin };
            self.cache.get_or_update(&mut fet).await
        }
    }
}
