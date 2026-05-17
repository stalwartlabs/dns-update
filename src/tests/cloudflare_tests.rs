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
    use crate::{DnsRecord, DnsRecordType, DnsUpdater, providers::cloudflare::CloudflareProvider};
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "Requires Cloudflare API token, zone, and FQDN"]
    async fn integration_test() {
        let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
        let origin = std::env::var("CLOUDFLARE_ORIGIN").unwrap_or_default();
        let fqdn = std::env::var("CLOUDFLARE_FQDN").unwrap_or_default();

        assert!(
            !token.is_empty(),
            "Set CLOUDFLARE_API_TOKEN to run this test"
        );
        assert!(
            !origin.is_empty(),
            "Set CLOUDFLARE_ORIGIN to run this test (e.g. example.com)"
        );
        assert!(
            !fqdn.is_empty(),
            "Set CLOUDFLARE_FQDN to run this test (e.g. test.example.com)"
        );

        let updater =
            DnsUpdater::new_cloudflare(token, None::<&str>, Some(Duration::from_secs(30)))
                .unwrap();

        let create_result = updater
            .create(&fqdn, DnsRecord::A([1, 1, 1, 1].into()), 300, &origin)
            .await;
        assert!(create_result.is_ok(), "create failed: {create_result:?}");

        let update_result = updater
            .update(&fqdn, DnsRecord::A([8, 8, 8, 8].into()), 300, &origin)
            .await;
        assert!(update_result.is_ok(), "update failed: {update_result:?}");

        let delete_result = updater.delete(&fqdn, &origin, DnsRecordType::A).await;
        assert!(delete_result.is_ok(), "delete failed: {delete_result:?}");
    }

    #[test]
    fn provider_creation() {
        let provider = CloudflareProvider::new(
            "cf-mock-token",
            None::<&str>,
            Some(Duration::from_secs(1)),
        );

        assert!(provider.is_ok());
    }

    #[test]
    fn dns_updater_creation() {
        let updater = DnsUpdater::new_cloudflare(
            "cf-mock-token",
            None::<&str>,
            Some(Duration::from_secs(30)),
        );

        assert!(
            matches!(updater, Ok(DnsUpdater::Cloudflare(..))),
            "Expected Cloudflare updater to provide a Cloudflare provider"
        );
    }
}
