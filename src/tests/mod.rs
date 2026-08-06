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

pub mod alidns_tests;
pub mod arvancloud_tests;
pub mod autodns_tests;
pub mod azuredns_tests;
pub mod baiducloud_tests;
pub mod bluecatv2_tests;
pub mod bunny_test;
pub mod cloudflare_tests;
pub mod cloudns_tests;
pub mod constellix_tests;
pub mod cpanel_tests;
pub mod ddnss_tests;
pub mod desec_tests;
pub mod digitalocean_tests;
pub mod dnsimple_tests;
pub mod dnsmadeeasy_tests;
pub mod domeneshop_tests;
pub mod dreamhost_tests;
pub mod duckdns_tests;
pub mod dynu_tests;
pub mod easydns_tests;
#[cfg(test)]
pub mod edgedns_tests;
pub mod exoscale_tests;
pub mod freemyip_tests;
pub mod gandiv5_tests;
pub mod gcore_tests;
pub mod glesys_tests;
pub mod godaddy_tests;
pub mod google_cloud_dns_tests;
pub mod hetzner_tests;
pub mod hostingde_tests;
pub mod hostinger_tests;
pub mod huaweicloud_tests;
pub mod hurricane_tests;
pub mod ibmcloud_tests;
pub mod infoblox_tests;
pub mod infomaniak_tests;
pub mod inwx_tests;
pub mod ionos_tests;
pub mod ipv64_tests;
pub mod joker_tests;
#[cfg(test)]
pub mod lib_tests;
#[cfg(test)]
pub mod lightsail_tests;
pub mod linode_tests;
pub mod luadns_tests;
pub mod mythicbeasts_tests;
pub mod namecheap_tests;
pub mod namedotcom_tests;
pub mod namesilo_tests;
pub mod netcup_tests;
pub mod netlify_tests;
pub mod nifcloud_tests;
pub mod ns1_tests;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod oraclecloud_tests;
pub mod ovh_tests;
pub mod plesk_tests;
pub mod porkbun_tests;
#[cfg(test)]
pub mod rfc2136_tests;
#[cfg(test)]
pub mod route53_tests;
pub mod safedns_tests;
pub mod scaleway_tests;
pub mod simply_tests;
pub mod spaceship_tests;
pub mod tencentcloud_tests;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod transip_tests;
pub mod ultradns_tests;
pub mod vercel_tests;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod volcengine_tests;
pub mod vultr_tests;
pub mod websupport_tests;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod yandexcloud_tests;
