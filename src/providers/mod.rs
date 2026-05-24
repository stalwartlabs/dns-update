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

use crate::DnsRecord;

pub mod alidns;
pub mod arvancloud;
pub mod autodns;
pub mod azuredns;
pub mod baiducloud;
pub mod bluecatv2;
pub mod bunny;
pub mod cloudflare;
pub mod cloudns;
pub mod constellix;
pub mod cpanel;
pub mod ddnss;
pub mod desec;
pub mod digitalocean;
pub mod dnsimple;
pub mod dnsmadeeasy;
pub mod domeneshop;
pub mod dreamhost;
pub mod duckdns;
pub mod dynu;
pub mod easydns;
pub mod edgedns;
pub mod exoscale;
pub mod freemyip;
pub mod gandiv5;
pub mod gcore;
pub mod glesys;
pub mod godaddy;
pub mod google_cloud_dns;
pub mod hetzner;
pub mod hostingde;
pub mod hostinger;
pub mod huaweicloud;
pub mod hurricane;
pub mod ibmcloud;
#[cfg(feature = "test_provider")]
pub mod in_memory;
pub mod infoblox;
pub mod infomaniak;
pub mod inwx;
pub mod ionos;
pub mod ipv64;
pub mod joker;
pub mod lightsail;
pub mod linode;
pub mod luadns;
pub mod mythicbeasts;
pub mod namecheap;
pub mod namedotcom;
pub mod namesilo;
pub mod netcup;
pub mod netlify;
pub mod nifcloud;
pub mod ns1;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod oraclecloud;
pub mod ovh;
#[cfg(feature = "test_provider")]
pub mod pebble;
pub mod plesk;
pub mod porkbun;
pub mod rfc2136;
pub mod route53;
pub mod safedns;
pub mod scaleway;
pub mod spaceship;
pub mod tencentcloud;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod transip;
pub mod ultradns;
pub mod vercel;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod volcengine;
pub mod vultr;
pub mod websupport;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub mod yandexcloud;

impl DnsRecord {
    pub fn priority(&self) -> Option<u16> {
        match self {
            DnsRecord::MX(record) => Some(record.priority),
            DnsRecord::SRV(record) => Some(record.priority),
            _ => None,
        }
    }
}
