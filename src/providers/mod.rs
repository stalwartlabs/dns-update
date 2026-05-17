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

pub mod bunny;
pub mod cloudflare;
pub mod ddnss;
pub mod desec;
pub mod digitalocean;
pub mod dnsimple;
pub mod gandiv5;
pub mod gcore;
pub mod godaddy;
pub mod duckdns;
pub mod dynu;
pub mod freemyip;
pub mod google_cloud_dns;
pub mod hetzner;
pub mod namedotcom;
pub mod namesilo;
#[cfg(feature = "test_provider")]
pub mod in_memory;
pub mod linode;
pub mod ipv64;
pub mod hostingde;
pub mod infomaniak;
pub mod ionos;
pub mod netcup;
pub mod netlify;
pub mod ovh;
#[cfg(feature = "test_provider")]
pub mod pebble;
pub mod porkbun;
pub mod rfc2136;
pub mod route53;
pub mod scaleway;
pub mod spaceship;
pub mod vercel;
pub mod vultr;

impl DnsRecord {
    pub fn priority(&self) -> Option<u16> {
        match self {
            DnsRecord::MX(record) => Some(record.priority),
            DnsRecord::SRV(record) => Some(record.priority),
            _ => None,
        }
    }
}
