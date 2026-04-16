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
pub mod desec;
pub mod digitalocean;
pub mod dnsimple;
pub mod google_cloud_dns;
#[cfg(feature = "test_provider")]
pub mod in_memory;
pub mod ovh;
#[cfg(feature = "test_provider")]
pub mod pebble;
pub mod porkbun;
pub mod rfc2136;
pub mod spaceship;
pub mod spaceship;

impl DnsRecord {
    pub fn priority(&self) -> Option<u16> {
        match self {
            DnsRecord::MX(record) => Some(record.priority),
            DnsRecord::SRV(record) => Some(record.priority),
            _ => None,
        }
    }
}
