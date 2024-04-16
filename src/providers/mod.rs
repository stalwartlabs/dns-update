/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::DnsRecord;

pub mod cloudflare;
pub mod rfc2136;

impl DnsRecord {
    pub fn priority(&self) -> Option<u16> {
        match self {
            DnsRecord::MX { priority, .. } => Some(*priority),
            DnsRecord::SRV { priority, .. } => Some(*priority),
            _ => None,
        }
    }
}
