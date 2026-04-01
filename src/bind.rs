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

use crate::{DnsRecord, IntoFqdn, NamedDnsRecord};
use std::fmt::Write;

pub struct BindSerializer;

impl BindSerializer {
    pub fn serialize(records: &[NamedDnsRecord]) -> String {
        let mut output = String::new();
        for named in records {
            let name = &named.name;
            match &named.record {
                DnsRecord::A(addr) => {
                    writeln!(output, "{name} IN A {addr}").unwrap();
                }
                DnsRecord::AAAA(addr) => {
                    writeln!(output, "{name} IN AAAA {addr}").unwrap();
                }
                DnsRecord::CNAME(cname) => {
                    writeln!(output, "{name} IN CNAME {}", cname.into_fqdn()).unwrap();
                }
                DnsRecord::NS(ns) => {
                    writeln!(output, "{name} IN NS {}", ns.into_fqdn()).unwrap();
                }
                DnsRecord::MX(mx) => {
                    writeln!(
                        output,
                        "{name} IN MX {} {}",
                        mx.priority,
                        (&mx.exchange).into_fqdn()
                    )
                    .unwrap();
                }
                DnsRecord::TXT(text) => {
                    write!(output, "{name} IN TXT ").unwrap();
                    if text.len() <= 255 {
                        writeln!(output, "\"{}\"", escape_txt(text)).unwrap();
                    } else {
                        writeln!(output, "(").unwrap();
                        for chunk in text.as_bytes().chunks(255) {
                            let chunk_str = String::from_utf8_lossy(chunk);
                            writeln!(output, "    \"{}\"", escape_txt(&chunk_str)).unwrap();
                        }
                        writeln!(output, ")").unwrap();
                    }
                }
                DnsRecord::SRV(srv) => {
                    writeln!(
                        output,
                        "{name} IN SRV {} {} {} {}",
                        srv.priority,
                        srv.weight,
                        srv.port,
                        (&srv.target).into_fqdn()
                    )
                    .unwrap();
                }
                DnsRecord::TLSA(tlsa) => {
                    writeln!(output, "{name} IN TLSA {tlsa}").unwrap();
                }
                DnsRecord::CAA(caa) => {
                    writeln!(output, "{name} IN CAA {caa}").unwrap();
                }
            }
        }
        output
    }
}

#[inline(always)]
fn escape_txt(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
