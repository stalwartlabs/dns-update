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

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn, NamedDnsRecord};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct InMemoryProvider {
    records: Arc<Mutex<Vec<NamedDnsRecord>>>,
}

impl InMemoryProvider {
    pub(crate) fn new(records: Arc<Mutex<Vec<NamedDnsRecord>>>) -> Self {
        Self { records }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let name = name.into_fqdn().into_owned();
        let mut store = self.records.lock().unwrap();
        store.retain(|r| !(r.name == name && r.record.as_type() == record_type));
        for record in records {
            store.push(NamedDnsRecord {
                name: name.clone(),
                record,
            });
        }
        Ok(())
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        _ttl: u32,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_fqdn().into_owned();
        let mut store = self.records.lock().unwrap();
        for record in records {
            let already_present = store.iter().any(|r| r.name == name && r.record == record);
            if !already_present {
                store.push(NamedDnsRecord {
                    name: name.clone(),
                    record,
                });
            }
        }
        Ok(())
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let name = name.into_fqdn().into_owned();
        let mut store = self.records.lock().unwrap();
        store.retain(|r| !(r.name == name && records.contains(&r.record)));
        Ok(())
    }

    pub(crate) async fn list_rrset(
        &self,
        _name: impl IntoFqdn<'_>,
        _record_type: DnsRecordType,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        Err(Error::Api(
            "InMemory does not support listing records".to_string(),
        ))
    }
}

fn check_record_types(expected: DnsRecordType, records: &[DnsRecord]) -> crate::Result<()> {
    for r in records {
        if r.as_type() != expected {
            return Err(Error::Api(format!(
                "RRSet record type mismatch: expected {}, got {}",
                expected.as_str(),
                r.as_type().as_str(),
            )));
        }
    }
    Ok(())
}
