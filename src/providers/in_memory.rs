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

use crate::{DnsRecord, DnsRecordType, IntoFqdn, NamedDnsRecord};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct InMemoryProvider {
    records: Arc<Mutex<Vec<NamedDnsRecord>>>,
}

impl InMemoryProvider {
    pub(crate) fn new(records: Arc<Mutex<Vec<NamedDnsRecord>>>) -> Self {
        Self { records }
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_fqdn().into_owned();
        self.records.lock().unwrap().push(NamedDnsRecord { name, record });
        Ok(())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        _ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_fqdn().into_owned();
        let record_type = record.as_type();
        let mut records = self.records.lock().unwrap();

        if let Some(existing) = records
            .iter_mut()
            .find(|r| r.name == name && r.record.as_type() == record_type)
        {
            existing.record = record;
        } else {
            records.push(NamedDnsRecord { name, record });
        }

        Ok(())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_fqdn().into_owned();
        self.records
            .lock()
            .unwrap()
            .retain(|r| !(r.name == name && r.record.as_type() == record));
        Ok(())
    }
}
