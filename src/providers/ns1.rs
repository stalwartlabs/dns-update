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

use crate::{
    CAARecord, DnsRecord, DnsRecordType, Error, IntoFqdn, KeyValue, MXRecord, SRVRecord,
    TLSARecord, TlsaCertUsage, TlsaMatching, TlsaSelector,
    http::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_API_ENDPOINT: &str = "https://api.nsone.net/v1";
const RETRIES: u32 = 3;

#[derive(Clone)]
pub struct Ns1Provider {
    client: HttpClient,
    endpoint: String,
}

#[derive(Serialize, Debug)]
struct RecordBody<'a> {
    zone: &'a str,
    domain: &'a str,
    #[serde(rename = "type")]
    rr_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    answers: Vec<Answer>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Answer {
    answer: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct EmptyResponse {}

#[derive(Deserialize, Debug)]
struct ListedRecord {
    #[serde(default)]
    answers: Vec<Answer>,
    #[serde(default)]
    ttl: Option<u32>,
}

impl Ns1Provider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> Self {
        let client = HttpClientBuilder::default()
            .with_header("X-NSONE-Key", api_key.as_ref())
            .with_timeout(timeout)
            .build();
        Self {
            client,
            endpoint: DEFAULT_API_ENDPOINT.to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    pub(crate) async fn set_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record_type.as_str();

        if records.is_empty() {
            return self.delete_rrset(&zone, &domain, rr_type).await;
        }

        let answers = records_to_answers(records)?;
        let exists = self.fetch_rrset(&zone, &domain, rr_type).await?.is_some();
        self.write_rrset(&zone, &domain, rr_type, ttl, answers, exists)
            .await
    }

    pub(crate) async fn add_to_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        ttl: u32,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let incoming = records_to_answers(records)?;

        let existing = self.fetch_rrset(&zone, &domain, rr_type).await?;
        let exists = existing.is_some();
        let (mut merged, effective_ttl) = match existing {
            Some(rec) => {
                let existing_ttl = rec.ttl.unwrap_or(ttl);
                (rec.answers, existing_ttl)
            }
            None => (Vec::new(), ttl),
        };
        let before = merged.len();
        for answer in incoming {
            if !merged.contains(&answer) {
                merged.push(answer);
            }
        }
        if merged.is_empty() {
            return Ok(());
        }
        if exists && merged.len() == before {
            return Ok(());
        }
        self.write_rrset(&zone, &domain, rr_type, effective_ttl, merged, exists)
            .await
    }

    pub(crate) async fn remove_from_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        records: Vec<DnsRecord>,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        check_record_types(record_type, &records)?;
        if records.is_empty() {
            return Ok(());
        }
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record_type.as_str();
        let to_remove = records_to_answers(records)?;

        let Some(existing) = self.fetch_rrset(&zone, &domain, rr_type).await? else {
            return Ok(());
        };

        let remaining: Vec<Answer> = existing
            .answers
            .into_iter()
            .filter(|answer| !to_remove.contains(answer))
            .collect();

        if remaining.is_empty() {
            return self.delete_rrset(&zone, &domain, rr_type).await;
        }

        let ttl = existing.ttl.unwrap_or(0);
        self.write_rrset(&zone, &domain, rr_type, ttl, remaining, true)
            .await
    }

    pub(crate) async fn list_rrset(
        &self,
        name: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<Vec<DnsRecord>> {
        let zone = origin.into_name().to_string();
        let domain = name.into_name().to_string();
        let rr_type = record_type.as_str();

        let Some(record) = self.fetch_rrset(&zone, &domain, rr_type).await? else {
            return Ok(Vec::new());
        };

        let mut out = Vec::with_capacity(record.answers.len());
        for answer in record.answers {
            out.push(answer_to_record(record_type, &answer)?);
        }
        Ok(out)
    }

    fn rrset_url(&self, zone: &str, domain: &str, rr_type: &str) -> String {
        format!(
            "{endpoint}/zones/{zone}/{domain}/{rr_type}",
            endpoint = self.endpoint,
        )
    }

    async fn fetch_rrset(
        &self,
        zone: &str,
        domain: &str,
        rr_type: &str,
    ) -> crate::Result<Option<ListedRecord>> {
        match self
            .client
            .get(self.rrset_url(zone, domain, rr_type))
            .send_with_retry::<ListedRecord>(RETRIES)
            .await
        {
            Ok(record) => Ok(Some(record)),
            Err(Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn write_rrset(
        &self,
        zone: &str,
        domain: &str,
        rr_type: &str,
        ttl: u32,
        answers: Vec<Answer>,
        exists: bool,
    ) -> crate::Result<()> {
        let body = RecordBody {
            zone,
            domain,
            rr_type,
            ttl: Some(ttl),
            answers,
        };
        let url = self.rrset_url(zone, domain, rr_type);
        let request = if exists {
            self.client.post(url)
        } else {
            self.client.put(url)
        };
        request
            .with_body(body)?
            .send_with_retry::<EmptyResponse>(RETRIES)
            .await
            .map(|_| ())
    }

    async fn delete_rrset(&self, zone: &str, domain: &str, rr_type: &str) -> crate::Result<()> {
        match self
            .client
            .delete(self.rrset_url(zone, domain, rr_type))
            .send_raw()
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
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

fn records_to_answers(records: Vec<DnsRecord>) -> crate::Result<Vec<Answer>> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let answers = record_to_answers(record)?;
        out.extend(answers);
    }
    Ok(out)
}

fn record_to_answers(record: DnsRecord) -> crate::Result<Vec<Answer>> {
    let parts: Vec<String> = match record {
        DnsRecord::A(addr) => vec![addr.to_string()],
        DnsRecord::AAAA(addr) => vec![addr.to_string()],
        DnsRecord::CNAME(content) => vec![content],
        DnsRecord::NS(content) => vec![content],
        DnsRecord::TXT(content) => vec![content],
        DnsRecord::MX(mx) => vec![mx.priority.to_string(), mx.exchange],
        DnsRecord::SRV(srv) => vec![
            srv.priority.to_string(),
            srv.weight.to_string(),
            srv.port.to_string(),
            srv.target,
        ],
        DnsRecord::TLSA(tlsa) => vec![
            u8::from(tlsa.cert_usage).to_string(),
            u8::from(tlsa.selector).to_string(),
            u8::from(tlsa.matching).to_string(),
            tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect(),
        ],
        DnsRecord::CAA(caa) => {
            let (flags, tag, value) = caa.decompose();
            vec![flags.to_string(), tag, value]
        }
    };

    if parts.is_empty() {
        return Err(Error::Api("Empty record data for NS1".to_string()));
    }
    Ok(vec![Answer { answer: parts }])
}

fn answer_to_record(record_type: DnsRecordType, answer: &Answer) -> crate::Result<DnsRecord> {
    let fields = &answer.answer;
    let need = |idx: usize| -> crate::Result<&String> {
        fields.get(idx).ok_or_else(|| {
            Error::Parse(format!(
                "NS1 {} answer is missing field {}",
                record_type.as_str(),
                idx,
            ))
        })
    };

    Ok(match record_type {
        DnsRecordType::A => DnsRecord::A(
            need(0)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 A value: {e}")))?,
        ),
        DnsRecordType::AAAA => DnsRecord::AAAA(
            need(0)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 AAAA value: {e}")))?,
        ),
        DnsRecordType::CNAME => DnsRecord::CNAME(need(0)?.clone()),
        DnsRecordType::NS => DnsRecord::NS(need(0)?.clone()),
        DnsRecordType::TXT => DnsRecord::TXT(need(0)?.clone()),
        DnsRecordType::MX => DnsRecord::MX(MXRecord {
            priority: need(0)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 MX priority: {e}")))?,
            exchange: need(1)?.clone(),
        }),
        DnsRecordType::SRV => DnsRecord::SRV(SRVRecord {
            priority: need(0)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 SRV priority: {e}")))?,
            weight: need(1)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 SRV weight: {e}")))?,
            port: need(2)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 SRV port: {e}")))?,
            target: need(3)?.clone(),
        }),
        DnsRecordType::TLSA => DnsRecord::TLSA(TLSARecord {
            cert_usage: tlsa_cert_usage_from_str(need(0)?)?,
            selector: tlsa_selector_from_str(need(1)?)?,
            matching: tlsa_matching_from_str(need(2)?)?,
            cert_data: decode_hex(need(3)?)?,
        }),
        DnsRecordType::CAA => {
            let flags: u8 = need(0)?
                .parse()
                .map_err(|e| Error::Parse(format!("invalid NS1 CAA flags: {e}")))?;
            let tag = need(1)?.to_ascii_lowercase();
            let value = need(2)?.clone();
            DnsRecord::CAA(build_caa(flags, &tag, value)?)
        }
    })
}

fn decode_hex(hex: &str) -> crate::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Parse(format!("invalid hex string: {hex}")));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::Parse(format!("invalid hex byte: {e}")))
        })
        .collect()
}

fn tlsa_cert_usage_from_str(value: &str) -> crate::Result<TlsaCertUsage> {
    let n: u8 = value
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA cert usage '{value}': {e}")))?;
    Ok(match n {
        0 => TlsaCertUsage::PkixTa,
        1 => TlsaCertUsage::PkixEe,
        2 => TlsaCertUsage::DaneTa,
        3 => TlsaCertUsage::DaneEe,
        255 => TlsaCertUsage::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA cert usage: {n}"))),
    })
}

fn tlsa_selector_from_str(value: &str) -> crate::Result<TlsaSelector> {
    let n: u8 = value
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA selector '{value}': {e}")))?;
    Ok(match n {
        0 => TlsaSelector::Full,
        1 => TlsaSelector::Spki,
        255 => TlsaSelector::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA selector: {n}"))),
    })
}

fn tlsa_matching_from_str(value: &str) -> crate::Result<TlsaMatching> {
    let n: u8 = value
        .parse()
        .map_err(|e| Error::Parse(format!("invalid TLSA matching '{value}': {e}")))?;
    Ok(match n {
        0 => TlsaMatching::Raw,
        1 => TlsaMatching::Sha256,
        2 => TlsaMatching::Sha512,
        255 => TlsaMatching::Private,
        _ => return Err(Error::Parse(format!("unknown TLSA matching: {n}"))),
    })
}

fn build_caa(flags: u8, tag: &str, value: String) -> crate::Result<CAARecord> {
    let issuer_critical = flags & 0x80 != 0;
    match tag {
        "issue" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::Issue {
                issuer_critical,
                name,
                options,
            })
        }
        "issuewild" => {
            let (name, options) = parse_caa_value(&value);
            Ok(CAARecord::IssueWild {
                issuer_critical,
                name,
                options,
            })
        }
        "iodef" => Ok(CAARecord::Iodef {
            issuer_critical,
            url: value,
        }),
        other => Err(Error::Parse(format!("unknown CAA tag: {other}"))),
    }
}

fn parse_caa_value(value: &str) -> (Option<String>, Vec<KeyValue>) {
    let mut parts = value.split(';').map(str::trim);
    let name_part = parts.next().unwrap_or("").trim().to_string();
    let name = if name_part.is_empty() {
        None
    } else {
        Some(name_part)
    };
    let options = parts
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => KeyValue {
                key: k.trim().to_string(),
                value: v.trim().to_string(),
            },
            None => KeyValue {
                key: p.trim().to_string(),
                value: String::new(),
            },
        })
        .collect();
    (name, options)
}
