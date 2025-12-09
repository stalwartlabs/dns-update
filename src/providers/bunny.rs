use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{http::HttpClientBuilder, DnsRecord, DnsRecordType, Error, IntoFqdn};

#[derive(Clone)]
pub struct BunnyProvider {
    client: HttpClientBuilder,
}

impl BunnyProvider {
    pub(crate) fn new(api_key: impl AsRef<str>, timeout: Option<Duration>) -> crate::Result<Self> {
        Ok(Self {
            client: HttpClientBuilder::default()
                .with_header("AccessKey", api_key.as_ref())
                .with_timeout(timeout),
        })
    }

    // ---
    // Library functions

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let zone_id = self.get_zone_data(origin).await?.id;
        let name = name.into_name();
        let body = DnsRecordData {
            name: name.into(),
            record_type: (&record).into(),
            ttl: Some(ttl),
        };

        self.client
            .put(format!("https://api.bunny.net/dnszone/{zone_id}/records"))
            .with_body(&body)?
            .send_with_retry::<BunnyDnsRecord>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = name.into_name();

        let zone_data = self.get_zone_data(origin).await?;
        let zone_id = zone_data.id;
        let bunny_record = zone_data
            .records
            .iter()
            .find(|r| r.record.name == name && r.record.record_type.eq_type(&record))
            .ok_or(Error::NotFound)?;

        self.client
            .post(format!(
                "https://api.bunny.net/dnszone/{zone_id}/records/{}",
                bunny_record.id
            ))
            .with_body(BunnyDnsRecord {
                id: bunny_record.id,
                record: DnsRecordData {
                    name: bunny_record.record.name.clone(),
                    record_type: (&record).into(),
                    ttl: Some(ttl),
                },
            })?
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record: DnsRecordType,
    ) -> crate::Result<()> {
        let name = name.into_name();

        let zone_data = self.get_zone_data(origin).await?;
        let zone_id = zone_data.id;
        let record_id = zone_data
            .records
            .iter()
            .find(|r| r.record.name == name && r.record.record_type == record)
            .map(|r| r.id)
            .ok_or(Error::NotFound)?;

        self.client
            .delete(format!(
                "https://api.bunny.net/dnszone/{zone_id}/records/{record_id}",
            ))
            .send_with_retry::<serde_json::Value>(3)
            .await
            .map(|_| ())
    }

    // ---
    // Utility functions

    async fn get_zone_data(&self, origin: impl IntoFqdn<'_>) -> crate::Result<PartialDnsZone> {
        let origin = origin.into_name();

        let query_string = serde_urlencoded::to_string([("search", origin.as_ref())])
            .expect("Unable to convert DNS origin into HTTP query string");
        self.client
            .get(format!("https://api.bunny.net/dnszone?{query_string}"))
            .send_with_retry::<ApiItems<PartialDnsZone>>(3)
            .await
            .and_then(|r| {
                r.items
                    .into_iter()
                    .find(|z| z.domain == origin.as_ref())
                    .ok_or_else(|| Error::Api(format!("DNS Record {origin} not found")))
            })
    }
}

// -----------
// Data types

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "Type")]
#[repr(u8)]
pub enum BunnyDnsRecordType {
    #[serde(rename_all = "PascalCase")]
    A {
        value: Ipv4Addr,
    },
    #[serde(rename_all = "PascalCase")]
    AAAA {
        value: Ipv6Addr,
    },
    #[serde(rename_all = "PascalCase")]
    CNAME {
        value: String,
    },
    #[serde(rename_all = "PascalCase")]
    TXT {
        value: String,
    },
    #[serde(rename_all = "PascalCase")]
    MX {
        value: String,
        priority: u16,
    },
    Redirect,
    Flatten,
    PullZone,
    #[serde(rename_all = "PascalCase")]
    SRV {
        value: String,
        priority: u16,
        port: u16,
        weight: u16,
    },
    CAA,
    PTR,
    Script,
    #[serde(rename_all = "PascalCase")]
    NS {
        value: String,
    },
    SVCB,
    HTTPS,
}

impl From<&DnsRecord> for BunnyDnsRecordType {
    fn from(record: &DnsRecord) -> Self {
        match record {
            DnsRecord::A { content } => BunnyDnsRecordType::A { value: (*content) },
            DnsRecord::AAAA { content } => BunnyDnsRecordType::AAAA { value: (*content) },
            DnsRecord::CNAME { content } => BunnyDnsRecordType::CNAME {
                value: content.to_string(),
            },
            DnsRecord::NS { content } => BunnyDnsRecordType::NS {
                value: content.to_string(),
            },
            DnsRecord::MX { content, priority } => BunnyDnsRecordType::MX {
                value: content.to_string(),
                priority: *priority,
            },
            DnsRecord::TXT { content } => BunnyDnsRecordType::TXT {
                value: content.to_string(),
            },
            DnsRecord::SRV {
                content,
                priority,
                weight,
                port,
            } => BunnyDnsRecordType::SRV {
                value: content.to_string(),
                priority: *priority,
                port: *port,
                weight: *weight,
            },
        }
    }
}

impl BunnyDnsRecordType {
    /// Tests `self` and `other`'s DNS record type to be equal
    fn eq_type(&self, other: &DnsRecord) -> bool {
        match other {
            DnsRecord::A { .. } => matches!(self, BunnyDnsRecordType::A { .. }),
            DnsRecord::AAAA { .. } => matches!(self, BunnyDnsRecordType::AAAA { .. }),
            DnsRecord::CNAME { .. } => matches!(self, BunnyDnsRecordType::CNAME { .. }),
            DnsRecord::NS { .. } => matches!(self, BunnyDnsRecordType::NS { .. }),
            DnsRecord::MX { .. } => matches!(self, BunnyDnsRecordType::MX { .. }),
            DnsRecord::TXT { .. } => matches!(self, BunnyDnsRecordType::TXT { .. }),
            DnsRecord::SRV { .. } => matches!(self, BunnyDnsRecordType::SRV { .. }),
        }
    }
}

impl PartialEq<DnsRecordType> for BunnyDnsRecordType {
    fn eq(&self, other: &DnsRecordType) -> bool {
        match other {
            DnsRecordType::A => matches!(self, BunnyDnsRecordType::A { .. }),
            DnsRecordType::AAAA => matches!(self, BunnyDnsRecordType::AAAA { .. }),
            DnsRecordType::CNAME => matches!(self, BunnyDnsRecordType::CNAME { .. }),
            DnsRecordType::NS => matches!(self, BunnyDnsRecordType::NS { .. }),
            DnsRecordType::MX => matches!(self, BunnyDnsRecordType::MX { .. }),
            DnsRecordType::TXT => matches!(self, BunnyDnsRecordType::TXT { .. }),
            DnsRecordType::SRV => matches!(self, BunnyDnsRecordType::SRV { .. }),
        }
    }
}

// -----------
// API Responses

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ApiItems<T> {
    pub items: Vec<T>,

    pub current_page: u32,
    pub total_items: u32,

    pub has_more_items: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PartialDnsZone {
    pub id: u32,
    pub domain: String,
    pub records: Vec<BunnyDnsRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BunnyDnsRecord {
    pub id: u32,
    #[serde(flatten)]
    pub record: DnsRecordData,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DnsRecordData {
    pub name: String,

    #[serde(flatten)]
    pub record_type: BunnyDnsRecordType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}
