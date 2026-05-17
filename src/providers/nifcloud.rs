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
    DnsRecord, DnsRecordType, Error, IntoFqdn, crypto::hmac_sha1, http::HttpClientBuilder,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use quick_xml::se::to_string as xml_to_string;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_ENDPOINT: &str = "https://dns.api.nifcloud.com";
const API_VERSION: &str = "2012-12-12N2013-12-16";
const XMLNS: &str = "https://route53.amazonaws.com/doc/2012-12-12/";

#[derive(Clone)]
pub struct NifcloudProvider {
    client: HttpClientBuilder,
    access_key: String,
    secret_key: String,
    endpoint: String,
}

#[derive(Serialize, Debug)]
#[serde(rename = "ChangeResourceRecordSetsRequest")]
struct ChangeRequest {
    #[serde(rename = "@xmlns")]
    xmlns: &'static str,
    #[serde(rename = "ChangeBatch")]
    change_batch: ChangeBatch,
}

#[derive(Serialize, Debug)]
struct ChangeBatch {
    #[serde(rename = "Comment")]
    comment: String,
    #[serde(rename = "Changes")]
    changes: Changes,
}

#[derive(Serialize, Debug)]
struct Changes {
    #[serde(rename = "Change")]
    change: Vec<Change>,
}

#[derive(Serialize, Debug)]
struct Change {
    #[serde(rename = "Action")]
    action: &'static str,
    #[serde(rename = "ResourceRecordSet")]
    resource_record_set: ResourceRecordSet,
}

#[derive(Serialize, Debug)]
struct ResourceRecordSet {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: &'static str,
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "ResourceRecords")]
    resource_records: ResourceRecords,
}

#[derive(Serialize, Debug)]
struct ResourceRecords {
    #[serde(rename = "ResourceRecord")]
    resource_record: Vec<ResourceRecord>,
}

#[derive(Serialize, Debug)]
struct ResourceRecord {
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Deserialize, Debug)]
struct ChangeResponse {
    #[serde(rename = "ChangeInfo")]
    #[allow(dead_code)]
    change_info: ChangeInfo,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ChangeInfo {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    #[serde(rename = "Error", default)]
    error: NifcloudError,
}

#[derive(Deserialize, Debug, Default)]
struct NifcloudError {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "Message", default)]
    message: String,
}

impl NifcloudProvider {
    pub(crate) fn new(
        access_key: impl AsRef<str>,
        secret_key: impl AsRef<str>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let access_key = access_key.as_ref();
        let secret_key = secret_key.as_ref();
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(Error::Api("Nifcloud credentials missing".into()));
        }
        let client = HttpClientBuilder::default()
            .with_header("Accept", "application/xml")
            .with_timeout(timeout);
        Ok(Self {
            client,
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            endpoint: DEFAULT_ENDPOINT.to_string(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_endpoint(self, endpoint: impl AsRef<str>) -> Self {
        Self {
            endpoint: endpoint.as_ref().to_string(),
            ..self
        }
    }

    fn signed(&self, request: crate::http::HttpClient) -> crate::http::HttpClient {
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mac = hmac_sha1(self.secret_key.as_bytes(), date.as_bytes());
        let signature = BASE64_STANDARD.encode(&mac);
        let auth = format!(
            "NIFTY3-HTTPS NiftyAccessKeyId={},Algorithm=HmacSHA1,Signature={}",
            self.access_key, signature
        );
        request
            .with_header("Date", date)
            .with_header("X-Nifty-Authorization", auth)
            .with_header("Content-Type", "text/xml; charset=utf-8")
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.change_record("CREATE", name, record, ttl, origin).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let original_value = build_value(&record)?;
        let original_type = dns_type(&record)?;
        let original_ttl = ttl;
        let name_fqdn = name.into_fqdn().to_string();
        let domain = origin.into_name();
        let subdomain_name =
            normalized_record_name(name_fqdn.trim_end_matches('.'), &domain);

        let delete_set = ResourceRecordSet {
            name: subdomain_name.clone(),
            record_type: original_type,
            ttl: original_ttl,
            resource_records: ResourceRecords {
                resource_record: vec![ResourceRecord {
                    value: original_value.clone(),
                }],
            },
        };

        let create_set = ResourceRecordSet {
            name: subdomain_name,
            record_type: original_type,
            ttl: original_ttl,
            resource_records: ResourceRecords {
                resource_record: vec![ResourceRecord {
                    value: original_value,
                }],
            },
        };

        let _ = self
            .send_change(
                &domain,
                ChangeRequest {
                    xmlns: XMLNS,
                    change_batch: ChangeBatch {
                        comment: "Managed by dns-update".into(),
                        changes: Changes {
                            change: vec![Change {
                                action: "DELETE",
                                resource_record_set: delete_set,
                            }],
                        },
                    },
                },
            )
            .await;

        self.send_change(
            &domain,
            ChangeRequest {
                xmlns: XMLNS,
                change_batch: ChangeBatch {
                    comment: "Managed by dns-update".into(),
                    changes: Changes {
                        change: vec![Change {
                            action: "CREATE",
                            resource_record_set: create_set,
                        }],
                    },
                },
            },
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name_str = name.into_name().to_string();
        let domain = origin.into_name();
        let subdomain_name = normalized_record_name(&name_str, &domain);
        let type_str = match record_type {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::NS => "NS",
            DnsRecordType::MX => "MX",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::SRV => "SRV",
            DnsRecordType::CAA => {
                return Err(Error::Api("CAA records are not supported by Nifcloud".into()));
            }
            DnsRecordType::TLSA => {
                return Err(Error::Api("TLSA records are not supported by Nifcloud".into()));
            }
        };
        let delete_set = ResourceRecordSet {
            name: subdomain_name,
            record_type: type_str,
            ttl: 0,
            resource_records: ResourceRecords {
                resource_record: vec![ResourceRecord {
                    value: String::new(),
                }],
            },
        };
        self.send_change(
            &domain,
            ChangeRequest {
                xmlns: XMLNS,
                change_batch: ChangeBatch {
                    comment: "Managed by dns-update".into(),
                    changes: Changes {
                        change: vec![Change {
                            action: "DELETE",
                            resource_record_set: delete_set,
                        }],
                    },
                },
            },
        )
        .await
        .map(|_| ())
    }

    async fn change_record(
        &self,
        action: &'static str,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name_str = name.into_name().to_string();
        let domain = origin.into_name();
        let subdomain_name = normalized_record_name(&name_str, &domain);
        let value = build_value(&record)?;
        let record_type = dns_type(&record)?;

        let body = ChangeRequest {
            xmlns: XMLNS,
            change_batch: ChangeBatch {
                comment: "Managed by dns-update".into(),
                changes: Changes {
                    change: vec![Change {
                        action,
                        resource_record_set: ResourceRecordSet {
                            name: subdomain_name,
                            record_type,
                            ttl,
                            resource_records: ResourceRecords {
                                resource_record: vec![ResourceRecord { value }],
                            },
                        },
                    }],
                },
            },
        };
        self.send_change(&domain, body).await.map(|_| ())
    }

    async fn send_change(&self, domain: &str, body: ChangeRequest) -> crate::Result<String> {
        let xml_body = xml_to_string(&body)
            .map_err(|e| Error::Serialize(format!("XML serialization failed: {e}")))?;
        let payload = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}", xml_body);
        let url = format!(
            "{}/{}/hostedzone/{}/rrset",
            self.endpoint, API_VERSION, domain
        );
        let response = self
            .signed(self.client.post(url).with_raw_body(payload))
            .send_raw()
            .await?;
        if response.contains("<Error>") {
            let parsed: Result<ErrorResponse, _> = quick_xml::de::from_str(&response);
            if let Ok(err) = parsed {
                return Err(Error::Api(format!(
                    "Nifcloud error {}: {}",
                    err.error.code, err.error.message
                )));
            }
            return Err(Error::Api(format!("Nifcloud error response: {response}")));
        }
        let _info: ChangeResponse = quick_xml::de::from_str(&response)
            .map_err(|e| Error::Serialize(format!("XML deserialization failed: {e}")))?;
        Ok(response)
    }
}

fn normalized_record_name(name: &str, domain: &str) -> String {
    let unfqdn = name.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    if unfqdn == domain {
        "@".to_string()
    } else {
        unfqdn.to_string()
    }
}

fn dns_type(record: &DnsRecord) -> crate::Result<&'static str> {
    match record {
        DnsRecord::A(_) => Ok("A"),
        DnsRecord::AAAA(_) => Ok("AAAA"),
        DnsRecord::CNAME(_) => Ok("CNAME"),
        DnsRecord::NS(_) => Ok("NS"),
        DnsRecord::MX(_) => Ok("MX"),
        DnsRecord::TXT(_) => Ok("TXT"),
        DnsRecord::SRV(_) => Ok("SRV"),
        DnsRecord::CAA(_) => Err(Error::Api("CAA records are not supported by Nifcloud".into())),
        DnsRecord::TLSA(_) => Err(Error::Api(
            "TLSA records are not supported by Nifcloud".into(),
        )),
    }
}

fn build_value(record: &DnsRecord) -> crate::Result<String> {
    Ok(match record {
        DnsRecord::A(addr) => addr.to_string(),
        DnsRecord::AAAA(addr) => addr.to_string(),
        DnsRecord::CNAME(target) => target.clone(),
        DnsRecord::NS(target) => target.clone(),
        DnsRecord::MX(mx) => format!("{} {}", mx.priority, mx.exchange),
        DnsRecord::TXT(text) => format!("\"{}\"", text.replace('\"', "\\\"")),
        DnsRecord::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority, srv.weight, srv.port, srv.target
        ),
        DnsRecord::CAA(_) => {
            return Err(Error::Api("CAA records are not supported by Nifcloud".into()));
        }
        DnsRecord::TLSA(_) => {
            return Err(Error::Api(
                "TLSA records are not supported by Nifcloud".into(),
            ));
        }
    })
}
