use std::{borrow::Cow, time::Duration};

use aws_config::{self, BehaviorVersion};
use aws_config::{retry::RetryConfig, sts::AssumeRoleProvider};
use aws_credential_types::{provider::SharedCredentialsProvider, Credentials};
use aws_sdk_route53::{
    types::{Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType},
    Client,
};
use aws_smithy_types::timeout::TimeoutConfig;
use aws_types::region::Region;

use crate::{DnsRecord, DnsRecordType, Error, IntoFqdn};

#[derive(Clone, Default)]
pub struct Route53Config {
    pub hosted_zone_id: Option<String>,
    pub region: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub assume_role_arn: Option<String>,
    pub external_id: Option<String>,
    pub max_attempts: Option<u32>,
    pub timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct Route53Provider {
    client: Client,
    hosted_zone_id: String,
}

fn env_or_file(key: &str) -> Option<String> {
    let file_key = format!("{key}_FILE");
    if let Ok(path) = std::env::var(file_key) {
        if !path.is_empty() {
            if let Ok(value) = std::fs::read_to_string(path) {
                let value = value.trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    std::env::var(key).ok().and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

impl Route53Provider {
    pub(crate) async fn new(
        hosted_zone_id: impl Into<String>,
        timeout: Option<Duration>,
    ) -> crate::Result<Self> {
        let config = Route53Config {
            hosted_zone_id: Some(hosted_zone_id.into()),
            timeout,
            ..Default::default()
        };
        Self::new_with_config(config).await
    }

    pub(crate) async fn new_with_config(config: Route53Config) -> crate::Result<Self> {
        let hosted_zone_id = config
            .hosted_zone_id
            .or_else(|| env_or_file("AWS_HOSTED_ZONE_ID"))
            .ok_or_else(|| Error::Parse("Missing AWS hosted zone ID".to_string()))?;

        let region = config.region.or_else(|| env_or_file("AWS_REGION"));

        let access_key_id = config
            .access_key_id
            .or_else(|| env_or_file("AWS_ACCESS_KEY_ID"));
        let secret_access_key = config
            .secret_access_key
            .or_else(|| env_or_file("AWS_SECRET_ACCESS_KEY"));
        let session_token = config
            .session_token
            .or_else(|| env_or_file("AWS_SESSION_TOKEN"));

        let assume_role_arn = config
            .assume_role_arn
            .or_else(|| env_or_file("AWS_ASSUME_ROLE_ARN"));
        let external_id = config
            .external_id
            .or_else(|| env_or_file("AWS_EXTERNAL_ID"));

        let max_attempts = config
            .max_attempts
            .or_else(|| env_or_file("AWS_MAX_RETRIES").and_then(|value| value.parse::<u32>().ok()));

        let mut loader = aws_config::from_env().behavior_version(BehaviorVersion::v2026_01_12());

        if let Some(region) = region {
            loader = loader.region(Region::new(region));
        }

        if let Some(max_attempts) = max_attempts {
            loader = loader.retry_config(RetryConfig::standard().with_max_attempts(max_attempts));
        }

        if let Some(timeout) = config.timeout {
            let timeout_config = TimeoutConfig::builder()
                .operation_timeout(timeout)
                .operation_attempt_timeout(timeout)
                .build();
            loader = loader.timeout_config(timeout_config);
        }

        if let (Some(access_key_id), Some(secret_access_key)) = (access_key_id, secret_access_key) {
            loader = loader.credentials_provider(Credentials::new(
                access_key_id,
                secret_access_key,
                session_token,
                None,
                "dns-update",
            ));
        }

        let base_config = loader.load().await;

        let final_config = if let Some(assume_role_arn) = assume_role_arn {
            let mut builder = AssumeRoleProvider::builder(assume_role_arn).configure(&base_config);
            if let Some(external_id) = external_id {
                builder = builder.external_id(external_id);
            }
            let provider = builder.session_name("dns-update").build().await;
            base_config
                .into_builder()
                .credentials_provider(SharedCredentialsProvider::new(provider))
                .build()
        } else {
            base_config
        };

        let client = Client::new(&final_config);

        Ok(Self {
            client,
            hosted_zone_id,
        })
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.upsert_record(name, record, ttl).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        _origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        self.upsert_record(name, record, ttl).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        _origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = normalize_name(name.into_fqdn());
        let existing = self.find_record_set(&name, record_type).await?;
        self.apply_change(existing, ChangeAction::Delete).await
    }

    async fn upsert_record(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
    ) -> crate::Result<()> {
        let name = normalize_name(name.into_fqdn());
        let record_data = Route53RecordData::from(record);
        let rrset = build_record_set(&name, record_data, ttl)?;
        self.apply_change(rrset, ChangeAction::Upsert).await
    }

    async fn find_record_set(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> crate::Result<ResourceRecordSet> {
        let target_type = rr_type_from_record_type(record_type);
        let mut start_name = Some(name.to_string());
        let mut start_type = Some(target_type.clone());

        loop {
            let mut request = self
                .client
                .list_resource_record_sets()
                .hosted_zone_id(&self.hosted_zone_id);

            if let Some(ref value) = start_name {
                request = request.start_record_name(value);
            }

            if let Some(ref value) = start_type {
                request = request.start_record_type(value.clone());
            }

            let response = request
                .send()
                .await
                .map_err(|err| Error::Api(format!("Route53 list record sets failed: {err}")))?;

            if let Some(found) = response
                .resource_record_sets()
                .iter()
                .find(|rr| record_matches(rr, name, &target_type))
            {
                return Ok(found.clone());
            }

            if response.is_truncated() {
                start_name = response.next_record_name().map(|value| value.to_string());
                start_type = response.next_record_type().cloned();
            } else {
                break;
            }
        }

        Err(Error::NotFound)
    }

    async fn apply_change(
        &self,
        rrset: ResourceRecordSet,
        action: ChangeAction,
    ) -> crate::Result<()> {
        let change = Change::builder()
            .action(action)
            .resource_record_set(rrset)
            .build()
            .map_err(|err| Error::Api(format!("Failed to build Route53 change: {err}")))?;

        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|err| Error::Api(format!("Failed to build Route53 change batch: {err}")))?;

        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .map(|_| ())
            .map_err(|err| Error::Api(format!("Route53 change request failed: {err}")))
    }
}

fn build_record_set(
    name: &str,
    data: Route53RecordData,
    ttl: u32,
) -> crate::Result<ResourceRecordSet> {
    let mut builder = ResourceRecordSet::builder()
        .name(name)
        .r#type(data.record_type)
        .ttl(ttl as i64);

    for value in data.values {
        let record = ResourceRecord::builder()
            .value(value)
            .build()
            .map_err(|err| Error::Api(format!("Failed to build Route53 record: {err}")))?;
        builder = builder.resource_records(record);
    }

    builder
        .build()
        .map_err(|err| Error::Api(format!("Failed to build Route53 record set: {err}")))
}

fn record_matches(rrset: &ResourceRecordSet, name: &str, record_type: &RrType) -> bool {
    names_equal(rrset.name(), name) && rrset.r#type() == record_type
}

fn names_equal(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

fn normalize_name(name: Cow<'_, str>) -> String {
    if name.ends_with('.') {
        name.into_owned()
    } else {
        format!("{}.", name)
    }
}

fn rr_type_from_record_type(record_type: DnsRecordType) -> RrType {
    match record_type {
        DnsRecordType::A => RrType::A,
        DnsRecordType::AAAA => RrType::Aaaa,
        DnsRecordType::CNAME => RrType::Cname,
        DnsRecordType::NS => RrType::Ns,
        DnsRecordType::MX => RrType::Mx,
        DnsRecordType::TXT => RrType::Txt,
        DnsRecordType::SRV => RrType::Srv,
    }
}

struct Route53RecordData {
    record_type: RrType,
    values: Vec<String>,
}

impl From<DnsRecord> for Route53RecordData {
    fn from(record: DnsRecord) -> Self {
        match record {
            DnsRecord::A { content } => Self {
                record_type: RrType::A,
                values: vec![content.to_string()],
            },
            DnsRecord::AAAA { content } => Self {
                record_type: RrType::Aaaa,
                values: vec![content.to_string()],
            },
            DnsRecord::CNAME { content } => Self {
                record_type: RrType::Cname,
                values: vec![content],
            },
            DnsRecord::NS { content } => Self {
                record_type: RrType::Ns,
                values: vec![content],
            },
            DnsRecord::MX { content, priority } => Self {
                record_type: RrType::Mx,
                values: vec![format!("{priority} {content}")],
            },
            DnsRecord::TXT { content } => Self {
                record_type: RrType::Txt,
                values: vec![format!("\"{}\"", content)],
            },
            DnsRecord::SRV {
                content,
                priority,
                weight,
                port,
            } => Self {
                record_type: RrType::Srv,
                values: vec![format!("{priority} {weight} {port} {content}")],
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_mx_record() {
        let record = DnsRecord::MX {
            content: "mail.example.com.".into(),
            priority: 10,
        };
        let data = Route53RecordData::from(record);

        assert_eq!(data.record_type, RrType::Mx);
        assert_eq!(data.values, vec!["10 mail.example.com.".to_string()]);
    }

    #[test]
    fn converts_txt_record() {
        let record = DnsRecord::TXT {
            content: "hello world".into(),
        };
        let data = Route53RecordData::from(record);

        assert_eq!(data.record_type, RrType::Txt);
        assert_eq!(data.values, vec!["\"hello world\"".to_string()]);
    }
}
