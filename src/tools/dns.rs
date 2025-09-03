use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsLookupResult {
    pub domain: String,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<MxRecord>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub soa_record: Option<SoaRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MxRecord {
    pub priority: u16,
    pub exchange: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoaRecord {
    pub primary_ns: String,
    pub responsible_party: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CloudflareAnswer {
    data: String,
    #[serde(rename = "TTL")]
    ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<CloudflareAnswer>>,
}

async fn cloudflare_dns_lookup(
    domain: &str,
    record_type: &str,
) -> Result<Vec<(String, Option<u32>)>> {
    let client = Client::new();

    let mut params = HashMap::new();
    params.insert("name", domain);
    params.insert("type", record_type);

    let response = client
        .get("https://cloudflare-dns.com/dns-query")
        .query(&params)
        .header("Accept", "application/dns-json")
        .send()
        .await?;

    if response.status().is_success() {
        let dns_response: CloudflareResponse = response.json().await?;

        if let Some(answers) = dns_response.answer {
            Ok(answers
                .into_iter()
                .map(|answer| (answer.data, answer.ttl))
                .collect())
        } else {
            Ok(Vec::new())
        }
    } else {
        Ok(Vec::new())
    }
}

pub async fn lookup(domain: &str) -> Result<DnsLookupResult> {
    let a_records = cloudflare_dns_lookup(domain, "A")
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(data, _ttl)| data)
        .collect();
    let aaaa_records = cloudflare_dns_lookup(domain, "AAAA")
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(data, _ttl)| data)
        .collect();

    let mx_records = match cloudflare_dns_lookup(domain, "MX").await {
        Ok(records) => records
            .into_iter()
            .filter_map(|(record, _ttl)| {
                let parts: Vec<&str> = record.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(priority) = parts[0].parse::<u16>() {
                        Some(MxRecord {
                            priority,
                            exchange: parts[1].to_string(),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    let txt_records = cloudflare_dns_lookup(domain, "TXT")
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(data, _ttl)| data)
        .collect();
    let ns_records = cloudflare_dns_lookup(domain, "NS")
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(data, _ttl)| data)
        .collect();
    let cname_records = cloudflare_dns_lookup(domain, "CNAME")
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(data, _ttl)| data)
        .collect();

    let soa_record = match cloudflare_dns_lookup(domain, "SOA").await {
        Ok(records) => {
            if let Some((soa_data, _ttl)) = records.first() {
                let parts: Vec<&str> = soa_data.split_whitespace().collect();
                if parts.len() >= 7 {
                    Some(SoaRecord {
                        primary_ns: parts[0].to_string(),
                        responsible_party: parts[1].to_string(),
                        serial: parts[2].parse().unwrap_or(0),
                        refresh: parts[3].parse().unwrap_or(0),
                        retry: parts[4].parse().unwrap_or(0),
                        expire: parts[5].parse().unwrap_or(0),
                        minimum: parts[6].parse().unwrap_or(0),
                    })
                } else {
                    None
                }
            } else {
                None
            }
        }
        Err(_) => None,
    };

    Ok(DnsLookupResult {
        domain: domain.to_string(),
        a_records,
        aaaa_records,
        mx_records,
        txt_records,
        ns_records,
        cname_records,
        soa_record,
    })
}

pub async fn get_dns_records(domain: &str) -> Result<Vec<DnsRecord>> {
    let mut records = Vec::new();
    let lookup_result = lookup(domain).await?;

    for record in &lookup_result.a_records {
        records.push(DnsRecord {
            record_type: "A".to_string(),
            name: domain.to_string(),
            value: record.clone(),
            ttl: None,
        });
    }

    for record in &lookup_result.aaaa_records {
        records.push(DnsRecord {
            record_type: "AAAA".to_string(),
            name: domain.to_string(),
            value: record.clone(),
            ttl: None,
        });
    }

    for mx in &lookup_result.mx_records {
        records.push(DnsRecord {
            record_type: "MX".to_string(),
            name: domain.to_string(),
            value: format!("{} {}", mx.priority, mx.exchange),
            ttl: None,
        });
    }

    for record in &lookup_result.txt_records {
        records.push(DnsRecord {
            record_type: "TXT".to_string(),
            name: domain.to_string(),
            value: record.clone(),
            ttl: None,
        });
    }

    for record in &lookup_result.ns_records {
        records.push(DnsRecord {
            record_type: "NS".to_string(),
            name: domain.to_string(),
            value: record.clone(),
            ttl: None,
        });
    }

    for record in &lookup_result.cname_records {
        records.push(DnsRecord {
            record_type: "CNAME".to_string(),
            name: domain.to_string(),
            value: record.clone(),
            ttl: None,
        });
    }

    if let Some(soa) = &lookup_result.soa_record {
        records.push(DnsRecord {
            record_type: "SOA".to_string(),
            name: domain.to_string(),
            value: format!(
                "{} {} {} {} {} {} {}",
                soa.primary_ns,
                soa.responsible_party,
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum
            ),
            ttl: None,
        });
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_lookup_result_serialization_test() {
        let mx_record = MxRecord {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };

        let soa_record = SoaRecord {
            primary_ns: "ns1.example.com".to_string(),
            responsible_party: "admin.example.com".to_string(),
            serial: 2023120101,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 86400,
        };

        let dns_result = DnsLookupResult {
            domain: "example.com".to_string(),
            a_records: vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()],
            aaaa_records: vec!["2001:db8::1".to_string()],
            mx_records: vec![mx_record],
            txt_records: vec!["v=spf1 include:_spf.google.com ~all".to_string()],
            ns_records: vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()],
            cname_records: vec!["www.example.com".to_string()],
            soa_record: Some(soa_record),
        };

        let serialized = serde_json::to_string(&dns_result).unwrap();
        let deserialized: DnsLookupResult = serde_json::from_str(&serialized).unwrap();

        assert_eq!(dns_result.domain, deserialized.domain);
        assert_eq!(dns_result.a_records, deserialized.a_records);
        assert_eq!(dns_result.aaaa_records, deserialized.aaaa_records);
        assert_eq!(dns_result.mx_records.len(), deserialized.mx_records.len());
        assert_eq!(dns_result.txt_records, deserialized.txt_records);
        assert_eq!(dns_result.ns_records, deserialized.ns_records);
        assert_eq!(dns_result.cname_records, deserialized.cname_records);
        assert!(dns_result.soa_record.is_some());
        assert!(deserialized.soa_record.is_some());
    }

    #[test]
    fn mx_record_serialization_test() {
        let mx_record = MxRecord {
            priority: 20,
            exchange: "backup.mail.example.com".to_string(),
        };

        let serialized = serde_json::to_string(&mx_record).unwrap();
        let deserialized: MxRecord = serde_json::from_str(&serialized).unwrap();

        assert_eq!(mx_record.priority, deserialized.priority);
        assert_eq!(mx_record.exchange, deserialized.exchange);
    }

    #[test]
    fn soa_record_serialization_test() {
        let soa_record = SoaRecord {
            primary_ns: "primary.dns.example.com".to_string(),
            responsible_party: "hostmaster.example.com".to_string(),
            serial: 2023120102,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 300,
        };

        let serialized = serde_json::to_string(&soa_record).unwrap();
        let deserialized: SoaRecord = serde_json::from_str(&serialized).unwrap();

        assert_eq!(soa_record.primary_ns, deserialized.primary_ns);
        assert_eq!(soa_record.responsible_party, deserialized.responsible_party);
        assert_eq!(soa_record.serial, deserialized.serial);
        assert_eq!(soa_record.refresh, deserialized.refresh);
        assert_eq!(soa_record.retry, deserialized.retry);
        assert_eq!(soa_record.expire, deserialized.expire);
        assert_eq!(soa_record.minimum, deserialized.minimum);
    }

    #[test]
    fn dns_record_serialization_test() {
        let dns_record = DnsRecord {
            record_type: "A".to_string(),
            name: "example.com".to_string(),
            value: "192.0.2.1".to_string(),
            ttl: Some(300),
        };

        let serialized = serde_json::to_string(&dns_record).unwrap();
        let deserialized: DnsRecord = serde_json::from_str(&serialized).unwrap();

        assert_eq!(dns_record.record_type, deserialized.record_type);
        assert_eq!(dns_record.name, deserialized.name);
        assert_eq!(dns_record.value, deserialized.value);
        assert_eq!(dns_record.ttl, deserialized.ttl);
    }

    #[test]
    fn dns_record_without_ttl_test() {
        let dns_record = DnsRecord {
            record_type: "CNAME".to_string(),
            name: "www.example.com".to_string(),
            value: "example.com".to_string(),
            ttl: None,
        };

        let serialized = serde_json::to_string(&dns_record).unwrap();
        let deserialized: DnsRecord = serde_json::from_str(&serialized).unwrap();

        assert_eq!(dns_record.record_type, deserialized.record_type);
        assert_eq!(dns_record.name, deserialized.name);
        assert_eq!(dns_record.value, deserialized.value);
        assert_eq!(dns_record.ttl, None);
    }

    #[test]
    fn mx_record_priority_test() {
        let high_priority = MxRecord {
            priority: 5,
            exchange: "primary.mail.example.com".to_string(),
        };

        let low_priority = MxRecord {
            priority: 10,
            exchange: "backup.mail.example.com".to_string(),
        };

        assert!(high_priority.priority < low_priority.priority);
    }

    #[test]
    fn empty_dns_lookup_result_test() {
        let empty_result = DnsLookupResult {
            domain: "nonexistent.example.com".to_string(),
            a_records: Vec::new(),
            aaaa_records: Vec::new(),
            mx_records: Vec::new(),
            txt_records: Vec::new(),
            ns_records: Vec::new(),
            cname_records: Vec::new(),
            soa_record: None,
        };

        assert!(empty_result.a_records.is_empty());
        assert!(empty_result.aaaa_records.is_empty());
        assert!(empty_result.mx_records.is_empty());
        assert!(empty_result.txt_records.is_empty());
        assert!(empty_result.ns_records.is_empty());
        assert!(empty_result.cname_records.is_empty());
        assert!(empty_result.soa_record.is_none());
    }
}
