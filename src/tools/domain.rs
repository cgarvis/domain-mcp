use anyhow::Result;
use futures::future::join_all;
use serde::{Deserialize, Serialize};

use super::dns;
use super::whois;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAvailability {
    pub domain: String,
    pub available: bool,
    pub reason: String,
    pub whois_available: Option<bool>,
    pub dns_available: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkCheckResult {
    pub domains: Vec<DomainAvailability>,
    pub summary: BulkCheckSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkCheckSummary {
    pub total: usize,
    pub available: usize,
    pub taken: usize,
    pub errors: usize,
}

pub async fn check_availability(domain: &str) -> Result<DomainAvailability> {
    let domain = normalize_domain(domain);

    let whois_future = whois::lookup(&domain);
    let dns_future = dns::lookup(&domain);

    let (whois_result, dns_result) = tokio::join!(whois_future, dns_future);

    let whois_available = whois_result
        .as_ref()
        .map(|info| {
            info.raw_data.contains("No matching record")
                || info.raw_data.contains("NOT FOUND")
                || info.raw_data.contains("No Data Found")
                || info.raw_data.contains("domain name not known")
                || info.registrar.is_none()
        })
        .unwrap_or(true);

    let dns_available = dns_result
        .as_ref()
        .map(|info| {
            info.a_records.is_empty() && info.aaaa_records.is_empty() && info.ns_records.is_empty()
        })
        .unwrap_or(true);

    let available = whois_available || dns_available;

    let reason = if available {
        if whois_available && dns_available {
            "Domain appears to be completely available (no WHOIS or DNS records)".to_string()
        } else if whois_available {
            "Domain has no WHOIS record but has DNS entries".to_string()
        } else {
            "Domain has WHOIS record but no DNS entries".to_string()
        }
    } else {
        "Domain is registered and active".to_string()
    };

    Ok(DomainAvailability {
        domain,
        available,
        reason,
        whois_available: Some(whois_available),
        dns_available: Some(dns_available),
    })
}

pub async fn bulk_check(domains: Vec<String>) -> Result<BulkCheckResult> {
    let mut futures = Vec::new();

    for domain in &domains {
        futures.push(check_availability(domain));
    }

    let results = join_all(futures).await;

    let mut available_count = 0;
    let mut taken_count = 0;
    let mut error_count = 0;
    let mut domain_results: Vec<DomainAvailability> = Vec::new();

    for (domain, result) in domains.iter().zip(results.iter()) {
        match result {
            Ok(availability) => {
                if availability.available {
                    available_count += 1;
                } else {
                    taken_count += 1;
                }
                domain_results.push(availability.clone());
            }
            Err(_) => {
                error_count += 1;
                domain_results.push(DomainAvailability {
                    domain: domain.clone(),
                    available: false,
                    reason: "Error checking domain".to_string(),
                    whois_available: None,
                    dns_available: None,
                });
            }
        }
    }

    Ok(BulkCheckResult {
        domains: domain_results,
        summary: BulkCheckSummary {
            total: domains.len(),
            available: available_count,
            taken: taken_count,
            errors: error_count,
        },
    })
}

fn normalize_domain(domain: &str) -> String {
    domain
        .trim()
        .to_lowercase()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("www.")
        .trim_end_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_test() {
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize_domain("  example.com  "), "example.com");
        assert_eq!(normalize_domain("http://example.com"), "example.com");
        assert_eq!(normalize_domain("https://example.com"), "example.com");
        assert_eq!(normalize_domain("www.example.com"), "example.com");
        assert_eq!(normalize_domain("example.com/"), "example.com");
        assert_eq!(normalize_domain("https://www.example.com/"), "example.com");
        assert_eq!(normalize_domain("HTTP://WWW.EXAMPLE.COM/"), "example.com");
        assert_eq!(
            normalize_domain("  https://www.example.com/  "),
            "example.com"
        );
    }

    #[test]
    fn domain_availability_serialization_test() {
        let availability = DomainAvailability {
            domain: "example.com".to_string(),
            available: true,
            reason: "Domain appears available".to_string(),
            whois_available: Some(true),
            dns_available: Some(true),
        };

        let serialized = serde_json::to_string(&availability).unwrap();
        let deserialized: DomainAvailability = serde_json::from_str(&serialized).unwrap();

        assert_eq!(availability.domain, deserialized.domain);
        assert_eq!(availability.available, deserialized.available);
        assert_eq!(availability.reason, deserialized.reason);
        assert_eq!(availability.whois_available, deserialized.whois_available);
        assert_eq!(availability.dns_available, deserialized.dns_available);
    }

    #[test]
    fn bulk_check_result_serialization_test() {
        let availability1 = DomainAvailability {
            domain: "example1.com".to_string(),
            available: true,
            reason: "Available".to_string(),
            whois_available: Some(true),
            dns_available: Some(true),
        };

        let availability2 = DomainAvailability {
            domain: "example2.com".to_string(),
            available: false,
            reason: "Taken".to_string(),
            whois_available: Some(false),
            dns_available: Some(false),
        };

        let bulk_result = BulkCheckResult {
            domains: vec![availability1, availability2],
            summary: BulkCheckSummary {
                total: 2,
                available: 1,
                taken: 1,
                errors: 0,
            },
        };

        let serialized = serde_json::to_string(&bulk_result).unwrap();
        let deserialized: BulkCheckResult = serde_json::from_str(&serialized).unwrap();

        assert_eq!(bulk_result.domains.len(), deserialized.domains.len());
        assert_eq!(bulk_result.summary.total, deserialized.summary.total);
        assert_eq!(
            bulk_result.summary.available,
            deserialized.summary.available
        );
        assert_eq!(bulk_result.summary.taken, deserialized.summary.taken);
        assert_eq!(bulk_result.summary.errors, deserialized.summary.errors);
    }

    #[test]
    fn bulk_check_summary_calculation_test() {
        let summary = BulkCheckSummary {
            total: 5,
            available: 2,
            taken: 2,
            errors: 1,
        };

        assert_eq!(
            summary.total,
            summary.available + summary.taken + summary.errors
        );
    }
}
