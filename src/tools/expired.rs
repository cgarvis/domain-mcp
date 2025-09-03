use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiredDomain {
    pub domain: String,
    pub status: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appraisal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starting_price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_dns: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct DomainsDBResponse {
    domains: Option<Vec<DomainsDBDomain>>,
}

#[derive(Debug, Deserialize)]
struct DomainsDBDomain {
    domain: Option<String>,
    create_date: Option<String>,
    update_date: Option<String>,
    #[serde(rename = "isDead")]
    is_dead: Option<String>,
    #[serde(rename = "A")]
    a_records: Option<Vec<String>>,
    #[serde(rename = "NS")]
    ns_records: Option<Vec<String>>,
}

pub async fn search_expired_domains(keyword: &str, tld: &str) -> Result<Vec<ExpiredDomain>> {
    let client = Client::builder()
        .user_agent("Domain-MCP-Rust/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut domains = Vec::new();
    let mut seen_domains = HashSet::new();

    // Method 1: DomainsDB API - Primary source for expired domains
    if let Ok(domainsdb_results) = search_domainsdb(&client, keyword, tld).await {
        for domain in domainsdb_results {
            if !seen_domains.contains(&domain.domain) {
                seen_domains.insert(domain.domain.clone());
                domains.push(domain);
                if domains.len() >= 10 {
                    return Ok(domains);
                }
            }
        }
    }

    // Method 2: Dynadot CSV - Pending delete domains with appraisal values
    if domains.len() < 10 {
        if let Ok(dynadot_results) = search_dynadot(&client, keyword, tld).await {
            for domain in dynadot_results {
                if !seen_domains.contains(&domain.domain) {
                    seen_domains.insert(domain.domain.clone());
                    domains.push(domain);
                    if domains.len() >= 10 {
                        return Ok(domains);
                    }
                }
            }
        }
    }

    // Method 3: NameJet inventory files
    if domains.len() < 10 {
        if let Ok(namejet_results) = search_namejet(&client, keyword, tld).await {
            for domain in namejet_results {
                if !seen_domains.contains(&domain.domain) {
                    seen_domains.insert(domain.domain.clone());
                    domains.push(domain);
                    if domains.len() >= 10 {
                        return Ok(domains);
                    }
                }
            }
        }
    }

    // Method 4: SnapNames CSV as fallback
    if domains.len() < 10 {
        if let Ok(snapnames_results) = search_snapnames(&client, keyword, tld).await {
            for domain in snapnames_results {
                if !seen_domains.contains(&domain.domain) {
                    seen_domains.insert(domain.domain.clone());
                    domains.push(domain);
                    if domains.len() >= 10 {
                        return Ok(domains);
                    }
                }
            }
        }
    }

    Ok(domains)
}

async fn search_domainsdb(client: &Client, keyword: &str, tld: &str) -> Result<Vec<ExpiredDomain>> {
    let mut params = vec![("isDead", "true"), ("limit", "50")];

    let keyword_owned;
    let tld_owned;

    if !keyword.is_empty() {
        keyword_owned = keyword.to_string();
        params.push(("domain", &keyword_owned));
    }

    if !tld.is_empty() {
        tld_owned = tld.to_string();
        params.push(("zone", &tld_owned));
    }

    let response = client
        .get("https://api.domainsdb.info/v1/domains/search")
        .query(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "DomainsDB API returned status: {}",
            response.status()
        ));
    }

    let data: DomainsDBResponse = response.json().await?;
    let mut results = Vec::new();

    if let Some(domains) = data.domains {
        for domain_info in domains {
            if let Some(domain_name) = domain_info.domain {
                if domain_name.contains('.') {
                    // Additional filtering for keyword and TLD
                    let matches_keyword = keyword.is_empty()
                        || domain_name.to_lowercase().contains(&keyword.to_lowercase());
                    let matches_tld = tld.is_empty() || domain_name.ends_with(&format!(".{}", tld));

                    if matches_keyword && matches_tld {
                        let has_dns =
                            domain_info.a_records.is_some() || domain_info.ns_records.is_some();

                        results.push(ExpiredDomain {
                            domain: domain_name,
                            status: if domain_info.is_dead == Some("True".to_string()) {
                                "expired".to_string()
                            } else {
                                "unknown".to_string()
                            },
                            source: "DomainsDB".to_string(),
                            created: domain_info.create_date,
                            updated: domain_info.update_date,
                            end_time: None,
                            appraisal: None,
                            starting_price: None,
                            has_dns: Some(has_dns),
                        });

                        if results.len() >= 10 {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

async fn search_dynadot(client: &Client, keyword: &str, tld: &str) -> Result<Vec<ExpiredDomain>> {
    let response = client
        .get("https://www.dynadot.com/market/backorder/backorders.csv")
        .header("User-Agent", "Mozilla/5.0 (compatible; Domain-MCP/1.0)")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Dynadot CSV returned status: {}",
            response.status()
        ));
    }

    let text = response.text().await?;
    let mut results = Vec::new();

    // Skip header line
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split(',').map(|p| p.trim()).collect();
        if parts.len() >= 2 {
            let domain_name = parts[0].trim();
            if domain_name.contains('.') {
                // Filter by keyword and TLD
                let matches_keyword = keyword.is_empty()
                    || domain_name.to_lowercase().contains(&keyword.to_lowercase());
                let matches_tld = tld.is_empty() || domain_name.ends_with(&format!(".{}", tld));

                if matches_keyword && matches_tld {
                    results.push(ExpiredDomain {
                        domain: domain_name.to_string(),
                        status: "pending delete".to_string(),
                        source: "Dynadot".to_string(),
                        created: None,
                        updated: None,
                        end_time: if parts.len() > 1 {
                            Some(parts[1].to_string())
                        } else {
                            None
                        },
                        appraisal: if parts.len() > 3 {
                            Some(parts[3].to_string())
                        } else {
                            None
                        },
                        starting_price: if parts.len() > 4 {
                            Some(parts[4].to_string())
                        } else {
                            None
                        },
                        has_dns: None,
                    });

                    if results.len() >= 10 {
                        break;
                    }
                }
            }
        }
    }

    Ok(results)
}

async fn search_namejet(client: &Client, keyword: &str, tld: &str) -> Result<Vec<ExpiredDomain>> {
    let urls = vec![
        "https://www.namejet.com/download/namejet_inventory.txt",
        "https://www.namejet.com/download/namejet-inventory.csv",
    ];

    let mut results = Vec::new();

    for url in urls {
        match client
            .get(url)
            .header("User-Agent", "Mozilla/5.0 (compatible; Domain-MCP/1.0)")
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let text = response.text().await?;

                for line in text.lines() {
                    if line.trim().is_empty() || line.starts_with('#') {
                        continue;
                    }

                    // Extract domain name (could be first column in CSV or whole line in TXT)
                    let domain_name = line
                        .split(',')
                        .next()
                        .unwrap_or(line)
                        .trim()
                        .trim_matches('"');

                    if domain_name.contains('.') && !domain_name.starts_with('#') {
                        // Filter by keyword and TLD
                        let matches_keyword = keyword.is_empty()
                            || domain_name.to_lowercase().contains(&keyword.to_lowercase());
                        let matches_tld =
                            tld.is_empty() || domain_name.ends_with(&format!(".{}", tld));

                        if matches_keyword && matches_tld {
                            results.push(ExpiredDomain {
                                domain: domain_name.to_string(),
                                status: "auction/pending".to_string(),
                                source: "NameJet".to_string(),
                                created: None,
                                updated: None,
                                end_time: None,
                                appraisal: None,
                                starting_price: None,
                                has_dns: None,
                            });

                            if results.len() >= 10 {
                                return Ok(results);
                            }
                        }
                    }
                }

                if !results.is_empty() {
                    break; // Stop trying other NameJet URLs if one worked
                }
            }
            _ => continue,
        }
    }

    Ok(results)
}

async fn search_snapnames(client: &Client, keyword: &str, tld: &str) -> Result<Vec<ExpiredDomain>> {
    let response = client
        .get("https://www.snapnames.com/file_dl.sn?file=deletinglist.csv")
        .header("User-Agent", "Mozilla/5.0 (compatible; Domain-MCP/1.0)")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "SnapNames CSV returned status: {}",
            response.status()
        ));
    }

    let text = response.text().await?;
    let mut results = Vec::new();

    // Skip header line
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line
            .split(',')
            .map(|p| p.trim().trim_matches('"'))
            .collect();

        if !parts.is_empty() && parts[0].contains('.') {
            let domain_name = parts[0];

            // Filter by keyword and TLD
            let matches_keyword =
                keyword.is_empty() || domain_name.to_lowercase().contains(&keyword.to_lowercase());
            let matches_tld = tld.is_empty() || domain_name.ends_with(&format!(".{}", tld));

            if matches_keyword && matches_tld {
                results.push(ExpiredDomain {
                    domain: domain_name.to_string(),
                    status: "pending delete".to_string(),
                    source: "SnapNames".to_string(),
                    created: None,
                    updated: None,
                    end_time: None,
                    appraisal: None,
                    starting_price: None,
                    has_dns: None,
                });

                if results.len() >= 10 {
                    break;
                }
            }
        }
    }

    Ok(results)
}
