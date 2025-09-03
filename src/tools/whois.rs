use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::rdap::{self, RdapClient};

#[derive(Debug, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub creation_date: Option<String>,
    pub expiry_date: Option<String>,
    pub updated_date: Option<String>,
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub raw_data: String,
    pub rdap_available: bool,
}

pub async fn lookup(domain: &str) -> Result<WhoisInfo> {
    let rdap_client = RdapClient::new();

    match rdap_client.lookup_domain(domain).await {
        Ok(rdap_domain) => {
            let registrar = rdap::extract_registrar(&rdap_domain);
            let creation_date = rdap::extract_creation_date(&rdap_domain);
            let expiry_date = rdap::extract_expiry_date(&rdap_domain);
            let updated_date = rdap::extract_updated_date(&rdap_domain);
            let name_servers = rdap::extract_nameservers(&rdap_domain);
            let status = rdap::extract_status(&rdap_domain);

            // Serialize the RDAP data as raw data
            let raw_data = serde_json::to_string_pretty(&rdap_domain)
                .unwrap_or_else(|_| "Failed to serialize RDAP data".to_string());

            Ok(WhoisInfo {
                domain: domain.to_string(),
                registrar,
                registrant: None, // RDAP typically doesn't expose registrant info due to privacy
                creation_date,
                expiry_date,
                updated_date,
                name_servers,
                status,
                raw_data,
                rdap_available: true,
            })
        }
        Err(e) => {
            // Fallback to command-line whois if RDAP fails
            match lookup_command_line_whois(domain).await {
                Ok(mut whois_info) => {
                    whois_info.rdap_available = false;
                    Ok(whois_info)
                }
                Err(_) => Ok(WhoisInfo {
                    domain: domain.to_string(),
                    registrar: None,
                    registrant: None,
                    creation_date: None,
                    expiry_date: None,
                    updated_date: None,
                    name_servers: Vec::new(),
                    status: Vec::new(),
                    raw_data: format!("RDAP lookup failed: {}", e),
                    rdap_available: false,
                }),
            }
        }
    }
}

// Fallback command-line whois implementation
async fn lookup_command_line_whois(domain: &str) -> Result<WhoisInfo> {
    use std::process::Command;

    let output = tokio::task::spawn_blocking({
        let domain = domain.to_string();
        move || Command::new("whois").arg(&domain).output()
    })
    .await??;

    let raw_data = String::from_utf8_lossy(&output.stdout).to_string();

    let registrar = extract_field(
        &raw_data,
        &[
            r"Registrar:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
            r"Registrar Name:\s*(.+)",
        ],
    );

    let registrant = extract_field(
        &raw_data,
        &[
            r"Registrant Organization:\s*(.+)",
            r"Registrant:\s*(.+)",
            r"Organization:\s*(.+)",
        ],
    );

    let creation_date = extract_field(
        &raw_data,
        &[
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"Domain Registration Date:\s*(.+)",
            r"created:\s*(.+)",
        ],
    );

    let expiry_date = extract_field(
        &raw_data,
        &[
            r"Registry Expiry Date:\s*(.+)",
            r"Expiry Date:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"expires:\s*(.+)",
        ],
    );

    let updated_date = extract_field(
        &raw_data,
        &[
            r"Updated Date:\s*(.+)",
            r"Last Updated:\s*(.+)",
            r"Modified:\s*(.+)",
            r"changed:\s*(.+)",
        ],
    );

    let name_servers = extract_name_servers(&raw_data);
    let status = extract_status(&raw_data);

    Ok(WhoisInfo {
        domain: domain.to_string(),
        registrar,
        registrant,
        creation_date,
        expiry_date,
        updated_date,
        name_servers,
        status,
        raw_data,
        rdap_available: false,
    })
}

fn extract_field(text: &str, patterns: &[&str]) -> Option<String> {
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                if let Some(matched) = caps.get(1) {
                    return Some(matched.as_str().trim().to_string());
                }
            }
        }
    }
    None
}

fn extract_name_servers(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let patterns = [
        r"Name Server:\s*(.+)",
        r"nserver:\s*(.+)",
        r"NS:\s*(.+)",
        r"Nameservers:\s*(.+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            for caps in re.captures_iter(text) {
                if let Some(matched) = caps.get(1) {
                    let server = matched.as_str().trim().to_lowercase();
                    if !servers.contains(&server) {
                        servers.push(server);
                    }
                }
            }
        }
    }

    servers
}

fn extract_status(text: &str) -> Vec<String> {
    let mut statuses = Vec::new();
    let patterns = [
        r"Domain Status:\s*(.+)",
        r"Status:\s*(.+)",
        r"state:\s*(.+)",
    ];

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            for caps in re.captures_iter(text) {
                if let Some(matched) = caps.get(1) {
                    let status = matched.as_str().trim().to_string();
                    if !statuses.contains(&status) {
                        statuses.push(status);
                    }
                }
            }
        }
    }

    statuses
}
