use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapDomain {
    #[serde(rename = "objectClassName")]
    pub object_class_name: Option<String>,
    pub handle: Option<String>,
    #[serde(rename = "ldhName")]
    pub ldh_name: Option<String>,
    pub status: Option<Vec<String>>,
    pub events: Option<Vec<RdapEvent>>,
    pub entities: Option<Vec<RdapEntity>>,
    #[serde(rename = "nameservers")]
    pub nameservers: Option<Vec<RdapNameserver>>,
    #[serde(rename = "secureDNS")]
    pub secure_dns: Option<RdapSecureDns>,
    pub links: Option<Vec<RdapLink>>,
    pub notices: Option<Vec<RdapNotice>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapEvent {
    #[serde(rename = "eventAction")]
    pub event_action: Option<String>,
    #[serde(rename = "eventDate")]
    pub event_date: Option<String>,
    #[serde(rename = "eventActor")]
    pub event_actor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapEntity {
    #[serde(rename = "objectClassName")]
    pub object_class_name: Option<String>,
    pub handle: Option<String>,
    #[serde(rename = "vcardArray")]
    pub vcard_array: Option<serde_json::Value>,
    pub roles: Option<Vec<String>>,
    #[serde(rename = "publicIds")]
    pub public_ids: Option<Vec<RdapPublicId>>,
    pub links: Option<Vec<RdapLink>>,
    pub events: Option<Vec<RdapEvent>>,
    pub entities: Option<Vec<RdapEntity>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapPublicId {
    #[serde(rename = "type")]
    pub id_type: Option<String>,
    pub identifier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapNameserver {
    #[serde(rename = "objectClassName")]
    pub object_class_name: Option<String>,
    #[serde(rename = "ldhName")]
    pub ldh_name: Option<String>,
    #[serde(rename = "ipAddresses")]
    pub ip_addresses: Option<RdapIpAddresses>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapIpAddresses {
    pub v4: Option<Vec<String>>,
    pub v6: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapSecureDns {
    #[serde(rename = "zoneSigned")]
    pub zone_signed: Option<bool>,
    #[serde(rename = "delegationSigned")]
    pub delegation_signed: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapLink {
    pub value: Option<String>,
    pub rel: Option<String>,
    pub href: Option<String>,
    #[serde(rename = "hreflang")]
    pub hreflang: Option<Vec<String>>,
    pub title: Option<String>,
    pub media: Option<String>,
    #[serde(rename = "type")]
    pub link_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapNotice {
    pub title: Option<String>,
    pub description: Option<Vec<String>>,
    pub links: Option<Vec<RdapLink>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdapBootstrapResponse {
    pub services: Option<Vec<Vec<serde_json::Value>>>,
    pub description: Option<String>,
}

pub struct RdapClient {
    client: Client,
    rdap_base_urls: HashMap<String, String>,
}

impl Default for RdapClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RdapClient {
    pub fn new() -> Self {
        let mut rdap_base_urls = HashMap::new();

        // Static mapping of TLD to RDAP servers (same as Python version)
        rdap_base_urls.insert(
            "com".to_string(),
            "https://rdap.verisign.com/com/v1".to_string(),
        );
        rdap_base_urls.insert(
            "net".to_string(),
            "https://rdap.verisign.com/net/v1".to_string(),
        );
        rdap_base_urls.insert(
            "org".to_string(),
            "https://rdap.publicinterestregistry.org/rdap".to_string(),
        );
        rdap_base_urls.insert(
            "info".to_string(),
            "https://rdap.afilias.net/rdap".to_string(),
        );
        rdap_base_urls.insert("io".to_string(), "https://rdap.nic.io".to_string());
        rdap_base_urls.insert("co".to_string(), "https://rdap.nic.co".to_string());
        rdap_base_urls.insert("me".to_string(), "https://rdap.nic.me".to_string());
        rdap_base_urls.insert("tv".to_string(), "https://rdap.nic.tv".to_string());
        rdap_base_urls.insert("app".to_string(), "https://rdap.nic.google".to_string());
        rdap_base_urls.insert("dev".to_string(), "https://rdap.nic.google".to_string());
        rdap_base_urls.insert("cloud".to_string(), "https://rdap.nic.google".to_string());

        Self {
            client: Client::builder()
                .user_agent("Domain-MCP-Rust/1.0")
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
            rdap_base_urls,
        }
    }

    pub async fn lookup_domain(&self, domain: &str) -> Result<RdapDomain> {
        let tld = domain
            .split('.')
            .next_back()
            .ok_or_else(|| anyhow::anyhow!("Invalid domain format"))?;

        // Try static mapping first
        if let Some(base_url) = self.rdap_base_urls.get(tld) {
            if let Ok(result) = self.query_rdap_server(base_url, domain).await {
                return Ok(result);
            }
        }

        // Fallback to IANA bootstrap
        if let Ok(result) = self.bootstrap_lookup(domain).await {
            return Ok(result);
        }

        Err(anyhow::anyhow!("RDAP lookup failed for domain: {}", domain))
    }

    async fn query_rdap_server(&self, base_url: &str, domain: &str) -> Result<RdapDomain> {
        let url = format!("{}/domain/{}", base_url, domain);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await?;

        if response.status().is_success() {
            let rdap_domain: RdapDomain = response.json().await?;
            Ok(rdap_domain)
        } else {
            Err(anyhow::anyhow!(
                "RDAP server returned status: {}",
                response.status()
            ))
        }
    }

    async fn bootstrap_lookup(&self, domain: &str) -> Result<RdapDomain> {
        // Query IANA bootstrap service
        let bootstrap_url = format!(
            "https://rdap-bootstrap.arin.net/bootstrap/domain/{}",
            domain
        );

        let bootstrap_response = self
            .client
            .get(&bootstrap_url)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !bootstrap_response.status().is_success() {
            return Err(anyhow::anyhow!("Bootstrap lookup failed"));
        }

        let bootstrap_data: RdapBootstrapResponse = bootstrap_response.json().await?;

        if let Some(services) = bootstrap_data.services {
            if !services.is_empty() && !services[0].is_empty() {
                if let Some(rdap_urls) = services[0].first() {
                    if let Some(rdap_url_array) = rdap_urls.as_array() {
                        if let Some(rdap_url) = rdap_url_array.first() {
                            if let Some(rdap_url_str) = rdap_url.as_str() {
                                let url = format!("{}/domain/{}", rdap_url_str, domain);

                                let response = self
                                    .client
                                    .get(&url)
                                    .header("Accept", "application/rdap+json")
                                    .send()
                                    .await?;

                                if response.status().is_success() {
                                    let rdap_domain: RdapDomain = response.json().await?;
                                    return Ok(rdap_domain);
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!("No RDAP servers found via bootstrap"))
    }
}

// Utility functions for parsing RDAP data
pub fn extract_creation_date(rdap_domain: &RdapDomain) -> Option<String> {
    rdap_domain
        .events
        .as_ref()?
        .iter()
        .find(|event| {
            event.event_action.as_deref() == Some("registration")
                || event.event_action.as_deref() == Some("last changed")
        })
        .and_then(|event| event.event_date.clone())
}

pub fn extract_expiry_date(rdap_domain: &RdapDomain) -> Option<String> {
    rdap_domain
        .events
        .as_ref()?
        .iter()
        .find(|event| event.event_action.as_deref() == Some("expiration"))
        .and_then(|event| event.event_date.clone())
}

pub fn extract_updated_date(rdap_domain: &RdapDomain) -> Option<String> {
    rdap_domain
        .events
        .as_ref()?
        .iter()
        .find(|event| {
            event.event_action.as_deref() == Some("last changed")
                || event.event_action.as_deref() == Some("last update of RDAP database")
        })
        .and_then(|event| event.event_date.clone())
}

pub fn extract_registrar(rdap_domain: &RdapDomain) -> Option<String> {
    if let Some(entities) = &rdap_domain.entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                if roles.contains(&"registrar".to_string()) {
                    // Try to extract registrar name from vCard
                    if let Some(vcard_array) = &entity.vcard_array {
                        if let Some(vcard_data) = vcard_array.as_array() {
                            if vcard_data.len() > 1 {
                                if let Some(vcard_entries) = vcard_data[1].as_array() {
                                    for entry in vcard_entries {
                                        if let Some(entry_array) = entry.as_array() {
                                            if entry_array.len() >= 4 {
                                                if let Some(field_name) = entry_array[0].as_str() {
                                                    if field_name == "fn" {
                                                        if let Some(name) = entry_array[3].as_str()
                                                        {
                                                            return Some(name.to_string());
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Fallback: try handle or other identifiers
                    if let Some(handle) = &entity.handle {
                        return Some(handle.clone());
                    }
                }
            }
        }
    }
    None
}

pub fn extract_nameservers(rdap_domain: &RdapDomain) -> Vec<String> {
    if let Some(nameservers) = &rdap_domain.nameservers {
        nameservers
            .iter()
            .filter_map(|ns| ns.ldh_name.clone())
            .collect()
    } else {
        Vec::new()
    }
}

pub fn extract_status(rdap_domain: &RdapDomain) -> Vec<String> {
    rdap_domain.status.clone().unwrap_or_default()
}
