pub mod tools;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
};
use serde_json::json;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DomainParam {
    pub domain: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DomainsParam {
    pub domains: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExpiredDomainsParam {
    pub keywords: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlds: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct DomainServer {
    tool_router: ToolRouter<DomainServer>,
}

impl Default for DomainServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl DomainServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Perform WHOIS lookup for a domain")]
    async fn whois_lookup(
        &self,
        Parameters(DomainParam { domain }): Parameters<DomainParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::whois::lookup(&domain).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "whois_lookup_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Perform DNS lookup for a domain")]
    async fn dns_lookup(
        &self,
        Parameters(DomainParam { domain }): Parameters<DomainParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::dns::lookup(&domain).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "dns_lookup_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Check if a domain is available for registration")]
    async fn check_domain_availability(
        &self,
        Parameters(DomainParam { domain }): Parameters<DomainParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::domain::check_availability(&domain).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "availability_check_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Get SSL certificate information for a domain")]
    async fn ssl_certificate_info(
        &self,
        Parameters(DomainParam { domain }): Parameters<DomainParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::ssl::get_certificate_info(&domain).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "ssl_info_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Search for expired domains based on keywords")]
    async fn search_expired_domains(
        &self,
        Parameters(ExpiredDomainsParam { keywords, tlds }): Parameters<ExpiredDomainsParam>,
    ) -> Result<CallToolResult, McpError> {
        // If keywords provided, use the first one (matching Python behavior)
        let keyword = keywords.first().map(|s| s.as_str()).unwrap_or("");

        // If TLDs provided, use the first one (matching Python behavior)
        let tld = tlds
            .as_ref()
            .and_then(|t| t.first())
            .map(|s| s.as_str())
            .unwrap_or("");

        match tools::expired::search_expired_domains(keyword, tld).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "expired_search_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Check the age of a domain")]
    async fn domain_age_check(
        &self,
        Parameters(DomainParam { domain }): Parameters<DomainParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::domain_age_check::check_age(&domain).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "age_check_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Check availability of multiple domains at once")]
    async fn bulk_domain_check(
        &self,
        Parameters(DomainsParam { domains }): Parameters<DomainsParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::domain::bulk_check(domains).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "bulk_check_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }

    #[tool(description = "Get all DNS records for a domain")]
    async fn get_dns_records(
        &self,
        Parameters(DomainParam { domain }): Parameters<DomainParam>,
    ) -> Result<CallToolResult, McpError> {
        match tools::dns::get_dns_records(&domain).await {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Error formatting result".to_string());
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => Err(McpError::internal_error(
                "dns_records_failed",
                Some(json!({ "error": e.to_string() })),
            )),
        }
    }
}

#[tool_handler]
impl ServerHandler for DomainServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "domain-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Domain MCP Server - Tools for domain name analysis and availability checking. \
                Available tools: whois_lookup, dns_lookup, check_domain_availability, \
                ssl_certificate_info, search_expired_domains, domain_age_check, \
                bulk_domain_check, get_dns_records"
                    .to_string(),
            ),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}
