pub mod dns;
pub mod domain;
pub mod domain_age_check;
pub mod expired;
pub mod rdap;
pub mod ssl;
pub mod whois;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolResponse {
    pub success: bool,
    pub data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ToolResponse {
    pub fn success(data: Value) -> Self {
        Self {
            success: true,
            data,
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: serde_json::json!(null),
            error: Some(message),
        }
    }
}
