#![warn(clippy::pedantic)]

use anyhow::Result;
use domain_mcp::DomainServer;
use rmcp::{transport::stdio, ServiceExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting Domain MCP Server");

    let controller = DomainServer::new();

    let service = controller.serve(stdio()).await.inspect_err(|e| {
        tracing::error!("serving error: {:?}", e);
    })?;

    service.waiting().await?;
    Ok(())
}
