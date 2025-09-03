# Domain MCP Server

An MCP (Model Context Protocol) server for domain name analysis and availability checking, built with Rust using the rmcp SDK.

> **Note**: This project is based on [domain-mcp by rinadelph](https://github.com/rinadelph/domain-mcp), reimplemented in Rust with additional features and comprehensive testing.

## Features

The Domain MCP Server provides 8 tools for comprehensive domain analysis:

1. **whois_lookup** - Perform WHOIS lookup using RDAP (Registration Data Access Protocol) with command-line fallback
2. **dns_lookup** - Perform DNS lookup for a domain using async DNS resolver
3. **check_domain_availability** - Check if a domain is available for registration
4. **ssl_certificate_info** - Get SSL certificate information for a domain
5. **search_expired_domains** - Search for expired domains based on keywords
6. **domain_age_check** - Check the age of a domain
7. **bulk_domain_check** - Check availability of multiple domains at once
8. **get_dns_records** - Get all DNS records for a domain

### RDAP Implementation

The WHOIS lookup tool uses RDAP (Registration Data Access Protocol), which provides:
- **Structured JSON data** instead of plain text parsing
- **Better reliability** with official registry endpoints
- **Privacy compliance** following modern data protection standards
- **Automatic fallback** to traditional command-line whois when RDAP fails

Supported RDAP servers include:
- Verisign (.com, .net)
- Public Interest Registry (.org)
- Various ccTLD registries (.io, .co, .me, .tv)
- Google registries (.app, .dev, .cloud)
- IANA bootstrap discovery for other TLDs

## Installation

### Prerequisites

- Rust 1.70+ 
- Cargo
- whois command-line tool (for WHOIS lookups)
- openssl command-line tool (for SSL certificate parsing)

### Build

```bash
cargo build --release
```

## Usage

### Running the Server

The server uses stdio transport for communication:

```bash
cargo run --release
```

### Testing with MCP Inspector

You can test the server using the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector cargo run --release
```

### Example Requests

Initialize the server:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "test-client",
      "version": "1.0.0"
    }
  }
}
```

List available tools:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

Check domain availability:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "check_domain_availability",
    "arguments": {
      "domain": "example.com"
    }
  }
}
```

Perform DNS lookup:
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "dns_lookup",
    "arguments": {
      "domain": "google.com"
    }
  }
}
```

Bulk domain check:
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "bulk_domain_check",
    "arguments": {
      "domains": ["example1.com", "example2.net", "example3.org"]
    }
  }
}
```

## Architecture

The server is built using:
- **rmcp** - Rust MCP SDK for implementing the Model Context Protocol
- **tokio** - Async runtime
- **trust-dns-resolver** - DNS resolution
- **reqwest** - HTTP client for API calls
- **rustls** - TLS/SSL implementation
- **serde** - Serialization/deserialization

## License

MIT
