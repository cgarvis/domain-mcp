# Domain MCP

MCP Server to check if a domain is available.

## Tools

- whois_lookup
- dns_lookup
- check_domain_availability
- ssl_certificate_info
- search_expired_domains
- domain_age_check
- bulk_domain_check
- get_dns_records

## Development
- ALWAYS write unit tests in the src directory in each file with the code that they’re testing. The convention is to create a module named tests in each file to contain the test functions and to annotate the module with cfg(test).
- ALWAYS run `cargo clippy --all-targets --all-features` and `cargo t` after making changes.
- Once code is working, format the code using `cargo fmt`

## Technology

- Rust
- MCP Rusk SDK
- Github
