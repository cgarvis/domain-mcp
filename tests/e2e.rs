mod common;

use common::{
    build_domain, build_server, initialize_mcp_server, send_request_and_get_response,
    spawn_mcp_server,
};
use serde_json::json;
use std::io::BufReader;

#[test]
fn test_mcp_server_full_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Build the server first
    build_server()?;

    // Start the server process
    let mut child = spawn_mcp_server()?;

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout);

    // Stage 1: Initialize the server
    println!("Stage 1: Initializing server...");
    let init_response = initialize_mcp_server(&mut stdin, &mut stdout_reader)?;

    // Verify initialization response
    assert_eq!(init_response["id"], 1);
    assert_eq!(init_response["jsonrpc"], "2.0");

    let result = &init_response["result"];
    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert_eq!(result["serverInfo"]["name"], "domain-mcp");
    assert!(result["capabilities"]["tools"].is_object());
    println!("✓ Server initialized successfully");

    // Stage 2: Get and verify available tools
    println!("Stage 2: Getting available tools...");
    let tools_request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    let tools_response =
        send_request_and_get_response(&mut stdin, &mut stdout_reader, tools_request)?;

    // Verify tools response
    assert_eq!(tools_response["id"], 2);
    assert_eq!(tools_response["jsonrpc"], "2.0");

    let tools = tools_response["result"]["tools"].as_array().unwrap();
    assert!(!tools.is_empty());

    // Check for all expected tools
    let tool_names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();

    let expected_tools = [
        "whois_lookup",
        "dns_lookup",
        "check_domain_availability",
        "ssl_certificate_info",
        "domain_age_check",
        "bulk_domain_check",
        "get_dns_records",
        "search_expired_domains",
    ];

    for expected_tool in expected_tools.iter() {
        assert!(
            tool_names.contains(expected_tool),
            "Tool '{}' not found in available tools: {:?}",
            expected_tool,
            tool_names
        );
    }
    println!(
        "✓ All {} expected tools are available",
        expected_tools.len()
    );

    // Stage 3: Test domain availability check
    println!("Stage 3: Testing domain availability check...");
    let availability_request = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "check_domain_availability",
            "arguments": {
                "domain": build_domain()
            }
        }
    });

    let availability_response =
        send_request_and_get_response(&mut stdin, &mut stdout_reader, availability_request)?;

    // Verify availability response
    assert_eq!(availability_response["id"], 3);
    assert_eq!(availability_response["jsonrpc"], "2.0");
    assert!(availability_response["result"]["content"].is_array());
    println!("✓ Domain availability check completed successfully");

    // Stage 4: Test DNS lookup
    println!("Stage 4: Testing DNS lookup...");
    let dns_request = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "dns_lookup",
            "arguments": {
                "domain": build_domain()
            }
        }
    });

    let dns_response = send_request_and_get_response(&mut stdin, &mut stdout_reader, dns_request)?;

    // Verify DNS response
    assert_eq!(dns_response["id"], 4);
    assert_eq!(dns_response["jsonrpc"], "2.0");

    let dns_content = &dns_response["result"]["content"];
    assert!(dns_content.is_array());
    let dns_content_array = dns_content.as_array().unwrap();
    assert!(!dns_content_array.is_empty());
    assert_eq!(dns_content_array[0]["type"], "text");
    println!("✓ DNS lookup completed successfully");

    // Stage 5: Test bulk domain check
    println!("Stage 5: Testing bulk domain check...");
    let bulk_request = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "bulk_domain_check",
            "arguments": {
                "domains": [build_domain(), build_domain(), build_domain()]
            }
        }
    });

    let bulk_response =
        send_request_and_get_response(&mut stdin, &mut stdout_reader, bulk_request)?;

    // Verify bulk response
    assert_eq!(bulk_response["id"], 5);
    assert_eq!(bulk_response["jsonrpc"], "2.0");
    assert!(bulk_response["result"]["content"].is_array());
    println!("✓ Bulk domain check completed successfully");

    // Stage 6: Test WHOIS lookup
    println!("Stage 6: Testing WHOIS lookup...");
    let whois_request = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "whois_lookup",
            "arguments": {
                "domain": build_domain()
            }
        }
    });

    let whois_response =
        send_request_and_get_response(&mut stdin, &mut stdout_reader, whois_request)?;

    // Verify WHOIS response
    assert_eq!(whois_response["id"], 6);
    assert_eq!(whois_response["jsonrpc"], "2.0");
    assert!(whois_response["result"]["content"].is_array());
    println!("✓ WHOIS lookup completed successfully");

    // Stage 7: Test domain age check
    println!("Stage 7: Testing domain age check...");
    let age_request = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "domain_age_check",
            "arguments": {
                "domain": build_domain()
            }
        }
    });

    let age_response = send_request_and_get_response(&mut stdin, &mut stdout_reader, age_request)?;

    // Verify age response
    assert_eq!(age_response["id"], 7);
    assert_eq!(age_response["jsonrpc"], "2.0");
    assert!(age_response["result"]["content"].is_array());
    println!("✓ Domain age check completed successfully");

    // Stage 8: Test error handling with invalid domain
    println!("Stage 8: Testing error handling...");
    let error_request = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "dns_lookup",
            "arguments": {
                "domain": "invalid..domain..name"
            }
        }
    });

    let error_response =
        send_request_and_get_response(&mut stdin, &mut stdout_reader, error_request)?;

    // Verify error response structure
    assert_eq!(error_response["id"], 8);
    assert_eq!(error_response["jsonrpc"], "2.0");
    // Should either return an error or content with error information
    assert!(error_response["error"].is_object() || error_response["result"]["content"].is_array());
    println!("✓ Error handling works correctly");

    println!("🎉 All stages completed successfully!");

    // Cleanup
    child.kill().expect("Failed to kill child process");
    child.wait().expect("Failed to wait for child process");

    Ok(())
}

#[test]
fn test_sequential_operations() -> Result<(), Box<dyn std::error::Error>> {
    // Build the server first
    build_server()?;

    // Start the server process
    let mut child = spawn_mcp_server()?;

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout);

    // Initialize the server
    initialize_mcp_server(&mut stdin, &mut stdout_reader)?;

    // Perform multiple sequential DNS lookups
    let domains = [build_domain(), build_domain(), build_domain()];

    for (i, domain) in domains.iter().enumerate() {
        let request_id = i + 2;
        let dns_request = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "dns_lookup",
                "arguments": {
                    "domain": domain
                }
            }
        });

        let response = send_request_and_get_response(&mut stdin, &mut stdout_reader, dns_request)?;

        // Verify each response
        assert_eq!(response["id"], request_id);
        assert_eq!(response["jsonrpc"], "2.0");
        assert!(response["result"]["content"].is_array());

        println!("✓ Sequential DNS lookup {} for {} completed", i + 1, domain);
    }

    // Cleanup
    child.kill().expect("Failed to kill child process");
    child.wait().expect("Failed to wait for child process");

    Ok(())
}

#[test]
fn test_tool_schema_validation() -> Result<(), Box<dyn std::error::Error>> {
    // Build the server first
    build_server()?;

    // Start the server process
    let mut child = spawn_mcp_server()?;

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut stdout_reader = BufReader::new(stdout);

    // Initialize the server
    initialize_mcp_server(&mut stdin, &mut stdout_reader)?;

    // Get tools and validate their schemas
    let tools_request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    let tools_response =
        send_request_and_get_response(&mut stdin, &mut stdout_reader, tools_request)?;
    let tools = tools_response["result"]["tools"].as_array().unwrap();

    // Validate each tool has required schema fields
    for tool in tools {
        assert!(tool["name"].is_string(), "Tool missing name field");
        assert!(
            tool["description"].is_string(),
            "Tool missing description field"
        );
        assert!(
            tool["inputSchema"].is_object(),
            "Tool missing inputSchema field"
        );

        let input_schema = &tool["inputSchema"];
        assert_eq!(
            input_schema["type"], "object",
            "InputSchema should be object type"
        );
        assert!(
            input_schema["properties"].is_object(),
            "InputSchema missing properties"
        );

        println!(
            "✓ Tool '{}' has valid schema",
            tool["name"].as_str().unwrap()
        );
    }

    // Cleanup
    child.kill().expect("Failed to kill child process");
    child.wait().expect("Failed to wait for child process");

    Ok(())
}
