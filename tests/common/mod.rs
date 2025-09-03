use rand::seq::SliceRandom;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

pub fn build_domain() -> &'static str {
    let domains = [
        "google.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
        "meta.com",
        "netflix.com",
        "twitter.com",
        "github.com",
        "stackoverflow.com",
        "reddit.com",
        "wikipedia.org",
        "youtube.com",
        "linkedin.com",
        "adobe.com",
        "salesforce.com",
        "oracle.com",
        "ibm.com",
        "intel.com",
        "nvidia.com",
        "cloudflare.com",
    ];

    domains.choose(&mut rand::thread_rng()).unwrap()
}

pub fn build_server() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .args(["build", "--release"])
        .output()
        .expect("Failed to execute cargo build");

    if !output.status.success() {
        return Err(format!("Build failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(())
}

pub fn send_request_and_get_response(
    stdin: &mut std::process::ChildStdin,
    stdout: &mut BufReader<std::process::ChildStdout>,
    request: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    // Send the request
    writeln!(stdin, "{}", serde_json::to_string(&request)?)?;
    stdin.flush()?;

    // Read the response
    let mut response_line = String::new();
    stdout.read_line(&mut response_line)?;

    // Parse the JSON response
    let response: Value = serde_json::from_str(response_line.trim())?;
    Ok(response)
}

pub fn initialize_mcp_server(
    stdin: &mut std::process::ChildStdin,
    stdout: &mut BufReader<std::process::ChildStdout>,
) -> Result<Value, Box<dyn std::error::Error>> {
    // Send initialization request
    let init_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {
                    "listChanged": false
                },
                "sampling": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    });

    let init_response = send_request_and_get_response(stdin, stdout, init_request)?;

    // Send initialized notification (required by MCP protocol)
    let initialized_notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });

    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&initialized_notification)?
    )?;
    stdin.flush()?;
    thread::sleep(Duration::from_millis(100)); // Give server time to process

    Ok(init_response)
}

pub fn spawn_mcp_server() -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let child = Command::new("target/release/domain-mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start domain-mcp server");

    // Give the server time to start
    thread::sleep(Duration::from_millis(1000));

    Ok(child)
}
