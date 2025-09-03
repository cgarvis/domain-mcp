use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug, Serialize, Deserialize)]
pub struct SslCertificateInfo {
    pub domain: String,
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub san_domains: Vec<String>,
    pub is_valid: bool,
    pub days_until_expiry: Option<i64>,
}

pub async fn get_certificate_info(domain: &str) -> Result<SslCertificateInfo> {
    let port = 443;
    let addr = format!("{}:{}", domain, port);

    let result = tokio::task::spawn_blocking({
        let domain = domain.to_string();
        let addr = addr.clone();
        move || get_cert_info_blocking(&domain, &addr)
    })
    .await??;

    Ok(result)
}

fn get_cert_info_blocking(domain: &str, addr: &str) -> Result<SslCertificateInfo> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    // Initialize the crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(domain.to_string())?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut tcp_stream = TcpStream::connect(addr)?;
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp_stream);

    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );
    tls_stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let _ = tls_stream.read_to_end(&mut response);

    let cert_chain = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("No certificates found"))?;

    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!("Certificate chain is empty"));
    }

    let cert_der = &cert_chain[0];
    let cert = parse_x509_certificate(cert_der.as_ref())?;

    Ok(cert)
}

fn parse_x509_certificate(cert_der: &[u8]) -> Result<SslCertificateInfo> {
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(cert_der)?;
    let temp_path = temp_file.path();

    let output = Command::new("openssl")
        .args([
            "x509",
            "-inform",
            "DER",
            "-in",
            temp_path.to_str().unwrap(),
            "-text",
            "-noout",
        ])
        .output()?;

    let cert_text = String::from_utf8_lossy(&output.stdout);

    let issuer = extract_cert_field(&cert_text, "Issuer: ");
    let subject = extract_cert_field(&cert_text, "Subject: ");
    let serial = extract_cert_field(&cert_text, "Serial Number:");
    let not_before = extract_cert_field(&cert_text, "Not Before:");
    let not_after = extract_cert_field(&cert_text, "Not After :");
    let sig_algo = extract_cert_field(&cert_text, "Signature Algorithm: ");

    let san_domains = extract_san_domains(&cert_text);

    let days_until_expiry = calculate_days_until_expiry(&not_after);
    let is_valid = days_until_expiry.is_some_and(|days| days > 0);

    Ok(SslCertificateInfo {
        domain: extract_cn_from_subject(&subject).unwrap_or_default(),
        issuer,
        subject,
        serial_number: serial,
        not_before,
        not_after,
        signature_algorithm: sig_algo,
        san_domains,
        is_valid,
        days_until_expiry,
    })
}

fn extract_cert_field(text: &str, field: &str) -> String {
    text.lines()
        .find(|line| line.contains(field))
        .map(|line| line.split(field).nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default()
}

fn extract_san_domains(text: &str) -> Vec<String> {
    let mut domains = Vec::new();
    let mut in_san_section = false;

    for line in text.lines() {
        if line.contains("X509v3 Subject Alternative Name:") {
            in_san_section = true;
            continue;
        }

        if in_san_section && line.starts_with("                ") {
            let parts: Vec<&str> = line.split(',').collect();
            for part in parts {
                if let Some(dns) = part.trim().strip_prefix("DNS:") {
                    domains.push(dns.to_string());
                }
            }
            break;
        }
    }

    domains
}

fn extract_cn_from_subject(subject: &str) -> Option<String> {
    subject
        .split(',')
        .find(|part| part.trim().starts_with("CN"))
        .and_then(|cn_part| cn_part.split('=').nth(1))
        .map(|cn| cn.trim().to_string())
}

fn calculate_days_until_expiry(not_after: &str) -> Option<i64> {
    use chrono::NaiveDateTime;

    let formats = ["%b %d %H:%M:%S %Y %Z", "%b %e %H:%M:%S %Y %Z"];

    for format in &formats {
        if let Ok(expiry) = NaiveDateTime::parse_from_str(not_after, format) {
            let expiry_utc = DateTime::<Utc>::from_naive_utc_and_offset(expiry, Utc);
            let now = Utc::now();
            let duration = expiry_utc.signed_duration_since(now);
            return Some(duration.num_days());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cert_field_test() {
        let sample_cert_text = r#"Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12345
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Test CA, O=Test Organization
        Validity
            Not Before: Jan  1 12:00:00 2024 GMT
            Not After : Jan  1 12:00:00 2025 GMT
        Subject: CN=example.com, O=Example Organization
"#;

        assert_eq!(
            extract_cert_field(sample_cert_text, "Issuer: "),
            "CN=Test CA, O=Test Organization"
        );
        assert_eq!(
            extract_cert_field(sample_cert_text, "Subject: "),
            "CN=example.com, O=Example Organization"
        );
        assert_eq!(
            extract_cert_field(sample_cert_text, "Serial Number:"),
            "12345"
        );
        assert_eq!(
            extract_cert_field(sample_cert_text, "Not Before:"),
            "Jan  1 12:00:00 2024 GMT"
        );
        assert_eq!(
            extract_cert_field(sample_cert_text, "Not After :"),
            "Jan  1 12:00:00 2025 GMT"
        );
        assert_eq!(
            extract_cert_field(sample_cert_text, "Signature Algorithm: "),
            "sha256WithRSAEncryption"
        );

        // Test field that doesn't exist
        assert_eq!(extract_cert_field(sample_cert_text, "NonExistent: "), "");
    }

    #[test]
    fn calculate_days_until_expiry_test() {
        // Test valid date formats
        let future_date = "Jan  1 12:00:00 2030 GMT";
        let days = calculate_days_until_expiry(future_date);
        assert!(days.is_some());
        assert!(days.unwrap() > 0);

        let past_date = "Jan  1 12:00:00 2020 GMT";
        let days = calculate_days_until_expiry(past_date);
        assert!(days.is_some());
        assert!(days.unwrap() < 0);

        // Test alternative format
        let future_date_alt = "Jan 15 12:00:00 2030 GMT";
        let days = calculate_days_until_expiry(future_date_alt);
        assert!(days.is_some());
        assert!(days.unwrap() > 0);

        // Test invalid format
        let invalid_date = "Invalid Date Format";
        let days = calculate_days_until_expiry(invalid_date);
        assert!(days.is_none());
    }

    #[test]
    fn extract_san_domains_test() {
        let sample_cert_text = r#"Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12345
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:example.com, DNS:www.example.com, DNS:api.example.com
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
"#;

        let domains = extract_san_domains(sample_cert_text);
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"www.example.com".to_string()));
        assert!(domains.contains(&"api.example.com".to_string()));

        // Test certificate without SAN
        let no_san_cert = r#"Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 12345
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
"#;

        let no_domains = extract_san_domains(no_san_cert);
        assert_eq!(no_domains.len(), 0);
    }

    #[test]
    fn extract_cn_from_subject_test() {
        let subject = "CN=example.com, O=Example Organization, C=US";
        assert_eq!(
            extract_cn_from_subject(subject),
            Some("example.com".to_string())
        );

        let subject_no_cn = "O=Example Organization, C=US";
        assert_eq!(extract_cn_from_subject(subject_no_cn), None);

        let subject_different_order = "O=Example Organization, CN=test.com, C=US";
        assert_eq!(
            extract_cn_from_subject(subject_different_order),
            Some("test.com".to_string())
        );

        let empty_subject = "";
        assert_eq!(extract_cn_from_subject(empty_subject), None);
    }
}
