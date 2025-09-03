use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::whois;

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainAge {
    pub domain: String,
    pub creation_date: Option<String>,
    pub age_days: Option<i64>,
    pub age_years: Option<f64>,
}

pub async fn check_age(domain: &str) -> Result<DomainAge> {
    let domain = normalize_domain(domain);
    let whois_info = whois::lookup(&domain).await?;

    let (age_days, age_years) = if let Some(creation_date_str) = &whois_info.creation_date {
        if let Some(days) = parse_date_and_calculate_age(creation_date_str) {
            let years = days as f64 / 365.25;
            (Some(days), Some(years))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    Ok(DomainAge {
        domain,
        creation_date: whois_info.creation_date,
        age_days,
        age_years,
    })
}

fn normalize_domain(domain: &str) -> String {
    domain
        .trim()
        .to_lowercase()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("www.")
        .trim_end_matches('/')
        .to_string()
}

fn parse_date_and_calculate_age(date_str: &str) -> Option<i64> {
    use chrono::{NaiveDate, NaiveDateTime};

    // First try parsing as NaiveDateTime for formats with time
    let datetime_formats = ["%Y-%m-%dT%H:%M:%S%.fZ", "%Y-%m-%d %H:%M:%S"];

    for format in &datetime_formats {
        if let Ok(date) = NaiveDateTime::parse_from_str(date_str, format) {
            let date_utc = DateTime::<Utc>::from_naive_utc_and_offset(date, Utc);
            let now = Utc::now();
            let duration = now.signed_duration_since(date_utc);
            return Some(duration.num_days());
        }
    }

    // Then try parsing as NaiveDate for date-only formats
    let date_formats = ["%Y-%m-%d", "%d-%b-%Y"];

    for format in &date_formats {
        if let Ok(date) = NaiveDate::parse_from_str(date_str, format) {
            let date_time = date.and_hms_opt(0, 0, 0).unwrap();
            let date_utc = DateTime::<Utc>::from_naive_utc_and_offset(date_time, Utc);
            let now = Utc::now();
            let duration = now.signed_duration_since(date_utc);
            return Some(duration.num_days());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize_domain("  example.com  "), "example.com");
        assert_eq!(normalize_domain("http://example.com"), "example.com");
        assert_eq!(normalize_domain("https://example.com"), "example.com");
        assert_eq!(normalize_domain("www.example.com"), "example.com");
        assert_eq!(normalize_domain("https://www.example.com/"), "example.com");
        assert_eq!(
            normalize_domain("https://WWW.EXAMPLE.COM/path"),
            "example.com/path"
        );
    }

    #[test]
    fn test_parse_date_and_calculate_age_iso_format() {
        let yesterday = Utc::now() - Duration::days(1);
        let date_str = yesterday.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string();

        let age_days = parse_date_and_calculate_age(&date_str);
        assert!(age_days.is_some());
        assert_eq!(age_days.unwrap(), 1);
    }

    #[test]
    fn test_parse_date_and_calculate_age_simple_date() {
        // Test simple date format YYYY-MM-DD
        let five_days_ago = Utc::now() - Duration::days(5);
        let date_str = five_days_ago.format("%Y-%m-%d").to_string();

        let age_days = parse_date_and_calculate_age(&date_str);
        assert!(age_days.is_some());
        assert!(age_days.unwrap() >= 4 && age_days.unwrap() <= 5);
    }

    #[test]
    fn test_parse_date_and_calculate_age_with_time() {
        let week_ago = Utc::now() - Duration::days(7);
        let date_str = week_ago.format("%Y-%m-%d %H:%M:%S").to_string();

        let age_days = parse_date_and_calculate_age(&date_str);
        assert!(age_days.is_some());
        assert!(age_days.unwrap() >= 6 && age_days.unwrap() <= 7);
    }

    #[test]
    fn test_parse_date_and_calculate_age_invalid_format() {
        let age_days = parse_date_and_calculate_age("invalid date");
        assert!(age_days.is_none());

        let age_days = parse_date_and_calculate_age("2024-99-99");
        assert!(age_days.is_none());

        let age_days = parse_date_and_calculate_age("");
        assert!(age_days.is_none());
    }

    #[test]
    fn test_parse_date_and_calculate_age_old_date() {
        // Test with a date from 1997 (like Google's registration)
        let age_days = parse_date_and_calculate_age("1997-09-15T04:00:00Z");
        assert!(age_days.is_some());
        let days = age_days.unwrap();
        // Should be roughly 27+ years old (27 * 365 = ~9855 days)
        assert!(days > 9000);
    }

    #[test]
    fn test_parse_date_and_calculate_age_future_date() {
        let tomorrow = Utc::now() + Duration::days(1);
        let date_str = tomorrow.format("%Y-%m-%dT%H:%M:%S%.fZ").to_string();

        let age_days = parse_date_and_calculate_age(&date_str);
        assert!(age_days.is_some());
        // Should be negative for future dates (could be 0 or -1 depending on timing)
        assert!(age_days.unwrap() <= 0);
    }

    #[test]
    fn test_parse_date_formats_variety() {
        // Test different supported formats

        // Simple date format
        let base_date = "2020-01-01";
        assert!(parse_date_and_calculate_age(base_date).is_some());

        // ISO format with timezone
        let iso_date = "2020-01-01T12:30:45Z";
        assert!(parse_date_and_calculate_age(iso_date).is_some());

        // DateTime format
        let datetime_date = "2020-01-01 12:30:45";
        assert!(parse_date_and_calculate_age(datetime_date).is_some());

        // Test the %d-%b-%Y format (like "15-Sep-1997")
        let whois_date = "15-Sep-1997";
        assert!(parse_date_and_calculate_age(whois_date).is_some());
    }
}
