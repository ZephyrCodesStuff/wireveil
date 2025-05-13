use httparse::{Request, EMPTY_HEADER};
use std::str;
use tracing::{debug, info, trace, warn};
use url::Url;

/// How many times we can reasonably expect an attacker to try obfuscating
/// the payload, by using URI encoding.
const MAX_ENCODING_LAYERS: usize = 5;

/// Determines if the payload contains an HTTP request and if so,
/// extracts and normalizes the URL.
pub fn process_http_packet(payload: &[u8]) -> Option<String> {
    // Check if this looks like an HTTP request
    if !is_http_request(payload) {
        return None;
    }

    // Parse the HTTP request to extract the URL
    extract_and_normalize_url(payload)
}

/// Checks if a packet payload appears to be an HTTP request
fn is_http_request(payload: &[u8]) -> bool {
    // Basic sanity check: HTTP methods are ASCII
    if payload.is_empty() {
        return false;
    }

    // Check for common HTTP methods
    let methods = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ",
    ];

    for method in methods.iter() {
        if payload.len() >= method.len() {
            if let Ok(start) = str::from_utf8(&payload[0..method.len()]) {
                if start == *method {
                    return true;
                }
            }
        }
    }

    // Use the httparse crate for more thorough detection
    let mut headers = [EMPTY_HEADER; 32];
    let mut req = Request::new(&mut headers);

    match req.parse(payload) {
        Ok(status) => status.is_complete() || status.is_partial(),
        Err(_) => false,
    }
}

/// Extracts and fully normalizes a URL from an HTTP request
fn extract_and_normalize_url(payload: &[u8]) -> Option<String> {
    // Try to parse the HTTP request
    let mut headers = [EMPTY_HEADER; 32];
    let mut req = Request::new(&mut headers);

    if req.parse(payload).is_err() {
        return None;
    }
    let (Some(method), Some(path)) = (req.method, req.path) else {
        return None;
    };
    trace!(method = %method, path = %path, "HTTP request detected");

    // Handle relative URLs by constructing a base
    let relative_url = path.to_string();

    // Look for the Host header to construct the full URL
    let mut host = None;
    for header in headers.iter() {
        if header.name.to_lowercase() == "host" {
            if let Ok(value) = str::from_utf8(header.value) {
                host = Some(value.trim());
                break;
            }
        }
    }

    let (original_url, normalized_url) = if let Some(host_value) = host {
        // Construct a full URL
        let scheme = if method == "CONNECT" { "https" } else { "http" };
        let url_string = format!("{scheme}://{host_value}{relative_url}");

        // Parse and normalize the URL
        trace!(original_url = %url_string, "Processing URL");
        (url_string.clone(), normalize_url(&url_string))
    } else {
        // Without a host, we can still normalize the path
        trace!(relative_path = %relative_url, "Processing relative URL");
        (
            relative_url.to_string(),
            normalize_relative_url(&relative_url),
        )
    };

    if let Some(ref norm_url) = normalized_url {
        if check_url_for_bypass(&original_url, norm_url) {
            // This is important security information - bump to info level
            info!(
                original = %original_url,
                normalized = %norm_url,
                "⚠️ URL encoding detected - potential bypass attempt"
            );
        } else {
            debug!(normalized = %norm_url, "URL normalized");
        }
    }

    normalized_url
}

/// Fully normalizes a URL, handling all encoding tricks
fn normalize_url(url_str: &str) -> Option<String> {
    // Attempt to parse the URL
    let Ok(mut url) = Url::parse(url_str) else {
        warn!(url = %url_str, "Failed to parse URL");
        return None;
    };

    // Normalize percent encodings
    url.set_path(&url.path().replace("%25", "%"));

    // Handle multiple encoding layers
    let mut path = url.path().to_string();
    let original_path = path.clone();

    // Multiple decode iterations to handle layered encoding
    for i in 0..MAX_ENCODING_LAYERS {
        // Limit iterations to prevent infinite loops
        let decoded = percent_encoding::percent_decode_str(&path)
            .decode_utf8_lossy()
            .to_string();

        if decoded == path {
            if i > 0 {
                trace!(
                    original = %original_path,
                    decoded = %path,
                    iterations = i,
                    "Multiple encoding layers detected"
                );
            }
            break; // No more encoding to decode
        }
        path = decoded;
    }

    // Set the decoded path back to the URL
    url.set_path(&path);

    // Normalize case in the host
    if let Some(host) = url.host_str() {
        // Create a normalized host (lowercase)
        let normalized_host = host.to_lowercase();

        // Only modify if different
        if normalized_host != host {
            trace!(original = %host, normalized = %normalized_host, "Normalizing hostname case");
            if let Err(e) = url.set_host(Some(&normalized_host)) {
                warn!(url = %url_str, error = %e, "Failed to normalize host in URL");
            }
        }
    }

    Some(url.to_string())
}

/// Normalizes a relative URL
fn normalize_relative_url(path: &str) -> Option<String> {
    // For relative URLs, we'll create a dummy base to use Url's normalization
    let base = "http://example.com";

    // Attempt to parse the base URL
    let Ok(url) = Url::parse(base) else {
        warn!(base = %base, "Failed to parse base URL for relative path normalization");
        return None;
    };

    let Ok(url) = url.join(path) else {
        warn!(base = %base, path = %path, "Failed to join base URL with relative path");
        return None;
    };

    let query_fmt = format!("?{}", url.query().unwrap_or(""));
    let path_and_query = url.path().to_string() + query_fmt.as_str();

    // Apply the same normalization for decoding
    let decoded_path = path_and_query;
    let original_path = decoded_path.clone();

    // Multiple decode iterations to handle layered encoding
    for i in 0..MAX_ENCODING_LAYERS {
        // Limit iterations to prevent infinite loops
        let decoded = urlencoding::decode(&decoded_path).unwrap_or_default();

        if decoded == decoded_path {
            if i > 0 {
                trace!(
                    original = %original_path,
                    decoded = %decoded_path,
                    iterations = i,
                    "Multiple encoding layers detected in relative URL"
                );
            }
            break; // No more encoding to decode
        }
    }

    Some(decoded_path)
}

/// Compares a raw URL with a normalized one for potential security bypasses
pub fn check_url_for_bypass(raw_url: &str, normalized_url: &str) -> bool {
    raw_url != normalized_url
}

// Function to determine if a port is typically used for HTTP traffic
pub fn is_http_traffic(port: u16) -> bool {
    // Common HTTP/HTTPS ports
    matches!(
        port,
        80 | 443 | 8000 | 8080 | 8443 | 3000 | 4000 | 8888 | 9000
    )
}
