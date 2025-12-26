// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use http::HeaderMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::LazyLock;

/// De-facto standard header keys.
const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";
const X_FORWARDED_SCHEME: &str = "x-forwarded-scheme";
const X_REAL_IP: &str = "x-real-ip";

/// RFC7239 defines a new "Forwarded: " header designed to replace the
/// existing use of X-Forwarded-* headers.
/// e.g. Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43
const FORWARDED: &str = "forwarded";

static FOR_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:for=)([^(;|,| )]+)(.*)").unwrap());
static PROTO_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(;|,| )+(?:proto=)(https|http)").unwrap());

/// Used to disable all processing of the X-Forwarded-For header in source IP discovery.
///
/// # Returns
/// A `bool` indicating whether the X-Forwarded-For header is enabled
///
fn is_xff_header_enabled() -> bool {
    env::var("_RUSTFS_API_XFF_HEADER")
        .unwrap_or_else(|_| "on".to_string())
        .to_lowercase()
        == "on"
}

/// TrustedProxies holds configuration for validating proxy sources
#[derive(Debug, Clone)]
pub struct TrustedProxies {
    /// List of trusted proxy IP networks (CIDR format)
    pub cidrs: Vec<IpNet>,
    /// Whether to enable proxy validation
    pub enable_validation: bool,
    /// Maximum allowed proxy chain length
    pub max_chain_length: usize,
}

impl TrustedProxies {
    /// Create a new TrustedProxies configuration
    pub fn new(cidrs: Vec<String>, enable_validation: bool, max_chain_length: usize) -> Self {
        let cidrs = cidrs.into_iter().filter_map(|s| s.parse::<IpNet>().ok()).collect();
        Self {
            cidrs,
            enable_validation,
            max_chain_length,
        }
    }

    /// Check if an IP address is within the trusted proxy ranges
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        if !self.enable_validation {
            return true; // Backward compatibility: trust all when disabled
        }
        self.cidrs.iter().any(|net| net.contains(&ip))
    }
}

impl Default for TrustedProxies {
    fn default() -> Self {
        Self {
            cidrs: vec![],
            enable_validation: true,
            max_chain_length: 10,
        }
    }
}

/// Validate if an IP string represents a valid client IP
/// Returns false for private/loopback addresses and invalid formats
fn is_valid_client_ip(ip_str: &str, max_chain_length: usize) -> bool {
    // Handle X-Forwarded-For chains
    if ip_str.contains(',') {
        let parts: Vec<&str> = ip_str.split(',').map(|s| s.trim()).collect();
        if parts.len() > max_chain_length {
            return false;
        }
        // Validate each IP in the chain
        for part in parts {
            if !is_valid_single_ip(part) {
                return false;
            }
        }
        return true;
    }

    is_valid_single_ip(ip_str)
}

/// Validate a single IP address string
fn is_valid_single_ip(ip_str: &str) -> bool {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => {
            // Reject private and loopback addresses as client IPs
            // (they should come from trusted proxies only)
            !is_private(ip) && !ip.is_loopback()
        }
        Err(_) => false,
    }
}

/// Check if an IP address is private
///
/// # Arguments
/// * `ip` - The IP address to check
///
/// # Returns
/// A `bool` indicating whether the IP is private
///

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(ipv6) => {
            // Check if it's in fc00::/7 (Unique Local Address)
            let octets = ipv6.octets();
            (octets[0] & 0xfe) == 0xfc
        }
    }
}

/// GetSourceScheme retrieves the scheme from the X-Forwarded-Proto and RFC7239
/// Forwarded headers (in that order).
///
/// # Arguments
/// * `headers` - HTTP headers from the request
///
/// # Returns
/// An `Option<String>` containing the source scheme if found
///
pub fn get_source_scheme(headers: &HeaderMap) -> Option<String> {
    // Retrieve the scheme from X-Forwarded-Proto.
    if let Some(proto) = headers.get(X_FORWARDED_PROTO) {
        if let Ok(proto_str) = proto.to_str() {
            return Some(proto_str.to_lowercase());
        }
    }

    if let Some(proto) = headers.get(X_FORWARDED_SCHEME) {
        if let Ok(proto_str) = proto.to_str() {
            return Some(proto_str.to_lowercase());
        }
    }

    if let Some(forwarded) = headers.get(FORWARDED) {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // match should contain at least two elements if the protocol was
            // specified in the Forwarded header. The first element will always be
            // the 'for=', which we ignore, subsequently we proceed to look for
            // 'proto=' which should precede right after `for=` if not
            // we simply ignore the values and return empty. This is in line
            // with the approach we took for returning first ip from multiple
            // params.
            if let Some(for_match) = FOR_REGEX.captures(forwarded_str) {
                if for_match.len() > 1 {
                    let remaining = &for_match[2];
                    if let Some(proto_match) = PROTO_REGEX.captures(remaining) {
                        if proto_match.len() > 1 {
                            return Some(proto_match[2].to_lowercase());
                        }
                    }
                }
            }
        }
    }

    None
}

/// GetSourceIPFromHeaders retrieves the IP from the X-Forwarded-For, X-Real-IP
/// and RFC7239 Forwarded headers (in that order)
///
/// # Arguments
/// * `headers` - HTTP headers from the request
///
/// # Returns
/// An `Option<String>` containing the source IP address if found
///
pub fn get_source_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    let mut addr = None;

    if is_xff_header_enabled() {
        if let Some(forwarded_for) = headers.get(X_FORWARDED_FOR) {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                // Only grab the first (client) address. Note that '192.168.0.1,
                // 10.1.1.1' is a valid key for X-Forwarded-For where addresses after
                // the first may represent forwarding proxies earlier in the chain.
                let first_comma = forwarded_str.find(", ");
                let end = first_comma.unwrap_or(forwarded_str.len());
                addr = Some(forwarded_str[..end].to_string());
            }
        }
    }

    if addr.is_none() {
        if let Some(real_ip) = headers.get(X_REAL_IP) {
            if let Ok(real_ip_str) = real_ip.to_str() {
                // X-Real-IP should only contain one IP address (the client making the
                // request).
                addr = Some(real_ip_str.to_string());
            }
        } else if let Some(forwarded) = headers.get(FORWARDED) {
            if let Ok(forwarded_str) = forwarded.to_str() {
                // match should contain at least two elements if the protocol was
                // specified in the Forwarded header. The first element will always be
                // the 'for=' capture, which we ignore. In the case of multiple IP
                // addresses (for=8.8.8.8, 8.8.4.4, 172.16.1.20 is valid) we only
                // extract the first, which should be the client IP.
                if let Some(for_match) = FOR_REGEX.captures(forwarded_str) {
                    if for_match.len() > 1 {
                        // IPv6 addresses in Forwarded headers are quoted-strings. We strip
                        // these quotes.
                        let ip = for_match[1].trim_matches('"');
                        addr = Some(ip.to_string());
                    }
                }
            }
        }
    }

    addr
}

/// GetSourceIPRaw retrieves the IP from the request headers with trusted proxy validation
/// and falls back to peer_addr when necessary.
///
/// # Arguments
/// * `headers` - HTTP headers from the request
/// * `peer_addr` - Peer IP address from the connection
/// * `trusted_proxies` - Trusted proxy configuration
///
/// # Returns
/// A `String` containing the validated source IP address
///
pub fn get_source_ip_raw(headers: &HeaderMap, peer_addr: IpAddr, trusted_proxies: &TrustedProxies) -> String {
    // If validation is disabled, use legacy behavior for backward compatibility
    if !trusted_proxies.enable_validation {
        let remote_addr_str = peer_addr.to_string();
        return get_source_ip_raw_legacy(headers, &remote_addr_str);
    }

    // Check if the direct connection is from a trusted proxy
    if trusted_proxies.is_trusted_proxy(peer_addr) {
        // Trusted proxy: try to get real client IP from headers
        if let Some(header_ip) = get_source_ip_from_headers(headers) {
            // Validate the IP from headers
            if is_valid_client_ip(&header_ip, trusted_proxies.max_chain_length) {
                return header_ip;
            }
            // If header IP is invalid, log warning and fall back to peer
            tracing::warn!("Invalid client IP in headers from trusted proxy {}: {}", peer_addr, header_ip);
        }
    }

    // Untrusted source or no valid header IP: use connection peer address
    peer_addr.to_string()
}

/// Legacy GetSourceIPRaw for backward compatibility when validation is disabled
fn get_source_ip_raw_legacy(headers: &HeaderMap, remote_addr: &str) -> String {
    let addr = get_source_ip_from_headers(headers).unwrap_or_else(|| remote_addr.to_string());

    // Default to remote address if headers not set.
    if let Ok(socket_addr) = SocketAddr::from_str(&addr) {
        socket_addr.ip().to_string()
    } else {
        addr
    }
}

/// GetSourceIP retrieves the IP from the request headers with trusted proxy validation
/// and falls back to peer_addr when necessary.
/// It brackets IPv6 addresses.
///
/// # Arguments
/// * `headers` - HTTP headers from the request
/// * `peer_addr` - Peer IP address from the connection
/// * `trusted_proxies` - Trusted proxy configuration
///
/// # Returns
/// A `String` containing the source IP address, with IPv6 addresses bracketed
///
pub fn get_source_ip(headers: &HeaderMap, peer_addr: IpAddr, trusted_proxies: &TrustedProxies) -> String {
    let addr = get_source_ip_raw(headers, peer_addr, trusted_proxies);
    if addr.contains(':') { format!("[{addr}]") } else { addr }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn create_test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers
    }

    #[test]
    fn test_get_source_scheme() {
        let headers = create_test_headers();
        assert_eq!(get_source_scheme(&headers), Some("https".to_string()));
    }

    #[test]
    fn test_get_source_ip_from_headers() {
        let headers = create_test_headers();
        assert_eq!(get_source_ip_from_headers(&headers), Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_trusted_proxies_validation() {
        let trusted_proxies = TrustedProxies::new(vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()], true, 5);

        // Trusted IPs
        assert!(trusted_proxies.is_trusted_proxy("192.168.1.1".parse().unwrap()));
        assert!(trusted_proxies.is_trusted_proxy("10.1.1.1".parse().unwrap()));

        // Untrusted IPs
        assert!(!trusted_proxies.is_trusted_proxy("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_get_source_ip_raw_with_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));

        let trusted_proxies = TrustedProxies::new(vec!["192.168.1.1/32".to_string()], true, 5);
        let peer_addr: IpAddr = "192.168.1.1".parse().unwrap();

        let result = get_source_ip_raw(&headers, peer_addr, &trusted_proxies);
        assert_eq!(result, "203.0.113.1");
    }

    #[test]
    fn test_get_source_ip_raw_with_untrusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));

        let trusted_proxies = TrustedProxies::new(vec![], true, 5);
        let peer_addr: IpAddr = "203.0.113.2".parse().unwrap();

        let result = get_source_ip_raw(&headers, peer_addr, &trusted_proxies);
        assert_eq!(result, "203.0.113.2"); // Should use peer_addr
    }

    #[test]
    fn test_get_source_ip_raw_legacy_mode() {
        let headers = create_test_headers();
        let trusted_proxies = TrustedProxies::new(vec![], false, 5); // Disabled validation
        let peer_addr: IpAddr = "127.0.0.1".parse().unwrap();

        let result = get_source_ip_raw(&headers, peer_addr, &trusted_proxies);
        assert_eq!(result, "192.168.1.1"); // Should use header IP
    }

    #[test]
    fn test_get_source_ip() {
        let headers = create_test_headers();
        let trusted_proxies = TrustedProxies::new(vec!["192.168.1.1/32".to_string()], true, 5);
        let peer_addr: IpAddr = "192.168.1.1".parse().unwrap();

        let result = get_source_ip(&headers, peer_addr, &trusted_proxies);
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_get_source_ip_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("2001:db8::1"));

        let trusted_proxies = TrustedProxies::new(vec!["192.168.1.1/32".to_string()], true, 5);
        let peer_addr: IpAddr = "192.168.1.1".parse().unwrap();

        let result = get_source_ip(&headers, peer_addr, &trusted_proxies);
        assert_eq!(result, "[2001:db8::1]");
    }

    #[test]
    fn test_is_valid_client_ip() {
        // Valid public IPs
        assert!(is_valid_client_ip("203.0.113.1", 5));
        assert!(is_valid_client_ip("2001:db8::1", 5));

        // Invalid private IPs
        assert!(!is_valid_client_ip("192.168.1.1", 5));
        assert!(!is_valid_client_ip("10.0.0.1", 5));
        assert!(!is_valid_client_ip("127.0.0.1", 5));

        // Valid chain
        assert!(is_valid_client_ip("203.0.113.1, 198.51.100.1", 5));

        // Invalid chain (too long)
        assert!(!is_valid_client_ip(
            "203.0.113.1, 198.51.100.1, 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4",
            5
        ));
    }
}
