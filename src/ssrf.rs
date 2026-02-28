//! SSRF (Server-Side Request Forgery) Protection.
//!
//! This module provides built-in deny rules to prevent agents from accessing
//! internal network resources, cloud metadata endpoints, and other sensitive
//! targets that should never be accessed from an agent.
//!
//! # Protected Resources
//!
//! - **Private IP Ranges**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//! - **Link-local**: 169.254.0.0/16
//! - **Localhost**: 127.0.0.0/8, localhost, ::1
//! - **Cloud Metadata Endpoints**: AWS (169.254.169.254), GCP, Azure
//! - **Internal DNS**: *.internal, *.local, *.localhost
//!
//! # Usage
//!
//! ```rust,ignore
//! use predicate_authorityd::ssrf::SsrfProtection;
//!
//! let ssrf = SsrfProtection::default();
//! if let Some(reason) = ssrf.check_resource("http://169.254.169.254/latest/meta-data/") {
//!     println!("Blocked: {}", reason);
//! }
//! ```

use std::net::IpAddr;

/// SSRF protection configuration
#[derive(Debug, Clone)]
pub struct SsrfProtection {
    /// Block private IP ranges (RFC 1918)
    pub block_private_ips: bool,
    /// Block link-local addresses (169.254.0.0/16)
    pub block_link_local: bool,
    /// Block localhost (127.0.0.0/8, ::1, localhost)
    pub block_localhost: bool,
    /// Block cloud metadata endpoints
    pub block_cloud_metadata: bool,
    /// Block internal DNS suffixes (.internal, .local, .localhost)
    pub block_internal_dns: bool,
    /// Additional blocked hostnames or patterns
    pub additional_blocked: Vec<String>,
}

impl Default for SsrfProtection {
    fn default() -> Self {
        Self {
            block_private_ips: true,
            block_link_local: true,
            block_localhost: true,
            block_cloud_metadata: true,
            block_internal_dns: true,
            additional_blocked: vec![],
        }
    }
}

impl SsrfProtection {
    /// Create a new SSRF protection instance with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an SSRF protection instance that allows all resources (disabled)
    pub fn disabled() -> Self {
        Self {
            block_private_ips: false,
            block_link_local: false,
            block_localhost: false,
            block_cloud_metadata: false,
            block_internal_dns: false,
            additional_blocked: vec![],
        }
    }

    /// Check if a resource URL is blocked by SSRF protection.
    /// Returns Some(reason) if blocked, None if allowed.
    pub fn check_resource(&self, resource: &str) -> Option<String> {
        // Parse the resource as a URL
        let host = self.extract_host(resource)?;

        // Check cloud metadata first (most specific)
        if self.block_cloud_metadata {
            if let Some(reason) = self.check_cloud_metadata(&host, resource) {
                return Some(reason);
            }
        }

        // Check if host is an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.check_ip_address(ip);
        }

        // Check hostname-based rules
        self.check_hostname(&host)
    }

    /// Extract the host from a resource string (URL or host:port)
    fn extract_host(&self, resource: &str) -> Option<String> {
        // Handle URLs with schemes
        if let Some(after_scheme) = resource
            .strip_prefix("http://")
            .or_else(|| resource.strip_prefix("https://"))
            .or_else(|| resource.strip_prefix("ftp://"))
        {
            // Extract host (before path, query, or port)
            let host_part = after_scheme.split('/').next().unwrap_or(after_scheme);

            // Handle IPv6 addresses in brackets: [::1]:8080 -> ::1
            if host_part.starts_with('[') {
                if let Some(end_bracket) = host_part.find(']') {
                    let ipv6_host = &host_part[1..end_bracket];
                    return Some(ipv6_host.to_lowercase());
                }
            }

            let host = host_part
                .split(':')
                .next()
                .unwrap_or(host_part)
                .to_lowercase();
            return Some(host);
        }

        // Handle bare hostnames or IP addresses
        let host = resource.split('/').next().unwrap_or(resource);

        // Handle IPv6 in brackets
        if host.starts_with('[') {
            if let Some(end_bracket) = host.find(']') {
                let ipv6_host = &host[1..end_bracket];
                return Some(ipv6_host.to_lowercase());
            }
        }

        let host = host.split(':').next().unwrap_or(host).to_lowercase();
        if !host.is_empty() {
            return Some(host);
        }

        None
    }

    /// Check if an IP address is blocked
    fn check_ip_address(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();

                // Localhost (127.0.0.0/8)
                if self.block_localhost && octets[0] == 127 {
                    return Some("SSRF: localhost IP blocked (127.0.0.0/8)".to_string());
                }

                // Link-local (169.254.0.0/16)
                if self.block_link_local && octets[0] == 169 && octets[1] == 254 {
                    return Some("SSRF: link-local IP blocked (169.254.0.0/16)".to_string());
                }

                // Private ranges (RFC 1918)
                if self.block_private_ips {
                    // 10.0.0.0/8
                    if octets[0] == 10 {
                        return Some("SSRF: private IP blocked (10.0.0.0/8)".to_string());
                    }
                    // 172.16.0.0/12
                    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                        return Some("SSRF: private IP blocked (172.16.0.0/12)".to_string());
                    }
                    // 192.168.0.0/16
                    if octets[0] == 192 && octets[1] == 168 {
                        return Some("SSRF: private IP blocked (192.168.0.0/16)".to_string());
                    }
                }

                None
            }
            IpAddr::V6(ipv6) => {
                // Localhost (::1)
                if self.block_localhost && ipv6.is_loopback() {
                    return Some("SSRF: localhost IP blocked (::1)".to_string());
                }

                // Check for IPv4-mapped addresses (::ffff:x.x.x.x)
                if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                    return self.check_ip_address(IpAddr::V4(ipv4));
                }

                None
            }
        }
    }

    /// Check hostname-based blocking rules
    fn check_hostname(&self, host: &str) -> Option<String> {
        // Localhost hostnames
        if self.block_localhost && (host == "localhost" || host == "localhost.localdomain") {
            return Some("SSRF: localhost hostname blocked".to_string());
        }

        // Internal DNS suffixes
        if self.block_internal_dns {
            if host.ends_with(".internal")
                || host.ends_with(".local")
                || host.ends_with(".localhost")
                || host.ends_with(".localdomain")
                || host.ends_with(".home")
                || host.ends_with(".lan")
                || host.ends_with(".corp")
                || host.ends_with(".intranet")
            {
                return Some(format!("SSRF: internal DNS suffix blocked ({})", host));
            }
        }

        // Additional blocked patterns
        for pattern in &self.additional_blocked {
            if host == pattern || host.ends_with(&format!(".{}", pattern)) {
                return Some(format!("SSRF: blocked by custom rule ({})", pattern));
            }
        }

        None
    }

    /// Check for cloud metadata endpoint access
    fn check_cloud_metadata(&self, host: &str, resource: &str) -> Option<String> {
        // AWS/GCP/Azure metadata endpoint IP
        if host == "169.254.169.254" {
            return Some("SSRF: cloud metadata endpoint blocked (169.254.169.254)".to_string());
        }

        // AWS Instance Metadata Service v2 hostname
        if host == "instance-data" || host.starts_with("instance-data.") {
            return Some("SSRF: AWS metadata hostname blocked".to_string());
        }

        // GCP metadata hostname
        if host == "metadata.google.internal" || host == "metadata" {
            return Some("SSRF: GCP metadata endpoint blocked".to_string());
        }

        // Azure metadata hostname
        if host == "169.254.169.254" || host == "metadata.azure.com" {
            return Some("SSRF: Azure metadata endpoint blocked".to_string());
        }

        // Kubernetes metadata
        if host == "kubernetes.default"
            || host == "kubernetes.default.svc"
            || host.starts_with("kubernetes.default.svc.")
        {
            return Some("SSRF: Kubernetes service endpoint blocked".to_string());
        }

        // Check for metadata paths (in case of DNS rebinding)
        let lower_resource = resource.to_lowercase();
        if lower_resource.contains("/latest/meta-data")
            || lower_resource.contains("/metadata/instance")
            || lower_resource.contains("/computemetadata/v1")
        {
            return Some("SSRF: cloud metadata path pattern blocked".to_string());
        }

        None
    }

    /// Add a hostname to the blocked list
    pub fn add_blocked_hostname(&mut self, hostname: &str) {
        self.additional_blocked.push(hostname.to_lowercase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_localhost_ip() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("http://127.0.0.1/").is_some());
        assert!(ssrf.check_resource("http://127.0.0.2:8080/api").is_some());
        assert!(ssrf.check_resource("http://127.255.255.255/").is_some());
    }

    #[test]
    fn test_block_localhost_hostname() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("http://localhost/").is_some());
        assert!(ssrf.check_resource("http://localhost:3000/api").is_some());
        assert!(ssrf.check_resource("http://LOCALHOST/").is_some());
    }

    #[test]
    fn test_block_private_ips() {
        let ssrf = SsrfProtection::default();

        // 10.0.0.0/8
        assert!(ssrf.check_resource("http://10.0.0.1/").is_some());
        assert!(ssrf.check_resource("http://10.255.255.255/").is_some());

        // 172.16.0.0/12
        assert!(ssrf.check_resource("http://172.16.0.1/").is_some());
        assert!(ssrf.check_resource("http://172.31.255.255/").is_some());

        // 192.168.0.0/16
        assert!(ssrf.check_resource("http://192.168.0.1/").is_some());
        assert!(ssrf.check_resource("http://192.168.255.255/").is_some());
    }

    #[test]
    fn test_allow_public_ips() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("http://8.8.8.8/").is_none());
        assert!(ssrf.check_resource("http://1.1.1.1/").is_none());
        assert!(ssrf.check_resource("http://93.184.216.34/").is_none());
    }

    #[test]
    fn test_block_link_local() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("http://169.254.0.1/").is_some());
        assert!(ssrf.check_resource("http://169.254.255.255/").is_some());
    }

    #[test]
    fn test_block_cloud_metadata() {
        let ssrf = SsrfProtection::default();

        // AWS metadata endpoint
        assert!(ssrf
            .check_resource("http://169.254.169.254/latest/meta-data/")
            .is_some());
        assert!(ssrf
            .check_resource("http://169.254.169.254/latest/user-data")
            .is_some());

        // GCP metadata
        assert!(ssrf
            .check_resource("http://metadata.google.internal/computeMetadata/v1/")
            .is_some());

        // Kubernetes
        assert!(ssrf
            .check_resource("http://kubernetes.default.svc/api/v1/")
            .is_some());
    }

    #[test]
    fn test_block_internal_dns() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf
            .check_resource("http://db.internal/connect")
            .is_some());
        assert!(ssrf
            .check_resource("http://api-server.local/")
            .is_some());
        assert!(ssrf
            .check_resource("http://secret.corp/admin")
            .is_some());
        assert!(ssrf
            .check_resource("http://service.intranet/")
            .is_some());
    }

    #[test]
    fn test_allow_external_domains() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("https://example.com/").is_none());
        assert!(ssrf.check_resource("https://api.github.com/").is_none());
        assert!(ssrf.check_resource("https://google.com/search").is_none());
    }

    #[test]
    fn test_disabled_protection() {
        let ssrf = SsrfProtection::disabled();

        assert!(ssrf.check_resource("http://127.0.0.1/").is_none());
        assert!(ssrf.check_resource("http://10.0.0.1/").is_none());
        assert!(ssrf.check_resource("http://localhost/").is_none());
    }

    #[test]
    fn test_custom_blocked_hostname() {
        let mut ssrf = SsrfProtection::default();
        ssrf.add_blocked_hostname("evil.com");

        assert!(ssrf.check_resource("http://evil.com/").is_some());
        assert!(ssrf.check_resource("http://sub.evil.com/").is_some());
        assert!(ssrf.check_resource("http://notevil.com/").is_none());
    }

    #[test]
    fn test_ipv6_localhost() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("http://[::1]/").is_some());
    }

    #[test]
    fn test_case_insensitive() {
        let ssrf = SsrfProtection::default();

        assert!(ssrf.check_resource("http://LocalHost/").is_some());
        assert!(ssrf.check_resource("http://LOCALHOST/").is_some());
        assert!(ssrf.check_resource("http://DB.INTERNAL/").is_some());
    }

    #[test]
    fn test_metadata_path_patterns() {
        let ssrf = SsrfProtection::default();

        // Even if someone bypasses DNS, the path patterns should be caught
        assert!(ssrf
            .check_resource("http://8.8.8.8/latest/meta-data/iam/")
            .is_some());
        assert!(ssrf
            .check_resource("http://example.com/computeMetadata/v1/instance")
            .is_some());
    }

    #[test]
    fn test_extract_host_from_url() {
        let ssrf = SsrfProtection::default();

        // Test that hosts are extracted correctly
        assert!(ssrf.check_resource("https://localhost:8443/path").is_some());
        assert!(ssrf
            .check_resource("http://127.0.0.1:9999/api/v1")
            .is_some());
    }
}
