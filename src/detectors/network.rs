//! Network monitoring for keylogger detection
//!
//! Keyloggers often exfiltrate captured data over the network.
//! This module monitors for:
//! - Suspicious outbound connections
//! - Known malicious ports
//! - Unusual data transfer patterns

use crate::utils::{
    Detection, DetectionCategory, DetectionDetails,
    generate_detection_id,
};
use chrono::Utc;
use colored::*;
use std::collections::HashMap;

/// Network connection information
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

/// Network analyzer for detecting suspicious connections
pub struct NetworkAnalyzer {
    suspicious_ports: Vec<u16>,
}

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_ports: super::SUSPICIOUS_PORTS.to_vec(),
        }
    }

    /// Get all network connections
    pub fn get_connections(&self) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();
        
        // Use platform-specific commands to get connection info
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-anv", "-p", "tcp"])
                .output()
            {
                connections.extend(self.parse_netstat_output(&String::from_utf8_lossy(&output.stdout), "tcp"));
            }
            
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-anv", "-p", "udp"])
                .output()
            {
                connections.extend(self.parse_netstat_output(&String::from_utf8_lossy(&output.stdout), "udp"));
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("ss")
                .args(["-tunap"])
                .output()
            {
                connections.extend(self.parse_ss_output(&String::from_utf8_lossy(&output.stdout)));
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-ano"])
                .output()
            {
                connections.extend(self.parse_windows_netstat(&String::from_utf8_lossy(&output.stdout)));
            }
        }

        connections
    }

    /// Parse macOS/BSD netstat output
    fn parse_netstat_output(&self, output: &str, protocol: &str) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                if let Some(conn) = self.parse_address_pair(parts.get(3), parts.get(4), protocol) {
                    let mut conn = conn;
                    // Try to get PID from the last column if present
                    if let Some(pid_str) = parts.last() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            conn.pid = Some(pid);
                        }
                    }
                    if parts.len() > 5 {
                        conn.state = parts[5].to_string();
                    }
                    connections.push(conn);
                }
            }
        }
        
        connections
    }

    /// Parse Linux ss output
    #[allow(dead_code)]
    fn parse_ss_output(&self, output: &str) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let protocol = parts.first().unwrap_or(&"tcp").to_string();
                if let Some(conn) = self.parse_address_pair(parts.get(4), parts.get(5), &protocol) {
                    let mut conn = conn;
                    conn.state = parts.get(1).unwrap_or(&"UNKNOWN").to_string();
                    // Parse PID/program from last column
                    if let Some(last) = parts.last() {
                        if last.contains("pid=") {
                            if let Some(pid_part) = last.split(',').find(|p| p.starts_with("pid=")) {
                                if let Ok(pid) = pid_part.trim_start_matches("pid=").parse::<u32>() {
                                    conn.pid = Some(pid);
                                }
                            }
                        }
                    }
                    connections.push(conn);
                }
            }
        }
        
        connections
    }

    /// Parse Windows netstat output
    #[allow(dead_code)]
    fn parse_windows_netstat(&self, output: &str) -> Vec<NetworkConnection> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let protocol = parts.first().unwrap_or(&"TCP").to_string();
                if let Some(conn) = self.parse_address_pair(parts.get(1), parts.get(2), &protocol) {
                    let mut conn = conn;
                    conn.state = parts.get(3).unwrap_or(&"UNKNOWN").to_string();
                    if let Some(pid_str) = parts.get(4) {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            conn.pid = Some(pid);
                        }
                    }
                    connections.push(conn);
                }
            }
        }
        
        connections
    }

    /// Parse address:port pairs
    fn parse_address_pair(&self, local: Option<&&str>, remote: Option<&&str>, protocol: &str) -> Option<NetworkConnection> {
        let local = local?;
        let remote = remote?;
        
        let (local_addr, local_port) = self.split_address_port(local)?;
        let (remote_addr, remote_port) = self.split_address_port(remote)?;
        
        Some(NetworkConnection {
            protocol: protocol.to_string(),
            local_address: local_addr,
            local_port,
            remote_address: remote_addr,
            remote_port,
            state: String::new(),
            pid: None,
            process_name: None,
        })
    }

    /// Split address:port string
    fn split_address_port(&self, addr: &str) -> Option<(String, u16)> {
        // Handle IPv6 addresses like [::1]:8080
        if addr.starts_with('[') {
            let parts: Vec<&str> = addr.rsplitn(2, "]:").collect();
            if parts.len() == 2 {
                let port = parts[0].parse().ok()?;
                let address = format!("{}]", parts[1]);
                return Some((address, port));
            }
        }
        
        // Handle IPv4 or simple address:port
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port = parts[0].parse().ok()?;
            let address = parts[1].to_string();
            return Some((address, port));
        }
        
        // Handle addresses with . separator (like netstat on some systems)
        let parts: Vec<&str> = addr.rsplitn(2, '.').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[0].parse::<u16>() {
                return Some((parts[1].to_string(), port));
            }
        }
        
        None
    }

    /// Scan for suspicious network connections
    pub fn scan(&self) -> Vec<Detection> {
        let mut detections = Vec::new();
        let connections = self.get_connections();

        for conn in &connections {
            let mut indicators = Vec::new();

            // Check for suspicious ports
            if self.suspicious_ports.contains(&conn.remote_port) {
                indicators.push(format!("Connection to suspicious port: {}", conn.remote_port));
            }
            if self.suspicious_ports.contains(&conn.local_port) {
                indicators.push(format!("Listening on suspicious port: {}", conn.local_port));
            }

            // Check for connections to unusual destinations
            if conn.state.contains("ESTABLISHED") || conn.state.contains("ESTAB") {
                // Check if connecting to external addresses
                if !is_local_address(&conn.remote_address) {
                    // Check if the process name is suspicious
                    if let Some(ref name) = conn.process_name {
                        let name_lower = name.to_lowercase();
                        for pattern in super::SUSPICIOUS_PROCESS_NAMES {
                            if name_lower.contains(pattern) {
                                indicators.push(format!("Suspicious process with network activity: {}", name));
                            }
                        }
                    }
                }
            }

            if !indicators.is_empty() {
                let threat_level = super::calculate_threat_level(&indicators);
                
                detections.push(Detection {
                    id: generate_detection_id(),
                    category: DetectionCategory::Network,
                    threat_level,
                    name: format!("Suspicious Network Connection"),
                    description: format!(
                        "Connection {}:{} -> {}:{} shows suspicious activity",
                        conn.local_address, conn.local_port,
                        conn.remote_address, conn.remote_port
                    ),
                    details: DetectionDetails {
                        process_id: conn.pid,
                        process_name: conn.process_name.clone(),
                        network_address: Some(conn.remote_address.clone()),
                        port: Some(conn.remote_port),
                        additional_info: indicators
                            .iter()
                            .enumerate()
                            .map(|(i, ind)| (format!("Indicator {}", i + 1), ind.clone()))
                            .collect(),
                        ..Default::default()
                    },
                    timestamp: Utc::now(),
                    recommendations: vec![
                        "Investigate the process making this connection".to_string(),
                        "Check if this connection is expected".to_string(),
                        "Consider blocking the connection if unauthorized".to_string(),
                    ],
                });
            }
        }

        detections
    }

    /// Get connection statistics
    pub fn get_statistics(&self) -> HashMap<String, usize> {
        let connections = self.get_connections();
        let mut stats = HashMap::new();
        
        stats.insert("total".to_string(), connections.len());
        stats.insert("tcp".to_string(), connections.iter().filter(|c| c.protocol.to_lowercase() == "tcp").count());
        stats.insert("udp".to_string(), connections.iter().filter(|c| c.protocol.to_lowercase() == "udp").count());
        stats.insert("established".to_string(), connections.iter().filter(|c| c.state.contains("ESTAB")).count());
        stats.insert("listening".to_string(), connections.iter().filter(|c| c.state.contains("LISTEN")).count());
        
        stats
    }

    /// Print network scan results
    #[allow(dead_code)]
    pub fn print_results(&self, verbose: bool) {
        let connections = self.get_connections();
        let detections = self.scan();
        let stats = self.get_statistics();

        println!("\n{}", "═══ Network Scan Results ═══".cyan().bold());
        println!("Total connections: {}", stats.get("total").unwrap_or(&0).to_string().green());
        println!("  TCP: {}, UDP: {}", 
            stats.get("tcp").unwrap_or(&0),
            stats.get("udp").unwrap_or(&0)
        );
        println!("  Established: {}, Listening: {}",
            stats.get("established").unwrap_or(&0),
            stats.get("listening").unwrap_or(&0)
        );

        if verbose {
            println!("\n{}", "All Connections:".yellow());
            for conn in &connections {
                let status = if detections.iter().any(|d| 
                    d.details.network_address.as_deref() == Some(&conn.remote_address)
                ) {
                    "⚠".red()
                } else {
                    "✓".green()
                };
                println!("  {} {} {}:{} -> {}:{} [{}]",
                    status,
                    conn.protocol,
                    conn.local_address, conn.local_port,
                    conn.remote_address, conn.remote_port,
                    conn.state
                );
            }
        }

        if detections.is_empty() {
            println!("\n{}", "✅ No suspicious network activity detected.".green());
        } else {
            println!("\n{}", format!("⚠️  {} suspicious connections detected:", detections.len()).red().bold());
            for detection in &detections {
                println!("\n  {} {}", "►".yellow(), detection.name.red());
                println!("    {}", detection.description);
                println!("    Threat Level: {}", detection.threat_level);
            }
        }
    }
}

impl Default for NetworkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an address is local
fn is_local_address(addr: &str) -> bool {
    addr.starts_with("127.") ||
    addr.starts_with("192.168.") ||
    addr.starts_with("10.") ||
    addr.starts_with("172.16.") ||
    addr.starts_with("172.17.") ||
    addr.starts_with("172.18.") ||
    addr.starts_with("172.19.") ||
    addr.starts_with("172.2") ||
    addr.starts_with("172.30.") ||
    addr.starts_with("172.31.") ||
    addr == "localhost" ||
    addr == "::1" ||
    addr == "*" ||
    addr == "0.0.0.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_local_address() {
        assert!(is_local_address("127.0.0.1"));
        assert!(is_local_address("192.168.1.1"));
        assert!(is_local_address("localhost"));
        assert!(!is_local_address("8.8.8.8"));
        assert!(!is_local_address("1.2.3.4"));
    }

    #[test]
    fn test_network_analyzer_creation() {
        let analyzer = NetworkAnalyzer::new();
        assert!(!analyzer.suspicious_ports.is_empty());
    }
}
