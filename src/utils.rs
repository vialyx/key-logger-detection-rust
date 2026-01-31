//! Utility functions and common types for the keylogger detector

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLevel::Safe => write!(f, "✅ Safe"),
            ThreatLevel::Low => write!(f, "🟡 Low"),
            ThreatLevel::Medium => write!(f, "🟠 Medium"),
            ThreatLevel::High => write!(f, "🔴 High"),
            ThreatLevel::Critical => write!(f, "⛔ Critical"),
        }
    }
}

/// A detected threat or suspicious activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    pub category: DetectionCategory,
    pub threat_level: ThreatLevel,
    pub name: String,
    pub description: String,
    pub details: DetectionDetails,
    pub timestamp: DateTime<Utc>,
    pub recommendations: Vec<String>,
}

/// Category of detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionCategory {
    Process,
    File,
    Network,
    InputHook,
    Registry,
    Memory,
    Behavior,
}

impl fmt::Display for DetectionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectionCategory::Process => write!(f, "Process"),
            DetectionCategory::File => write!(f, "File"),
            DetectionCategory::Network => write!(f, "Network"),
            DetectionCategory::InputHook => write!(f, "Input Hook"),
            DetectionCategory::Registry => write!(f, "Registry"),
            DetectionCategory::Memory => write!(f, "Memory"),
            DetectionCategory::Behavior => write!(f, "Behavior"),
        }
    }
}

/// Detailed information about a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionDetails {
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub file_path: Option<String>,
    pub network_address: Option<String>,
    pub port: Option<u16>,
    pub hash: Option<String>,
    pub matched_signature: Option<String>,
    pub additional_info: Vec<(String, String)>,
}

impl Default for DetectionDetails {
    fn default() -> Self {
        Self {
            process_id: None,
            process_name: None,
            file_path: None,
            network_address: None,
            port: None,
            hash: None,
            matched_signature: None,
            additional_info: Vec::new(),
        }
    }
}

/// Information about a running process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmd_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
    pub memory_usage: u64,
    pub cpu_usage: f32,
    pub start_time: Option<DateTime<Utc>>,
    pub threat_indicators: Vec<String>,
}

/// Scan result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub total_processes_scanned: usize,
    pub total_files_scanned: usize,
    pub total_connections_scanned: usize,
    pub detections: Vec<Detection>,
    pub system_info: SystemInfo,
}

impl ScanResult {
    pub fn threat_summary(&self) -> ThreatSummary {
        let mut summary = ThreatSummary::default();
        for detection in &self.detections {
            match detection.threat_level {
                ThreatLevel::Safe => summary.safe += 1,
                ThreatLevel::Low => summary.low += 1,
                ThreatLevel::Medium => summary.medium += 1,
                ThreatLevel::High => summary.high += 1,
                ThreatLevel::Critical => summary.critical += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub safe: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub kernel_version: String,
    pub total_memory: u64,
    pub available_memory: u64,
    pub cpu_count: usize,
}

/// Generate a unique ID for detections
pub fn generate_detection_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("DET-{:016X}", timestamp)
}

/// Calculate SHA-256 hash of a file
#[allow(dead_code)]
pub fn calculate_file_hash(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::{Sha256, Digest};
    use std::fs::File;
    use std::io::{BufReader, Read};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Check if a string contains any suspicious patterns
pub fn contains_suspicious_pattern(text: &str, patterns: &[&str]) -> Option<String> {
    let text_lower = text.to_lowercase();
    for pattern in patterns {
        if text_lower.contains(&pattern.to_lowercase()) {
            return Some(pattern.to_string());
        }
    }
    None
}

/// Format bytes to human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Safe < ThreatLevel::Low);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
        assert!(ThreatLevel::Medium < ThreatLevel::High);
        assert!(ThreatLevel::High < ThreatLevel::Critical);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.00 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn test_contains_suspicious_pattern() {
        let patterns = &["keylog", "hook", "capture"];
        assert_eq!(
            contains_suspicious_pattern("KeyLogger.exe", patterns),
            Some("keylog".to_string())
        );
        assert_eq!(
            contains_suspicious_pattern("normal_app.exe", patterns),
            None
        );
    }
}
