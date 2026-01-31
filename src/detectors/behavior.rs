//! Behavioral analysis for keylogger detection
//!
//! This module analyzes system behavior patterns to identify potential keylogger activity:
//! - Unusual file write patterns (logging keystrokes)
//! - Periodic data exfiltration attempts
//! - Suspicious timing patterns

use crate::utils::{
    Detection, DetectionCategory, DetectionDetails,
    generate_detection_id,
};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use walkdir::WalkDir;
use regex::Regex;

/// Behavioral analyzer for detecting keylogger-like activity
pub struct BehaviorAnalyzer {
    suspicious_patterns: Vec<Regex>,
    log_file_patterns: Vec<Regex>,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_patterns: vec![
                Regex::new(r"(?i)key\s*log").unwrap(),
                Regex::new(r"(?i)keystroke").unwrap(),
                Regex::new(r"(?i)key\s*press").unwrap(),
                Regex::new(r"(?i)keyboard\s*capture").unwrap(),
                Regex::new(r"(?i)input\s*monitor").unwrap(),
                Regex::new(r"(?i)key\s*capture").unwrap(),
                Regex::new(r"(?i)GetAsyncKeyState").unwrap(),
                Regex::new(r"(?i)SetWindowsHookEx").unwrap(),
            ],
            log_file_patterns: vec![
                Regex::new(r"(?i)^\d{4}-\d{2}-\d{2}.*key").unwrap(),
                Regex::new(r"(?i)pressed:\s*\w+").unwrap(),
                Regex::new(r"(?i)\[key\]:\s*").unwrap(),
                Regex::new(r"(?i)keystroke:").unwrap(),
            ],
        }
    }

    /// Scan a directory for suspicious files that might be keylogger logs
    pub fn scan_for_log_files(&self, path: &PathBuf) -> Vec<Detection> {
        let mut detections = Vec::new();
        
        for entry in WalkDir::new(path)
            .follow_links(false)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(detection) = self.analyze_file(entry.path()) {
                    detections.push(detection);
                }
            }
        }

        detections
    }

    /// Analyze a single file for suspicious content
    fn analyze_file(&self, path: &std::path::Path) -> Option<Detection> {
        // Skip binary files and very large files
        let metadata = std::fs::metadata(path).ok()?;
        if metadata.len() > 10_000_000 {
            return None; // Skip files larger than 10MB
        }

        // Check file name first
        let file_name = path.file_name()?.to_string_lossy().to_lowercase();
        let mut indicators = Vec::new();

        // Check for suspicious file names
        for pattern in super::SUSPICIOUS_PROCESS_NAMES {
            if file_name.contains(pattern) {
                indicators.push(format!("Suspicious filename pattern: '{}'", pattern));
            }
        }

        // Check for suspicious extensions
        if let Some(ext) = path.extension() {
            let ext_str = format!(".{}", ext.to_string_lossy().to_lowercase());
            for suspicious_ext in super::SUSPICIOUS_EXTENSIONS {
                if ext_str == *suspicious_ext {
                    indicators.push(format!("Suspicious extension: '{}'", suspicious_ext));
                }
            }
        }

        // Try to read text files and check content
        if let Ok(content) = std::fs::read_to_string(path) {
            // Check for suspicious patterns in content
            for pattern in &self.suspicious_patterns {
                if pattern.is_match(&content) {
                    indicators.push(format!("Content matches pattern: '{}'", pattern.as_str()));
                }
            }

            // Check for log-like patterns
            for pattern in &self.log_file_patterns {
                if pattern.is_match(&content) {
                    indicators.push(format!("Log pattern detected: '{}'", pattern.as_str()));
                }
            }

            // Check for high frequency of printable characters that might indicate keystroke logging
            if self.looks_like_keystroke_log(&content) {
                indicators.push("File appears to contain keystroke data".to_string());
            }
        }

        if indicators.is_empty() {
            return None;
        }

        let threat_level = super::calculate_threat_level(&indicators);
        
        Some(Detection {
            id: generate_detection_id(),
            category: DetectionCategory::File,
            threat_level,
            name: format!("Suspicious File: {}", file_name),
            description: format!(
                "File '{}' may contain keylogger data or be related to keylogger activity",
                path.display()
            ),
            details: DetectionDetails {
                file_path: Some(path.to_string_lossy().to_string()),
                additional_info: indicators
                    .iter()
                    .enumerate()
                    .map(|(i, ind)| (format!("Indicator {}", i + 1), ind.clone()))
                    .collect(),
                ..Default::default()
            },
            timestamp: Utc::now(),
            recommendations: vec![
                format!("Review file contents: {}", path.display()),
                "If suspicious, quarantine or delete the file".to_string(),
                "Check for related processes or files".to_string(),
            ],
        })
    }

    /// Check if content looks like keystroke logging data
    fn looks_like_keystroke_log(&self, content: &str) -> bool {
        let lines: Vec<&str> = content.lines().take(100).collect();
        if lines.len() < 5 {
            return false;
        }

        // Count lines that look like keystroke entries
        let mut keystroke_like = 0;
        for line in &lines {
            let trimmed = line.trim();
            // Check for common keystroke log patterns
            if trimmed.len() <= 50 && !trimmed.is_empty() {
                // Very short lines with timestamps or key names
                if trimmed.chars().filter(|c| c.is_alphanumeric()).count() <= 20 {
                    keystroke_like += 1;
                }
            }
        }

        // If more than 70% of lines look like keystroke entries
        keystroke_like as f64 / lines.len() as f64 > 0.7
    }

    /// Find recently modified files that might be keystroke logs
    #[allow(dead_code)]
    pub fn find_recent_suspicious_files(&self, path: &PathBuf, hours: u64) -> Vec<Detection> {
        let mut detections = Vec::new();
        let cutoff = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(hours * 3600))
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        for entry in WalkDir::new(path)
            .follow_links(false)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if modified > cutoff {
                            if let Some(detection) = self.analyze_file(entry.path()) {
                                detections.push(detection);
                            }
                        }
                    }
                }
            }
        }

        detections
    }

    /// Analyze file access patterns (would need elevated permissions in real scenarios)
    #[allow(dead_code)]
    pub fn analyze_access_patterns(&self) -> HashMap<String, usize> {
        // In a real implementation, this would use system-specific APIs
        // to monitor file access patterns
        HashMap::new()
    }
}

impl Default for BehaviorAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_behavior_analyzer_creation() {
        let analyzer = BehaviorAnalyzer::new();
        assert!(!analyzer.suspicious_patterns.is_empty());
    }

    #[test]
    fn test_suspicious_file_detection() {
        let analyzer = BehaviorAnalyzer::new();
        let dir = tempdir().unwrap();
        
        // Create a suspicious file
        let file_path = dir.path().join("keylog_data.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "2024-01-01 keystroke: A").unwrap();
        writeln!(file, "2024-01-01 keystroke: B").unwrap();
        writeln!(file, "2024-01-01 key pressed: Enter").unwrap();
        
        let detections = analyzer.scan_for_log_files(&dir.path().to_path_buf());
        assert!(!detections.is_empty());
    }
}
