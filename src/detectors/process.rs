//! Process-based keylogger detection
//!
//! This module analyzes running processes to identify potential keylogger activity.
//! It checks for:
//! - Suspicious process names
//! - Unusual process behavior (high CPU with low visibility)
//! - Processes accessing input devices
//! - Hidden or obfuscated processes

use crate::utils::{
    Detection, DetectionCategory, DetectionDetails, ProcessInfo,
    contains_suspicious_pattern, generate_detection_id,
};
use chrono::Utc;
use sysinfo::{System, Pid};
use colored::*;

/// Process detector for identifying suspicious processes
pub struct ProcessDetector {
    system: System,
}

impl ProcessDetector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self { system }
    }

    /// Refresh process information
    pub fn refresh(&mut self) {
        self.system.refresh_all();
    }

    /// Get all running processes with threat analysis
    pub fn get_processes(&self) -> Vec<ProcessInfo> {
        self.system
            .processes()
            .iter()
            .map(|(pid, process)| {
                let indicators = self.analyze_process_indicators(process);
                ProcessInfo {
                    pid: pid.as_u32(),
                    name: process.name().to_string(),
                    exe_path: process.exe().map(|p| p.to_string_lossy().to_string()),
                    cmd_line: Some(process.cmd().join(" ")),
                    parent_pid: process.parent().map(|p| p.as_u32()),
                    user: process.user_id().map(|u| format!("{:?}", u)),
                    memory_usage: process.memory(),
                    cpu_usage: process.cpu_usage(),
                    start_time: None, // Would need additional platform-specific code
                    threat_indicators: indicators,
                }
            })
            .collect()
    }

    /// Analyze a process for threat indicators
    fn analyze_process_indicators(&self, process: &sysinfo::Process) -> Vec<String> {
        let mut indicators = Vec::new();
        let name = process.name().to_lowercase();
        let exe_path = process.exe()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let cmd_line = process.cmd().join(" ").to_lowercase();

        // Check for suspicious name patterns
        if let Some(pattern) = contains_suspicious_pattern(&name, super::SUSPICIOUS_PROCESS_NAMES) {
            indicators.push(format!("Suspicious name pattern: '{}'", pattern));
        }

        // Check executable path
        if let Some(pattern) = contains_suspicious_pattern(&exe_path, super::SUSPICIOUS_PROCESS_NAMES) {
            indicators.push(format!("Suspicious path pattern: '{}'", pattern));
        }

        // Check command line arguments
        if let Some(pattern) = contains_suspicious_pattern(&cmd_line, super::SUSPICIOUS_PROCESS_NAMES) {
            indicators.push(format!("Suspicious command line: '{}'", pattern));
        }

        // Check for processes that might be reading keyboard input
        let input_keywords = ["keyboard", "input", "getasynckeystate", "keybd", "hook"];
        if let Some(pattern) = contains_suspicious_pattern(&cmd_line, &input_keywords) {
            indicators.push(format!("Potential input capture: '{}'", pattern));
        }

        // Check for hidden/temp directory execution
        if exe_path.contains("/tmp/") || exe_path.contains("/temp/") || exe_path.contains("\\temp\\") {
            indicators.push("Running from temporary directory".to_string());
        }

        // Check for processes running from hidden directories
        if exe_path.contains("/.") || exe_path.contains("\\.") {
            indicators.push("Running from hidden directory".to_string());
        }

        // High memory usage with suspicious name
        if process.memory() > 100_000_000 && !indicators.is_empty() {
            indicators.push("High memory usage combined with suspicious indicators".to_string());
        }

        indicators
    }

    /// Scan all processes and return detections
    pub fn scan(&self) -> Vec<Detection> {
        let mut detections = Vec::new();

        for process_info in self.get_processes() {
            if !process_info.threat_indicators.is_empty() {
                let threat_level = super::calculate_threat_level(&process_info.threat_indicators);
                
                let detection = Detection {
                    id: generate_detection_id(),
                    category: DetectionCategory::Process,
                    threat_level,
                    name: format!("Suspicious Process: {}", process_info.name),
                    description: format!(
                        "Process '{}' (PID: {}) exhibits suspicious behavior",
                        process_info.name, process_info.pid
                    ),
                    details: DetectionDetails {
                        process_id: Some(process_info.pid),
                        process_name: Some(process_info.name.clone()),
                        file_path: process_info.exe_path.clone(),
                        additional_info: process_info.threat_indicators
                            .iter()
                            .enumerate()
                            .map(|(i, ind)| (format!("Indicator {}", i + 1), ind.clone()))
                            .collect(),
                        ..Default::default()
                    },
                    timestamp: Utc::now(),
                    recommendations: generate_recommendations(&process_info),
                };

                detections.push(detection);
            }
        }

        detections
    }

    /// Check a specific process by PID
    pub fn check_process(&mut self, pid: u32) -> Option<ProcessInfo> {
        self.refresh();
        let pid = Pid::from_u32(pid);
        
        self.system.process(pid).map(|process| {
            let indicators = self.analyze_process_indicators(process);
            ProcessInfo {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                exe_path: process.exe().map(|p| p.to_string_lossy().to_string()),
                cmd_line: Some(process.cmd().join(" ")),
                parent_pid: process.parent().map(|p| p.as_u32()),
                user: process.user_id().map(|u| format!("{:?}", u)),
                memory_usage: process.memory(),
                cpu_usage: process.cpu_usage(),
                start_time: None,
                threat_indicators: indicators,
            }
        })
    }

    /// Print process scan results to console
    #[allow(dead_code)]
    pub fn print_scan_results(&self, verbose: bool) {
        let processes = self.get_processes();
        let suspicious: Vec<_> = processes
            .iter()
            .filter(|p| !p.threat_indicators.is_empty())
            .collect();

        println!("\n{}", "═══ Process Scan Results ═══".cyan().bold());
        println!("Total processes scanned: {}", processes.len().to_string().green());
        println!("Suspicious processes found: {}", 
            if suspicious.is_empty() {
                "0".green().to_string()
            } else {
                suspicious.len().to_string().red().bold().to_string()
            }
        );

        if verbose {
            println!("\n{}", "All Processes:".yellow());
            for process in &processes {
                let status = if process.threat_indicators.is_empty() {
                    "✓".green()
                } else {
                    "⚠".red()
                };
                println!("  {} {} (PID: {})", status, process.name, process.pid);
            }
        }

        if !suspicious.is_empty() {
            println!("\n{}", "⚠️  Suspicious Processes Detected:".red().bold());
            for process in suspicious {
                println!("\n  {} {} (PID: {})", "►".yellow(), 
                    process.name.red().bold(), process.pid);
                if let Some(ref path) = process.exe_path {
                    println!("    Path: {}", path.dimmed());
                }
                println!("    Threat indicators:");
                for indicator in &process.threat_indicators {
                    println!("      • {}", indicator.yellow());
                }
            }
        } else {
            println!("\n{}", "✅ No suspicious processes detected.".green());
        }
    }
}

impl Default for ProcessDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate recommendations based on process information
fn generate_recommendations(process: &ProcessInfo) -> Vec<String> {
    let mut recommendations = Vec::new();

    recommendations.push(format!(
        "Investigate process '{}' (PID: {}) manually",
        process.name, process.pid
    ));

    if let Some(ref path) = process.exe_path {
        recommendations.push(format!("Check file integrity at: {}", path));
        recommendations.push("Scan the executable with antivirus software".to_string());
    }

    recommendations.push("Review process startup configuration".to_string());
    recommendations.push("Check if this process should be running on your system".to_string());

    if process.threat_indicators.len() >= 3 {
        recommendations.push("Consider terminating this process if unauthorized".to_string());
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_detector_creation() {
        let detector = ProcessDetector::new();
        let processes = detector.get_processes();
        // Should have at least one process (the test itself)
        assert!(!processes.is_empty());
    }
}
