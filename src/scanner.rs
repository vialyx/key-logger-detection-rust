//! Main scanner module that coordinates all detection mechanisms
//!
//! This module brings together all the detection components:
//! - Process scanning
//! - File system analysis
//! - Network monitoring
//! - Signature matching
//! - Hook detection

use crate::detectors::process::ProcessDetector;
use crate::detectors::behavior::BehaviorAnalyzer;
use crate::detectors::hooks::HookDetector;
use crate::detectors::network::NetworkAnalyzer;
use crate::signatures::SignatureDatabase;
use crate::utils::{
    Detection, ScanResult, SystemInfo,
    format_bytes, generate_detection_id,
};
use chrono::Utc;
use colored::*;
use std::path::PathBuf;
use sysinfo::System;

/// Run a comprehensive system scan
pub async fn run_full_scan(
    detailed: bool,
    path: Option<PathBuf>,
    verbose: bool,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let start_time = Utc::now();
    let mut all_detections: Vec<Detection> = Vec::new();
    
    println!("\n{}", "Starting comprehensive security scan...".cyan());
    println!("{}", "═".repeat(60).dimmed());

    // 1. Process Scan
    println!("\n{}", "📋 Phase 1: Process Analysis".yellow().bold());
    let process_detector = ProcessDetector::new();
    let process_detections = process_detector.scan();
    println!("  Scanned {} processes", process_detector.get_processes().len());
    println!("  Found {} suspicious processes", 
        if process_detections.is_empty() {
            "0".green().to_string()
        } else {
            process_detections.len().to_string().red().to_string()
        }
    );
    all_detections.extend(process_detections);

    // 2. Signature Check
    println!("\n{}", "🔏 Phase 2: Signature Analysis".yellow().bold());
    let sig_db = SignatureDatabase::new();
    println!("  Loaded {} known signatures", sig_db.get_signatures().len());
    
    // Check running processes against signatures
    for proc in process_detector.get_processes() {
        let matches = sig_db.check_process_name(&proc.name);
        for sig in matches {
            all_detections.push(Detection {
                id: generate_detection_id(),
                category: crate::utils::DetectionCategory::Process,
                threat_level: sig.threat_level,
                name: format!("Signature Match: {}", sig.name),
                description: sig.description.clone(),
                details: crate::utils::DetectionDetails {
                    process_id: Some(proc.pid),
                    process_name: Some(proc.name.clone()),
                    matched_signature: Some(sig.id.clone()),
                    ..Default::default()
                },
                timestamp: Utc::now(),
                recommendations: vec![
                    "Immediately terminate this process".to_string(),
                    "Quarantine associated files".to_string(),
                    "Scan for related malware".to_string(),
                ],
            });
        }
    }

    // 3. Hook Detection
    println!("\n{}", "🪝 Phase 3: Hook Detection".yellow().bold());
    let hook_detector = HookDetector::new();
    let hook_detections = hook_detector.scan();
    println!("  Checked for keyboard/input hooks");
    println!("  Found {} potential hooks",
        if hook_detections.is_empty() {
            "0".green().to_string()
        } else {
            hook_detections.len().to_string().red().to_string()
        }
    );
    all_detections.extend(hook_detections);

    // 4. Network Analysis
    println!("\n{}", "🌐 Phase 4: Network Analysis".yellow().bold());
    let network_analyzer = NetworkAnalyzer::new();
    let network_detections = network_analyzer.scan();
    let stats = network_analyzer.get_statistics();
    println!("  Analyzed {} network connections", stats.get("total").unwrap_or(&0));
    println!("  Found {} suspicious connections",
        if network_detections.is_empty() {
            "0".green().to_string()
        } else {
            network_detections.len().to_string().red().to_string()
        }
    );
    all_detections.extend(network_detections);

    // 5. File System Scan
    println!("\n{}", "📁 Phase 5: File System Analysis".yellow().bold());
    let behavior_analyzer = BehaviorAnalyzer::new();
    let scan_path = path.unwrap_or_else(|| {
        #[cfg(target_os = "macos")]
        { PathBuf::from(format!("{}/Library", std::env::var("HOME").unwrap_or_default())) }
        #[cfg(target_os = "linux")]
        { PathBuf::from("/var/log") }
        #[cfg(target_os = "windows")]
        { PathBuf::from(std::env::var("APPDATA").unwrap_or_default()) }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        { PathBuf::from(".") }
    });
    println!("  Scanning: {}", scan_path.display());
    let file_detections = behavior_analyzer.scan_for_log_files(&scan_path);
    println!("  Found {} suspicious files",
        if file_detections.is_empty() {
            "0".green().to_string()
        } else {
            file_detections.len().to_string().red().to_string()
        }
    );
    all_detections.extend(file_detections);

    // Generate results
    let end_time = Utc::now();
    let system_info = get_system_info();
    
    let scan_result = ScanResult {
        scan_id: generate_detection_id(),
        start_time,
        end_time,
        total_processes_scanned: process_detector.get_processes().len(),
        total_files_scanned: 0, // Would need actual count
        total_connections_scanned: *stats.get("total").unwrap_or(&0),
        detections: all_detections.clone(),
        system_info,
    };

    // Print summary
    print_scan_summary(&scan_result, detailed);

    // Save to file if requested
    if let Some(output_path) = output {
        let json = serde_json::to_string_pretty(&scan_result)?;
        std::fs::write(&output_path, json)?;
        println!("\n{}", format!("📄 Results saved to: {}", output_path.display()).green());
    }

    if verbose {
        print_detailed_results(&all_detections);
    }

    Ok(())
}

/// Check a single process by PID
pub async fn check_single_process(pid: u32, verbose: bool) -> anyhow::Result<()> {
    let mut detector = ProcessDetector::new();
    
    if let Some(process_info) = detector.check_process(pid) {
        println!("\n{}", "═══ Process Information ═══".cyan().bold());
        println!("PID: {}", process_info.pid.to_string().yellow());
        println!("Name: {}", process_info.name.bold());
        
        if let Some(ref path) = process_info.exe_path {
            println!("Path: {}", path);
        }
        
        if let Some(ref cmd) = process_info.cmd_line {
            if !cmd.is_empty() {
                println!("Command Line: {}", cmd.dimmed());
            }
        }
        
        if let Some(parent) = process_info.parent_pid {
            println!("Parent PID: {}", parent);
        }
        
        println!("Memory: {}", format_bytes(process_info.memory_usage));
        println!("CPU: {:.1}%", process_info.cpu_usage);

        // Check against signatures
        let sig_db = SignatureDatabase::new();
        let matches = sig_db.check_process_name(&process_info.name);
        
        println!("\n{}", "═══ Threat Analysis ═══".cyan().bold());
        
        if process_info.threat_indicators.is_empty() && matches.is_empty() {
            println!("{}", "✅ No suspicious indicators found.".green());
        } else {
            if !process_info.threat_indicators.is_empty() {
                println!("{}", "⚠️  Threat Indicators:".red().bold());
                for indicator in &process_info.threat_indicators {
                    println!("  • {}", indicator.yellow());
                }
            }
            
            if !matches.is_empty() {
                println!("{}", "⛔ Signature Matches:".red().bold());
                for sig in &matches {
                    println!("  • {} - {}", sig.name.red(), sig.description);
                    println!("    Threat Level: {}", sig.threat_level);
                }
            }
        }

        if verbose {
            // Show network connections for this process
            println!("\n{}", "═══ Network Connections ═══".cyan().bold());
            let analyzer = NetworkAnalyzer::new();
            let connections = analyzer.get_connections();
            let proc_connections: Vec<_> = connections
                .iter()
                .filter(|c| c.pid == Some(pid))
                .collect();
            
            if proc_connections.is_empty() {
                println!("No network connections found for this process.");
            } else {
                for conn in proc_connections {
                    println!("  {} {}:{} -> {}:{} [{}]",
                        conn.protocol,
                        conn.local_address, conn.local_port,
                        conn.remote_address, conn.remote_port,
                        conn.state
                    );
                }
            }
        }
    } else {
        println!("{}", format!("❌ Process with PID {} not found.", pid).red());
    }

    Ok(())
}

/// Get system information
fn get_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    SystemInfo {
        os_name: System::name().unwrap_or_else(|| "Unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        hostname: System::host_name().unwrap_or_else(|| "Unknown".to_string()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
        total_memory: sys.total_memory(),
        available_memory: sys.available_memory(),
        cpu_count: sys.cpus().len(),
    }
}

/// Print scan summary
fn print_scan_summary(result: &ScanResult, detailed: bool) {
    let summary = result.threat_summary();
    
    println!("\n{}", "═".repeat(60).cyan());
    println!("{}", "                    SCAN SUMMARY".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    
    println!("\n{}", "System Information:".yellow());
    println!("  OS: {} {}", result.system_info.os_name, result.system_info.os_version);
    println!("  Hostname: {}", result.system_info.hostname);
    println!("  Memory: {} / {}", 
        format_bytes(result.system_info.available_memory),
        format_bytes(result.system_info.total_memory)
    );
    
    println!("\n{}", "Scan Statistics:".yellow());
    println!("  Duration: {:?}", result.end_time.signed_duration_since(result.start_time));
    println!("  Processes Scanned: {}", result.total_processes_scanned);
    println!("  Connections Analyzed: {}", result.total_connections_scanned);
    
    println!("\n{}", "Threat Summary:".yellow());
    println!("  {} Safe", format!("{:3}", summary.safe).green());
    println!("  {} Low", format!("{:3}", summary.low).yellow());
    println!("  {} Medium", format!("{:3}", summary.medium).yellow().bold());
    println!("  {} High", format!("{:3}", summary.high).red());
    println!("  {} Critical", format!("{:3}", summary.critical).red().bold());
    
    let total_threats = summary.low + summary.medium + summary.high + summary.critical;
    
    println!("\n{}", "═".repeat(60).cyan());
    if total_threats == 0 {
        println!("{}", "✅ SYSTEM APPEARS CLEAN - No keylogger indicators detected".green().bold());
    } else {
        println!("{}", format!("⚠️  {} POTENTIAL THREAT(S) DETECTED", total_threats).red().bold());
        if summary.critical > 0 || summary.high > 0 {
            println!("{}", "   IMMEDIATE ACTION RECOMMENDED!".red().bold());
        }
    }
    println!("{}", "═".repeat(60).cyan());

    if detailed && !result.detections.is_empty() {
        println!("\n{}", "Detected Threats:".red().bold());
        for (i, detection) in result.detections.iter().enumerate() {
            println!("\n{}. {} [{}]", i + 1, detection.name, detection.threat_level);
            println!("   Category: {}", detection.category);
            println!("   {}", detection.description);
        }
    }
}

/// Print detailed detection results
fn print_detailed_results(detections: &[Detection]) {
    if detections.is_empty() {
        return;
    }

    println!("\n{}", "═══ DETAILED DETECTION REPORT ═══".cyan().bold());
    
    for (i, detection) in detections.iter().enumerate() {
        println!("\n{}", format!("Detection #{}", i + 1).yellow().bold());
        println!("  ID: {}", detection.id.dimmed());
        println!("  Name: {}", detection.name.bold());
        println!("  Category: {}", detection.category);
        println!("  Threat Level: {}", detection.threat_level);
        println!("  Description: {}", detection.description);
        println!("  Timestamp: {}", detection.timestamp);
        
        if detection.details.process_id.is_some() || detection.details.file_path.is_some() {
            println!("  Details:");
            if let Some(pid) = detection.details.process_id {
                println!("    Process ID: {}", pid);
            }
            if let Some(ref name) = detection.details.process_name {
                println!("    Process Name: {}", name);
            }
            if let Some(ref path) = detection.details.file_path {
                println!("    File Path: {}", path);
            }
            if let Some(ref hash) = detection.details.hash {
                println!("    Hash: {}", hash);
            }
            if let Some(ref sig) = detection.details.matched_signature {
                println!("    Matched Signature: {}", sig);
            }
        }
        
        if !detection.recommendations.is_empty() {
            println!("  Recommendations:");
            for rec in &detection.recommendations {
                println!("    • {}", rec);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_system_info() {
        let info = get_system_info();
        assert!(!info.os_name.is_empty() || info.os_name == "Unknown");
        assert!(info.total_memory > 0);
    }
}
