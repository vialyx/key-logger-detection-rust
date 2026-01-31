//! Report generation for scan results
//!
//! Generates security reports in multiple formats:
//! - Plain text
//! - JSON
//! - HTML

use crate::utils::{ScanResult, ThreatLevel, format_bytes};
use colored::*;
use std::path::PathBuf;

/// Generate a security report
pub async fn generate_report(format: &str, output: Option<PathBuf>) -> anyhow::Result<()> {
    // Run a scan first to get data for the report
    println!("{}", "Running scan to generate report data...".yellow());
    
    let scan_result = run_scan_for_report().await?;
    
    let report_content = match format.to_lowercase().as_str() {
        "json" => generate_json_report(&scan_result)?,
        "html" => generate_html_report(&scan_result),
        "text" | _ => generate_text_report(&scan_result),
    };

    if let Some(output_path) = output {
        std::fs::write(&output_path, &report_content)?;
        println!("{}", format!("✅ Report saved to: {}", output_path.display()).green());
    } else {
        println!("{}", report_content);
    }

    Ok(())
}

/// Run a scan and collect results for reporting
async fn run_scan_for_report() -> anyhow::Result<ScanResult> {
    use crate::detectors::process::ProcessDetector;
    use crate::detectors::network::NetworkAnalyzer;
    use crate::detectors::hooks::HookDetector;
    use crate::utils::{SystemInfo, Detection, generate_detection_id};
    use chrono::Utc;
    use sysinfo::System;

    let start_time = Utc::now();
    let mut all_detections: Vec<Detection> = Vec::new();

    // Process scan
    let process_detector = ProcessDetector::new();
    all_detections.extend(process_detector.scan());

    // Hook detection
    let hook_detector = HookDetector::new();
    all_detections.extend(hook_detector.scan());

    // Network analysis
    let network_analyzer = NetworkAnalyzer::new();
    let network_detections = network_analyzer.scan();
    let conn_count = *network_analyzer.get_statistics().get("total").unwrap_or(&0);
    all_detections.extend(network_detections);

    let end_time = Utc::now();

    // Get system info
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let system_info = SystemInfo {
        os_name: System::name().unwrap_or_else(|| "Unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        hostname: System::host_name().unwrap_or_else(|| "Unknown".to_string()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
        total_memory: sys.total_memory(),
        available_memory: sys.available_memory(),
        cpu_count: sys.cpus().len(),
    };

    Ok(ScanResult {
        scan_id: generate_detection_id(),
        start_time,
        end_time,
        total_processes_scanned: process_detector.get_processes().len(),
        total_files_scanned: 0,
        total_connections_scanned: conn_count,
        detections: all_detections,
        system_info,
    })
}

/// Generate JSON report
fn generate_json_report(result: &ScanResult) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(result)?)
}

/// Generate plain text report
fn generate_text_report(result: &ScanResult) -> String {
    let mut report = String::new();
    let summary = result.threat_summary();

    report.push_str("╔════════════════════════════════════════════════════════════════╗\n");
    report.push_str("║           KEYLOGGER DETECTION SECURITY REPORT                  ║\n");
    report.push_str("╚════════════════════════════════════════════════════════════════╝\n\n");

    report.push_str(&format!("Report ID: {}\n", result.scan_id));
    report.push_str(&format!("Generated: {}\n", result.end_time));
    report.push_str(&format!("Scan Duration: {:?}\n\n", 
        result.end_time.signed_duration_since(result.start_time)));

    report.push_str("═══ SYSTEM INFORMATION ═══\n");
    report.push_str(&format!("Hostname: {}\n", result.system_info.hostname));
    report.push_str(&format!("OS: {} {}\n", result.system_info.os_name, result.system_info.os_version));
    report.push_str(&format!("Kernel: {}\n", result.system_info.kernel_version));
    report.push_str(&format!("CPUs: {}\n", result.system_info.cpu_count));
    report.push_str(&format!("Memory: {} / {}\n\n",
        format_bytes(result.system_info.available_memory),
        format_bytes(result.system_info.total_memory)));

    report.push_str("═══ SCAN STATISTICS ═══\n");
    report.push_str(&format!("Processes Scanned: {}\n", result.total_processes_scanned));
    report.push_str(&format!("Files Scanned: {}\n", result.total_files_scanned));
    report.push_str(&format!("Network Connections Analyzed: {}\n\n", result.total_connections_scanned));

    report.push_str("═══ THREAT SUMMARY ═══\n");
    report.push_str(&format!("Safe:     {}\n", summary.safe));
    report.push_str(&format!("Low:      {}\n", summary.low));
    report.push_str(&format!("Medium:   {}\n", summary.medium));
    report.push_str(&format!("High:     {}\n", summary.high));
    report.push_str(&format!("Critical: {}\n\n", summary.critical));

    let total_threats = summary.low + summary.medium + summary.high + summary.critical;
    
    if total_threats == 0 {
        report.push_str("✅ OVERALL STATUS: CLEAN\n");
        report.push_str("No keylogger indicators were detected during this scan.\n\n");
    } else {
        report.push_str(&format!("⚠️  OVERALL STATUS: {} THREAT(S) DETECTED\n\n", total_threats));
    }

    if !result.detections.is_empty() {
        report.push_str("═══ DETAILED DETECTIONS ═══\n\n");
        
        for (i, detection) in result.detections.iter().enumerate() {
            report.push_str(&format!("--- Detection #{} ---\n", i + 1));
            report.push_str(&format!("ID: {}\n", detection.id));
            report.push_str(&format!("Name: {}\n", detection.name));
            report.push_str(&format!("Category: {}\n", detection.category));
            report.push_str(&format!("Threat Level: {}\n", detection.threat_level));
            report.push_str(&format!("Description: {}\n", detection.description));
            report.push_str(&format!("Timestamp: {}\n", detection.timestamp));
            
            if let Some(pid) = detection.details.process_id {
                report.push_str(&format!("Process ID: {}\n", pid));
            }
            if let Some(ref name) = detection.details.process_name {
                report.push_str(&format!("Process Name: {}\n", name));
            }
            if let Some(ref path) = detection.details.file_path {
                report.push_str(&format!("File Path: {}\n", path));
            }
            if let Some(ref hash) = detection.details.hash {
                report.push_str(&format!("File Hash: {}\n", hash));
            }
            if let Some(ref sig) = detection.details.matched_signature {
                report.push_str(&format!("Matched Signature: {}\n", sig));
            }
            
            if !detection.recommendations.is_empty() {
                report.push_str("Recommendations:\n");
                for rec in &detection.recommendations {
                    report.push_str(&format!("  • {}\n", rec));
                }
            }
            report.push('\n');
        }
    }

    report.push_str("═══ RECOMMENDATIONS ═══\n");
    if total_threats == 0 {
        report.push_str("• Continue regular security scans\n");
        report.push_str("• Keep your system and software updated\n");
        report.push_str("• Use strong, unique passwords\n");
        report.push_str("• Be cautious with email attachments and downloads\n");
    } else {
        report.push_str("• Investigate all detected threats immediately\n");
        report.push_str("• Quarantine or remove suspicious files\n");
        report.push_str("• Consider changing passwords if keylogger was active\n");
        report.push_str("• Run a full antivirus scan\n");
        report.push_str("• Check for unauthorized network activity\n");
        report.push_str("• Review startup programs and scheduled tasks\n");
    }

    report.push_str("\n═════════════════════════════════════════════════════════════════\n");
    report.push_str("                    END OF REPORT\n");
    report.push_str("═════════════════════════════════════════════════════════════════\n");

    report
}

/// Generate HTML report
fn generate_html_report(result: &ScanResult) -> String {
    let summary = result.threat_summary();
    let total_threats = summary.low + summary.medium + summary.high + summary.critical;

    let status_class = if total_threats == 0 { "clean" } else { "threat" };
    let status_text = if total_threats == 0 { "CLEAN" } else { "THREATS DETECTED" };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keylogger Detection Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ 
            text-align: center; 
            margin-bottom: 2rem;
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .card {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .card h2 {{
            color: #00d9ff;
            margin-bottom: 1rem;
            font-size: 1.3rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding-bottom: 0.5rem;
        }}
        .status {{ 
            text-align: center; 
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
        }}
        .status.clean {{ background: linear-gradient(135deg, #00c853, #00e676); }}
        .status.threat {{ background: linear-gradient(135deg, #ff1744, #f50057); }}
        .status h2 {{ color: white; font-size: 2rem; margin: 0; }}
        .status p {{ color: rgba(255,255,255,0.9); margin-top: 0.5rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; }}
        .stat {{ text-align: center; padding: 1rem; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #00ff88; }}
        .stat-label {{ color: #aaa; font-size: 0.9rem; }}
        .detection {{
            background: rgba(255, 23, 68, 0.1);
            border-left: 4px solid #ff1744;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0 8px 8px 0;
        }}
        .detection.critical {{ border-color: #ff1744; }}
        .detection.high {{ border-color: #ff9100; }}
        .detection.medium {{ border-color: #ffea00; }}
        .detection.low {{ border-color: #00e5ff; }}
        .detection h3 {{ color: #ff1744; margin-bottom: 0.5rem; }}
        .detection.high h3 {{ color: #ff9100; }}
        .detection.medium h3 {{ color: #ffea00; }}
        .detection.low h3 {{ color: #00e5ff; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge-critical {{ background: #ff1744; }}
        .badge-high {{ background: #ff9100; }}
        .badge-medium {{ background: #ffea00; color: #000; }}
        .badge-low {{ background: #00e5ff; color: #000; }}
        .badge-safe {{ background: #00c853; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ color: #00d9ff; }}
        .footer {{ text-align: center; margin-top: 2rem; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Keylogger Detection Report</h1>
        
        <div class="status {status_class}">
            <h2>{status_text}</h2>
            <p>Report ID: {scan_id}</p>
        </div>

        <div class="card">
            <h2>📊 Scan Statistics</h2>
            <div class="grid">
                <div class="stat">
                    <div class="stat-value">{processes}</div>
                    <div class="stat-label">Processes Scanned</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{connections}</div>
                    <div class="stat-label">Connections Analyzed</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{total_threats}</div>
                    <div class="stat-label">Threats Found</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>💻 System Information</h2>
            <table>
                <tr><th>Hostname</th><td>{hostname}</td></tr>
                <tr><th>Operating System</th><td>{os_name} {os_version}</td></tr>
                <tr><th>Kernel</th><td>{kernel}</td></tr>
                <tr><th>Memory</th><td>{memory_available} / {memory_total}</td></tr>
                <tr><th>CPUs</th><td>{cpus}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>⚠️ Threat Summary</h2>
            <div class="grid">
                <div class="stat">
                    <div class="stat-value" style="color: #ff1744;">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #ff9100;">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #ffea00;">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #00e5ff;">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #00c853;">{safe}</div>
                    <div class="stat-label">Safe</div>
                </div>
            </div>
        </div>

        {detections_html}

        <div class="footer">
            <p>Generated: {timestamp}</p>
            <p>Keylogger Detection Tool v0.1.0</p>
        </div>
    </div>
</body>
</html>"#,
        status_class = status_class,
        status_text = status_text,
        scan_id = result.scan_id,
        processes = result.total_processes_scanned,
        connections = result.total_connections_scanned,
        total_threats = total_threats,
        hostname = result.system_info.hostname,
        os_name = result.system_info.os_name,
        os_version = result.system_info.os_version,
        kernel = result.system_info.kernel_version,
        memory_available = format_bytes(result.system_info.available_memory),
        memory_total = format_bytes(result.system_info.total_memory),
        cpus = result.system_info.cpu_count,
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        safe = summary.safe,
        detections_html = generate_detections_html(&result.detections),
        timestamp = result.end_time,
    )
}

fn generate_detections_html(detections: &[crate::utils::Detection]) -> String {
    if detections.is_empty() {
        return String::from(r#"<div class="card"><h2>🔍 Detections</h2><p>No threats detected.</p></div>"#);
    }

    let mut html = String::from(r#"<div class="card"><h2>🔍 Detections</h2>"#);
    
    for detection in detections {
        let level_class = match detection.threat_level {
            ThreatLevel::Critical => "critical",
            ThreatLevel::High => "high",
            ThreatLevel::Medium => "medium",
            ThreatLevel::Low => "low",
            ThreatLevel::Safe => "safe",
        };
        
        html.push_str(&format!(
            r#"<div class="detection {level_class}">
                <h3>{name}</h3>
                <span class="badge badge-{level_class}">{level}</span>
                <p>{description}</p>
            </div>"#,
            level_class = level_class,
            name = detection.name,
            level = detection.threat_level,
            description = detection.description,
        ));
    }
    
    html.push_str("</div>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_report_generation() {
        use crate::utils::{ScanResult, SystemInfo};
        use chrono::Utc;
        
        let result = ScanResult {
            scan_id: "TEST-001".to_string(),
            start_time: Utc::now(),
            end_time: Utc::now(),
            total_processes_scanned: 100,
            total_files_scanned: 50,
            total_connections_scanned: 25,
            detections: vec![],
            system_info: SystemInfo {
                os_name: "Test OS".to_string(),
                os_version: "1.0".to_string(),
                hostname: "testhost".to_string(),
                kernel_version: "5.0".to_string(),
                total_memory: 8_000_000_000,
                available_memory: 4_000_000_000,
                cpu_count: 4,
            },
        };
        
        let report = generate_text_report(&result);
        assert!(report.contains("KEYLOGGER DETECTION SECURITY REPORT"));
        assert!(report.contains("testhost"));
    }
}
