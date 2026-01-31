//! Hook detection for keylogger identification
//!
//! This module detects system-level keyboard hooks that keyloggers commonly use.
//! On different platforms:
//! - macOS: Checks for accessibility permissions and input monitoring
//! - Linux: Monitors /dev/input devices and X11 extensions
//! - Windows: Detects SetWindowsHookEx API usage

use crate::utils::{
    Detection, DetectionCategory, DetectionDetails, ThreatLevel,
    generate_detection_id,
};
use chrono::Utc;
use colored::*;

/// Hook detector for identifying keyboard/input hooks
pub struct HookDetector {
    platform: Platform,
}

#[derive(Debug, Clone)]
enum Platform {
    MacOS,
    Linux,
    Windows,
    Unknown,
}

impl HookDetector {
    pub fn new() -> Self {
        let platform = if cfg!(target_os = "macos") {
            Platform::MacOS
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Unknown
        };

        Self { platform }
    }

    /// Scan for potential keyboard hooks
    pub fn scan(&self) -> Vec<Detection> {
        match self.platform {
            Platform::MacOS => self.scan_macos(),
            Platform::Linux => self.scan_linux(),
            Platform::Windows => self.scan_windows(),
            Platform::Unknown => {
                log::warn!("Unknown platform, hook detection limited");
                Vec::new()
            }
        }
    }

    /// macOS-specific hook detection
    #[cfg(target_os = "macos")]
    fn scan_macos(&self) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for processes with accessibility permissions
        // These can monitor keyboard input
        if let Ok(output) = std::process::Command::new("sqlite3")
            .args([
                "/Library/Application Support/com.apple.TCC/TCC.db",
                "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND allowed=1",
            ])
            .output()
        {
            if output.status.success() {
                let apps = String::from_utf8_lossy(&output.stdout);
                for app in apps.lines() {
                    if !is_known_safe_accessibility_app(app) {
                        detections.push(create_hook_detection(
                            "Accessibility Permission",
                            &format!("Application '{}' has accessibility permissions that allow keyboard monitoring", app),
                            ThreatLevel::Medium,
                            Some(app.to_string()),
                        ));
                    }
                }
            }
        }

        // Check for Input Monitoring permissions
        if let Ok(output) = std::process::Command::new("sqlite3")
            .args([
                "/Library/Application Support/com.apple.TCC/TCC.db",
                "SELECT client FROM access WHERE service='kTCCServiceListenEvent' AND allowed=1",
            ])
            .output()
        {
            if output.status.success() {
                let apps = String::from_utf8_lossy(&output.stdout);
                for app in apps.lines() {
                    if !is_known_safe_input_monitoring_app(app) {
                        detections.push(create_hook_detection(
                            "Input Monitoring Permission",
                            &format!("Application '{}' has input monitoring permissions", app),
                            ThreatLevel::High,
                            Some(app.to_string()),
                        ));
                    }
                }
            }
        }

        // Check for suspicious launch agents/daemons
        let launch_paths = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            &format!("{}/Library/LaunchAgents", std::env::var("HOME").unwrap_or_default()),
        ];

        for path in launch_paths {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    for pattern in super::SUSPICIOUS_PROCESS_NAMES {
                        if name.contains(pattern) {
                            detections.push(create_hook_detection(
                                "Suspicious Launch Agent",
                                &format!("Launch agent '{}' has suspicious name pattern", entry.path().display()),
                                ThreatLevel::High,
                                Some(entry.path().to_string_lossy().to_string()),
                            ));
                        }
                    }
                }
            }
        }

        detections
    }

    #[cfg(not(target_os = "macos"))]
    fn scan_macos(&self) -> Vec<Detection> {
        Vec::new()
    }

    /// Linux-specific hook detection
    #[cfg(target_os = "linux")]
    fn scan_linux(&self) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Check for processes accessing /dev/input devices
        if let Ok(entries) = std::fs::read_dir("/dev/input") {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.to_string_lossy().contains("event") {
                    // Check what processes have this device open
                    if let Ok(output) = std::process::Command::new("fuser")
                        .arg(&path)
                        .output()
                    {
                        if output.status.success() {
                            let pids = String::from_utf8_lossy(&output.stdout);
                            if !pids.trim().is_empty() {
                                // Check if any of these PIDs are suspicious
                                for pid in pids.split_whitespace() {
                                    if let Ok(cmdline) = std::fs::read_to_string(
                                        format!("/proc/{}/cmdline", pid.trim_end_matches(':'))
                                    ) {
                                        let cmd_lower = cmdline.to_lowercase();
                                        for pattern in super::SUSPICIOUS_PROCESS_NAMES {
                                            if cmd_lower.contains(pattern) {
                                                detections.push(create_hook_detection(
                                                    "Input Device Access",
                                                    &format!("Suspicious process accessing {}: {}", 
                                                        path.display(), cmdline.replace('\0', " ")),
                                                    ThreatLevel::High,
                                                    Some(pid.to_string()),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for xinput command running (can be used to log keystrokes)
        if let Ok(output) = std::process::Command::new("pgrep")
            .args(["-a", "xinput"])
            .output()
        {
            if output.status.success() && !output.stdout.is_empty() {
                let processes = String::from_utf8_lossy(&output.stdout);
                for line in processes.lines() {
                    if line.contains("test") || line.contains("query-state") {
                        detections.push(create_hook_detection(
                            "XInput Monitoring",
                            &format!("xinput test/query detected: {}", line),
                            ThreatLevel::Medium,
                            None,
                        ));
                    }
                }
            }
        }

        // Check for logkeys or similar
        if let Ok(output) = std::process::Command::new("pgrep")
            .args(["-a", "logkeys"])
            .output()
        {
            if output.status.success() && !output.stdout.is_empty() {
                detections.push(create_hook_detection(
                    "Logkeys Process",
                    "logkeys keylogger process detected",
                    ThreatLevel::Critical,
                    None,
                ));
            }
        }

        detections
    }

    #[cfg(not(target_os = "linux"))]
    fn scan_linux(&self) -> Vec<Detection> {
        Vec::new()
    }

    /// Windows-specific hook detection
    #[cfg(target_os = "windows")]
    fn scan_windows(&self) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Note: Full Windows implementation would require winapi calls
        // This is a simplified version that checks for common indicators

        // Check for known keylogger registry entries
        let suspicious_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ];

        for key_path in suspicious_keys {
            if let Ok(output) = std::process::Command::new("reg")
                .args(["query", &format!("HKCU\\{}", key_path)])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for pattern in super::SUSPICIOUS_PROCESS_NAMES {
                    if output_str.contains(pattern) {
                        detections.push(create_hook_detection(
                            "Suspicious Registry Entry",
                            &format!("Suspicious startup entry found matching '{}'", pattern),
                            ThreatLevel::High,
                            None,
                        ));
                    }
                }
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    fn scan_windows(&self) -> Vec<Detection> {
        Vec::new()
    }

    /// Print hook scan results
    #[allow(dead_code)]
    pub fn print_results(&self) {
        let detections = self.scan();
        
        println!("\n{}", "═══ Hook Detection Results ═══".cyan().bold());
        println!("Platform: {:?}", self.platform);
        
        if detections.is_empty() {
            println!("{}", "✅ No suspicious hooks detected.".green());
        } else {
            println!("{}", format!("⚠️  {} potential hooks detected:", detections.len()).red().bold());
            for detection in &detections {
                println!("\n  {} {}", "►".yellow(), detection.name.red());
                println!("    Threat Level: {}", detection.threat_level);
                println!("    {}", detection.description);
            }
        }
    }
}

impl Default for HookDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a hook detection entry
fn create_hook_detection(
    name: &str,
    description: &str,
    threat_level: ThreatLevel,
    file_path: Option<String>,
) -> Detection {
    Detection {
        id: generate_detection_id(),
        category: DetectionCategory::InputHook,
        threat_level,
        name: name.to_string(),
        description: description.to_string(),
        details: DetectionDetails {
            file_path,
            additional_info: vec![],
            ..Default::default()
        },
        timestamp: Utc::now(),
        recommendations: vec![
            "Review the application's legitimacy".to_string(),
            "Check if you authorized this application".to_string(),
            "Consider revoking permissions if suspicious".to_string(),
        ],
    }
}

/// Check if an app is a known safe accessibility app on macOS
#[cfg(target_os = "macos")]
fn is_known_safe_accessibility_app(app: &str) -> bool {
    let safe_apps = [
        "com.apple",
        "com.microsoft",
        "com.google.Chrome",
        "org.mozilla.firefox",
        "com.brave.Browser",
        "com.sublimetext",
        "com.visualstudio",
        "com.jetbrains",
        "com.1password",
        "com.bitwarden",
        "com.alfredapp",
        "com.raycast",
    ];
    
    safe_apps.iter().any(|safe| app.starts_with(safe))
}

/// Check if an app is a known safe input monitoring app on macOS
#[cfg(target_os = "macos")]
fn is_known_safe_input_monitoring_app(app: &str) -> bool {
    let safe_apps = [
        "com.apple",
        "com.1password",
        "com.bitwarden",
    ];
    
    safe_apps.iter().any(|safe| app.starts_with(safe))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_detector_creation() {
        let detector = HookDetector::new();
        // Just ensure it creates without panicking
        let _ = detector.scan();
    }
}
