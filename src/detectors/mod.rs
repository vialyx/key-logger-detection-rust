//! Detection modules for identifying keylogger activity
//!
//! This module contains various detection strategies:
//! - Process analysis
//! - Behavioral detection
//! - Hook detection
//! - Network monitoring

pub mod process;
pub mod behavior;
pub mod hooks;
pub mod network;

use crate::utils::{Detection, ThreatLevel};

/// Common trait for all detection modules
#[allow(dead_code)]
pub trait Detector {
    /// Run the detection scan
    fn scan(&self) -> Vec<Detection>;
    
    /// Get the detector name
    fn name(&self) -> &str;
    
    /// Get the detector description
    fn description(&self) -> &str;
}

/// Suspicious process name patterns that may indicate keylogger activity
pub const SUSPICIOUS_PROCESS_NAMES: &[&str] = &[
    "keylog",
    "keycap",
    "keysniff",
    "keystroke",
    "inputcap",
    "hooker",
    "spykey",
    "keyspy",
    "logkeys",
    "pykeylogger",
    "shadowkey",
    "refog",
    "actualspy",
    "ardamax",
    "revealer",
    "spytector",
    "elite_keylogger",
    "perfect_keylogger",
    "all_in_one_keylogger",
];

/// Suspicious file extensions
pub const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".keylog",
    ".klog",
    ".keydata",
    ".keystroke",
    ".inputlog",
];

/// Suspicious directory patterns
#[allow(dead_code)]
pub const SUSPICIOUS_DIRECTORIES: &[&str] = &[
    "keylog",
    "keycap",
    "keystroke",
    "inputmonitor",
    "spyware",
    "hidden_logs",
    ".keydata",
    ".inputcache",
];

/// Known malicious network ports often used by keyloggers
pub const SUSPICIOUS_PORTS: &[u16] = &[
    4444,   // Metasploit default
    5555,   // Common RAT port
    6666,   // Common malware
    7777,   // Common RAT
    8888,   // Alternative HTTP
    9999,   // Common malware
    12345,  // NetBus
    31337,  // Back Orifice
    54321,  // Common reverse shell
];

/// Analyze threat level based on indicators
pub fn calculate_threat_level(indicators: &[String]) -> ThreatLevel {
    let count = indicators.len();
    match count {
        0 => ThreatLevel::Safe,
        1 => ThreatLevel::Low,
        2..=3 => ThreatLevel::Medium,
        4..=5 => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    }
}
