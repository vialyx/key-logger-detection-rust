//! Known keylogger signatures and detection patterns
//!
//! This module maintains a database of known keylogger signatures including:
//! - File hashes (SHA-256)
//! - Process name patterns
//! - Registry keys (Windows)
//! - File path patterns

use crate::utils::{
    Detection, DetectionCategory, DetectionDetails, ThreatLevel,
    calculate_file_hash, generate_detection_id,
};
use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A known keylogger signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub description: String,
    pub threat_level: ThreatLevel,
    pub signatures: Vec<SignatureType>,
    pub references: Vec<String>,
}

/// Types of signatures we can match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    /// SHA-256 file hash
    FileHash(String),
    /// Process name pattern (regex)
    ProcessName(String),
    /// File path pattern (regex)
    FilePath(String),
    /// Registry key (Windows)
    RegistryKey(String),
    /// Network indicator (IP or domain)
    NetworkIndicator(String),
    /// Mutex name
    Mutex(String),
}

/// Signature database
pub struct SignatureDatabase {
    signatures: Vec<Signature>,
    #[allow(dead_code)]
    hash_map: HashMap<String, String>, // hash -> signature id
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let signatures = Self::load_builtin_signatures();
        let hash_map = Self::build_hash_map(&signatures);
        
        Self {
            signatures,
            hash_map,
        }
    }

    /// Load built-in signature database
    fn load_builtin_signatures() -> Vec<Signature> {
        vec![
            // Ardamax Keylogger
            Signature {
                id: "KL-001".to_string(),
                name: "Ardamax Keylogger".to_string(),
                description: "Commercial keylogger often used maliciously".to_string(),
                threat_level: ThreatLevel::Critical,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)ardamax".to_string()),
                    SignatureType::FilePath(r"(?i)ardamax".to_string()),
                    SignatureType::RegistryKey(r"SOFTWARE\Ardamax".to_string()),
                ],
                references: vec![
                    "https://www.ardamax.com".to_string(),
                ],
            },
            // Refog Keylogger
            Signature {
                id: "KL-002".to_string(),
                name: "Refog Keylogger".to_string(),
                description: "Employee monitoring software often misused".to_string(),
                threat_level: ThreatLevel::High,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)refog".to_string()),
                    SignatureType::ProcessName(r"(?i)mpk\.exe".to_string()),
                    SignatureType::FilePath(r"(?i)refog".to_string()),
                ],
                references: vec![
                    "https://www.refog.com".to_string(),
                ],
            },
            // Actual Spy
            Signature {
                id: "KL-003".to_string(),
                name: "Actual Spy".to_string(),
                description: "Keylogger and monitoring tool".to_string(),
                threat_level: ThreatLevel::High,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)actualspy".to_string()),
                    SignatureType::ProcessName(r"(?i)actual\s*spy".to_string()),
                    SignatureType::FilePath(r"(?i)actualspy".to_string()),
                ],
                references: vec![],
            },
            // LogKeys (Linux)
            Signature {
                id: "KL-004".to_string(),
                name: "LogKeys".to_string(),
                description: "Open-source Linux keylogger".to_string(),
                threat_level: ThreatLevel::Critical,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)^logkeys$".to_string()),
                    SignatureType::FilePath(r"/var/log/logkeys".to_string()),
                ],
                references: vec![
                    "https://github.com/kernc/logkeys".to_string(),
                ],
            },
            // PyKeylogger
            Signature {
                id: "KL-005".to_string(),
                name: "PyKeylogger".to_string(),
                description: "Python-based keylogger".to_string(),
                threat_level: ThreatLevel::High,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)pykeylogger".to_string()),
                    SignatureType::FilePath(r"(?i)pykeylogger".to_string()),
                    SignatureType::FilePath(r"(?i)keylogger\.py".to_string()),
                ],
                references: vec![],
            },
            // Elite Keylogger
            Signature {
                id: "KL-006".to_string(),
                name: "Elite Keylogger".to_string(),
                description: "Commercial keylogger software".to_string(),
                threat_level: ThreatLevel::Critical,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)elite.*keylogger".to_string()),
                    SignatureType::FilePath(r"(?i)elite.*keylogger".to_string()),
                    SignatureType::RegistryKey(r"SOFTWARE\Elite Keylogger".to_string()),
                ],
                references: vec![],
            },
            // Perfect Keylogger
            Signature {
                id: "KL-007".to_string(),
                name: "Perfect Keylogger".to_string(),
                description: "Blazing Tools Perfect Keylogger".to_string(),
                threat_level: ThreatLevel::Critical,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)perfect.*keylogger".to_string()),
                    SignatureType::ProcessName(r"(?i)pkr\.exe".to_string()),
                    SignatureType::FilePath(r"(?i)perfect.*keylogger".to_string()),
                ],
                references: vec![],
            },
            // Revealer Keylogger
            Signature {
                id: "KL-008".to_string(),
                name: "Revealer Keylogger".to_string(),
                description: "Free keylogger software".to_string(),
                threat_level: ThreatLevel::High,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)revealer".to_string()),
                    SignatureType::FilePath(r"(?i)revealer.*keylogger".to_string()),
                ],
                references: vec![
                    "https://www.logixoft.com".to_string(),
                ],
            },
            // HawkEye Keylogger (Malware)
            Signature {
                id: "KL-009".to_string(),
                name: "HawkEye Keylogger".to_string(),
                description: "Malware keylogger distributed via phishing".to_string(),
                threat_level: ThreatLevel::Critical,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)hawkeye".to_string()),
                    SignatureType::Mutex("HawkEye_Keylogger".to_string()),
                ],
                references: vec![
                    "https://attack.mitre.org/software/S0434/".to_string(),
                ],
            },
            // Agent Tesla (Malware)
            Signature {
                id: "KL-010".to_string(),
                name: "Agent Tesla".to_string(),
                description: "Popular .NET-based keylogger/RAT malware".to_string(),
                threat_level: ThreatLevel::Critical,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)agent.*tesla".to_string()),
                    SignatureType::Mutex("AgentTesla".to_string()),
                ],
                references: vec![
                    "https://attack.mitre.org/software/S0331/".to_string(),
                ],
            },
            // Generic keyboard hook detection
            Signature {
                id: "KL-GEN-001".to_string(),
                name: "Generic Keyboard Hook".to_string(),
                description: "Generic patterns indicating keyboard hooking".to_string(),
                threat_level: ThreatLevel::Medium,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)key\s*hook".to_string()),
                    SignatureType::ProcessName(r"(?i)keyboard\s*hook".to_string()),
                    SignatureType::ProcessName(r"(?i)key\s*capture".to_string()),
                    SignatureType::FilePath(r"(?i)key\s*hook".to_string()),
                ],
                references: vec![],
            },
            // Generic input monitoring
            Signature {
                id: "KL-GEN-002".to_string(),
                name: "Generic Input Monitor".to_string(),
                description: "Generic patterns indicating input monitoring".to_string(),
                threat_level: ThreatLevel::Medium,
                signatures: vec![
                    SignatureType::ProcessName(r"(?i)input\s*monitor".to_string()),
                    SignatureType::ProcessName(r"(?i)input\s*capture".to_string()),
                    SignatureType::FilePath(r"(?i)input\s*log".to_string()),
                ],
                references: vec![],
            },
        ]
    }

    /// Build hash lookup map
    fn build_hash_map(signatures: &[Signature]) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for sig in signatures {
            for sig_type in &sig.signatures {
                if let SignatureType::FileHash(hash) = sig_type {
                    map.insert(hash.to_lowercase(), sig.id.clone());
                }
            }
        }
        map
    }

    /// Check if a file hash matches any known signature
    #[allow(dead_code)]
    pub fn check_hash(&self, hash: &str) -> Option<&Signature> {
        self.hash_map.get(&hash.to_lowercase())
            .and_then(|id| self.signatures.iter().find(|s| s.id == *id))
    }

    /// Check if a process name matches any signature
    pub fn check_process_name(&self, name: &str) -> Vec<&Signature> {
        let mut matches = Vec::new();
        
        for sig in &self.signatures {
            for sig_type in &sig.signatures {
                if let SignatureType::ProcessName(pattern) = sig_type {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        if re.is_match(name) {
                            matches.push(sig);
                            break;
                        }
                    }
                }
            }
        }
        
        matches
    }

    /// Check if a file path matches any signature
    #[allow(dead_code)]
    pub fn check_file_path(&self, path: &str) -> Vec<&Signature> {
        let mut matches = Vec::new();
        
        for sig in &self.signatures {
            for sig_type in &sig.signatures {
                if let SignatureType::FilePath(pattern) = sig_type {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        if re.is_match(path) {
                            matches.push(sig);
                            break;
                        }
                    }
                }
            }
        }
        
        matches
    }

    /// Get all signatures
    pub fn get_signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Scan a file against the signature database
    #[allow(dead_code)]
    pub fn scan_file(&self, path: &Path) -> Option<Detection> {
        // Check file path first
        let path_str = path.to_string_lossy();
        let path_matches = self.check_file_path(&path_str);
        
        if !path_matches.is_empty() {
            let sig = &path_matches[0];
            return Some(Detection {
                id: generate_detection_id(),
                category: DetectionCategory::File,
                threat_level: sig.threat_level,
                name: format!("Known Keylogger: {}", sig.name),
                description: sig.description.clone(),
                details: DetectionDetails {
                    file_path: Some(path_str.to_string()),
                    matched_signature: Some(sig.id.clone()),
                    ..Default::default()
                },
                timestamp: Utc::now(),
                recommendations: vec![
                    "Quarantine or delete the file immediately".to_string(),
                    "Scan system for additional infections".to_string(),
                    "Check for data exfiltration".to_string(),
                ],
            });
        }

        // Calculate and check hash
        if let Ok(hash) = calculate_file_hash(path) {
            if let Some(sig) = self.check_hash(&hash) {
                return Some(Detection {
                    id: generate_detection_id(),
                    category: DetectionCategory::File,
                    threat_level: sig.threat_level,
                    name: format!("Known Keylogger: {}", sig.name),
                    description: sig.description.clone(),
                    details: DetectionDetails {
                        file_path: Some(path_str.to_string()),
                        hash: Some(hash),
                        matched_signature: Some(sig.id.clone()),
                        ..Default::default()
                    },
                    timestamp: Utc::now(),
                    recommendations: vec![
                        "Quarantine or delete the file immediately".to_string(),
                        "Scan system for additional infections".to_string(),
                        "Check for data exfiltration".to_string(),
                    ],
                });
            }
        }

        None
    }

    /// Print all known signatures
    pub fn print_signatures(&self) {
        println!("\n{}", "═══ Known Keylogger Signatures ═══".cyan().bold());
        println!("Total signatures: {}\n", self.signatures.len().to_string().green());

        for sig in &self.signatures {
            println!("{} {} ({})", 
                "►".yellow(),
                sig.name.bold(),
                sig.id.dimmed()
            );
            println!("  Threat Level: {}", sig.threat_level);
            println!("  Description: {}", sig.description);
            println!("  Signatures:");
            for sig_type in &sig.signatures {
                match sig_type {
                    SignatureType::FileHash(h) => println!("    • Hash: {}", h),
                    SignatureType::ProcessName(p) => println!("    • Process: {}", p),
                    SignatureType::FilePath(p) => println!("    • Path: {}", p),
                    SignatureType::RegistryKey(k) => println!("    • Registry: {}", k),
                    SignatureType::NetworkIndicator(n) => println!("    • Network: {}", n),
                    SignatureType::Mutex(m) => println!("    • Mutex: {}", m),
                }
            }
            println!();
        }
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// List all known signatures
pub fn list_signatures() -> anyhow::Result<()> {
    let db = SignatureDatabase::new();
    db.print_signatures();
    Ok(())
}

/// Update signature database (placeholder for future implementation)
pub async fn update_signatures() -> anyhow::Result<()> {
    println!("{}", "Signature update not yet implemented.".yellow());
    println!("Currently using built-in signature database.");
    println!("Future versions will support online signature updates.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_creation() {
        let db = SignatureDatabase::new();
        assert!(!db.signatures.is_empty());
    }

    #[test]
    fn test_process_name_matching() {
        let db = SignatureDatabase::new();
        let matches = db.check_process_name("ardamax.exe");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].name, "Ardamax Keylogger");
    }

    #[test]
    fn test_file_path_matching() {
        let db = SignatureDatabase::new();
        let matches = db.check_file_path("/var/log/logkeys/output.log");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_no_match() {
        let db = SignatureDatabase::new();
        let matches = db.check_process_name("safe_normal_app.exe");
        assert!(matches.is_empty());
    }
}
