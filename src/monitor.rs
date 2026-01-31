//! Real-time monitoring for keylogger activity
//!
//! This module provides continuous monitoring capabilities:
//! - Watch for new suspicious processes
//! - Monitor file system changes in sensitive locations
//! - Track network connection changes
//! - Alert on hook installations

use crate::detectors::process::ProcessDetector;
use crate::detectors::network::NetworkAnalyzer;
use crate::detectors::hooks::HookDetector;
use crate::signatures::SignatureDatabase;
use crate::utils::ThreatLevel;
use colored::*;
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::interval;

/// Start real-time system monitoring
pub async fn start_monitoring(duration_secs: u64, verbose: bool) -> anyhow::Result<()> {
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "       REAL-TIME KEYLOGGER MONITORING ACTIVE".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    
    if duration_secs == 0 {
        println!("Mode: Continuous monitoring (Press Ctrl+C to stop)");
    } else {
        println!("Mode: Monitoring for {} seconds", duration_secs);
    }
    println!();

    let mut monitor = SystemMonitor::new();
    
    // Create interval for periodic scanning
    let mut scan_interval = interval(Duration::from_secs(5));
    
    let start = std::time::Instant::now();
    let duration = if duration_secs == 0 {
        Duration::from_secs(u64::MAX)
    } else {
        Duration::from_secs(duration_secs)
    };

    loop {
        scan_interval.tick().await;
        
        if start.elapsed() >= duration {
            break;
        }

        let events = monitor.check_for_changes(verbose);
        
        for event in events {
            event.print();
        }
    }

    println!("\n{}", "Monitoring stopped.".yellow());
    monitor.print_summary();

    Ok(())
}

/// Monitor event types
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    NewProcess {
        pid: u32,
        name: String,
        threat_level: ThreatLevel,
        indicators: Vec<String>,
    },
    ProcessTerminated {
        pid: u32,
        name: String,
    },
    NewConnection {
        local: String,
        remote: String,
        process_name: Option<String>,
        suspicious: bool,
    },
    #[allow(dead_code)]
    ConnectionClosed {
        local: String,
        remote: String,
    },
    HookDetected {
        description: String,
        threat_level: ThreatLevel,
    },
    SignatureMatch {
        name: String,
        matched_item: String,
        threat_level: ThreatLevel,
    },
}

impl MonitorEvent {
    pub fn print(&self) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        
        match self {
            MonitorEvent::NewProcess { pid, name, threat_level, indicators } => {
                if *threat_level >= ThreatLevel::Medium {
                    println!("[{}] {} New suspicious process: {} (PID: {})",
                        timestamp.to_string().dimmed(),
                        "⚠️".red(),
                        name.red().bold(),
                        pid
                    );
                    println!("         Threat Level: {}", threat_level);
                    for indicator in indicators {
                        println!("         • {}", indicator.yellow());
                    }
                } else if *threat_level >= ThreatLevel::Low {
                    println!("[{}] {} New process with low-level indicators: {} (PID: {})",
                        timestamp.to_string().dimmed(),
                        "ℹ️".yellow(),
                        name.yellow(),
                        pid
                    );
                }
            }
            
            MonitorEvent::ProcessTerminated { pid, name } => {
                println!("[{}] {} Process terminated: {} (PID: {})",
                    timestamp.to_string().dimmed(),
                    "✓".green(),
                    name,
                    pid
                );
            }
            
            MonitorEvent::NewConnection { local, remote, process_name, suspicious } => {
                if *suspicious {
                    println!("[{}] {} Suspicious connection: {} -> {}",
                        timestamp.to_string().dimmed(),
                        "🌐".red(),
                        local,
                        remote.red()
                    );
                    if let Some(name) = process_name {
                        println!("         Process: {}", name);
                    }
                }
            }
            
            MonitorEvent::ConnectionClosed { local, remote } => {
                // Only log in verbose mode
                log::debug!("Connection closed: {} -> {}", local, remote);
            }
            
            MonitorEvent::HookDetected { description, threat_level } => {
                println!("[{}] {} Hook detected: {}",
                    timestamp.to_string().dimmed(),
                    "🪝".red(),
                    description.red()
                );
                println!("         Threat Level: {}", threat_level);
            }
            
            MonitorEvent::SignatureMatch { name, matched_item, threat_level } => {
                println!("[{}] {} SIGNATURE MATCH: {}",
                    timestamp.to_string().dimmed(),
                    "⛔".red().bold(),
                    name.red().bold()
                );
                println!("         Matched: {}", matched_item);
                println!("         Threat Level: {}", threat_level);
            }
        }
    }
}

/// System monitor that tracks changes
pub struct SystemMonitor {
    known_pids: HashSet<u32>,
    known_connections: HashSet<String>,
    process_detector: ProcessDetector,
    network_analyzer: NetworkAnalyzer,
    hook_detector: HookDetector,
    signature_db: SignatureDatabase,
    events_count: usize,
    threats_detected: usize,
}

impl SystemMonitor {
    pub fn new() -> Self {
        let process_detector = ProcessDetector::new();
        let network_analyzer = NetworkAnalyzer::new();
        
        // Initialize known processes and connections
        let known_pids: HashSet<u32> = process_detector
            .get_processes()
            .iter()
            .map(|p| p.pid)
            .collect();
        
        let known_connections: HashSet<String> = network_analyzer
            .get_connections()
            .iter()
            .map(|c| format!("{}:{}-{}:{}", c.local_address, c.local_port, c.remote_address, c.remote_port))
            .collect();

        Self {
            known_pids,
            known_connections,
            process_detector,
            network_analyzer,
            hook_detector: HookDetector::new(),
            signature_db: SignatureDatabase::new(),
            events_count: 0,
            threats_detected: 0,
        }
    }

    /// Check for changes since last check
    pub fn check_for_changes(&mut self, verbose: bool) -> Vec<MonitorEvent> {
        let mut events = Vec::new();

        // Check for new/terminated processes
        self.process_detector.refresh();
        let current_processes = self.process_detector.get_processes();
        let current_pids: HashSet<u32> = current_processes.iter().map(|p| p.pid).collect();

        // New processes
        for process in &current_processes {
            if !self.known_pids.contains(&process.pid) {
                // Check against signatures
                let sig_matches = self.signature_db.check_process_name(&process.name);
                
                if !sig_matches.is_empty() {
                    for sig in &sig_matches {
                        events.push(MonitorEvent::SignatureMatch {
                            name: sig.name.clone(),
                            matched_item: process.name.clone(),
                            threat_level: sig.threat_level,
                        });
                        self.threats_detected += 1;
                    }
                }

                let threat_level = crate::detectors::calculate_threat_level(&process.threat_indicators);
                
                if !process.threat_indicators.is_empty() || verbose {
                    events.push(MonitorEvent::NewProcess {
                        pid: process.pid,
                        name: process.name.clone(),
                        threat_level,
                        indicators: process.threat_indicators.clone(),
                    });
                    
                    if threat_level >= ThreatLevel::Medium {
                        self.threats_detected += 1;
                    }
                }
            }
        }

        // Terminated processes (that were suspicious)
        for pid in &self.known_pids {
            if !current_pids.contains(pid) {
                // We don't have the name anymore, but we can note it was terminated
                if verbose {
                    events.push(MonitorEvent::ProcessTerminated {
                        pid: *pid,
                        name: "Unknown".to_string(),
                    });
                }
            }
        }

        self.known_pids = current_pids;

        // Check for new network connections
        let current_connections = self.network_analyzer.get_connections();
        let current_conn_set: HashSet<String> = current_connections
            .iter()
            .map(|c| format!("{}:{}-{}:{}", c.local_address, c.local_port, c.remote_address, c.remote_port))
            .collect();

        for conn in &current_connections {
            let conn_id = format!("{}:{}-{}:{}", 
                conn.local_address, conn.local_port, 
                conn.remote_address, conn.remote_port
            );
            
            if !self.known_connections.contains(&conn_id) {
                let suspicious = crate::detectors::SUSPICIOUS_PORTS.contains(&conn.remote_port)
                    || crate::detectors::SUSPICIOUS_PORTS.contains(&conn.local_port);
                
                if suspicious || verbose {
                    events.push(MonitorEvent::NewConnection {
                        local: format!("{}:{}", conn.local_address, conn.local_port),
                        remote: format!("{}:{}", conn.remote_address, conn.remote_port),
                        process_name: conn.process_name.clone(),
                        suspicious,
                    });
                    
                    if suspicious {
                        self.threats_detected += 1;
                    }
                }
            }
        }

        self.known_connections = current_conn_set;

        // Periodic hook check (less frequent)
        if self.events_count % 12 == 0 {  // Every minute or so
            let hook_detections = self.hook_detector.scan();
            for detection in hook_detections {
                events.push(MonitorEvent::HookDetected {
                    description: detection.description.clone(),
                    threat_level: detection.threat_level,
                });
                self.threats_detected += 1;
            }
        }

        self.events_count += 1;
        events
    }

    /// Print monitoring summary
    pub fn print_summary(&self) {
        println!("\n{}", "═══ Monitoring Summary ═══".cyan().bold());
        println!("Total checks performed: {}", self.events_count);
        println!("Current processes tracked: {}", self.known_pids.len());
        println!("Current connections tracked: {}", self.known_connections.len());
        println!("Threats detected: {}", 
            if self.threats_detected == 0 {
                "0".green().to_string()
            } else {
                self.threats_detected.to_string().red().bold().to_string()
            }
        );
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_creation() {
        let monitor = SystemMonitor::new();
        assert!(!monitor.known_pids.is_empty());
    }

    #[test]
    fn test_monitor_event_print() {
        let event = MonitorEvent::NewProcess {
            pid: 1234,
            name: "test_process".to_string(),
            threat_level: ThreatLevel::Low,
            indicators: vec!["Test indicator".to_string()],
        };
        // Just ensure it doesn't panic
        event.print();
    }
}
