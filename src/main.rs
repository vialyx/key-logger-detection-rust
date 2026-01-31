//! Keylogger Detection Tool
//!
//! A comprehensive security tool for detecting potential keylogger activity
//! on your system. This tool demonstrates Rust's memory safety features
//! while providing practical cybersecurity functionality.
//!
//! ## Features
//! - Process scanning for suspicious activity
//! - File system monitoring for keylogger artifacts
//! - Network connection analysis
//! - Known signature detection
//! - Real-time monitoring mode

mod detectors;
mod scanner;
mod signatures;
mod monitor;
mod report;
mod utils;

use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;

/// Keylogger Detection Tool - A Rust-based security scanner
#[derive(Parser)]
#[command(name = "keylogger-detector")]
#[command(author = "Security Researcher")]
#[command(version = "0.1.0")]
#[command(about = "Detect potential keylogger activity on your system", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output results to JSON file
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform a full system scan
    Scan {
        /// Include detailed process information
        #[arg(short, long)]
        detailed: bool,

        /// Scan specific directory for suspicious files
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Monitor system in real-time for suspicious activity
    Monitor {
        /// Duration in seconds (0 for continuous)
        #[arg(short, long, default_value = "0")]
        duration: u64,
    },

    /// Check a specific process by PID
    CheckProcess {
        /// Process ID to check
        pid: u32,
    },

    /// Scan for known keylogger signatures
    Signatures {
        /// Update signature database
        #[arg(short, long)]
        update: bool,
    },

    /// Generate a security report
    Report {
        /// Output format (json, html, text)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

fn print_banner() {
    println!("{}", r#"
    ╔═══════════════════════════════════════════════════════════════╗
    ║     🔒 KEYLOGGER DETECTION TOOL v0.1.0                        ║
    ║     Built with Rust for Memory-Safe Security                  ║
    ╚═══════════════════════════════════════════════════════════════╝
    "#.cyan());
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    print_banner();

    match cli.command {
        Commands::Scan { detailed, path } => {
            println!("{}", "🔍 Starting system scan...".yellow());
            scanner::run_full_scan(detailed, path, cli.verbose, cli.output).await?;
        }

        Commands::Monitor { duration } => {
            println!("{}", "👁️  Starting real-time monitoring...".yellow());
            monitor::start_monitoring(duration, cli.verbose).await?;
        }

        Commands::CheckProcess { pid } => {
            println!("{}", format!("🔎 Checking process {}...", pid).yellow());
            scanner::check_single_process(pid, cli.verbose).await?;
        }

        Commands::Signatures { update } => {
            if update {
                println!("{}", "📥 Updating signature database...".yellow());
                signatures::update_signatures().await?;
            } else {
                println!("{}", "📋 Listing known signatures...".yellow());
                signatures::list_signatures()?;
            }
        }

        Commands::Report { format } => {
            println!("{}", "📊 Generating security report...".yellow());
            report::generate_report(&format, cli.output).await?;
        }
    }

    Ok(())
}
