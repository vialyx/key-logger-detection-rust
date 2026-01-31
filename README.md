# 🔒 Keylogger Detection Tool

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/paypalme/vialyx)

A comprehensive keylogger detection tool written in Rust, demonstrating memory-safe security programming practices.

## 🎯 Project Goals

This project is part of a Cybersecurity Deep Dive study plan focused on:
- Applying Rust to build secure tools and cryptographic applications
- Understanding secure communication protocols
- Learning how Rust prevents common vulnerabilities (memory corruption, buffer overflows)

## 🚀 Features

- **Process Analysis**: Scans running processes for suspicious patterns and known keylogger signatures
- **Hook Detection**: Identifies system-level keyboard/input hooks (platform-specific)
- **Network Monitoring**: Analyzes network connections for suspicious activity and data exfiltration
- **File System Scanning**: Detects suspicious files and potential keystroke logs
- **Signature Database**: Matches against known keylogger signatures
- **Real-time Monitoring**: Continuous monitoring mode for ongoing protection
- **Report Generation**: Generate reports in text, JSON, or HTML format

## 📋 Requirements

- Rust 1.70 or later
- Cargo package manager

### Platform-Specific Notes

- **macOS**: Some features require accessibility permissions
- **Linux**: May require root for full input device monitoring
- **Windows**: Requires administrator privileges for complete scanning

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/keylogger-detector
cd keylogger-detector

# Build in release mode
cargo build --release

# The binary will be at target/release/keylogger-detector
```

## 📖 Usage

### Full System Scan

```bash
# Basic scan
cargo run -- scan

# Detailed scan with verbose output
cargo run -- scan --detailed --verbose

# Scan specific directory
cargo run -- scan --path /path/to/scan

# Save results to JSON
cargo run -- scan --output results.json
```

### Real-time Monitoring

```bash
# Continuous monitoring
cargo run -- monitor

# Monitor for 60 seconds
cargo run -- monitor --duration 60

# Verbose monitoring
cargo run -- monitor --verbose
```

### Check Specific Process

```bash
# Check a process by PID
cargo run -- check-process 1234

# With verbose output
cargo run -- check-process 1234 --verbose
```

### Signature Management

```bash
# List known keylogger signatures
cargo run -- signatures

# Update signature database (future feature)
cargo run -- signatures --update
```

### Generate Reports

```bash
# Generate text report
cargo run -- report --format text

# Generate HTML report
cargo run -- report --format html --output report.html

# Generate JSON report
cargo run -- report --format json --output report.json
```

## 🏗️ Architecture

```
src/
├── main.rs           # CLI entry point and command handling
├── utils.rs          # Common types and utility functions
├── scanner.rs        # Main scanning coordinator
├── monitor.rs        # Real-time monitoring
├── signatures.rs     # Signature database
├── report.rs         # Report generation
└── detectors/
    ├── mod.rs        # Detector module definitions
    ├── process.rs    # Process-based detection
    ├── behavior.rs   # Behavioral analysis
    ├── hooks.rs      # Hook detection
    └── network.rs    # Network monitoring
```

## 🔐 How Rust Prevents Vulnerabilities

This project demonstrates several ways Rust's safety features help prevent common security vulnerabilities:

### 1. Memory Safety
- **No Buffer Overflows**: Rust's bounds checking prevents reading/writing beyond array boundaries
- **No Use-After-Free**: Ownership system ensures memory is valid when accessed
- **No Null Pointer Dereferences**: `Option<T>` type forces explicit handling of missing values

### 2. Thread Safety
- **Data Race Prevention**: Rust's type system prevents data races at compile time
- **Safe Concurrency**: `Send` and `Sync` traits ensure thread-safe data sharing

### 3. Error Handling
- **No Unchecked Errors**: `Result<T, E>` type forces error handling
- **No Silent Failures**: Panics are explicit and controlled

### Example of Rust's Safety

```rust
// Rust prevents buffer overflows
fn safe_read(data: &[u8], index: usize) -> Option<u8> {
    data.get(index).copied()  // Returns None if out of bounds
}

// Ownership prevents use-after-free
fn process_data(data: Vec<u8>) {
    // data is moved here, original owner can't use it
    process(data);
}
// data is dropped here, memory is freed safely

// Result type ensures error handling
fn read_file(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)  // Must be handled!
}
```

## 🔍 Detection Methods

### Process Detection
- Pattern matching on process names
- Command line argument analysis
- Executable path inspection
- Memory usage anomalies
- Parent-child process relationships

### Hook Detection
- **macOS**: Accessibility and Input Monitoring permissions
- **Linux**: /dev/input device access, xinput monitoring
- **Windows**: SetWindowsHookEx API detection, registry analysis

### Network Detection
- Suspicious port monitoring (common RAT/malware ports)
- Connection to unknown external addresses
- Data exfiltration patterns

### Signature Detection
- SHA-256 file hash matching
- Process name patterns
- File path patterns
- Known mutex names

## 📊 Threat Levels

| Level | Description |
|-------|-------------|
| ✅ Safe | No suspicious indicators |
| 🟡 Low | Minor suspicious activity, likely false positive |
| 🟠 Medium | Moderate concern, investigation recommended |
| 🔴 High | Significant threat indicators detected |
| ⛔ Critical | Known malware signature matched |

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/keylogger-detector
cd keylogger-detector

# Run tests
cargo test

# Run with debug output
RUST_LOG=debug cargo run -- scan

# Check formatting
cargo fmt --check

# Run linter
cargo clippy
```

## ⚠️ Disclaimer

This tool is for educational and defensive security purposes only. Use responsibly and in accordance with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 📚 Further Reading

- [The Rust Book - Ownership](https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [OWASP Keylogger Detection](https://owasp.org/www-community/attacks/Keystroke_logging)

## 📄 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
