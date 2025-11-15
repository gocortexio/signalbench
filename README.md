<div align="center">
  <img src="assets/signalbench-logo-supersized.png" alt="SignalBench Logo" width="600"/>
</div>

# SignalBench

Endpoint Telemetry Generator from GoCortex.io

A Rust-based application for Linux that generates endpoint telemetry aligned with MITRE ATT&CK techniques for security analytics, research, and training environments.

## Overview

SignalBench allows security professionals to generate realistic endpoint telemetry patterns for analytics development, research, and training scenarios. It implements multiple techniques from the MITRE ATT&CK framework across different categories such as persistence, privilege escalation, defence evasion, credential access, discovery, lateral movement, and execution.

### Important: Telemetry Generation Design

SignalBench **executes actual OS commands** that emulate technique-aligned activity patterns whilst remaining safe and non-destructive. This design choice ensures realistic telemetry generation for security analytics:

- Activities perform real actions (network operations, file manipulation, process injection, etc.)
- Each technique executes commands that generate observable endpoint signals
- All activities are designed to be controlled and limited to avoid actual compromise
- Proper cleanup procedures ensure no lasting system changes remain

### Simulation-Aware Environment Notice

Many modern security products are simulation-aware and may not generate alerts for research tools by design. This tool is intended for controlled lab environments, analytics development, and training scenarios - not as a comparative benchmark of security products.

### v1.5.22 The Ultimate Supersized Release

SignalBench v1.5.22 represents the pinnacle of realistic telemetry generation with **42 total techniques** and **36 supersized (86% coverage)**. This release adds 9 powerful new techniques (4 upgrades + 5 brand new) including the COLLECTION and IMPACT categories, bringing comprehensive coverage across the MITRE ATT&CK framework whilst maintaining 100% safety and reversibility:

**4 UPGRADED SUPERSIZED TECHNIQUES:**
- **T1053.003 Cron Job**: Creates REAL system-wide and user cron jobs in /etc/cron.d/ and via crontab, executes benign commands, full backup/restore
- **T1547.002 Startup Folder**: Actually modifies /etc/profile.d/, ~/.bashrc, ~/.bash_profile with persistence commands, comprehensive backup/restoration
- **T1036.003 Masquerading**: Compiles REAL C binaries with misleading names ([kworker/0:0], systemd-journald, crond), uses prctl() for process name spoofing
- **T1505.003 Web Shell**: Deploys REAL malicious PHP and Python web shells with eval(), system(), exec() backdoor patterns, multiple variants

**5 BRAND NEW SUPERSIZED TECHNIQUES:**
- **T1119 Automated Collection**: Recursively collects sensitive files from /home/, /var/, /opt/, creates tar archives, generates comprehensive JSON reports
- **T1070.004 File Deletion**: Anti-forensics with shred -uvz, secure file wiping, log tampering simulation, all with backup/restore
- **T1003.008 /etc/passwd and /etc/shadow**: Comprehensive user enumeration, shadow file parsing (if root), password hash extraction
- **T1098 Account Manipulation**: Modifies user accounts, injects SSH keys into authorized_keys, changes shells, group manipulation (requires root)
- **T1496 Resource Hijacking**: Controlled CPU stress (crypto-mining simulation), memory allocation, disk I/O stress with safety limits

All 36 supersized techniques generate high-volume, realistic telemetry designed for detection by security products whilst remaining 100% safe and reversible through comprehensive artifact tracking and cleanup verification.

### v1.5.13 The Supersized Menu

SignalBench v1.5.13 dramatically expands realistic telemetry coverage to **27 of 37 techniques (73%)** with 13 new or enhanced implementations driven by real-world security product testing that showed 50% detection on v1.5.0. This release maximises detection whilst maintaining 100% safety and reversibility:

**6 NEW SUPERSIZED TECHNIQUES:**
- **T1110.002 SSH Brute Force**: Creates temporary test user, performs REAL failed SSH authentication attempts against localhost:22, generates auth.log entries, measures timing patterns
- **T1021.004 SSH Lateral Movement**: Generates SSH keys, modifies authorized_keys, executes REAL SSH connections with port forwarding attempts
- **T1049 Network Connections**: Comprehensive enumeration via netstat/ss/lsof, parses active connections, listening ports, process-to-socket mappings
- **T1070.003 Clear Command History**: Actually backs up and modifies shell history files (.bash_history, .zsh_history, etc.), removes suspicious patterns, full restoration
- **T1548.003 Sudoers Modification**: Creates REAL sudoers files with NOPASSWD rules, validates with visudo, comprehensive backup/restore
- **T1548.001 SUID Binary**: Compiles C wrapper, sets SUID bit, attempts privileged operations, complete cleanup

**7 ENHANCED v1.5.0 TECHNIQUES FOR IMPROVED DETECTION:**
- **T1056.001 Keylogging**: Expanded to enumerate ALL /dev/input/event0-15 (16 devices), added 5 new history files (.sqlite_history, .redis_history, .node_repl_history), enhanced auth.log parsing
- **T1552.001 Credentials in Files**: Added 8 new search directories (/var/www, /opt, /srv, /var/lib, /root/.ssh, /usr/local/etc), database dump file analysis, expanded credential patterns
- **T1046 Port Scanning**: Increased from 10 ports to 1,032 TCP ports (1-1024 + backdoor ports), added UDP scanning (DNS, NTP, SNMP), scans both IPv4/IPv6 localhost
- **T1059.006 Python Script**: Added persistent socket listener (20s accept loop), /proc/*/fd enumeration, reads environment variables from all processes, comprehensive recon reporting
- **T1574.007 PATH Interception**: Expanded from 3 to 7 trojan binaries (added sudo, ssh, curl, wget), enhanced logging with PID/timestamp/arguments
- **T1562.002 Disable Audit**: Added systemctl service manipulation, /etc/audit/audit.rules modification option, multi-method approach
- **T1068 Privilege Escalation**: Attempts actual exploitation - creates systemd test services, tests Docker operations, executes sudo -l vulnerabilities

All 27 supersized techniques generate high-volume, realistic telemetry designed for maximum detection by security products whilst remaining 100% safe and reversible through comprehensive artifact tracking and cleanup verification.

### v1.5.0 Realistic Telemetry Upgrade

SignalBench v1.5.0 introduces a major upgrade from simulations to REAL attack behaviours across 14 core techniques:

**CREDENTIAL ACCESS**: Real memory dumping (gcore, /proc/mem), actual keystroke capture from /dev/input devices, genuine filesystem credential harvesting, live process memory parsing

**DISCOVERY**: Comprehensive system enumeration with security tool detection, comprehensive network reconnaissance including ARP/VPN/VLAN discovery, real TCP port scanning with banner grabbing

**EXECUTION**: Actual reverse shell execution to localhost, real Python-based reconnaissance with socket listeners, genuine command injection patterns

**DEFENSE EVASION**: Real PATH hijacking with trojan binaries, actual audit log manipulation requiring root privileges

**PRIVILEGE ESCALATION**: Comprehensive local account creation with sudo access, real SUID binary enumeration, genuine privilege escalation vector identification

**COMMAND & CONTROL**: Actual iptables rule installation for port knocking, real network traffic signalling

All techniques remain 100% safe and reversible with comprehensive cleanup, but now generate authentic telemetry that security products will actually detect. Many techniques require elevated privileges for full functionality.

## Features

- Command-line interface for Linux environments
- Generate endpoint telemetry based on MITRE ATT&CK techniques
- Support for common technique categories including Discovery, Credential Access, Defence Evasion, Execution, Command and Control, and Exfiltration
- Multi-category execution support for running multiple technique categories simultaneously
- Universal Linux compatibility with static musl builds (works on any distribution)
- GLIBC compatibility validation for distribution-specific builds
- Configurable activity parameters via JSON configuration files
- Safe execution environment to prevent accidental harm
- Logging of all telemetry generation activities
- Dry-run mode to preview actions without executing them
- Automatic cleanup functionality to remove all artifacts after execution
- Optional --no-cleanup flag to preserve artifacts for debugging and analysis
- Support for selecting techniques by exact name when multiple techniques share the same MITRE ATT&CK ID
- Comprehensive documentation of all implemented techniques

## Installation

### Option 1: Download Pre-built Binary (Recommended)

SignalBench provides pre-built binaries for maximum compatibility across Linux distributions.

**For Universal Linux Compatibility (Recommended):**
```bash
# Download static binary that works on any Linux distribution
wget https://github.com/gocortex/signalbench/releases/download/v1.5.22/signalbench-1.5.22-linux-musl-x86_64
chmod +x signalbench-1.5.22-linux-musl-x86_64
sudo mv signalbench-1.5.22-linux-musl-x86_64 /usr/local/bin/signalbench

# For ARM64 systems (Apple Silicon, ARM servers)
wget https://github.com/gocortex/signalbench/releases/download/v1.5.22/signalbench-1.5.22-linux-musl-aarch64
chmod +x signalbench-1.5.22-linux-musl-aarch64
sudo mv signalbench-1.5.22-linux-musl-aarch64 /usr/local/bin/signalbench
```

**For Specific Distributions:**
```bash
# Debian 12/Ubuntu 22.04+ systems (requires GLIBC 2.36+)
wget https://github.com/gocortex/signalbench/releases/download/v1.5.22/signalbench-1.5.22-debian12-glibc2.36-x86_64
chmod +x signalbench-1.5.22-debian12-glibc2.36-x86_64
sudo mv signalbench-1.5.22-debian12-glibc2.36-x86_64 /usr/local/bin/signalbench
```

### Option 2: Build from Source

1. Ensure you have Rust and Cargo installed.
2. Clone this repository.
3. Build the application:

```bash
cargo build --release
```

## Usage

```bash
# List all available techniques
signalbench list

# Generate telemetry for a specific technique
signalbench run <technique_id_or_name> [--dry-run] [--no-cleanup]

# Generate telemetry for all techniques in a category
signalbench category <category> [--dry-run] [--no-cleanup]

# Generate telemetry for multiple categories simultaneously
signalbench category <category1> <category2> <category3> [--dry-run] [--no-cleanup]

# Run with custom configuration
signalbench run <technique_id_or_name> --config <config_file.json>

# Generate telemetry for technique with duplicate MITRE ID using exact name
signalbench run "Possible C2 via dnscat2" [--dry-run]

# Preserve artifacts for debugging (skip cleanup)
signalbench run <technique_id_or_name> --no-cleanup
```

For detailed information on available techniques and implementations, refer to the comprehensive [Technical Documentation](docs/TECHNIQUES.md).

### Using Configuration Files

You can customise technique parameters using a JSON configuration file. This allows for more complex scenarios and customisation of technique behaviour.

Example:
```bash
# Generate telemetry for a specific technique with custom parameters
signalbench run T1003.001 --config docs/config-example.json

# Generate telemetry for all techniques in a category with custom parameters
signalbench category credential_access --config docs/config-example.json

# Generate telemetry for multiple categories with custom parameters
signalbench category discovery execution credential_access --config docs/config-example.json
```

A sample configuration file is provided at [docs/config-example.json](docs/config-example.json) that shows how to customise parameters for all techniques.

### Multi-Category Execution

SignalBench supports running multiple technique categories simultaneously, which is particularly useful for comprehensive analytics scenarios and training exercises:

```bash
# Generate telemetry for discovery and execution techniques together
signalbench category discovery execution --dry-run

# Generate telemetry for privilege escalation and credential access techniques
signalbench category privilege_escalation credential_access

# Generate comprehensive telemetry across multiple categories
signalbench category discovery execution credential_access command_and_control exfiltration --dry-run
```

This feature allows security teams to generate complex telemetry patterns that span multiple tactics in the MITRE ATT&CK framework, providing realistic data for analytics development and training scenarios.

## Contact & Support

For documentation, updates, and support, visit [GoCortex.io](https://gocortex.io).

Developed by Simon Sigre at GoCortex.io.