# SignalBench Endpoint Telemetry Generator

## Overview

SignalBench is a Rust-based endpoint telemetry generator designed for Linux environments that emulates MITRE ATT&CK technique patterns for security analytics, research, and training. The application executes actual OS commands that generate realistic endpoint telemetry while remaining safe and non-destructive, providing valuable data for security analytics development.

## System Architecture

### Core Technology Stack
- **Language**: Rust
- **Platform**: Linux-focused
- **CLI Framework**: Clap for command-line interface
- **Configuration**: JSON-based configuration files
- **Logging**: Built-in logging system for telemetry generation activities
- **Networking**: Native Rust networking libraries (tokio, mio)
- **Serialization**: Serde for JSON handling

### Application Structure
The application follows a modular Rust architecture with:
- Binary executable as the main entry point
- Library modules for different MITRE ATT&CK technique categories
- Configuration management system
- Logging and cleanup functionality
- Command-line interface for user interaction

## Key Components

### Telemetry Generation Implementation
- **MITRE ATT&CK Framework Integration**: Implements technique-aligned activity patterns from various categories including Discovery, Credential Access, Defense Evasion, Execution, Command and Control, and Exfiltration
- **Real Command Execution**: Unlike simple simulations, SignalBench executes actual OS commands to generate realistic endpoint telemetry
- **Safety Mechanisms**: Built-in safeguards to prevent accidental system damage
- **Cleanup System**: Automatic artifact removal after telemetry generation

### Configuration System
- **JSON-based Configuration**: Flexible parameter configuration for each technique
- **Technique Selection**: Support for selecting techniques by MITRE ID or descriptive names
- **Parameter Customization**: Configurable telemetry generation parameters per technique
- **Cleanup Control**: Per-technique cleanup configuration

### Command-Line Interface
- **Technique Listing**: Display all available MITRE ATT&CK techniques
- **Dry-run Mode**: Preview actions without execution
- **Configuration File Support**: Load telemetry generation parameters from JSON files
- **Interactive Execution**: Real-time feedback during telemetry generation

## Data Flow

1. **Configuration Loading**: JSON configuration files define telemetry generation parameters and technique selection
2. **Technique Selection**: Users select specific MITRE ATT&CK techniques to execute
3. **Command Execution**: Real OS commands are executed based on technique definitions
4. **Logging**: All activities are logged for analysis and audit purposes
5. **Cleanup**: Automatic removal of artifacts to restore system state
6. **Result Reporting**: Telemetry generation outcomes provide valuable data for analytics and research

## External Dependencies

### Runtime Dependencies
- **Operating System**: Linux environment required
- **Network Access**: Required for command and control and exfiltration technique telemetry
- **System Tools**: Various Linux utilities (netstat, ss, ip, ifconfig) for telemetry generation
- **File System Access**: Read/write permissions for telemetry artifact creation

### Rust Ecosystem Dependencies
- **Clap**: Command-line argument parsing
- **Serde/Serde JSON**: Configuration serialization
- **Tokio**: Asynchronous networking
- **Chrono**: Date/time handling for logging
- **UUID**: Unique identifier generation
- **Hex**: Hexadecimal encoding/decoding
- **Various system libraries**: For OS interaction and networking

## Deployment Strategy

### Build Process
- **Cargo Build System**: Standard Rust compilation with `cargo build --release`
- **Static Binary**: Self-contained executable with minimal external dependencies
- **Linux Target**: Optimized for Linux environments

### Installation Requirements
- **Rust Toolchain**: Required for building from source
- **System Permissions**: Appropriate privileges for executing telemetry generation commands
- **Network Configuration**: Proper network access for relevant techniques

### Usage Considerations
- **Analytics Environment**: Designed for controlled lab environments, analytics development, and training scenarios
- **Controlled Research**: Should be used only in authorized research and training environments
- **Simulation-Aware**: Many modern security products are simulation-aware and may not generate alerts for research tools by design

## Changelog

```
Changelog:
- October 24, 2025. Version 1.4.3 - Fixed PACEMAKER YARA signature embedding to ensure detection by FE_APT_Trojan_Linux_PACEMAKER rule. Enhanced helper binary with realistic /proc reading behaviour, process inspection, and credential harvesting simulation based on Mandiant APT report. Added YARA verification to GitHub Actions build process. Updated TECHNIQUES.md with complete UNC2630 attribution and behavioural analysis.
- October 24, 2025. Version 1.4.2 - Fixed cleanup process to properly remove all artifacts after technique execution. Improved S1109 PACEMAKER cleanup to remove directory and all files. Fixed T1205 traffic signaling cron cleanup. Updated GitHub Actions workflow to build static MUSL helper binaries for true portable Linux compatibility. All clippy warnings resolved.
- October 24, 2025. Version 1.4.1 - Added SOFTWARE category for malware simulations with S1109 PACEMAKER credential stealer. Implemented embedded helper binary architecture (helpers/pacemaker/) containing YARA signatures (/proc/%d/mem, credential format strings, x86 byte patterns) matching FE_APT_Trojan_Linux_PACEMAKER rules. Simulation deploys to /tmp/signalbench_sim-pacemaker with launcher script and creates three credential files matching Mandiant APT documentation. Added 'software' CLI category for S* malware IDs alongside T* technique IDs. Hardened file creation with O_NOFOLLOW and create_new() flags to prevent symlink attacks. Fixed 127 clippy warnings for code quality. Helper binary must be built via GitHub Actions or musl-tools for proper static linking (Replit Nix environment lacks MUSL Rust std library). Created BUILD_NOTES.md with detailed build instructions. Total techniques: 37 (36 T* + 1 S*).
- October 23, 2025. Version 1.3.0 - Cleanup consistency improvements and debugging support: Audited all 36 techniques and fixed 7 with incomplete cleanup implementations (command_interpreter, persistence x2, dns_recon, dnscat_c2, network x3) to properly remove both files and directories. Added --no-cleanup flag to run and category commands for preserving artifacts during debugging and analysis. All cleanup methods now use is_dir() checks and remove_dir_all() for directories. Updated README.md and TECHNIQUES.md with comprehensive cleanup behaviour documentation.
- October 23, 2025. Version 1.2.1 - Added 4 new MITRE ATT&CK techniques for enhanced telemetry generation: T1059.004.001 (Uncommon Remote Shell Commands with random malicious-sounding names), T1036.003 (Masquerading as Linux Crond Process), T1105.001 (Suspicious GitHub Tool Transfer from fictional simonsigre repositories), and T1110.002 (Hydra Brute Force Tool Simulation using Wildfire test file). All techniques follow SignalBench patterns with dry-run support, cleanup mechanisms, and comprehensive documentation. Total technique count increased to 36.
- October 23, 2025. Version 1.1.2 - Security maintenance release: updated all dependencies to latest versions to address RUSTSEC-2025-0047 vulnerability in slab crate. Updated 79 packages including tokio 1.48.0, clap 4.5.50, serde 1.0.228, chrono 0.4.42, and other dependencies. All security audits pass with no known vulnerabilities.
- September 12, 2025. Version 1.1.1 - Added T1003.007 OS Credential Dumping: Proc Filesystem technique implementing realistic memory analysis using dd utility and /proc filesystem. Enhanced TECHNIQUES.md documentation with comprehensive coverage of all 32 implemented techniques. Fixed category casing and permission metadata for consistent framework integration.
- September 12, 2025. Version 1.1.0 - Added T1205 Traffic Signaling technique that uses cron to install TCP filters on network interfaces for covert C2 communication simulation. Supports both iptables and tc_filter methods with configurable target ports, cron schedules, and interface selection. Enhanced security measures including precise cron cleanup, network rule teardown, and privilege handling with graceful degradation.
- September 12, 2025. Version 1.0.1 - Added T1548.003.001 sudo unsigned integer privilege escalation technique implementing CVE-2019-14287 vulnerability exploitation. This new technique tests both negative user ID (-u#-1) and large unsigned integer (-u#4294967295) methods to bypass sudo restrictions and execute commands as root. Comprehensive documentation added to TECHNIQUES.md and configuration example added to config-example.json.
- September 12, 2025. Version 1.0.0 - Production release with GLIBC compatibility fixes. Added musl static linking builds for universal Linux compatibility. Fixed GitHub Actions workflow to build proper static binaries that work on any Linux distribution. Removed problematic debian:latest builds that caused GLIBC version conflicts. Added GLIBC version validation in CI pipeline.
- September 11, 2025. Version 0.5.0 - Major rebrand from Snellen to SignalBench with repositioning as an "Endpoint Telemetry Generator for Analytics, Research, and Training". Updated all user-facing language from testing/attack terminology to neutral telemetry generation language. Binary name changed from 'snellen' to 'signalbench'. Added simulation-aware environment notice to address concerns about making security products look inadequate. Comprehensive cleanup of all technique descriptions, file paths, and documentation.
- August 7, 2025. Version 0.4.2 - Streamlined GitHub Actions workflow to build for Ubuntu Latest, Debian Latest, and Debian 12 (all x86_64 and aarch64). Removed problematic Ubuntu 20.04 builds and fixed YAML formatting issues for improved reliability.
- August 7, 2025. Version 0.4.1 - Fixed all Rust clippy format string warnings for modern syntax compliance. Added Ubuntu 20.04 build targets (x86_64 and aarch64) to GitHub Actions workflow for broader Linux distribution support.
- August 5, 2025. Version 0.4.0 - Added four new MITRE ATT&CK techniques: T1505.003 (Web Shell Deployment), T1136.001 (Local Account Creation), T1068 (Privilege Escalation Exploits), and T1552.001 (Credentials in Files). All techniques compile successfully and are properly integrated into the framework with comprehensive documentation and safety mechanisms.
- August 5, 2025. Version 0.3.1 - Comprehensive security update: updated all dependencies to latest versions (tokio 1.47.1, clap 4.5.42, serde_json 1.0.142), completed British English consistency throughout codebase, cleaned temporary files, verified code compilation and execution
- July 25, 2025. Version 0.3.1 - Added multi-category execution support, updated documentation to British English
- June 29, 2025. Version 0.3.0 - Removed production environment protection, updated dependencies
- June 28, 2025. Initial setup
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```