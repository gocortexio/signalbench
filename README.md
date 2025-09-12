<div align="center">
  <img src="assets/signalbench-logo.png" alt="SignalBench Logo" width="300"/>
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
- Cleanup functionality to remove artifacts
- Support for selecting techniques by exact name when multiple techniques share the same MITRE ATT&CK ID
- Comprehensive documentation of all implemented techniques

## Installation

### Option 1: Download Pre-built Binary (Recommended)

SignalBench provides pre-built binaries for maximum compatibility across Linux distributions.

**For Universal Linux Compatibility (Recommended):**
```bash
# Download static binary that works on any Linux distribution
wget https://github.com/gocortex/signalbench/releases/download/v1.0.0/signalbench-1.0.0-linux-musl-x86_64
chmod +x signalbench-1.0.0-linux-musl-x86_64
sudo mv signalbench-1.0.0-linux-musl-x86_64 /usr/local/bin/signalbench

# For ARM64 systems (Apple Silicon, ARM servers)
wget https://github.com/gocortex/signalbench/releases/download/v1.0.0/signalbench-1.0.0-linux-musl-aarch64
chmod +x signalbench-1.0.0-linux-musl-aarch64
sudo mv signalbench-1.0.0-linux-musl-aarch64 /usr/local/bin/signalbench
```

**For Specific Distributions:**
```bash
# Debian 12/Ubuntu 22.04+ systems (requires GLIBC 2.36+)
wget https://github.com/gocortex/signalbench/releases/download/v1.0.0/signalbench-1.0.0-debian12-glibc2.36-x86_64
chmod +x signalbench-1.0.0-debian12-glibc2.36-x86_64
sudo mv signalbench-1.0.0-debian12-glibc2.36-x86_64 /usr/local/bin/signalbench
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
signalbench run <technique_id_or_name> [--dry-run]

# Generate telemetry for all techniques in a category
signalbench category <category> [--dry-run]

# Generate telemetry for multiple categories simultaneously
signalbench category <category1> <category2> <category3> [--dry-run]

# Run with custom configuration
signalbench run <technique_id_or_name> --config <config_file.json>

# Generate telemetry for technique with duplicate MITRE ID using exact name
signalbench run "Possible C2 via dnscat2" [--dry-run]
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