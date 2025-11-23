// SIGNALBENCH - DNS Reconnaissance Technique
// DNS Reconnaissance Test (T1016 - System Network Configuration Discovery)
// 
// This module implements DNS reconnaissance or enumeration via DNSRecon
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use log::{error, info};

// ======================================
// T1016 - DNS Reconnaissance via DNSRecon
// ======================================
pub struct DNSReconTest {}

#[async_trait]
impl AttackTechnique for DNSReconTest {
    fn info(&self) -> Technique {
        Technique {
            id: "T1016".to_string(),
            name: "DNS reconnaissance or enumeration via DNSRecon".to_string(),
            description: "Generates telemetry for DNS reconnaissance and enumeration activities".to_string(),
            category: "DISCOVERY".to_string(),
            detection: "Monitor for DNS queries to multiple subdomains in short succession".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
            parameters: vec![
                TechniqueParameter {
                    name: "domain".to_string(),
                    description: "Target domain to perform reconnaissance on".to_string(),
                    required: false,
                    default: Some("example.com".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory to save execution artifacts".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_dnsrecon".to_string()),
                },
            ],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        let output_dir = config
            .parameters
            .get("output_dir")
            .unwrap_or(&"/tmp/signalbench_dnsrecon".to_string())
            .clone();
            
        let domain = config
            .parameters
            .get("domain")
            .unwrap_or(&"example.com".to_string())
            .clone();
            
        Box::pin(async move {
            // Create output directory if it doesn't exist
            if !Path::new(&output_dir).exists() {
                std::fs::create_dir_all(&output_dir)
                    .map_err(|e| format!("Failed to create output directory: {e}"))?;
            }
            
            let script_file = format!("{output_dir}/signalbench-dnsrecon.py");
            
            // Create a benign Python script for DNS reconnaissance
            let script_content = format!(r#"#!/usr/bin/env python3
# SIGNALBENCH - DNS Reconnaissance Technique
# DNS Reconnaissance Script
# This is a benign simulation of DNS reconnaissance tools like DNSRecon

import sys
import socket
import argparse
import time
import datetime

def banner():
    print("=" * 70)
    print("SignalBench DNS Reconnaissance")
    print("Benign DNS reconnaissance simulation for EDR testing")
    print("Developed by GoCortex.io")
    print("=" * 70)
    print()

def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error: {{e}}"

def resolve_hostnames(domain):
    print(f"[*] Starting DNS reconnaissance for {{domain}}")
    print(f"[*] Time: {{datetime.datetime.now()}}")
    print()
    
    # Basic DNS resolution
    print(f"[+] Basic DNS resolution for {{domain}}")
    ip = get_ip_address(domain)
    print(f"    {{domain}} -> {{ip}}")
    print()
    
    # Common subdomain check (simulation only)
    print(f"[+] Common subdomain check for {{domain}}")
    for subdomain in ['www', 'mail', 'api', 'admin', 'blog']:
        full_domain = f"{{subdomain}}.{{domain}}"
        print(f"    [*] Checking {{full_domain}}...")
        time.sleep(0.2)  # Add realistic delay
        
        try:
            ip = socket.gethostbyname(full_domain)
            print(f"    [+] {{full_domain}} -> {{ip}}")
        except:
            print(f"    [-] Could not resolve {{full_domain}}")
    
    print()
    print("[+] DNS reconnaissance simulation complete")
    print("=" * 70)

if __name__ == "__main__":
    banner()
    
    parser = argparse.ArgumentParser(description="SignalBench DNS Reconnaissance")
    parser.add_argument("--domain", type=str, default="{domain}", help="Target domain")
    args = parser.parse_args()
    
    resolve_hostnames(args.domain)
"#);
            
            if dry_run {
                info!("[DRY RUN] Would create DNS reconnaissance script at {script_file}");
                info!("[DRY RUN] Would execute DNS reconnaissance against domain {domain}");
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform DNS reconnaissance".to_string(),
                    artifacts: vec![script_file],
                    cleanup_required: false,
                });
            }
            
            // Create the Python script
            info!("Creating DNS reconnaissance script at {script_file}");
            
            let mut file = File::create(&script_file)
                .map_err(|e| format!("Failed to create script file: {e}"))?;
                
            file.write_all(script_content.as_bytes())
                .map_err(|e| format!("Failed to write to script file: {e}"))?;
                
            // Make the script executable
            std::fs::set_permissions(&script_file, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .map_err(|e| format!("Failed to set script permissions: {e}"))?;
                
            // Execute the script
            info!("Executing DNS reconnaissance script against domain {domain}");
            
            let output = Command::new("python3")
                .arg(&script_file)
                .arg("--domain")
                .arg(&domain)
                .output()
                .await
                .map_err(|e| format!("Failed to execute script: {e}"))?;
                
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Save the output to a log file
            let log_file = format!("{output_dir}/dnsrecon_log.txt");
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log, "=== DNSRecon Simulation Log ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "Domain: {domain}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "=== STDOUT ===\n{stdout}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "=== STDERR ===\n{stderr}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully performed DNS reconnaissance simulation against {domain}"),
                artifacts: vec![script_file, log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        let artifacts = artifacts.to_vec();
        
        Box::pin(async move {
            for artifact in &artifacts {
                if Path::new(artifact).exists() {
                    info!("Removing artifact: {artifact}");
                    
                    // Check if artifact is a directory
                    if Path::new(artifact).is_dir() {
                        if let Err(e) = std::fs::remove_dir_all(artifact) {
                            error!("Failed to remove directory {artifact}: {e}");
                        }
                    } else if let Err(e) = std::fs::remove_file(artifact) {
                        error!("Failed to remove artifact {artifact}: {e}");
                    }
                }
            }
            
            // Try to remove the parent directory if it's empty
            if !artifacts.is_empty() {
                if let Some(dir) = Path::new(&artifacts[0]).parent() {
                    if dir.exists() {
                        match std::fs::read_dir(dir) {
                            Ok(entries) => {
                                if entries.count() == 0 {
                                    if let Err(e) = std::fs::remove_dir(dir) {
                                        error!("Failed to remove directory {}: {}", dir.display(), e);
                                    }
                                }
                            }
                            Err(e) => error!("Failed to read directory {}: {}", dir.display(), e),
                        }
                    }
                }
            }
            
            Ok(())
        })
    }
}