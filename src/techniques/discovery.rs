use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::{Write, BufRead, BufReader};
use std::path::Path;
use tokio::process::Command;

pub struct NetworkDiscovery {}

#[async_trait]
impl AttackTechnique for NetworkDiscovery {
    fn info(&self) -> Technique {
        Technique {
            id: "T1016".to_string(),
            name: "System Network Configuration Discovery".to_string(),
            description: "Performs comprehensive network reconnaissance including ARP table enumeration, VPN detection, VLAN identification, routing table analysis, network bridge discovery, and firewall rule enumeration".to_string(),
            category: "discovery".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "File to save network discovery results".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_network_info".to_string()),
                },
                TechniqueParameter {
                    name: "commands".to_string(),
                    description: "Comma-separated list of commands to run".to_string(),
                    required: false,
                    default: Some("ip addr,ip route,ifconfig,netstat -tuln".to_string()),
                },
            ],
            detection: "Monitor for ARP table queries, VPN configuration access, VLAN enumeration, routing table reads, network bridge enumeration, and iptables/nftables rule queries".to_string(),
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
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_network_info".to_string())
                .clone();
                
            let commands_str = config
                .parameters
                .get("commands")
                .unwrap_or(&"ip addr,ip route,ifconfig,netstat -tuln".to_string())
                .clone();
                
            let commands: Vec<&str> = commands_str.split(',').collect();
            
            if dry_run {
                info!("[DRY RUN] Would perform comprehensive network reconnaissance: ARP enumeration, VPN detection, VLAN identification, routing analysis, bridge discovery, firewall rules");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform comprehensive network reconnaissance".to_string(),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            // Counters for CLI output
            let mut interface_count = 0;
            let mut arp_entries = 0;
            let mut vpn_configs_detected: Vec<String> = Vec::new();
            let mut vlans_detected: Vec<String> = Vec::new();
            
            // Create the output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
            
            // Write header to file
            writeln!(file, "=== SignalBench Comprehensive Network Configuration Discovery ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Network interfaces with detailed information
            info!("Enumerating network interfaces with detailed information");
            writeln!(file, "=== Network Interface Enumeration (ip link show) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(ip_link_output) = Command::new("ip").arg("link").arg("show").output().await {
                if ip_link_output.status.success() {
                    let output_str = String::from_utf8_lossy(&ip_link_output.stdout);
                    // Count interfaces (lines starting with a number followed by colon)
                    interface_count = output_str.lines()
                        .filter(|line| line.chars().next().is_some_and(|c| c.is_numeric()))
                        .count();
                    file.write_all(&ip_link_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "Could not execute ip link show")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // ARP table enumeration using ip neigh
            info!("Enumerating ARP table using ip neigh");
            writeln!(file, "=== ARP Table Enumeration (ip neigh) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(ip_neigh_output) = Command::new("ip").arg("neigh").output().await {
                if ip_neigh_output.status.success() {
                    let output_str = String::from_utf8_lossy(&ip_neigh_output.stdout);
                    arp_entries = output_str.lines().filter(|line| !line.trim().is_empty()).count();
                    file.write_all(&ip_neigh_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "Could not execute ip neigh")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // ARP table enumeration using arp -a
            info!("Enumerating ARP table using arp -a");
            writeln!(file, "=== ARP Table Enumeration (arp -a) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(arp_output) = Command::new("arp").arg("-a").output().await {
                if arp_output.status.success() {
                    file.write_all(&arp_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "Could not execute arp -a")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Routing table analysis with default gateway identification
            info!("Parsing routing table to identify default gateways");
            writeln!(file, "=== Routing Table Analysis with Default Gateway Identification ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(ip_route_output) = Command::new("ip").arg("route").arg("show").output().await {
                if ip_route_output.status.success() {
                    let output_str = String::from_utf8_lossy(&ip_route_output.stdout);
                    file.write_all(&ip_route_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    // Parse and highlight default gateways
                    writeln!(file, "\n--- Default Gateways Identified ---")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    for line in output_str.lines() {
                        if line.starts_with("default") {
                            writeln!(file,"GATEWAY: {line}")
                                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        }
                    }
                } else {
                    writeln!(file, "Could not execute ip route show")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // VPN configuration detection
            info!("Detecting VPN configurations in /etc/openvpn/ and /etc/wireguard/");
            writeln!(file, "=== VPN Configuration Detection ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Check /etc/openvpn/
            writeln!(file, "--- OpenVPN Configurations (/etc/openvpn/) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if Path::new("/etc/openvpn").exists() {
                if let Ok(entries) = fs::read_dir("/etc/openvpn") {
                    let mut found_openvpn = false;
                    for entry in entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if file_name.ends_with(".conf") || file_name.ends_with(".ovpn") {
                                writeln!(file,"DETECTED OpenVPN config: /etc/openvpn/{file_name}")
                                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                vpn_configs_detected.push(format!("OpenVPN: {file_name}"));
                                found_openvpn = true;
                            }
                        }
                    }
                    if !found_openvpn {
                        writeln!(file, "No OpenVPN configuration files found")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                } else {
                    writeln!(file, "Could not access /etc/openvpn/")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "/etc/openvpn/ does not exist")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            // Check /etc/wireguard/
            writeln!(file, "\n--- WireGuard Configurations (/etc/wireguard/) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if Path::new("/etc/wireguard").exists() {
                if let Ok(entries) = fs::read_dir("/etc/wireguard") {
                    let mut found_wireguard = false;
                    for entry in entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if file_name.ends_with(".conf") {
                                writeln!(file,"DETECTED WireGuard config: /etc/wireguard/{file_name}")
                                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                vpn_configs_detected.push(format!("WireGuard: {file_name}"));
                                found_wireguard = true;
                            }
                        }
                    }
                    if !found_wireguard {
                        writeln!(file, "No WireGuard configuration files found")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                } else {
                    writeln!(file, "Could not access /etc/wireguard/")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "/etc/wireguard/ does not exist")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // VLAN configuration detection
            info!("Detecting VLAN configurations in /proc/net/vlan/ and network interfaces");
            writeln!(file, "=== VLAN Configuration Detection ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Check /proc/net/vlan/
            writeln!(file, "--- VLAN Information (/proc/net/vlan/) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if Path::new("/proc/net/vlan").exists() {
                if let Ok(entries) = fs::read_dir("/proc/net/vlan") {
                    let mut found_vlan = false;
                    for entry in entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if file_name != "config" {
                                writeln!(file,"DETECTED VLAN interface: {file_name}")
                                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                vlans_detected.push(file_name.clone());
                                
                                // Read VLAN interface details
                                let vlan_path = format!("/proc/net/vlan/{file_name}");
                                if let Ok(vlan_content) = fs::read_to_string(&vlan_path) {
                                    writeln!(file,"Details for {file_name}:")
                                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                    file.write_all(vlan_content.as_bytes())
                                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                    writeln!(file)
                                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                }
                                found_vlan = true;
                            }
                        }
                    }
                    if !found_vlan {
                        writeln!(file, "No VLAN interfaces found in /proc/net/vlan/")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                } else {
                    writeln!(file, "Could not access /proc/net/vlan/")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "/proc/net/vlan/ does not exist")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            // Check for VLAN interfaces in ip link output (interfaces with dot notation like eth0.10)
            writeln!(file, "\n--- VLAN Detection from Interface Names ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(ip_link_output) = Command::new("ip").arg("link").arg("show").output().await {
                if ip_link_output.status.success() {
                    let output_str = String::from_utf8_lossy(&ip_link_output.stdout);
                    for line in output_str.lines() {
                        if line.contains('@') || line.contains("vlan") {
                            if let Some(iface_name) = line.split(':').nth(1) {
                                let iface_name = iface_name.trim().split('@').next().unwrap_or("").trim();
                                if iface_name.contains('.') || line.contains("vlan") {
                                    writeln!(file,"DETECTED potential VLAN interface: {iface_name}")
                                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                                    if !vlans_detected.contains(&iface_name.to_string()) {
                                        vlans_detected.push(iface_name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Network bridge detection
            info!("Detecting network bridges");
            writeln!(file, "=== Network Bridge Detection ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Try brctl show
            writeln!(file, "--- Bridge Control (brctl show) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(brctl_output) = Command::new("brctl").arg("show").output().await {
                if brctl_output.status.success() {
                    file.write_all(&brctl_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "brctl not available or failed")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "brctl command not found")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            // Try ip link show type bridge
            writeln!(file, "\n--- IP Bridge Enumeration (ip link show type bridge) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(ip_bridge_output) = Command::new("ip").arg("link").arg("show").arg("type").arg("bridge").output().await {
                if ip_bridge_output.status.success() {
                    file.write_all(&ip_bridge_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "Could not enumerate bridges with ip command")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // iptables/nftables firewall rules
            info!("Enumerating iptables/nftables firewall rules");
            writeln!(file, "=== Firewall Rule Enumeration ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Try iptables
            writeln!(file, "--- iptables Rules (iptables -L -n -v) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(iptables_output) = Command::new("iptables").arg("-L").arg("-n").arg("-v").output().await {
                if iptables_output.status.success() {
                    file.write_all(&iptables_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "iptables not available or insufficient permissions")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "iptables command not found")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            // Try nftables
            writeln!(file, "\n--- nftables Rules (nft list ruleset) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(nft_output) = Command::new("nft").arg("list").arg("ruleset").output().await {
                if nft_output.status.success() {
                    file.write_all(&nft_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "nft not available or insufficient permissions")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "nft command not found")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Execute standard commands from configuration
            writeln!(file, "=== Standard Network Commands ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            for cmd in &commands {
                let cmd = cmd.trim();
                let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
                
                if cmd_parts.is_empty() {
                    continue;
                }
                
                let program = cmd_parts[0];
                let args = &cmd_parts[1..];
                
                info!("Executing network discovery command: {cmd}");
                
                writeln!(file, "=== Command: {cmd} ===")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                
                let output = Command::new(program)
                    .args(args)
                    .output()
                    .await;
                
                match output {
                    Ok(output) => {
                        writeln!(file, "Exit Code: {}", output.status.code().unwrap_or(-1))
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        writeln!(file, "Stdout:")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        file.write_all(&output.stdout)
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        writeln!(file, "Stderr:")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        file.write_all(&output.stderr)
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    },
                    Err(e) => {
                        writeln!(file, "Error executing command: {e}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                }
                
                writeln!(file)
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            info!("Comprehensive network reconnaissance complete - Interfaces: {}, ARP entries: {}, VPN configs: {}, VLANs: {}", 
                  interface_count, arp_entries, vpn_configs_detected.len(), vlans_detected.len());
            
            let vpn_msg = if vpn_configs_detected.is_empty() {
                "none".to_string()
            } else {
                vpn_configs_detected.join(", ")
            };
            
            let vlan_msg = if vlans_detected.is_empty() {
                "none".to_string()
            } else {
                vlans_detected.join(", ")
            };
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Comprehensive network reconnaissance: {interface_count} interfaces, {arp_entries} ARP entries, VPN configs: {vpn_msg}, VLANs: {vlan_msg}"),
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
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}

// Hidden reference: This technique was inspired by Simon Sigre's research on EDR evasion
pub struct SystemInformationDiscovery {}

#[async_trait]
impl AttackTechnique for SystemInformationDiscovery {
    fn info(&self) -> Technique {
        Technique {
            id: "T1082".to_string(),
            name: "System Information Discovery".to_string(),
            description: "Performs comprehensive system enumeration including user account parsing, package enumeration, security tool detection, and comprehensive system reconnaissance".to_string(),
            category: "discovery".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "File to save system discovery results".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_system_info".to_string()),
                },
                TechniqueParameter {
                    name: "commands".to_string(),
                    description: "Comma-separated list of commands to run".to_string(),
                    required: false,
                    default: Some("uname -a,hostnamectl,cat /etc/os-release,lscpu,free -m,df -h".to_string()),
                },
            ],
            detection: "Monitor for /etc/passwd access, package manager queries, security tool enumeration, /proc filesystem reads, and kernel module enumeration".to_string(),
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
            let output_file = config
                .parameters
                .get("output_file")
                .unwrap_or(&"/tmp/signalbench_system_info".to_string())
                .clone();
                
            let commands_str = config
                .parameters
                .get("commands")
                .unwrap_or(&"uname -a,whoami,hostnamectl,cat /etc/os-release,lscpu,free -m,df -h".to_string())
                .clone();
                
            let commands: Vec<&str> = commands_str.split(',').collect();
            
            if dry_run {
                info!("[DRY RUN] Would perform comprehensive system enumeration: user accounts, packages, security tools, CPU/memory details, kernel modules, containerisation checks");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform comprehensive system enumeration".to_string(),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            // Counters for CLI output
            let mut user_count = 0;
            let mut package_count = 0;
            let mut security_tools_detected: Vec<String> = Vec::new();
            
            // Create the output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
            
            // Write header to file
            writeln!(file, "=== SignalBench Comprehensive System Information Discovery ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Add basic system information using Rust libraries
            writeln!(file, "=== Basic System Information (collected via Rust) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                
            writeln!(file, "Username: {}", whoami::username())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                
            writeln!(file, "Hostname: {}", hostname::get().unwrap_or_default().to_string_lossy())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                
            writeln!(file, "OS: {}", whoami::distro())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Parse /etc/passwd for user accounts
            info!("Parsing /etc/passwd for user account enumeration");
            writeln!(file, "=== User Account Enumeration (/etc/passwd) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(passwd_file) = File::open("/etc/passwd") {
                let reader = BufReader::new(passwd_file);
                for line in reader.lines().map_while(Result::ok) {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 7 {
                        user_count += 1;
                        let username = parts[0];
                        let uid = parts[2];
                        let home = parts[5];
                        let shell = parts[6];
                        writeln!(file,"User: {username} | UID: {uid} | Home: {home} | Shell: {shell}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                }
            } else {
                writeln!(file, "Could not access /etc/passwd")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Package enumeration
            info!("Enumerating installed packages");
            writeln!(file, "=== Installed Package Enumeration ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Try dpkg for Debian/Ubuntu
            writeln!(file, "--- Debian/Ubuntu Packages (dpkg) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            if let Ok(dpkg_output) = Command::new("dpkg").arg("-l").output().await {
                if dpkg_output.status.success() {
                    let output_str = String::from_utf8_lossy(&dpkg_output.stdout);
                    let pkg_lines: Vec<&str> = output_str.lines()
                        .filter(|line| line.starts_with("ii"))
                        .collect();
                    package_count += pkg_lines.len();
                    file.write_all(&dpkg_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "dpkg not available or failed")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            
            // Try rpm for RHEL/CentOS
            writeln!(file, "--- RHEL/CentOS Packages (rpm) ---")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            if let Ok(rpm_output) = Command::new("rpm").arg("-qa").output().await {
                if rpm_output.status.success() {
                    let output_str = String::from_utf8_lossy(&rpm_output.stdout);
                    let rpm_count = output_str.lines().count();
                    if rpm_count > 0 {
                        package_count = rpm_count;
                    }
                    file.write_all(&rpm_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                } else {
                    writeln!(file, "rpm not available or failed")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Security tool detection
            info!("Detecting security tools");
            writeln!(file, "=== Security Tool Detection ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            let security_tools = vec![
                ("falcon-sensor", "CrowdStrike Falcon"),
                ("cb-defense", "Carbon Black Defense"),
                ("cbagentd", "Carbon Black Agent"),
                ("wazuh-agent", "Wazuh Agent"),
                ("osqueryd", "osquery"),
                ("auditd", "Linux Audit Daemon"),
            ];
            
            for (process_name, tool_name) in &security_tools {
                // Check running processes
                if let Ok(ps_output) = Command::new("pgrep").arg("-f").arg(process_name).output().await {
                    if ps_output.status.success() && !ps_output.stdout.is_empty() {
                        let pids = String::from_utf8_lossy(&ps_output.stdout).trim().to_string();
                        writeln!(file,"DETECTED: {tool_name} (process: {process_name}) - PIDs: {pids}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        security_tools_detected.push(tool_name.to_string());
                        continue;
                    }
                }
                
                // Check for binary files
                let paths = vec![
                    format!("/usr/bin/{process_name}"),
                    format!("/usr/sbin/{process_name}"),
                    format!("/opt/{process_name}"),
                ];
                
                for path in paths {
                    if Path::new(&path).exists() {
                        writeln!(file,"DETECTED: {tool_name} (binary: {path})")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        security_tools_detected.push(tool_name.to_string());
                        break;
                    }
                }
            }
            
            if security_tools_detected.is_empty() {
                writeln!(file, "No known security tools detected")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // CPU information from /proc/cpuinfo
            info!("Reading detailed CPU information from /proc/cpuinfo");
            writeln!(file, "=== Detailed CPU Information (/proc/cpuinfo) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                file.write_all(cpuinfo.as_bytes())
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            } else {
                writeln!(file, "Could not access /proc/cpuinfo")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Memory information from /proc/meminfo
            info!("Reading detailed memory information from /proc/meminfo");
            writeln!(file, "=== Detailed Memory Information (/proc/meminfo) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
                file.write_all(meminfo.as_bytes())
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            } else {
                writeln!(file, "Could not access /proc/meminfo")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Kernel modules
            info!("Enumerating loaded kernel modules");
            writeln!(file, "=== Loaded Kernel Modules (lsmod) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(lsmod_output) = Command::new("lsmod").output().await {
                file.write_all(&lsmod_output.stdout)
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            } else {
                writeln!(file, "Could not execute lsmod")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Containerisation detection
            info!("Checking for containerisation markers");
            writeln!(file, "=== Containerisation Detection (/proc/1/cgroup) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
                let is_docker = cgroup.contains("docker");
                let is_kubernetes = cgroup.contains("kubepods");
                let is_containerd = cgroup.contains("containerd");
                
                writeln!(file, "Docker: {}", if is_docker { "DETECTED" } else { "Not detected" })
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                writeln!(file, "Kubernetes: {}", if is_kubernetes { "DETECTED" } else { "Not detected" })
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                writeln!(file, "containerd: {}", if is_containerd { "DETECTED" } else { "Not detected" })
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                writeln!(file, "\nFull cgroup content:")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                file.write_all(cgroup.as_bytes())
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            } else {
                writeln!(file, "Could not access /proc/1/cgroup")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Execute standard commands
            for cmd in &commands {
                let cmd = cmd.trim();
                let cmd_parts: Vec<&str> = cmd.split_whitespace().collect();
                
                if cmd_parts.is_empty() {
                    continue;
                }
                
                let program = cmd_parts[0];
                let args = &cmd_parts[1..];
                
                info!("Executing system discovery command: {cmd}");
                
                writeln!(file, "=== Command: {cmd} ===")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                
                let output = Command::new(program)
                    .args(args)
                    .output()
                    .await;
                
                match output {
                    Ok(output) => {
                        writeln!(file, "Exit Code: {}", output.status.code().unwrap_or(-1))
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        writeln!(file, "Stdout:")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        file.write_all(&output.stdout)
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        writeln!(file, "Stderr:")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        file.write_all(&output.stderr)
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    },
                    Err(e) => {
                        writeln!(file, "Error executing command: {e}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                }
                
                writeln!(file)
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            info!("Comprehensive system enumeration complete - Users: {}, Packages: {}, Security tools detected: {}", 
                  user_count, package_count, security_tools_detected.len());
            
            let security_tools_msg = if security_tools_detected.is_empty() {
                "none".to_string()
            } else {
                security_tools_detected.join(", ")
            };
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Comprehensive system enumeration: {user_count} user accounts, {package_count} packages, security tools detected: {security_tools_msg}"),
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
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}
pub struct NetworkConnectionsDiscovery {}

#[async_trait]
impl AttackTechnique for NetworkConnectionsDiscovery {
    fn info(&self) -> Technique {
        Technique {
            id: "T1049".to_string(),
            name: "System Network Connections Discovery".to_string(),
            description: "Executes real-time network connection enumeration via netstat, ss, and lsof to discover active TCP/UDP connections, listening ports, process-to-socket mappings, and foreign addresses. Generates significant process execution telemetry detectable by EDRs.".to_string(),
            category: "discovery".to_string(),
            parameters: vec![],
            detection: "Monitor for execution of netstat -antp, ss -tulpn, lsof -i, and other network enumeration commands. Detect abnormal process execution patterns for network reconnaissance. Watch for rapid sequential network tool invocations.".to_string(),
            cleanup_support: false,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        _config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            // Generate session ID for unique log filename
            let session_id = uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("unknown").to_string();
            let output_file = format!("/tmp/signalbench_network_connections_{session_id}.log");
            
            if dry_run {
                info!("[DRY RUN] Would execute real-time network connection enumeration: netstat -antp, ss -tulpn, lsof -i -n -P, netstat -rn");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would execute real-time network connection discovery".to_string(),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            // Counters for CLI output
            let mut total_connections = 0;
            let mut listening_ports = 0;
            let mut established_connections = 0;
            let mut suspicious_patterns: Vec<String> = Vec::new();
            
            // Create the output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
            
            // Write header to file
            writeln!(file, "=== SignalBench Real-time Network Connections Discovery (T1049) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Session ID: {session_id}")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Hostname: {}", hostname::get().unwrap_or_default().to_string_lossy())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // REAL NETWORK ENUMERATION 1: netstat -antp (All TCP connections with process info)
            info!("Executing netstat -antp for TCP connections with process information");
            writeln!(file, "=== TCP Connections with Process Information (netstat -antp) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(netstat_tcp_output) = Command::new("netstat").args(["-antp"]).output().await {
                if netstat_tcp_output.status.success() {
                    let output_str = String::from_utf8_lossy(&netstat_tcp_output.stdout);
                    
                    // Parse and categorize connections
                    writeln!(file, "Raw Output:")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    file.write_all(&netstat_tcp_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    // Parse connections
                    writeln!(file, "\n--- Parsed TCP Connections by State ---")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    let mut established = Vec::new();
                    let mut listen = Vec::new();
                    let mut time_wait = Vec::new();
                    let mut other_states = Vec::new();
                    
                    for line in output_str.lines().skip(2) {
                        if line.trim().is_empty() || line.starts_with("Proto") {
                            continue;
                        }
                        
                        total_connections += 1;
                        
                        if line.contains("ESTABLISHED") {
                            established.push(line.to_string());
                            established_connections += 1;
                        } else if line.contains("LISTEN") {
                            listen.push(line.to_string());
                            listening_ports += 1;
                        } else if line.contains("TIME_WAIT") {
                            time_wait.push(line.to_string());
                        } else if line.contains("tcp") {
                            other_states.push(line.to_string());
                        }
                    }
                    
                    // Output categorised connections
                    writeln!(file, "\nESTABLISHED Connections ({}):", established.len())
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    for conn in &established {
                        writeln!(file, "  {conn}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        
                        // Check for suspicious patterns (connections to unusual ports)
                        if conn.contains(":22 ") || conn.contains(":3389 ") || conn.contains(":4444 ") {
                            suspicious_patterns.push(format!("Suspicious ESTABLISHED connection: {conn}"));
                        }
                    }
                    
                    writeln!(file, "\nLISTENING Ports ({}):", listen.len())
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    for conn in &listen {
                        writeln!(file, "  {conn}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        
                        // Check for suspicious listening ports
                        if conn.contains(":1337 ") || conn.contains(":31337 ") || conn.contains(":4444 ") || conn.contains(":5555 ") {
                            suspicious_patterns.push(format!("Suspicious LISTEN port: {conn}"));
                        }
                    }
                    
                    writeln!(file, "\nTIME_WAIT Connections ({}):", time_wait.len())
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    for conn in &time_wait {
                        writeln!(file, "  {conn}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    }
                    
                    if !other_states.is_empty() {
                        writeln!(file, "\nOther TCP States ({}):", other_states.len())
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        for conn in &other_states {
                            writeln!(file, "  {conn}")
                                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&netstat_tcp_output.stderr);
                    writeln!(file, "netstat -antp failed: {stderr}")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    info!("netstat -antp failed (may require elevated privileges)");
                }
            } else {
                writeln!(file, "netstat command not available")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // REAL NETWORK ENUMERATION 2: ss -tulpn (TCP/UDP listening sockets with process names)
            info!("Executing ss -tulpn for TCP/UDP listening sockets with process names");
            writeln!(file, "=== TCP/UDP Listening Sockets with Process Names (ss -tulpn) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(ss_output) = Command::new("ss").args(["-tulpn"]).output().await {
                if ss_output.status.success() {
                    let output_str = String::from_utf8_lossy(&ss_output.stdout);
                    
                    writeln!(file, "Raw Output:")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    file.write_all(&ss_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    // Parse process-to-socket mappings
                    writeln!(file, "\n--- Process-to-Socket Mappings ---")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    for line in output_str.lines().skip(1) {
                        if line.trim().is_empty() || line.starts_with("Netid") {
                            continue;
                        }
                        
                        // Extract process information if available
                        if line.contains("users:") {
                            writeln!(file, "  {line}")
                                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&ss_output.stderr);
                    writeln!(file, "ss -tulpn failed: {stderr}")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    info!("ss -tulpn failed (may require elevated privileges)");
                }
            } else {
                writeln!(file, "ss command not available")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // REAL NETWORK ENUMERATION 3: lsof -i -n -P (Open network connections)
            info!("Executing lsof -i -n -P for open network connections");
            writeln!(file, "=== Open Network Connections (lsof -i -n -P) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(lsof_output) = Command::new("lsof").args(["-i", "-n", "-P"]).output().await {
                if lsof_output.status.success() {
                    let output_str = String::from_utf8_lossy(&lsof_output.stdout);
                    
                    writeln!(file, "Raw Output:")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    file.write_all(&lsof_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    // Parse by process
                    writeln!(file, "\n--- Connections Grouped by Process ---")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    let mut process_connections: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
                    
                    for line in output_str.lines().skip(1) {
                        if line.trim().is_empty() || line.starts_with("COMMAND") {
                            continue;
                        }
                        
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let process_key = format!("{} (PID: {})", parts[0], parts[1]);
                            process_connections.entry(process_key)
                                .or_default()
                                .push(line.to_string());
                        }
                    }
                    
                    for (process, connections) in &process_connections {
                        writeln!(file, "\nProcess: {process}")
                            .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        for conn in connections {
                            writeln!(file, "  {conn}")
                                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&lsof_output.stderr);
                    writeln!(file, "lsof -i -n -P failed: {stderr}")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    info!("lsof -i -n -P failed (may require elevated privileges)");
                }
            } else {
                writeln!(file, "lsof command not available")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // REAL NETWORK ENUMERATION 4: netstat -rn (Routing table)
            info!("Executing netstat -rn for routing table enumeration");
            writeln!(file, "=== Routing Table (netstat -rn) ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            if let Ok(netstat_route_output) = Command::new("netstat").args(["-rn"]).output().await {
                if netstat_route_output.status.success() {
                    let output_str = String::from_utf8_lossy(&netstat_route_output.stdout);
                    
                    writeln!(file, "Raw Output:")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    file.write_all(&netstat_route_output.stdout)
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    // Highlight default routes
                    writeln!(file, "\n--- Default Routes ---")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                    
                    for line in output_str.lines() {
                        if line.starts_with("0.0.0.0") || line.contains("default") {
                            writeln!(file, "  DEFAULT ROUTE: {line}")
                                .map_err(|e| format!("Failed to write to output file: {e}"))?;
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&netstat_route_output.stderr);
                    writeln!(file, "netstat -rn failed: {stderr}")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
            } else {
                writeln!(file, "netstat command not available")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // SUSPICIOUS PATTERNS SUMMARY
            if !suspicious_patterns.is_empty() {
                writeln!(file, "=== SUSPICIOUS PATTERNS DETECTED ===")
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
                for pattern in &suspicious_patterns {
                    writeln!(file, "  ⚠️  {pattern}")
                        .map_err(|e| format!("Failed to write to output file: {e}"))?;
                }
                writeln!(file)
                    .map_err(|e| format!("Failed to write to output file: {e}"))?;
            }
            
            // STATISTICS SUMMARY
            writeln!(file, "=== CONNECTION STATISTICS ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Total TCP Connections: {total_connections}")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Listening Ports: {listening_ports}")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Established Sessions: {established_connections}")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Suspicious Patterns: {}", suspicious_patterns.len())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            info!("Network connection discovery complete - Total: {}, Listening: {}, Established: {}, Suspicious: {}", 
                  total_connections, listening_ports, established_connections, suspicious_patterns.len());
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Network connections discovery: {} total, {} listening, {} established, {} suspicious patterns", 
                                total_connections, listening_ports, established_connections, suspicious_patterns.len()),
                artifacts: vec![output_file],
                cleanup_required: false,
            })
        })
    }

    fn cleanup<'a>(&'a self, _artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // No cleanup needed - read-only enumeration
            Ok(())
        })
    }
}
