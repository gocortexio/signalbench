use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;

pub struct NetworkDiscovery {}

#[async_trait]
impl AttackTechnique for NetworkDiscovery {
    fn info(&self) -> Technique {
        Technique {
            id: "T1016".to_string(),
            name: "System Network Configuration Discovery".to_string(),
            description: "Generates telemetry for network configuration discovery activities".to_string(),
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
            detection: "Monitor for multiple network information commands in short succession".to_string(),
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
            let cmd_count = commands.len();
            
            if dry_run {
                info!("[DRY RUN] Would collect network information using commands: {commands_str}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would collect network information using {cmd_count} commands"),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            // Create the output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
            
            // Write header to file
            writeln!(file, "=== SignalBench Network Discovery ===")
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to output file: {e}"))?;
            
            // Execute each command
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
            
            info!("Network discovery complete, results saved to: {output_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully collected network information using {cmd_count} commands"),
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
            description: "Generates telemetry for system information discovery activities".to_string(),
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
            detection: "Monitor for multiple system information commands in short succession".to_string(),
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
            let cmd_count = commands.len();
            
            if dry_run {
                info!("[DRY RUN] Would collect system information using commands: {commands_str}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would collect system information using {cmd_count} commands"),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            // Create the output file
            let mut file = File::create(&output_file)
                .map_err(|e| format!("Failed to create output file: {e}"))?;
            
            // Write header to file
            writeln!(file, "=== SignalBench System Information Discovery ===")
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
            
            // Execute each command
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
            
            info!("System information discovery complete, results saved to: {output_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully collected system information using {cmd_count} commands"),
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