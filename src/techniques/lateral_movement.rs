use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;

pub struct SshLateralMovement {}

#[async_trait]
impl AttackTechnique for SshLateralMovement {
    fn info(&self) -> Technique {
        Technique {
            id: "T1021.004".to_string(),
            name: "SSH Lateral Movement".to_string(),
            description: "Generates telemetry for SSH lateral movement activities".to_string(),
            category: "lateral_movement".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_hosts".to_string(),
                    description: "Comma-separated list of target hosts to attempt connection".to_string(),
                    required: false,
                    default: Some("localhost,127.0.0.1".to_string()),
                },
                TechniqueParameter {
                    name: "username".to_string(),
                    description: "Username to use for SSH attempt".to_string(),
                    required: false,
                    default: Some("root".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save lateral movement attempts log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_ssh_lateral_movement".to_string()),
                },
            ],
            detection: "Monitor for multiple SSH connections in short succession".to_string(),
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
            let targets_str = config
                .parameters
                .get("target_hosts")
                .unwrap_or(&"localhost,127.0.0.1".to_string())
                .clone();
                
            let username = config
                .parameters
                .get("username")
                .unwrap_or(&"root".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_ssh_lateral_movement".to_string())
                .clone();
                
            let targets: Vec<&str> = targets_str.split(',').collect();
            let target_count = targets.len();
            
            if dry_run {
                info!("[DRY RUN] Would attempt SSH lateral movement to hosts: {targets_str}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would attempt SSH connections to {target_count} targets"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create the log file
            let mut file = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            // Write header to file
            writeln!(file, "=== SignalBench SSH Lateral Movement ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "Username: {username}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Attempt connection to each target
            let mut success_count = 0;
            
            for target in &targets {
                let target = target.trim();
                if target.is_empty() {
                    continue;
                }
                
                info!("Attempting SSH connection to {username}@{target}");
                
                writeln!(file, "=== Target: {target} ===")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
                // We'll use a command with a 1-second timeout to avoid hanging
                let cmd = format!("ssh -o ConnectTimeout=1 -o BatchMode=yes -o StrictHostKeyChecking=no -o PasswordAuthentication=no {username}@{target} 'echo SIGNALBENCH_CONNECTION_TEST'");
                
                let output = Command::new("bash")
                    .args(["-c", &cmd])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to execute SSH command: {e}"))?;
                
                writeln!(file, "Exit Code: {}", output.status.code().unwrap_or(-1))
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                writeln!(file, "Stdout:")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                file.write_all(&output.stdout)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                writeln!(file, "Stderr:")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                file.write_all(&output.stderr)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
                if output.status.success() {
                    success_count += 1;
                    writeln!(file, "Result: SUCCESS")
                        .map_err(|e| format!("Failed to write to log file: {e}"))?;
                } else {
                    writeln!(file, "Result: FAILED")
                        .map_err(|e| format!("Failed to write to log file: {e}"))?;
                }
                
                writeln!(file)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
            }
            
            info!("SSH lateral movement simulation complete, successful connections: {success_count}/{target_count}");
            info!("Log saved to: {log_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true, // Simulation is successful even if the connections fail
                message: format!("Successfully performed SSH lateral movement to {target_count} targets, {success_count} successful connections"),
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