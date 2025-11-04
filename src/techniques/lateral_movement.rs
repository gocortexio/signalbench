use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::{Write, Read};
use std::path::Path;
use tokio::process::Command;
use uuid::Uuid;

pub struct SshLateralMovement {}

#[async_trait]
impl AttackTechnique for SshLateralMovement {
    fn info(&self) -> Technique {
        Technique {
            id: "T1021.004".to_string(),
            name: "SSH Lateral Movement - AGGRESSIVE".to_string(),
            description: "AGGRESSIVE: Performs REAL SSH lateral movement by generating an RSA key pair, modifying ~/.ssh/authorized_keys, and executing genuine SSH connections to localhost (127.0.0.1). Executes multiple commands via SSH including whoami, uname, hostname, env, and id. Attempts SSH port forwarding (-L) and dynamic tunnelling (-D) to simulate advanced lateral movement tactics. Generates authentic SSH connection logs and authorized_keys modifications detectable by EDR/XDR systems. Includes comprehensive backup and restore of authorized_keys.".to_string(),
            category: "lateral_movement".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save detailed SSH lateral movement execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_ssh_lateral_movement.log".to_string()),
                },
                TechniqueParameter {
                    name: "commands".to_string(),
                    description: "Comma-separated list of commands to execute via SSH".to_string(),
                    required: false,
                    default: Some("whoami,uname -a,hostname,id,env".to_string()),
                },
            ],
            detection: "Monitor for SSH key generation (ssh-keygen), authorized_keys file modifications, SSH connections to localhost/127.0.0.1, rapid succession of SSH connection attempts, SSH port forwarding attempts (-L/-D flags), unusual command execution patterns via SSH, and systematic credential-based lateral movement".to_string(),
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
                .unwrap_or(&"/tmp/signalbench_ssh_lateral_movement.log".to_string())
                .clone();
                
            let commands_str = config
                .parameters
                .get("commands")
                .unwrap_or(&"whoami,uname -a,hostname,id,env".to_string())
                .clone();
            
            let session_id = Uuid::new_v4().to_string().split('-').next().unwrap_or("default").to_string();
            let key_dir = format!("/tmp/signalbench_ssh_lateral_{session_id}");
            let private_key = format!("{key_dir}/id_rsa");
            let public_key = format!("{key_dir}/id_rsa.pub");
            
            let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let ssh_dir = format!("{home_dir}/.ssh");
            let authorized_keys = format!("{ssh_dir}/authorized_keys");
            let authorized_keys_backup = format!("{ssh_dir}/authorized_keys.signalbench_backup_{session_id}");
            
            let current_user = std::env::var("USER").unwrap_or_else(|_| "runner".to_string());
            
            if dry_run {
                info!("[DRY RUN] Would generate SSH key pair in: {key_dir}");
                info!("[DRY RUN] Would backup authorized_keys to: {authorized_keys_backup}");
                info!("[DRY RUN] Would execute REAL SSH connections to {current_user}@127.0.0.1");
                info!("[DRY RUN] Would execute commands: {commands_str}");
                info!("[DRY RUN] Would attempt SSH port forwarding and tunnelling");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform REAL SSH lateral movement with key generation and authorized_keys modification".to_string(),
                    artifacts: vec![log_file, key_dir.clone(), authorized_keys_backup],
                    cleanup_required: false,
                });
            }

            info!("Starting AGGRESSIVE SSH lateral movement technique...");
            info!("Session ID: {session_id}");
            
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench AGGRESSIVE SSH Lateral Movement ===").unwrap();
            writeln!(log, "Session ID: {session_id}").unwrap();
            writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "Target User: {current_user}@127.0.0.1").unwrap();
            writeln!(log).unwrap();
            
            let mut artifacts = vec![log_file.clone(), key_dir.clone()];
            
            // Step 1: Generate SSH key pair
            info!("Step 1: Generating SSH key pair...");
            writeln!(log, "=== Step 1: SSH Key Generation ===").unwrap();
            
            fs::create_dir_all(&key_dir)
                .map_err(|e| format!("Failed to create key directory: {e}"))?;
            
            let keygen_output = Command::new("ssh-keygen")
                .args([
                    "-t", "rsa",
                    "-b", "2048",
                    "-f", &private_key,
                    "-N", "",
                    "-C", &format!("signalbench_lateral_{session_id}")
                ])
                .output()
                .await
                .map_err(|e| format!("Failed to generate SSH key: {e}"))?;
            
            writeln!(log, "ssh-keygen exit code: {}", keygen_output.status.code().unwrap_or(-1)).unwrap();
            writeln!(log, "ssh-keygen output: {}", String::from_utf8_lossy(&keygen_output.stdout)).unwrap();
            if !keygen_output.stderr.is_empty() {
                writeln!(log, "ssh-keygen stderr: {}", String::from_utf8_lossy(&keygen_output.stderr)).unwrap();
            }
            
            if !keygen_output.status.success() {
                return Err(format!("SSH key generation failed: {}", String::from_utf8_lossy(&keygen_output.stderr)));
            }
            
            info!("Generated SSH key pair: {private_key}, {public_key}");
            writeln!(log, "Generated key pair: {private_key}, {public_key}").unwrap();
            writeln!(log).unwrap();
            
            // Step 2: Backup and modify authorized_keys
            info!("Step 2: Modifying authorized_keys...");
            writeln!(log, "=== Step 2: Authorized Keys Modification ===").unwrap();
            
            fs::create_dir_all(&ssh_dir)
                .map_err(|e| format!("Failed to create .ssh directory: {e}"))?;
            
            // Set proper permissions on .ssh directory (700)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("Failed to set permissions on .ssh directory: {e}"))?;
            }
            
            // Backup existing authorized_keys if it exists
            if Path::new(&authorized_keys).exists() {
                fs::copy(&authorized_keys, &authorized_keys_backup)
                    .map_err(|e| format!("Failed to backup authorized_keys: {e}"))?;
                info!("Backed up authorized_keys to: {authorized_keys_backup}");
                writeln!(log, "Backed up existing authorized_keys to: {authorized_keys_backup}").unwrap();
                artifacts.push(authorized_keys_backup.clone());
            } else {
                writeln!(log, "No existing authorized_keys file found").unwrap();
            }
            
            // Read the public key
            let mut pub_key_content = String::new();
            File::open(&public_key)
                .and_then(|mut f| f.read_to_string(&mut pub_key_content))
                .map_err(|e| format!("Failed to read public key: {e}"))?;
            
            // Append public key to authorized_keys
            let mut auth_keys_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&authorized_keys)
                .map_err(|e| format!("Failed to open authorized_keys: {e}"))?;
            
            writeln!(auth_keys_file, "{}", pub_key_content.trim())
                .map_err(|e| format!("Failed to write to authorized_keys: {e}"))?;
            
            // Set proper permissions on authorized_keys (600)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("Failed to set permissions on authorized_keys: {e}"))?;
            }
            
            info!("Appended public key to authorized_keys");
            writeln!(log, "Appended public key to: {authorized_keys}").unwrap();
            writeln!(log, "Set permissions to 600 on authorized_keys").unwrap();
            writeln!(log).unwrap();
            
            // Step 3: Execute REAL SSH connections
            info!("Step 3: Executing REAL SSH connections to 127.0.0.1...");
            writeln!(log, "=== Step 3: SSH Connection Attempts ===").unwrap();
            
            let commands: Vec<&str> = commands_str.split(',').collect();
            let mut successful_connections = 0;
            
            // Execute each command via SSH
            for (idx, cmd) in commands.iter().enumerate() {
                let cmd = cmd.trim();
                if cmd.is_empty() {
                    continue;
                }
                
                info!("Executing command {}: {cmd}", idx + 1);
                writeln!(log, "--- Command {} ---", idx + 1).unwrap();
                writeln!(log, "Command: {cmd}").unwrap();
                
                let ssh_cmd = format!(
                    "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -i {private_key} {current_user}@127.0.0.1 '{cmd}'"
                );
                
                let output = Command::new("bash")
                    .args(["-c", &ssh_cmd])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to execute SSH command: {e}"))?;
                
                writeln!(log, "Exit code: {}", output.status.code().unwrap_or(-1)).unwrap();
                writeln!(log, "Stdout:\n{}", String::from_utf8_lossy(&output.stdout)).unwrap();
                if !output.stderr.is_empty() {
                    writeln!(log, "Stderr:\n{}", String::from_utf8_lossy(&output.stderr)).unwrap();
                }
                
                if output.status.success() {
                    successful_connections += 1;
                    writeln!(log, "Result: SUCCESS").unwrap();
                } else {
                    writeln!(log, "Result: FAILED").unwrap();
                }
                writeln!(log).unwrap();
            }
            
            // Step 4: Attempt SSH port forwarding
            info!("Step 4: Attempting SSH port forwarding (-L)...");
            writeln!(log, "=== Step 4: SSH Port Forwarding Attempt ===").unwrap();
            
            let port_forward_cmd = format!(
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -i {private_key} -L 8080:localhost:80 -N -f {current_user}@127.0.0.1 && sleep 1 && pkill -f 'ssh.*-L 8080:localhost:80'"
            );
            
            let pf_output = Command::new("bash")
                .args(["-c", &port_forward_cmd])
                .output()
                .await
                .map_err(|e| format!("Failed to execute port forwarding: {e}"))?;
            
            writeln!(log, "Port forwarding command: ssh -L 8080:localhost:80").unwrap();
            writeln!(log, "Exit code: {}", pf_output.status.code().unwrap_or(-1)).unwrap();
            writeln!(log, "Stdout: {}", String::from_utf8_lossy(&pf_output.stdout)).unwrap();
            if !pf_output.stderr.is_empty() {
                writeln!(log, "Stderr: {}", String::from_utf8_lossy(&pf_output.stderr)).unwrap();
            }
            writeln!(log).unwrap();
            
            // Step 5: Attempt SSH dynamic tunnelling
            info!("Step 5: Attempting SSH dynamic tunnelling (-D)...");
            writeln!(log, "=== Step 5: SSH Dynamic Tunnelling Attempt ===").unwrap();
            
            let tunnel_cmd = format!(
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -i {private_key} -D 1080 -N -f {current_user}@127.0.0.1 && sleep 1 && pkill -f 'ssh.*-D 1080'"
            );
            
            let tunnel_output = Command::new("bash")
                .args(["-c", &tunnel_cmd])
                .output()
                .await
                .map_err(|e| format!("Failed to execute dynamic tunnelling: {e}"))?;
            
            writeln!(log, "Dynamic tunnelling command: ssh -D 1080").unwrap();
            writeln!(log, "Exit code: {}", tunnel_output.status.code().unwrap_or(-1)).unwrap();
            writeln!(log, "Stdout: {}", String::from_utf8_lossy(&tunnel_output.stdout)).unwrap();
            if !tunnel_output.stderr.is_empty() {
                writeln!(log, "Stderr: {}", String::from_utf8_lossy(&tunnel_output.stderr)).unwrap();
            }
            writeln!(log).unwrap();
            
            writeln!(log, "=== Summary ===").unwrap();
            writeln!(log, "Total commands executed: {}", commands.len()).unwrap();
            writeln!(log, "Successful connections: {successful_connections}").unwrap();
            writeln!(log, "Artifacts generated: {}", artifacts.len()).unwrap();
            writeln!(log, "Log file: {log_file}").unwrap();
            
            info!("SSH lateral movement technique complete!");
            info!("Successful SSH connections: {successful_connections}/{}", commands.len());
            info!("Artifacts: {}", artifacts.join(", "));
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Successfully executed AGGRESSIVE SSH lateral movement: generated key pair, modified authorized_keys, executed {} commands via SSH ({} successful), attempted port forwarding and tunnelling",
                    commands.len(), successful_connections
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting comprehensive cleanup of SSH lateral movement artifacts...");
            
            let mut key_dir: Option<String> = None;
            let mut backup_file: Option<String> = None;
            let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let authorized_keys = format!("{home_dir}/.ssh/authorized_keys");
            
            // Identify key directory and backup file from artifacts
            for artifact in artifacts {
                if artifact.contains("/signalbench_ssh_lateral_") && !artifact.contains(".log") && Path::new(artifact).is_dir() {
                    key_dir = Some(artifact.clone());
                }
                if artifact.contains("authorized_keys.signalbench_backup_") {
                    backup_file = Some(artifact.clone());
                }
            }
            
            // Step 1: Remove appended key from authorized_keys
            if let Some(backup) = &backup_file {
                if Path::new(backup).exists() {
                    info!("Restoring authorized_keys from backup: {backup}");
                    match fs::copy(backup, &authorized_keys) {
                        Ok(_) => {
                            info!("Successfully restored authorized_keys");
                            
                            // Set proper permissions (600)
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                if let Err(e) = fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600)) {
                                    warn!("Failed to set permissions on restored authorized_keys: {e}");
                                }
                            }
                            
                            // Remove backup file
                            match fs::remove_file(backup) {
                                Ok(_) => info!("Removed backup file: {backup}"),
                                Err(e) => warn!("Failed to remove backup file {backup}: {e}"),
                            }
                        }
                        Err(e) => warn!("Failed to restore authorized_keys from backup: {e}"),
                    }
                }
            } else {
                // If no backup exists, we need to manually remove the appended key
                if Path::new(&authorized_keys).exists() {
                    info!("No backup found, attempting to remove appended key from authorized_keys");
                    
                    if let Ok(content) = fs::read_to_string(&authorized_keys) {
                        let filtered: Vec<&str> = content
                            .lines()
                            .filter(|line| !line.contains("signalbench_lateral_"))
                            .collect();
                        
                        if let Ok(mut file) = File::create(&authorized_keys) {
                            for line in filtered {
                                let _ = writeln!(file, "{line}");
                            }
                            info!("Removed SignalBench key from authorized_keys");
                            
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600));
                            }
                        }
                    }
                }
            }
            
            // Step 2: Delete key directory and all contents
            if let Some(dir) = key_dir {
                if Path::new(&dir).exists() {
                    match fs::remove_dir_all(&dir) {
                        Ok(_) => info!("Removed key directory: {dir}"),
                        Err(e) => warn!("Failed to remove key directory {dir}: {e}"),
                    }
                }
            }
            
            // Step 3: Clean up remaining artifacts (log files, etc.)
            for artifact in artifacts {
                if artifact.ends_with(".log") && Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed log file: {artifact}"),
                        Err(e) => warn!("Failed to remove log file {artifact}: {e}"),
                    }
                }
            }
            
            // Step 4: Verify authorized_keys restored
            if Path::new(&authorized_keys).exists() {
                if let Ok(content) = fs::read_to_string(&authorized_keys) {
                    if content.contains("signalbench_lateral_") {
                        warn!("Warning: authorized_keys may still contain SignalBench key!");
                    } else {
                        info!("Verified: authorized_keys does not contain SignalBench key");
                    }
                }
            }
            
            info!("SSH lateral movement cleanup complete");
            Ok(())
        })
    }
}
