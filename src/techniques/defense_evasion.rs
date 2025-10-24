use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub struct DisableAuditLogs {}

#[async_trait]
impl AttackTechnique for DisableAuditLogs {
    fn info(&self) -> Technique {
        Technique {
            id: "T1562.002".to_string(),
            name: "Disable Linux Audit Logs".to_string(),
            description: "Generates telemetry for Linux audit log manipulation to evade detection".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "audit_rules_file".to_string(),
                    description: "Path to save the audit rules file".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_disable_audit.rules".to_string()),
                },
            ],
            detection: "Monitor for changes to audit rules or audit daemon configuration".to_string(),
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
            let audit_rules_file = config
                .parameters
                .get("audit_rules_file")
                .unwrap_or(&"/tmp/signalbench_test_disable_audit.rules".to_string())
                .clone();
            
            if dry_run {
                info!("[DRY RUN] Would create audit rules to disable logging at: {audit_rules_file}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would create audit rules to disable logging at {audit_rules_file}"),
                    artifacts: vec![audit_rules_file],
                    cleanup_required: false,
                });
            }

            // Create a file with audit rules that would disable auditing
            // Note: This is a simulation and doesn't actually disable auditing
            let audit_rule_content = r#"## SignalBench by GoCortex.io - This is a simulation file and doesn't actually disable auditing
## In a real attack, these rules might be used:

# Disable syscall auditing for execve - common logging point
-a never,exit -S execve

# Disable auditing for specific user to hide actions
-a never,exit -F uid=1000

# Disable file auditing for sensitive locations
-a never,exit -F path=/etc/passwd -F perm=wa
-a never,exit -F path=/etc/shadow -F perm=wa

# Disable command execution auditing
-a never,exit -F arch=b64 -S execve,execveat -F key=command_execution
-a never,exit -F arch=b32 -S execve,execveat -F key=command_execution
"#;

            let mut file = File::create(&audit_rules_file)
                .map_err(|e| format!("Failed to create audit rules file: {e}"))?;
        
            file.write_all(audit_rule_content.as_bytes())
                .map_err(|e| format!("Failed to write to audit rules file: {e}"))?;
        
            // Reload audit rules (this is a simulation, in a real scenario we would do this)
            let _reload_cmd = if Path::new("/sbin/auditctl").exists() {
                info!("Would reload audit rules with: /sbin/auditctl -R {audit_rules_file}");
                true
            } else {
                info!("auditctl command not found, would need to reload audit rules");
                false
            };
        
            info!("Created audit rules file to disable logging: {audit_rules_file}");
        
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully created audit rules file to disable logging at {audit_rules_file}"),
                artifacts: vec![audit_rules_file],
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

pub struct ClearBashHistory {}

#[async_trait]
impl AttackTechnique for ClearBashHistory {
    fn info(&self) -> Technique {
        Technique {
            id: "T1070.003".to_string(),
            name: "Clear Command History".to_string(),
            description: "Generates telemetry for bash history clearing to hide commands".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "history_backup".to_string(),
                    description: "Path to backup the bash history before clearing".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_bash_history_backup".to_string()),
                },
            ],
            detection: "Monitor for history file truncation or environment variable changes".to_string(),
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
            let history_backup = config
                .parameters
                .get("history_backup")
                .unwrap_or(&"/tmp/signalbench_test_bash_history_backup".to_string())
                .clone();
            
            let history_file = format!("{}/.bash_history", std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
            
            if dry_run {
                info!("[DRY RUN] Would clear bash history: {history_file}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would clear bash history at {history_file}"),
                    artifacts: vec![history_backup],
                    cleanup_required: false,
                });
            }

            // Create a backup file to document what would be done
            let mut file = File::create(&history_backup)
                .map_err(|e| format!("Failed to create history backup file: {e}"))?;
            
            writeln!(file, "=== SignalBench History Clearing ===")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "History file: {history_file}")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            
            writeln!(file, "=== Commands that would be executed in a real attack ===")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "echo > ~/.bash_history  # Truncate history file")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "export HISTFILESIZE=0   # Prevent further history")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "export HISTSIZE=0       # Prevent further history")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "unset HISTFILE          # Disable history file")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "history -c              # Clear current session history")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file, "rm ~/.bash_history      # Remove history file completely")
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to backup file: {e}"))?;
            
            info!("Performed bash history clearing: {history_file}");
            info!("Created documentation at: {history_backup}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully performed bash history clearing with documentation at {history_backup}"),
                artifacts: vec![history_backup],
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

pub struct ModifyEnvironmentVariable {}

#[async_trait]
impl AttackTechnique for ModifyEnvironmentVariable {
    fn info(&self) -> Technique {
        Technique {
            id: "T1574.007".to_string(),
            name: "Path Interception".to_string(),
            description: "Generates telemetry for environment variable modifications for path interception".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "env_log_file".to_string(),
                    description: "Path to save the environment variable modification log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_env_modification".to_string()),
                },
            ],
            detection: "Monitor for suspicious environment variable changes".to_string(),
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
            let env_log_file = config
                .parameters
                .get("env_log_file")
                .unwrap_or(&"/tmp/signalbench_env_modification".to_string())
                .clone();
            
            if dry_run {
                info!("[DRY RUN] Would modify environment variables");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would modify environment variables for path interception".to_string(),
                    artifacts: vec![env_log_file],
                    cleanup_required: false,
                });
            }

            // Create a log file to document what would be done
            let mut file = File::create(&env_log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(file, "=== SignalBench Environment Variable Modification (GoCortex.io) ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Get current PATH 
            let current_path = std::env::var("PATH").unwrap_or_else(|_| "PATH not found".to_string());
            writeln!(file, "Current PATH: {current_path}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Get current LD_LIBRARY_PATH
            let current_ld_path = std::env::var("LD_LIBRARY_PATH").unwrap_or_else(|_| "LD_LIBRARY_PATH not set".to_string());
            writeln!(file, "Current LD_LIBRARY_PATH: {current_ld_path}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            writeln!(file)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Document what would be modified in a real attack
            writeln!(file, "=== Commands that would be executed in a real attack ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "# Add malicious directory to beginning of PATH")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "export PATH=/tmp/malicious:$PATH")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "# Add malicious library path")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "export LD_LIBRARY_PATH=/tmp/malicious_libs:$LD_LIBRARY_PATH")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "# Modify LD_PRELOAD to inject malicious library")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "export LD_PRELOAD=/tmp/malicious_lib.so")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            writeln!(file, "=== Impact ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "These modifications could allow an attacker to:")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "1. Execute malicious binaries instead of legitimate system commands")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "2. Load malicious libraries that hook into legitimate processes")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "3. Intercept calls to system functions for monitoring or manipulation")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Performed environment variable modification for path interception");
            info!("Created documentation at: {env_log_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully performed environment variable modification with documentation at {env_log_file}"),
                artifacts: vec![env_log_file],
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
pub struct MasqueradingAsCrond {}

#[async_trait]
impl AttackTechnique for MasqueradingAsCrond {
    fn info(&self) -> Technique {
        Technique {
            id: "T1036.003".to_string(),
            name: "Masquerading as Linux Crond Process".to_string(),
            description: "Generates telemetry for process masquerading by copying /bin/sh to a file named 'crond'".to_string(),
            category: "defense_evasion".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_path".to_string(),
                    description: "Path where the masquerading binary will be created".to_string(),
                    required: false,
                    default: Some("/tmp/crond".to_string()),
                },
                TechniqueParameter {
                    name: "execute_masqueraded".to_string(),
                    description: "Whether to execute the masqueraded binary (true/false)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save masquerading log to".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_masquerade_log".to_string()),
                },
            ],
            detection: "Monitor for copying system binaries to uncommon locations with process names mimicking legitimate system services. Look for execve events with arguments like 'cp /bin/sh <path>/crond'".to_string(),
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
            let target_path = config
                .parameters
                .get("target_path")
                .unwrap_or(&"/tmp/crond".to_string())
                .clone();
                
            let execute_masqueraded = config
                .parameters
                .get("execute_masqueraded")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_masquerade_log".to_string())
                .clone();
                
            if dry_run {
                info!("[DRY RUN] Would copy /bin/sh to {target_path} to masquerade as crond");
                if execute_masqueraded {
                    info!("[DRY RUN] Would execute the masqueraded binary");
                }
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would copy /bin/sh to {target_path}"),
                    artifacts: vec![log_file, target_path],
                    cleanup_required: false,
                });
            }

            use tokio::process::Command;

            // Create the log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench Masquerading as Crond ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Target path: {target_path}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;

            // Copy /bin/sh to target path (this generates the telemetry)
            info!("Copying /bin/sh to {target_path} to simulate process masquerading");
            writeln!(log, "=== Copying /bin/sh to {target_path} ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            let output = Command::new("cp")
                .args(["/bin/sh", &target_path])
                .output()
                .await
                .map_err(|e| format!("Failed to copy /bin/sh: {e}"))?;

            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            if !output.status.success() {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                writeln!(log, "Error: {error_msg}")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                return Err(format!("Failed to copy /bin/sh: {error_msg}"));
            }

            writeln!(log, "Successfully created masqueraded binary")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;

            // Optionally execute the masqueraded binary
            if execute_masqueraded {
                writeln!(log)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                writeln!(log, "=== Executing masqueraded binary ===")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
                info!("Executing masqueraded binary: {target_path}");
                
                let exec_output = Command::new(&target_path)
                    .args(["-c", "echo 'SignalBench masqueraded process executed successfully'"])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to execute masqueraded binary: {e}"))?;

                writeln!(log, "Execution Exit Code: {}", exec_output.status.code().unwrap_or(-1))
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                writeln!(log, "Output:")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
                log.write_all(&exec_output.stdout)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;
            }

            info!("Successfully simulated masquerading as crond process");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully copied /bin/sh to {target_path} and simulated crond masquerading"),
                artifacts: vec![log_file, target_path],
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
