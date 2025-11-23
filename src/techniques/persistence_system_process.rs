// SIGNALBENCH - System Process Persistence Techniques
// Create or Modify System Process (T1543)
// 
// This module implements system process creation and modification techniques
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use log::{debug, error, info};

// ======================================
// T1543 - Create or Modify System Process
// ======================================
pub struct CreateOrModifySystemProcess {}

#[async_trait]
impl AttackTechnique for CreateOrModifySystemProcess {
    fn info(&self) -> Technique {
        Technique {
            id: "T1543".to_string(),
            name: "Create or Modify System Process".to_string(),
            description: "Creates or modifies system services and processes for persistence".to_string(),
            category: "PERSISTENCE".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "technique".to_string(),
                    description: "Specific technique to use (systemd, init, rc)".to_string(),
                    required: false,
                    default: Some("systemd".to_string()),
                },
                TechniqueParameter {
                    name: "service_name".to_string(),
                    description: "Name for the service to create".to_string(),
                    required: false,
                    default: Some("signalbench-persistence".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory to save service files and artifacts".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_system_process".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_system_process.log".to_string()),
                },
                TechniqueParameter {
                    name: "install_service".to_string(),
                    description: "Whether to attempt installation of the service (requires root)".to_string(),
                    required: false,
                    default: Some("false".to_string()),
                },
            ],
            detection: "Monitor for creation or modification of system services and processes".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string(), "root".to_string()],
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
            let technique_type = config
                .parameters
                .get("technique")
                .unwrap_or(&"systemd".to_string())
                .clone()
                .to_lowercase();
                
            let service_name = config
                .parameters
                .get("service_name")
                .unwrap_or(&"signalbench-persistence".to_string())
                .clone();
                
            let output_dir = config
                .parameters
                .get("output_dir")
                .unwrap_or(&"/tmp/signalbench_system_process".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_system_process.log".to_string())
                .clone();
                
            let install_service = config
                .parameters
                .get("install_service")
                .unwrap_or(&"false".to_string())
                .clone()
                .to_lowercase() == "true";
            
            // Create artifact list for cleanup
            let mut artifacts = vec![log_file.clone(), output_dir.clone()];
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would create {technique_type} service named {service_name} in {output_dir}, install: {install_service}"),
                    artifacts,
                    cleanup_required: true,
                });
            }
            
            // Create output directory
            if !Path::new(&output_dir).exists() {
                std::fs::create_dir_all(&output_dir)
                    .map_err(|e| format!("Failed to create output directory: {e}"))?;
            }
            
            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            // Write header
            writeln!(log_file_handle, "# SignalBench Create or Modify System Process").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1543").unwrap();
            writeln!(log_file_handle, "# Technique Type: {technique_type}").unwrap();
            writeln!(log_file_handle, "# Service Name: {service_name}").unwrap();
            writeln!(log_file_handle, "# Output Directory: {output_dir}").unwrap();
            writeln!(log_file_handle, "# Install Service: {install_service}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Check if running as root (required for actual installation)
            let is_root = unsafe { libc::geteuid() == 0 };
            writeln!(log_file_handle, "Running as root: {is_root}").unwrap();
            
            if install_service && !is_root {
                writeln!(log_file_handle, "WARNING: Service installation requested but not running as root. Will create files but not install.").unwrap();
            }
            
            // Create a simple payload script
            let payload_file = format!("{output_dir}/{service_name}_payload.sh");
            let payload_script = format!(r#"#!/bin/bash
# SignalBench Persistence Test - System Process
# This generates persistent payload telemetry for system startup
echo "[+] SignalBench System Process Payload - Started at $(date)" >> /tmp/signalbench_persistence.log
echo "[+] Running as: $(whoami)" >> /tmp/signalbench_persistence.log
echo "[+] Current directory: $(pwd)" >> /tmp/signalbench_persistence.log
echo "[+] Hostname: $(hostname)" >> /tmp/signalbench_persistence.log

# In a real malicious scenario, this could:
# - Establish C2 connections
# - Install additional backdoors
# - Exfiltrate data
# - Mine cryptocurrency
# - Etc.

# Create a marker file to show the service executed
echo "SignalBench Persistence Test - System Process Executed" > /tmp/signalbench_system_process_executed
echo "$(date)" >> /tmp/signalbench_system_process_executed
echo "Service: {service_name}" >> /tmp/signalbench_system_process_executed

exit 0
"#);
            
            if let Err(e) = std::fs::write(&payload_file, payload_script) {
                writeln!(log_file_handle, "Failed to write payload script: {e}").unwrap();
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: false,
                    message: format!("Failed to create payload script: {e}"),
                    artifacts,
                    cleanup_required: true,
                });
            }
            
            artifacts.push(payload_file.clone());
            artifacts.push("/tmp/signalbench_persistence.log".to_string());
            artifacts.push("/tmp/signalbench_system_process_executed".to_string());
            
            // Make the payload executable
            let chmod_cmd = format!("chmod +x {payload_file}");
            let _ = Command::new("bash")
                .arg("-c")
                .arg(&chmod_cmd)
                .output()
                .await;
            
            writeln!(log_file_handle, "Created payload script: {payload_file}").unwrap();
            
            // Implement different persistence techniques based on the selected type
            match technique_type.as_str() {
                "systemd" => {
                    writeln!(log_file_handle, "\n## Creating systemd service").unwrap();
                    
                    // Create systemd service file
                    let service_file = format!("{output_dir}/{service_name}.service");
                    let service_content = format!(r#"[Unit]
Description=SignalBench Persistence Test - systemd service
After=network.target

[Service]
Type=simple
ExecStart={payload_file}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"#);
                    
                    if let Err(e) = std::fs::write(&service_file, service_content) {
                        writeln!(log_file_handle, "Failed to write systemd service file: {e}").unwrap();
                    } else {
                        artifacts.push(service_file.clone());
                        
                        writeln!(log_file_handle, "Created systemd service file: {service_file}").unwrap();
                        
                        // If installation is requested and we're running as root
                        if install_service && is_root {
                            writeln!(log_file_handle, "Attempting to install systemd service...").unwrap();
                            
                            // Copy service file to systemd directory
                            let install_cmd = format!("cp {service_file} /etc/systemd/system/");
                            let install_output = Command::new("bash")
                                .arg("-c")
                                .arg(&install_cmd)
                                .output()
                                .await;
                                
                            match install_output {
                                Ok(output) => {
                                    let exit_code = output.status.code().unwrap_or(-1);
                                    
                                    if exit_code == 0 {
                                        writeln!(log_file_handle, "Service file installed to /etc/systemd/system/").unwrap();
                                        
                                        // Reload systemd
                                        let reload_cmd = "systemctl daemon-reload";
                                        let reload_output = Command::new("bash")
                                            .arg("-c")
                                            .arg(reload_cmd)
                                            .output()
                                            .await;
                                            
                                        match reload_output {
                                            Ok(output) => {
                                                let exit_code = output.status.code().unwrap_or(-1);
                                                
                                                if exit_code == 0 {
                                                    writeln!(log_file_handle, "Systemd daemon reloaded successfully").unwrap();
                                                    
                                                    // Enable the service
                                                    let enable_cmd = format!("systemctl enable {service_name}");
                                                    let enable_output = Command::new("bash")
                                                        .arg("-c")
                                                        .arg(&enable_cmd)
                                                        .output()
                                                        .await;
                                                        
                                                    match enable_output {
                                                        Ok(output) => {
                                                            let exit_code = output.status.code().unwrap_or(-1);
                                                            let stdout = String::from_utf8_lossy(&output.stdout);
                                                            let stderr = String::from_utf8_lossy(&output.stderr);
                                                            
                                                            writeln!(log_file_handle, "Service enable exit code: {exit_code}").unwrap();
                                                            if !stdout.is_empty() {
                                                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                                            }
                                                            if !stderr.is_empty() {
                                                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                                            }
                                                            
                                                            if exit_code == 0 {
                                                                writeln!(log_file_handle, "Service enabled successfully").unwrap();
                                                                
                                                                // Add service to cleanup list
                                                                artifacts.push(format!("/etc/systemd/system/{service_name}.service"));
                                                            }
                                                        },
                                                        Err(e) => {
                                                            writeln!(log_file_handle, "Failed to enable service: {e}").unwrap();
                                                        }
                                                    }
                                                } else {
                                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                                    writeln!(log_file_handle, "Failed to reload systemd: {exit_code} ({stderr})").unwrap();
                                                }
                                            },
                                            Err(e) => {
                                                writeln!(log_file_handle, "Failed to reload systemd: {e}").unwrap();
                                            }
                                        }
                                    } else {
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        writeln!(log_file_handle, "Failed to install service file: {exit_code} ({stderr})").unwrap();
                                    }
                                },
                                Err(e) => {
                                    writeln!(log_file_handle, "Failed to install service file: {e}").unwrap();
                                }
                            }
                        } else {
                            writeln!(log_file_handle, "Service installation skipped due to configuration or not running as root").unwrap();
                            
                            // Instructions for manual installation
                            writeln!(log_file_handle, "\nTo manually install the service:").unwrap();
                            writeln!(log_file_handle, "  1. sudo cp {service_file} /etc/systemd/system/").unwrap();
                            writeln!(log_file_handle, "  2. sudo systemctl daemon-reload").unwrap();
                            writeln!(log_file_handle, "  3. sudo systemctl enable {service_name}").unwrap();
                            writeln!(log_file_handle, "  4. sudo systemctl start {service_name}").unwrap();
                        }
                    }
                },
                "init" => {
                    writeln!(log_file_handle, "\n## Creating init.d script").unwrap();
                    
                    // Create init.d script
                    let init_file = format!("{output_dir}/{service_name}");
                    let init_script = format!(r#"#!/bin/bash
### BEGIN INIT INFO
# Provides:          {service_name}
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SignalBench Persistence Test
# Description:       SignalBench demonstrates creating init.d scripts for persistence
### END INIT INFO

DAEMON={payload_file}
NAME={service_name}
DESC="SignalBench Persistence Test - init.d script"

case "$1" in
  start)
    echo "Starting $DESC: $NAME"
    $DAEMON
    ;;
  stop)
    echo "Stopping $DESC: $NAME"
    pkill -f "$DAEMON" || true
    ;;
  restart)
    echo "Restarting $DESC: $NAME"
    pkill -f "$DAEMON" || true
    sleep 1
    $DAEMON
    ;;
  status)
    if pgrep -f "$DAEMON" >/dev/null; then
      echo "$DESC: $NAME is running"
    else
      echo "$DESC: $NAME is not running"
      exit 1
    fi
    ;;
  *)
    echo "Usage: $0 {{start|stop|restart|status}}"
    exit 1
    ;;
esac

exit 0
"#);
                    
                    if let Err(e) = std::fs::write(&init_file, init_script) {
                        writeln!(log_file_handle, "Failed to write init.d script: {e}").unwrap();
                    } else {
                        artifacts.push(init_file.clone());
                        
                        // Make executable
                        let chmod_cmd = format!("chmod +x {init_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                        
                        writeln!(log_file_handle, "Created init.d script: {init_file}").unwrap();
                        
                        // If installation is requested and we're running as root
                        if install_service && is_root {
                            writeln!(log_file_handle, "Attempting to install init.d service...").unwrap();
                            
                            // Copy init script to /etc/init.d/
                            let install_cmd = format!("cp {init_file} /etc/init.d/");
                            let install_output = Command::new("bash")
                                .arg("-c")
                                .arg(&install_cmd)
                                .output()
                                .await;
                                
                            match install_output {
                                Ok(output) => {
                                    let exit_code = output.status.code().unwrap_or(-1);
                                    
                                    if exit_code == 0 {
                                        writeln!(log_file_handle, "Init script installed to /etc/init.d/").unwrap();
                                        
                                        // Update rc.d links
                                        let update_cmd = format!("update-rc.d {service_name} defaults");
                                        let update_output = Command::new("bash")
                                            .arg("-c")
                                            .arg(&update_cmd)
                                            .output()
                                            .await;
                                            
                                        match update_output {
                                            Ok(output) => {
                                                let exit_code = output.status.code().unwrap_or(-1);
                                                let stdout = String::from_utf8_lossy(&output.stdout);
                                                let stderr = String::from_utf8_lossy(&output.stderr);
                                                
                                                writeln!(log_file_handle, "Update-rc.d exit code: {exit_code}").unwrap();
                                                if !stdout.is_empty() {
                                                    writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                                }
                                                if !stderr.is_empty() {
                                                    writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                                }
                                                
                                                if exit_code == 0 {
                                                    writeln!(log_file_handle, "Service enabled successfully").unwrap();
                                                    
                                                    // Add service to cleanup list
                                                    artifacts.push(format!("/etc/init.d/{service_name}"));
                                                }
                                            },
                                            Err(e) => {
                                                writeln!(log_file_handle, "Failed to enable service: {e}").unwrap();
                                            }
                                        }
                                    } else {
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        writeln!(log_file_handle, "Failed to install init script: {exit_code} ({stderr})").unwrap();
                                    }
                                },
                                Err(e) => {
                                    writeln!(log_file_handle, "Failed to install init script: {e}").unwrap();
                                }
                            }
                        } else {
                            writeln!(log_file_handle, "Service installation skipped due to configuration or not running as root").unwrap();
                            
                            // Instructions for manual installation
                            writeln!(log_file_handle, "\nTo manually install the init.d service:").unwrap();
                            writeln!(log_file_handle, "  1. sudo cp {init_file} /etc/init.d/").unwrap();
                            writeln!(log_file_handle, "  2. sudo chmod +x /etc/init.d/{service_name}").unwrap();
                            writeln!(log_file_handle, "  3. sudo update-rc.d {service_name} defaults").unwrap();
                            writeln!(log_file_handle, "  4. sudo service {service_name} start").unwrap();
                        }
                    }
                },
                "rc" => {
                    writeln!(log_file_handle, "\n## Creating rc.local entry").unwrap();
                    
                    // Create a modified rc.local file
                    let rc_file = format!("{output_dir}/rc.local");
                    let rc_script = format!(r#"#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# SignalBench Persistence Test - Modified rc.local

# Original content would be here...

# Added malicious payload
echo "Running SignalBench persistence test payload from rc.local"
{payload_file}

exit 0
"#);
                    
                    if let Err(e) = std::fs::write(&rc_file, rc_script) {
                        writeln!(log_file_handle, "Failed to write rc.local file: {e}").unwrap();
                    } else {
                        artifacts.push(rc_file.clone());
                        
                        // Make executable
                        let chmod_cmd = format!("chmod +x {rc_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                        
                        writeln!(log_file_handle, "Created modified rc.local file: {rc_file}").unwrap();
                        
                        // If installation is requested and we're running as root
                        if install_service && is_root {
                            writeln!(log_file_handle, "Attempting to install rc.local file...").unwrap();
                            
                            // Backup existing rc.local if it exists
                            let backup_cmd = "if [ -f /etc/rc.local ]; then cp /etc/rc.local /etc/rc.local.signalbench.bak; fi";
                            let _ = Command::new("bash")
                                .arg("-c")
                                .arg(backup_cmd)
                                .output()
                                .await;
                            
                            // Copy rc.local to /etc/
                            let install_cmd = format!("cp {rc_file} /etc/rc.local");
                            let install_output = Command::new("bash")
                                .arg("-c")
                                .arg(&install_cmd)
                                .output()
                                .await;
                                
                            match install_output {
                                Ok(output) => {
                                    let exit_code = output.status.code().unwrap_or(-1);
                                    
                                    if exit_code == 0 {
                                        writeln!(log_file_handle, "Modified rc.local installed to /etc/rc.local").unwrap();
                                        
                                        // Make it executable
                                        let chmod_cmd = "chmod +x /etc/rc.local";
                                        let _ = Command::new("bash")
                                            .arg("-c")
                                            .arg(chmod_cmd)
                                            .output()
                                            .await;
                                        
                                        writeln!(log_file_handle, "Made /etc/rc.local executable").unwrap();
                                        
                                        // Add to cleanup list
                                        artifacts.push("/etc/rc.local".to_string());
                                    } else {
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        writeln!(log_file_handle, "Failed to install rc.local: {exit_code} ({stderr})").unwrap();
                                    }
                                },
                                Err(e) => {
                                    writeln!(log_file_handle, "Failed to install rc.local: {e}").unwrap();
                                }
                            }
                        } else {
                            writeln!(log_file_handle, "rc.local installation skipped due to configuration or not running as root").unwrap();
                            
                            // Instructions for manual installation
                            writeln!(log_file_handle, "\nTo manually install the rc.local file:").unwrap();
                            writeln!(log_file_handle, "  1. sudo cp {rc_file} /etc/rc.local").unwrap();
                            writeln!(log_file_handle, "  2. sudo chmod +x /etc/rc.local").unwrap();
                        }
                    }
                },
                _ => {
                    writeln!(log_file_handle, "\n## ERROR: Unsupported technique '{technique_type}'").unwrap();
                    writeln!(log_file_handle, "Supported techniques: systemd, init, rc").unwrap();
                }
            }
            
            // Close log file
            drop(log_file_handle);
            
            info!("Create or modify system process test complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Create or modify system process ({technique_type}) test completed. Logs: {log_file}"),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // First, check if we are running as root for service cleanup
            let is_root = unsafe { libc::geteuid() == 0 };
            
            // Attempt to identify if we installed any services
            let mut systemd_service_name = None;
            let mut init_service_name = None;
            
            for artifact in artifacts {
                // Look for systemd service
                if artifact.starts_with("/etc/systemd/system/") && artifact.ends_with(".service") {
                    systemd_service_name = Some(artifact.split("/").last().unwrap().to_string());
                }
                
                // Look for init.d script
                if artifact.starts_with("/etc/init.d/") {
                    init_service_name = Some(artifact.split("/").last().unwrap().to_string());
                }
                
                // Special handle for rc.local
                if artifact == "/etc/rc.local" && is_root {
                    // Restore backup if it exists
                    let restore_cmd = "if [ -f /etc/rc.local.signalbench.bak ]; then mv /etc/rc.local.signalbench.bak /etc/rc.local; else rm /etc/rc.local; fi";
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(restore_cmd)
                        .output()
                        .await;
                        
                    debug!("Restored or removed /etc/rc.local");
                }
            }
            
            // Clean up systemd service if we installed one and running as root
            if let Some(service_name) = systemd_service_name {
                if is_root {
                    // Stop the service
                    let stop_cmd = format!("systemctl stop {service_name}");
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(&stop_cmd)
                        .output()
                        .await;
                    
                    // Disable the service
                    let disable_cmd = format!("systemctl disable {service_name}");
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(&disable_cmd)
                        .output()
                        .await;
                    
                    // Remove the service file
                    let remove_cmd = format!("rm /etc/systemd/system/{service_name}");
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(&remove_cmd)
                        .output()
                        .await;
                    
                    // Reload systemd
                    let reload_cmd = "systemctl daemon-reload";
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(reload_cmd)
                        .output()
                        .await;
                        
                    debug!("Removed systemd service: {service_name}");
                }
            }
            
            // Clean up init.d service if we installed one and running as root
            if let Some(service_name) = init_service_name {
                if is_root {
                    // Stop the service
                    let stop_cmd = format!("service {service_name} stop");
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(&stop_cmd)
                        .output()
                        .await;
                    
                    // Remove from startup
                    let remove_links_cmd = format!("update-rc.d -f {service_name} remove");
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(&remove_links_cmd)
                        .output()
                        .await;
                    
                    // Remove the service file
                    let remove_cmd = format!("rm /etc/init.d/{service_name}");
                    let _ = Command::new("bash")
                        .arg("-c")
                        .arg(&remove_cmd)
                        .output()
                        .await;
                        
                    debug!("Removed init.d service: {service_name}");
                }
            }
            
            // Clean up remaining file artifacts
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    // Skip system files if not root
                    if (artifact.starts_with("/etc/") || artifact.starts_with("/lib/")) && !is_root {
                        continue;
                    }
                    
                    // If it's a directory, try to remove it recursively
                    if Path::new(artifact).is_dir() {
                        if let Err(e) = std::fs::remove_dir_all(artifact) {
                            error!("Failed to remove directory {artifact}: {e}");
                        } else {
                            debug!("Removed directory: {artifact}");
                        }
                    } else {
                        // Otherwise try to remove as a file
                        if let Err(e) = std::fs::remove_file(artifact) {
                            error!("Failed to remove artifact {artifact}: {e}");
                        } else {
                            debug!("Removed artifact: {artifact}");
                        }
                    }
                }
            }
            Ok(())
        })
    }
}