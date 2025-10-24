use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;

pub struct CommandLineInterface {}

#[async_trait]
impl AttackTechnique for CommandLineInterface {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059.004".to_string(),
            name: "Unix Shell Execution".to_string(),
            description: "Generates telemetry for suspicious command execution via shell".to_string(),
            category: "execution".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "shell".to_string(),
                    description: "Shell to use".to_string(),
                    required: false,
                    default: Some("/bin/bash".to_string()),
                },
                TechniqueParameter {
                    name: "command".to_string(),
                    description: "Command to execute".to_string(),
                    required: false,
                    default: Some("echo 'SignalBench Command Execution' > /tmp/signalbench_cmd_exec".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save command execution log to".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_cmd_log".to_string()),
                },
            ],
            detection: "Monitor for suspicious command execution".to_string(),
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
            let shell = config
                .parameters
                .get("shell")
                .unwrap_or(&"/bin/bash".to_string())
                .clone();
                
            let command = config
                .parameters
                .get("command")
                .unwrap_or(&"echo 'SignalBench Command Execution Test - GoCortex.io' > /tmp/signalbench_test_cmd_exec".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_test_cmd_log".to_string())
                .clone();

            // Output file from the command is also considered an artifact
            let output_file = if command.contains(">") {
                let parts: Vec<&str> = command.split(">").collect();
                if parts.len() > 1 {
                    let redirect_path = parts[1].trim();
                    Some(redirect_path.to_string())
                } else {
                    None
                }
            } else {
                None
            };
                
            if dry_run {
                info!("[DRY RUN] Would execute command via {shell}: {command}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would execute command via {shell}: {command}"),
                    artifacts: if let Some(output_path) = output_file {
                        vec![log_file, output_path]
                    } else {
                        vec![log_file]
                    },
                    cleanup_required: false,
                });
            }

            // Create the log file
            let mut file = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            // Write initial log entry
            writeln!(file, "=== SignalBench Command Execution Test (GoCortex.io) ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "Shell: {shell}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "Command: {command}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Execute the command
            let shell_clone = shell.clone(); // Clone the shell string before moving it
            let output = Command::new(&shell_clone)
                .args(["-c", &command])
                .output()
                .await
                .map_err(|e| format!("Failed to execute command: {e}"))?;
            
            // Write command output to log file
            writeln!(file, "=== Command Output ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
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
            
            info!("Executed command via {shell_clone}: {command}");
            
            let artifacts = if let Some(output_path) = output_file {
                vec![log_file, output_path]
            } else {
                vec![log_file]
            };
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: output.status.success(),
                message: format!("Successfully executed command via {shell_clone}: {command}"),
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

pub struct ScriptExecution {}

#[async_trait]
impl AttackTechnique for ScriptExecution {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059.006".to_string(),
            name: "Python Script Execution".to_string(),
            description: "Generates telemetry for malicious Python script execution".to_string(),
            category: "execution".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "script_file".to_string(),
                    description: "Path to save the script file".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_script.py".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save script execution log to".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_script_log".to_string()),
                },
            ],
            detection: "Monitor for suspicious script execution".to_string(),
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
            let script_file = config
                .parameters
                .get("script_file")
                .unwrap_or(&"/tmp/signalbench_test_script.py".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_test_script_log".to_string())
                .clone();
            
            // Create a suspicious-looking Python script
            let script_content = r#"#!/usr/bin/env python3
# SignalBench by GoCortex.io - Attack technique telemetry

import os
import sys
import platform
import socket
import subprocess
import base64

print("SignalBench (GoCortex.io) - Python Script Execution")

# System reconnaissance
print("Gathering system information...")
print(f"Platform: {platform.platform()}")
print(f"Hostname: {platform.node()}")
print(f"Username: {os.getlogin()}")

# File operations
print("Performing file operations...")
with open("/tmp/signalbench_test_script_output", "w") as f:
    f.write("SignalBench Test Script Output (GoCortex.io)\n")
    f.write(f"User: {os.getlogin()}\n")
    f.write(f"Path: {os.getcwd()}\n")

# Network operations
print("Performing network operations...")
try:
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(f"IP Address: {ip}")
    
    # Generate connection telemetry
    print("Simulating connection to C2 server...")
    # This is just a simulation, no actual connection is made
    print("Connection to evil.example.com:4444 attempted")
except Exception as e:
    print(f"Network error: {e}")

# Process operations
print("Performing process operations...")
try:
    # List running processes
    processes = subprocess.check_output(["ps", "aux"]).decode()
    print(f"Found {len(processes.split('\n'))} running processes")
except Exception as e:
    print(f"Process error: {e}")

# Encode data (simulating data exfiltration)
print("Simulating data exfiltration...")
sensitive_data = "This is test sensitive data from the system"
encoded_data = base64.b64encode(sensitive_data.encode()).decode()
print(f"Encoded data: {encoded_data}")
print("Exfiltration simulation complete")

print("SignalBench by GoCortex.io - Script execution completed")
"#;
                
            if dry_run {
                info!("[DRY RUN] Would create and execute Python script: {script_file}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would create and execute Python script: {script_file}"),
                    artifacts: vec![script_file, log_file, "/tmp/signalbench_test_script_output".to_string()],
                    cleanup_required: false,
                });
            }

            // Create the script file
            let mut file = File::create(&script_file)
                .map_err(|e| format!("Failed to create script file: {e}"))?;
            
            file.write_all(script_content.as_bytes())
                .map_err(|e| format!("Failed to write to script file: {e}"))?;
            
            // Make the script executable
            let status = Command::new("chmod")
                .args(["+x", &script_file])
                .status()
                .await
                .map_err(|e| format!("Failed to make script executable: {e}"))?;
                
            if !status.success() {
                return Err("Failed to make script executable".to_string());
            }
            
            // Create the log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            // Write initial log entry
            writeln!(log, "=== SignalBench Script Execution ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Script: {script_file}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            // Execute the script
            let output = Command::new("python3")
                .arg(&script_file)
                .output()
                .await
                .map_err(|e| format!("Failed to execute script: {e}"))?;
            
            // Write script output to log file
            writeln!(log, "=== Script Output ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Stdout:")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            log.write_all(&output.stdout)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Stderr:")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            log.write_all(&output.stderr)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            
            info!("Created and executed Python script: {script_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: output.status.success(),
                message: format!("Successfully created and executed Python script: {script_file}"),
                artifacts: vec![script_file, log_file, "/tmp/signalbench_script_output".to_string()],
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
pub struct UncommonRemoteShellCommands {}

#[async_trait]
impl AttackTechnique for UncommonRemoteShellCommands {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059.004.001".to_string(),
            name: "Uncommon Remote Shell Commands".to_string(),
            description: "Generates telemetry for uncommon command execution patterns with suspicious command names".to_string(),
            category: "execution".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "command_count".to_string(),
                    description: "Number of uncommon commands to execute".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "File to save command execution log to".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_uncommon_cmds".to_string()),
                },
            ],
            detection: "Monitor for execution of uncommon binaries with suspicious names indicating potential remote access tools".to_string(),
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
        use rand::seq::SliceRandom;
        
        let command_count: usize = config
            .parameters
            .get("command_count")
            .unwrap_or(&"5".to_string())
            .parse()
            .unwrap_or(5);
            
        let log_file = config
            .parameters
            .get("log_file")
            .unwrap_or(&"/tmp/signalbench_uncommon_cmds".to_string())
            .clone();

        // Scary-sounding command suffixes for simulation
        let scary_suffixes = vec![
            "backdoor", "rootkit", "keylogger", "cryptominer", "ransomware",
            "botnet", "exploit", "shellcode", "payload", "dropper",
            "stealer", "trojan", "beacon", "implant", "injector",
            "dumper", "exfiltrate", "scanner", "harvester", "persistence",
        ];

        // Generate random selections BEFORE async block
        let mut rng = rand::thread_rng();
        let mut command_list = Vec::new();
        for _ in 0..command_count {
            let suffix = scary_suffixes.choose(&mut rng).unwrap_or(&"backdoor");
            let cmd_name = format!("signalbench_{suffix}");
            let cmd_path = format!("/tmp/{cmd_name}");
            command_list.push((cmd_name, cmd_path));
        }

        Box::pin(async move {
            let mut artifacts = vec![log_file.clone()];

            if dry_run {
                let cmd_names: Vec<String> = command_list.iter()
                    .map(|(name, _)| name.clone())
                    .collect();
                info!("[DRY RUN] Would execute uncommon commands: {}", cmd_names.join(", "));
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would execute {command_count} uncommon commands"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create the log file
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench Uncommon Remote Shell Commands ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log, "Command count: {command_count}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
            writeln!(log)
                .map_err(|e| format!("Failed to write to log file: {e}"))?;

            // Create and execute each uncommon command
            for (cmd_name, cmd_path) in &command_list {
                writeln!(log, "=== Executing: {cmd_name} ===")
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;

                // Create a simple shell script with the scary name
                let script_content = format!(
                    "#!/bin/sh\necho 'SignalBench telemetry generator - {} executed'\necho 'Timestamp: {}'\necho 'User: {}'\n",
                    cmd_name,
                    chrono::Local::now().to_rfc3339(),
                    whoami::username()
                );

                let mut script_file = File::create(cmd_path)
                    .map_err(|e| format!("Failed to create command script: {e}"))?;
                
                script_file.write_all(script_content.as_bytes())
                    .map_err(|e| format!("Failed to write command script: {e}"))?;

                // Make it executable
                let _ = Command::new("chmod")
                    .args(["+x", cmd_path])
                    .status()
                    .await;

                // Execute the uncommon command
                info!("Executing uncommon command: {cmd_name}");
                let output = Command::new(cmd_path)
                    .output()
                    .await;

                match output {
                    Ok(output) => {
                        writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        writeln!(log, "Output:")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        log.write_all(&output.stdout)
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        if !output.stderr.is_empty() {
                            writeln!(log, "Stderr:")
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                            log.write_all(&output.stderr)
                                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                        }
                    },
                    Err(e) => {
                        writeln!(log, "Error executing command: {e}")
                            .map_err(|e| format!("Failed to write to log file: {e}"))?;
                    }
                }

                writeln!(log)
                    .map_err(|e| format!("Failed to write to log file: {e}"))?;

                artifacts.push(cmd_path.clone());
            }

            info!("Executed {command_count} uncommon remote shell commands");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully executed {command_count} uncommon remote shell commands"),
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
