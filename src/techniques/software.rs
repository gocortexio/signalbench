// SOFTWARE category: Simulations of known malware families from MITRE ATT&CK
// EXPERIMENTAL: These implementations represent research-grade malware behaviour simulations
// designed to match YARA signatures and documented techniques for security analytics research

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use tokio::process::Command;

// Embed the compiled pacemaker helper binary
static PACEMAKER_BINARY: &[u8] = include_bytes!("../../embedded_binaries/pacemaker_helper");

pub struct S1109Pacemaker;

#[async_trait]
impl AttackTechnique for S1109Pacemaker {
    fn info(&self) -> Technique {
        Technique {
            id: "S1109".to_string(),
            name: "PACEMAKER".to_string(),
            description: "Deploys PACEMAKER credential stealer simulation that matches YARA signatures and creates credential harvesting artifacts. This benign simulation mimics the memory-reading credential stealer used in APT attacks against Pulse Secure VPN appliances.".to_string(),
            category: "software".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "timeout".to_string(),
                    description: "Timeout in seconds for memread simulation".to_string(),
                    required: false,
                    default: Some("3".to_string()),
                },
                TechniqueParameter {
                    name: "memory_size".to_string(),
                    description: "Memory read size in MB".to_string(),
                    required: false,
                    default: Some("16".to_string()),
                },
                TechniqueParameter {
                    name: "scan_interval".to_string(),
                    description: "Memory scan interval in seconds".to_string(),
                    required: false,
                    default: Some("2".to_string()),
                },
            ],
            detection: "YARA signatures (FE_APT_Trojan_Linux_PACEMAKER), credential file creation in /tmp/ds*.statementcounters, suspicious process execution patterns".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let binary_path = "/tmp/signalbench_sim-pacemaker";
            let launcher_path = "/tmp/signalbench_sim-pacemaker-launcher.sh";
            
            let timeout = config
                .parameters
                .get("timeout")
                .unwrap_or(&"3".to_string())
                .clone();
                
            let memory_size = config
                .parameters
                .get("memory_size")
                .unwrap_or(&"16".to_string())
                .clone();
                
            let scan_interval = config
                .parameters
                .get("scan_interval")
                .unwrap_or(&"2".to_string())
                .clone();
            
            let cred_files = vec![
                "/tmp/signalbench_sim_dsactiveuser.statementcounters",
                "/tmp/signalbench_sim_dsstartssh.statementcounters",
                "/tmp/signalbench_sim_dsserver-check.statementcounters",
            ];

            if dry_run {
                let message = format!(
                    "[DRY RUN] Would perform the following actions:\n\
                    1. Extract embedded PACEMAKER binary ({} bytes) to: {}\n\
                    2. Make binary executable (chmod +x)\n\
                    3. Create launcher script: {}\n\
                    4. Execute: {} -t {} -m {} -s {}\n\
                    5. Create credential files:\n   - {}\n   - {}\n   - {}\n\
                    \nNote: This simulation contains YARA signatures matching FE_APT_Trojan_Linux_PACEMAKER",
                    PACEMAKER_BINARY.len(),
                    binary_path, launcher_path,
                    binary_path, timeout, memory_size, scan_interval,
                    cred_files[0], cred_files[1], cred_files[2]
                );
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message,
                    artifacts: vec![
                        binary_path.to_string(),
                        launcher_path.to_string(),
                        cred_files[0].to_string(),
                        cred_files[1].to_string(),
                        cred_files[2].to_string(),
                    ],
                    cleanup_required: false,
                });
            }

            info!("Extracting embedded PACEMAKER simulation binary ({} bytes)", PACEMAKER_BINARY.len());
            
            // Securely create the binary file using create_new() and O_NOFOLLOW to prevent symlink attacks
            // O_NOFOLLOW ensures that symlinks are rejected, even if they point to non-existent files
            // This will fail if the file already exists or if the path is a symlink
            let mut binary_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .custom_flags(libc::O_NOFOLLOW)
                .open(binary_path)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        format!("PACEMAKER binary path already exists (possible symlink attack): {binary_path}")
                    } else if e.raw_os_error() == Some(libc::ELOOP) {
                        format!("PACEMAKER binary path is a symlink (symlink attack prevented): {binary_path}")
                    } else {
                        format!("Failed to create PACEMAKER binary: {e}")
                    }
                })?;

            binary_file.write_all(PACEMAKER_BINARY)
                .map_err(|e| format!("Failed to write PACEMAKER binary content: {e}"))?;
            
            // Explicitly drop the file handle to close it before execution
            drop(binary_file);

            info!("Creating PACEMAKER launcher script");
            
            // Securely create the launcher script using create_new() and O_NOFOLLOW to prevent symlink attacks
            let launcher_script = format!(
                "#!/bin/bash\n\
                # SignalBench simulation of PACEMAKER launcher\n\
                # Based on Mandiant report: SHA256 4c5555955b2e6dc55f52b0c1a3326f3d07b325b112060329c503b294208960ec\n\
                {binary_path} -t $1 -m 16 -s 2 &\n"
            );
            
            let mut launcher_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .custom_flags(libc::O_NOFOLLOW)
                .open(launcher_path)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        format!("Launcher script path already exists (possible symlink attack): {launcher_path}")
                    } else if e.raw_os_error() == Some(libc::ELOOP) {
                        format!("Launcher script path is a symlink (symlink attack prevented): {launcher_path}")
                    } else {
                        format!("Failed to create launcher script: {e}")
                    }
                })?;

            launcher_file.write_all(launcher_script.as_bytes())
                .map_err(|e| format!("Failed to write launcher script content: {e}"))?;
            
            // Explicitly drop the file handle to close it before execution
            drop(launcher_file);

            info!("Executing PACEMAKER simulation (timeout: {timeout}s, memory: {memory_size}MB, interval: {scan_interval}s)");
            
            // Execute the binary with parameters matching Mandiant report
            let output = Command::new(binary_path)
                .args(["-t", &timeout, "-m", &memory_size, "-s", &scan_interval])
                .output()
                .await
                .map_err(|e| format!("Failed to execute PACEMAKER binary: {e}"))?;

            if !output.status.success() {
                return Err(format!(
                    "PACEMAKER execution failed with exit code: {}",
                    output.status.code().unwrap_or(-1)
                ));
            }

            // Verify credential files were created
            let mut created_files = Vec::new();
            for file in &cred_files {
                if std::path::Path::new(file).exists() {
                    created_files.push(file.to_string());
                }
            }

            info!("PACEMAKER simulation completed successfully");

            let message = format!(
                "Successfully deployed PACEMAKER simulation\n\
                \nCreated artifacts:\n  - {} (ELF binary with YARA signatures)\n  - {} (launcher script)\n  - {} credential file(s)\n\
                \nBehaviour simulated:\n  - Memory credential scraping (memread -t {} -m {} -s {})\n  - Credential exfiltration to /tmp/signalbench_sim_ds*.statementcounters files\n\
                \nYARA detection:\n  - Matches FE_APT_Trojan_Linux_PACEMAKER rule\n  - Contains signature strings: /proc/%%d/mem, /proc/%%s/maps, etc.\n  - Contains credential format: Name:%%s || Pwd:%%s || AuthNum:%%s",
                binary_path, launcher_path, created_files.len(),
                timeout, memory_size, scan_interval
            );

            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: vec![
                    binary_path.to_string(),
                    launcher_path.to_string(),
                    cred_files[0].to_string(),
                    cred_files[1].to_string(),
                    cred_files[2].to_string(),
                ],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Cleaning up PACEMAKER simulation artifacts");

            for artifact in artifacts {
                if std::path::Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("Failed to remove {artifact}: {e}");
                    } else {
                        info!("Removed: {artifact}");
                    }
                }
            }

            // Also clean up any leftover credential files from previous runs
            let additional_files = vec![
                "/tmp/signalbench_sim_dsactiveuser.statementcounters",
                "/tmp/signalbench_sim_dsstartssh.statementcounters",
                "/tmp/signalbench_sim_dsserver-check.statementcounters",
            ];
            
            for file in &additional_files {
                if std::path::Path::new(file).exists() {
                    if let Err(e) = fs::remove_file(file) {
                        warn!("Failed to remove credential file {file}: {e}");
                    } else {
                        info!("Removed credential file: {file}");
                    }
                }
            }

            Ok(())
        })
    }
}
