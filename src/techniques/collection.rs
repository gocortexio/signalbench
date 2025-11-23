// SIGNALBENCH - Collection Techniques
// Collection techniques for the MITRE ATT&CK framework
// 
// This module implements techniques for gathering data from target systems
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::process::Command;
use uuid::Uuid;

pub struct AutomatedCollection {}

#[async_trait]
impl AttackTechnique for AutomatedCollection {
    fn info(&self) -> Technique {
        Technique {
            id: "T1119".to_string(),
            name: "Automated Collection".to_string(),
            description: "Recursively searches and collects sensitive files from /home/*/,  /var/log/, /opt/, /tmp/ targeting patterns like *.key, *.pem, *.conf, *.db, *.sql, *secret*, *password*, *.env. Creates staging directory in /tmp/signalbench_collection_<uuid>/, copies ALL matching files, archives them with tar czf, extracts comprehensive metadata (sizes, timestamps, permissions, owners), and generates detailed JSON collection report. FULLY REVERSIBLE with complete cleanup of staging directory and archives.".to_string(),
            category: "collection".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "max_files".to_string(),
                    description: "Maximum number of files to collect (default: 50)".to_string(),
                    required: false,
                    default: Some("50".to_string()),
                },
                TechniqueParameter {
                    name: "max_file_size".to_string(),
                    description: "Maximum file size in bytes to collect (default: 1048576 = 1MB)".to_string(),
                    required: false,
                    default: Some("1048576".to_string()),
                },
                TechniqueParameter {
                    name: "output_report".to_string(),
                    description: "Path to save collection report JSON".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_collection_report.json".to_string()),
                },
            ],
            detection: "Monitor for recursive file system enumeration, access to sensitive configuration files, tar/archive creation with suspicious patterns, mass file copying operations, metadata extraction from system files, and creation of staging directories in /tmp. Watch for processes reading multiple .key, .pem, .env, and configuration files.".to_string(),
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
            let max_files = config
                .parameters
                .get("max_files")
                .unwrap_or(&"50".to_string())
                .parse::<usize>()
                .unwrap_or(50);
            
            let max_file_size = config
                .parameters
                .get("max_file_size")
                .unwrap_or(&"1048576".to_string())
                .parse::<u64>()
                .unwrap_or(1048576);
            
            let output_report = config
                .parameters
                .get("output_report")
                .unwrap_or(&"/tmp/signalbench_collection_report.json".to_string())
                .clone();
            
            let session_id = Uuid::new_v4().to_string().replace("-", "");
            let staging_dir = format!("/tmp/signalbench_collection_{session_id}");
            let archive_path = format!("{staging_dir}/collection_archive.tar.gz");
            
            let search_dirs = vec![
                format!("{}/", std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())),
                "/tmp/".to_string(),
                "/var/log/".to_string(),
                "/opt/".to_string(),
            ];
            
            let target_patterns = vec![
                "*.key", "*.pem", "*.conf", "*.db", "*.sql", 
                "*secret*", "*password*", "*.env", "*.cfg",
                "*.config", "*.ini", "*.yaml", "*.yml", "*.json",
            ];
            
            if dry_run {
                info!("[DRY RUN] Would perform automated file collection:");
                info!("[DRY RUN]   Search directories: {}", search_dirs.join(", "));
                info!("[DRY RUN]   Target patterns: {}", target_patterns.join(", "));
                info!("[DRY RUN]   Max files: {max_files}, Max size: {max_file_size} bytes");
                info!("[DRY RUN]   Staging: {staging_dir}");
                info!("[DRY RUN]   Archive: {archive_path}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would collect sensitive files, create archive, and generate metadata report".to_string(),
                    artifacts: vec![staging_dir, archive_path, output_report],
                    cleanup_required: false,
                });
            }

            info!("Starting automated collection (Session: {session_id})...");
            info!("Creating staging directory: {staging_dir}");
            
            fs::create_dir_all(&staging_dir)
                .map_err(|e| format!("Failed to create staging directory: {e}"))?;
            
            let mut artifacts = vec![staging_dir.clone(), output_report.clone()];
            let mut collected_files = Vec::new();
            let mut collection_metadata = Vec::new();
            let mut total_size = 0u64;
            
            // Phase 1: File Discovery and Collection
            info!("Phase 1: Discovering and collecting files...");
            
            for search_dir in &search_dirs {
                if !Path::new(search_dir).exists() {
                    warn!("Directory does not exist or not accessible: {search_dir}");
                    continue;
                }
                
                info!("Searching directory: {search_dir}");
                
                if let Ok(entries) = fs::read_dir(search_dir) {
                    for entry in entries.flatten() {
                        if collected_files.len() >= max_files {
                            info!("Reached maximum file limit ({max_files})");
                            break;
                        }
                        
                        let path = entry.path();
                        
                        // Skip if not a file
                        if !path.is_file() {
                            continue;
                        }
                        
                        // Get file metadata
                        let metadata = match fs::metadata(&path) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        
                        // Skip if file is too large
                        if metadata.len() > max_file_size {
                            continue;
                        }
                        
                        // Check if file matches any pattern
                        let file_name = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        
                        let mut matches = false;
                        for pattern in &target_patterns {
                            let pattern_str = pattern.replace("*", "");
                            if pattern.starts_with('*') && pattern.ends_with('*') {
                                if file_name.contains(&pattern_str) {
                                    matches = true;
                                    break;
                                }
                            } else if pattern.starts_with('*') {
                                if file_name.ends_with(&pattern_str) {
                                    matches = true;
                                    break;
                                }
                            } else if pattern.ends_with('*')
                                && file_name.starts_with(&pattern_str) {
                                    matches = true;
                                    break;
                                }
                        }
                        
                        if !matches {
                            continue;
                        }
                        
                        // Collect file metadata
                        let modified = metadata.modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        
                        let permissions = format!("{:o}", metadata.permissions().mode() & 0o777);
                        
                        // Copy file to staging directory
                        let dest_path = format!("{staging_dir}/{file_name}");
                        if fs::copy(&path, &dest_path).is_ok() {
                            info!("Collected: {} ({} bytes)", path.display(), metadata.len());
                            
                            collection_metadata.push(serde_json::json!({
                                "original_path": path.to_string_lossy(),
                                "file_name": file_name,
                                "size_bytes": metadata.len(),
                                "modified_timestamp": modified,
                                "permissions": permissions,
                                "copied_to": dest_path,
                            }));
                            
                            collected_files.push(dest_path);
                            total_size += metadata.len();
                        }
                    }
                }
                
                if collected_files.len() >= max_files {
                    break;
                }
            }
            
            info!("Collected {} files ({} bytes total)", collected_files.len(), total_size);
            
            // Phase 2: Create tar archive
            info!("Phase 2: Creating tar.gz archive...");
            
            if !collected_files.is_empty() {
                let tar_output = Command::new("tar")
                    .args(["czf", &archive_path, "-C", &staging_dir, "."])
                    .output()
                    .await;
                
                match tar_output {
                    Ok(output) if output.status.success() => {
                        info!("Archive created successfully: {archive_path}");
                        artifacts.push(archive_path.clone());
                        
                        // Get archive size
                        if let Ok(archive_metadata) = fs::metadata(&archive_path) {
                            info!("Archive size: {} bytes", archive_metadata.len());
                        }
                    }
                    Ok(output) => {
                        warn!("tar command failed: {}", String::from_utf8_lossy(&output.stderr));
                    }
                    Err(e) => {
                        warn!("Failed to execute tar: {e}");
                    }
                }
            }
            
            // Phase 3: Generate comprehensive collection report
            info!("Phase 3: Generating collection report...");
            
            let report = serde_json::json!({
                "technique_id": "T1119",
                "technique_name": "Automated Collection",
                "session_id": session_id,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "collection_summary": {
                    "total_files_collected": collected_files.len(),
                    "total_size_bytes": total_size,
                    "max_files_limit": max_files,
                    "max_file_size_limit": max_file_size,
                    "search_directories": search_dirs,
                    "target_patterns": target_patterns,
                },
                "staging_directory": staging_dir,
                "archive_path": archive_path,
                "collected_files": collection_metadata,
            });
            
            let mut report_file = File::create(&output_report)
                .map_err(|e| format!("Failed to create report file: {e}"))?;
            
            report_file.write_all(serde_json::to_string_pretty(&report)
                .unwrap_or_else(|_| "{}".to_string())
                .as_bytes())
                .map_err(|e| format!("Failed to write report: {e}"))?;
            
            info!("Collection report saved to: {output_report}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Successfully collected {} files ({} bytes) into staging directory and archive. Report generated.",
                    collected_files.len(),
                    total_size
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting cleanup of automated collection artifacts...");
            
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if Path::new(artifact).is_dir() {
                        match fs::remove_dir_all(artifact) {
                            Ok(_) => info!("Removed staging directory: {artifact}"),
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
            
            info!("Automated collection cleanup completed");
            Ok(())
        })
    }
}
