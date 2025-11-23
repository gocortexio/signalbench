// SIGNALBENCH - Impact Techniques
// Impact techniques for the MITRE ATT&CK framework
// 
// This module implements techniques for disrupting system availability and integrity
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use sha2::{Sha256, Digest};

pub struct ResourceHijacking {}

#[async_trait]
impl AttackTechnique for ResourceHijacking {
    fn info(&self) -> Technique {
        Technique {
            id: "T1496".to_string(),
            name: "Resource Hijacking".to_string(),
            description: "Simulates cryptocurrency mining and resource abuse by spawning controlled CPU stress processes performing SHA256 hashing loops, allocating large memory blocks (100MB chunks), and rapid disk I/O operations in /tmp/. Limited to 30 seconds maximum duration with safety limits. Monitors and logs resource usage during stress, demonstrates resource hijacking patterns detectable by EDR systems. FULLY REVERSIBLE with guaranteed process termination, memory cleanup, and temporary file removal.".to_string(),
            category: "impact".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "duration_seconds".to_string(),
                    description: "Duration of resource stress in seconds (max 30)".to_string(),
                    required: false,
                    default: Some("10".to_string()),
                },
                TechniqueParameter {
                    name: "cpu_threads".to_string(),
                    description: "Number of CPU stress threads (max 4)".to_string(),
                    required: false,
                    default: Some("2".to_string()),
                },
                TechniqueParameter {
                    name: "memory_mb".to_string(),
                    description: "Memory to allocate in MB (max 500)".to_string(),
                    required: false,
                    default: Some("100".to_string()),
                },
                TechniqueParameter {
                    name: "disk_io_files".to_string(),
                    description: "Number of temp files for disk I/O stress (max 100)".to_string(),
                    required: false,
                    default: Some("20".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save resource hijacking log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_resource_hijacking.log".to_string()),
                },
            ],
            detection: "Monitor for sustained high CPU usage from unexpected processes, unusual memory allocation patterns, rapid file creation/deletion cycles in /tmp/, processes performing cryptographic hashing operations, suspicious resource consumption spikes, and process names resembling crypto miners. Watch for sudden system resource exhaustion.".to_string(),
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
            let duration_seconds = config
                .parameters
                .get("duration_seconds")
                .unwrap_or(&"10".to_string())
                .parse::<u64>()
                .unwrap_or(10)
                .min(30);
            
            let cpu_threads = config
                .parameters
                .get("cpu_threads")
                .unwrap_or(&"2".to_string())
                .parse::<usize>()
                .unwrap_or(2)
                .min(4);
            
            let memory_mb = config
                .parameters
                .get("memory_mb")
                .unwrap_or(&"100".to_string())
                .parse::<usize>()
                .unwrap_or(100)
                .min(500);
            
            let disk_io_files = config
                .parameters
                .get("disk_io_files")
                .unwrap_or(&"20".to_string())
                .parse::<usize>()
                .unwrap_or(20)
                .min(100);
            
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_resource_hijacking.log".to_string())
                .clone();
            
            let session_id = Uuid::new_v4().to_string().replace("-", "");
            let temp_dir = format!("/tmp/signalbench_io_stress_{session_id}");
            
            if dry_run {
                info!("[DRY RUN] Would perform resource hijacking simulation:");
                info!("[DRY RUN]   Duration: {duration_seconds}s (max 30s)");
                info!("[DRY RUN]   CPU threads: {cpu_threads} (SHA256 hashing)");
                info!("[DRY RUN]   Memory: {memory_mb}MB (max 500MB)");
                info!("[DRY RUN]   Disk I/O: {disk_io_files} files");
                info!("[DRY RUN]   Temp directory: {temp_dir}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would simulate cryptocurrency mining with CPU/memory/disk stress".to_string(),
                    artifacts: vec![temp_dir, log_file],
                    cleanup_required: false,
                });
            }

            info!("Starting resource hijacking simulation (Session: {session_id})...");
            info!("Duration: {duration_seconds}s, CPU threads: {cpu_threads}, Memory: {memory_mb}MB, Disk I/O: {disk_io_files} files");
            
            let mut log = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
            
            writeln!(log, "=== SignalBench Resource Hijacking Simulation ===").unwrap();
            writeln!(log, "Session ID: {session_id}").unwrap();
            writeln!(log, "Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log, "Duration: {duration_seconds}s").unwrap();
            writeln!(log, "CPU threads: {cpu_threads}").unwrap();
            writeln!(log, "Memory allocation: {memory_mb}MB").unwrap();
            writeln!(log, "Disk I/O files: {disk_io_files}").unwrap();
            writeln!(log).unwrap();
            
            let artifacts = vec![log_file.clone(), temp_dir.clone()];
            
            // Create temp directory for disk I/O stress
            fs::create_dir_all(&temp_dir)
                .map_err(|e| format!("Failed to create temp directory: {e}"))?;
            
            let start_time = std::time::Instant::now();
            let stop_flag = Arc::new(AtomicBool::new(false));
            
            // Phase 1: CPU Stress - SHA256 hashing (simulates crypto mining)
            info!("Phase 1: Starting CPU stress with {cpu_threads} SHA256 hashing threads...");
            writeln!(log, "=== Phase 1: CPU Stress (SHA256 Hashing) ===").unwrap();
            
            let mut cpu_handles = Vec::new();
            for thread_id in 0..cpu_threads {
                let stop_flag_clone = Arc::clone(&stop_flag);
                let handle = tokio::spawn(async move {
                    let mut hasher = Sha256::new();
                    let mut counter = 0u64;
                    let data = b"SignalBench cryptocurrency mining simulation - MITRE ATT&CK T1496";
                    
                    while !stop_flag_clone.load(Ordering::Relaxed) {
                        hasher.update(data);
                        hasher.update(counter.to_le_bytes());
                        let _hash = hasher.finalize_reset();
                        counter = counter.wrapping_add(1);
                        
                        if counter.is_multiple_of(100000) {
                            tokio::task::yield_now().await;
                        }
                    }
                    
                    counter
                });
                cpu_handles.push(handle);
                info!("Started CPU stress thread {thread_id}");
                writeln!(log, "Started CPU stress thread {thread_id}").unwrap();
            }
            
            // Phase 2: Memory Stress - Allocate memory blocks
            info!("Phase 2: Allocating {memory_mb}MB of memory...");
            writeln!(log, "\n=== Phase 2: Memory Stress ===").unwrap();
            writeln!(log, "Allocating {memory_mb}MB in 100MB chunks...").unwrap();
            
            let mut memory_blocks: Vec<Vec<u8>> = Vec::new();
            let chunks = (memory_mb / 100).max(1);
            
            for chunk_id in 0..chunks {
                let chunk_size = if chunk_id == chunks - 1 {
                    (memory_mb % 100) * 1024 * 1024
                } else {
                    100 * 1024 * 1024
                };
                
                if chunk_size > 0 {
                    let block = vec![0u8; chunk_size];
                    memory_blocks.push(block);
                    info!("Allocated memory chunk {chunk_id} ({chunk_size} bytes)");
                    writeln!(log, "Allocated memory chunk {chunk_id} ({chunk_size} bytes)").unwrap();
                }
            }
            
            // Phase 3: Disk I/O Stress
            info!("Phase 3: Starting disk I/O stress with {disk_io_files} files...");
            writeln!(log, "\n=== Phase 3: Disk I/O Stress ===").unwrap();
            
            let mut io_file_paths = Vec::new();
            for file_id in 0..disk_io_files {
                let file_path = format!("{temp_dir}/stress_file_{file_id}.tmp");
                let data = vec![0xAA; 1024 * 1024]; // 1MB per file
                
                match fs::write(&file_path, &data) {
                    Ok(_) => {
                        io_file_paths.push(file_path.clone());
                        if file_id % 10 == 0 {
                            info!("Created I/O stress file {} of {}", file_id + 1, disk_io_files);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to create stress file {file_id}: {e}");
                    }
                }
            }
            
            writeln!(log, "Created {} I/O stress files", io_file_paths.len()).unwrap();
            
            // Monitor and wait for duration
            info!("Resource stress active for {duration_seconds} seconds...");
            writeln!(log, "\n=== Monitoring Resource Usage ===").unwrap();
            
            let monitor_interval = (duration_seconds / 5).max(1);
            for i in 0..duration_seconds {
                sleep(Duration::from_secs(1)).await;
                
                if i % monitor_interval == 0 {
                    let elapsed = start_time.elapsed().as_secs();
                    info!("Resource stress ongoing... ({elapsed}s / {duration_seconds}s)");
                    writeln!(log, "Timestamp +{elapsed}s: Resource stress active").unwrap();
                }
            }
            
            // Stop CPU stress threads
            info!("Stopping CPU stress threads...");
            writeln!(log, "\n=== Stopping Resource Stress ===").unwrap();
            stop_flag.store(true, Ordering::Relaxed);
            
            let mut total_hashes = 0u64;
            for (thread_id, handle) in cpu_handles.into_iter().enumerate() {
                if let Ok(hashes) = handle.await {
                    total_hashes += hashes;
                    info!("CPU thread {thread_id} completed {hashes} hash operations");
                    writeln!(log, "CPU thread {thread_id} completed {hashes} hash operations").unwrap();
                }
            }
            
            info!("Total SHA256 hash operations: {total_hashes}");
            writeln!(log, "Total SHA256 hash operations: {total_hashes}").unwrap();
            
            // Release memory
            info!("Releasing {memory_mb}MB of allocated memory...");
            writeln!(log, "Releasing {memory_mb}MB of allocated memory...").unwrap();
            drop(memory_blocks);
            
            // Delete I/O stress files
            info!("Cleaning up {} I/O stress files...", io_file_paths.len());
            writeln!(log, "Cleaning up {} I/O stress files...", io_file_paths.len()).unwrap();
            
            for file_path in &io_file_paths {
                let _ = fs::remove_file(file_path);
            }
            
            let total_duration = start_time.elapsed();
            writeln!(log, "\n=== Summary ===").unwrap();
            writeln!(log, "Total duration: {:.2}s", total_duration.as_secs_f64()).unwrap();
            writeln!(log, "CPU threads: {cpu_threads}").unwrap();
            writeln!(log, "Total hashes: {total_hashes}").unwrap();
            writeln!(log, "Peak memory: {memory_mb}MB").unwrap();
            writeln!(log, "I/O files created: {}", io_file_paths.len()).unwrap();
            
            info!("Resource hijacking simulation completed successfully");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!(
                    "Resource hijacking simulation completed: {} CPU threads, {}MB memory, {} I/O files, {} hash operations over {:.1}s",
                    cpu_threads,
                    memory_mb,
                    io_file_paths.len(),
                    total_hashes,
                    total_duration.as_secs_f64()
                ),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting cleanup of resource hijacking artifacts...");
            
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if Path::new(artifact).is_dir() {
                        match fs::remove_dir_all(artifact) {
                            Ok(_) => info!("Removed temp directory: {artifact}"),
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
            
            info!("Resource hijacking cleanup completed");
            Ok(())
        })
    }
}
