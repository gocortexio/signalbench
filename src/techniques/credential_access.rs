use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

pub struct MemoryDumping {}

#[async_trait]
impl AttackTechnique for MemoryDumping {
    fn info(&self) -> Technique {
        Technique {
            id: "T1003.001".to_string(),
            name: "Memory Dumping".to_string(),
            description: "Emulates memory dumping patterns for credential access analysis".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_pid".to_string(),
                    description: "PID of process to dump memory from (0 = self)".to_string(),
                    required: false,
                    default: Some("0".to_string()),
                },
                TechniqueParameter {
                    name: "dump_file".to_string(),
                    description: "Path to save memory dump file".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_memory_dump".to_string()),
                },
            ],
            detection: "Monitor for memory dumping utilities and suspicious access to process memory".to_string(),
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
            let target_pid = config
                .parameters
                .get("target_pid")
                .unwrap_or(&"0".to_string())
                .clone();
                
            let dump_file = config
                .parameters
                .get("dump_file")
                .unwrap_or(&"/tmp/signalbench_memory_dump".to_string())
                .clone();
            
            let pid = if target_pid == "0" {
                std::process::id().to_string()
            } else {
                target_pid
            };
            
            if dry_run {
                info!("[DRY RUN] Would dump memory from process with PID: {pid}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would dump memory from process with PID: {pid}"),
                    artifacts: vec![dump_file],
                    cleanup_required: false,
                });
            }

            // Create test memory dump file
            let mut file = File::create(&dump_file)
                .map_err(|e| format!("Failed to create memory dump file: {e}"))?;
            
            // Write header
            writeln!(file, "=== SignalBench Memory Dump ===")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "Time: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "Target PID: {pid}")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            
            // Create test memory dump content with sample credentials
            writeln!(file, "00000000: 7573 6572 6e61 6d65 3d61 646d 696e 0000  username=admin..")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "00000010: 7061 7373 776f 7264 3d50 4073 7357 6f72  password=P@ssWor")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "00000020: 6431 3233 2100 0000 0000 0000 0000 0000  d123!...........")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "00000030: 4241 5349 435f 4155 5448 3a61 646d 696e  BASIC_AUTH:admin")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "00000040: 3a73 6563 7265 7431 3233 0000 0000 0000  :secret123......")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "00000050: 6f61 7574 685f 746f 6b65 6e3d 6579 4a68  oauth_token=eyJh")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "00000060: 6263 6465 6667 6869 6a6b 6c6d 6e6f 7071  bcdefghijklmnopq")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            
            // Add realistic delay while dumping memory
            info!("Generating memory dump telemetry for process {pid}, this may take a moment...");
            sleep(Duration::from_millis(1500)).await;
            
            info!("Memory dump complete, saved to: {dump_file}");
            
            // Generate extracted credential sample data
            writeln!(file, "\n=== Extracted Credentials ===")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "Username: admin")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "Password: P@ssW0rd123!")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "Basic Auth: admin:secret123")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            writeln!(file, "OAuth Token: eyJhbcdefghijklmnopq...")
                .map_err(|e| format!("Failed to write to memory dump: {e}"))?;
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully dumped memory from process {pid} and extracted credentials"),
                artifacts: vec![dump_file],
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

pub struct KeyloggerSimulation {}

#[async_trait]
impl AttackTechnique for KeyloggerSimulation {
    fn info(&self) -> Technique {
        Technique {
            id: "T1056.001".to_string(),
            name: "Keylogging".to_string(),
            description: "Emulates keylogging patterns for credential capture analysis".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save keylogger output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_keylogger.log".to_string()),
                },
                TechniqueParameter {
                    name: "duration".to_string(),
                    description: "Duration to run keylogger telemetry generation (seconds)".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
            ],
            detection: "Monitor for processes reading keyboard device files or using suspicious APIs".to_string(),
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
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_keylogger.log".to_string())
                .clone();
                
            let duration_str = config
                .parameters
                .get("duration")
                .unwrap_or(&"5".to_string())
                .clone();
                
            let duration = duration_str.parse::<u64>().unwrap_or(5);
            
            if dry_run {
                info!("[DRY RUN] Would run keylogger for {duration} seconds");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would run keylogger for {duration} seconds"),
                    artifacts: vec![log_file],
                    cleanup_required: false,
                });
            }

            // Create test keylogger log file
            let mut file = File::create(&log_file)
                .map_err(|e| format!("Failed to create keylogger log file: {e}"))?;
            
            // Write header
            writeln!(file, "=== SignalBench Keylogger ===")
                .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
            writeln!(file, "Started: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
            writeln!(file)
                .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
            
            // Generate keylogger telemetry
            info!("Simulating keylogger running for {duration} seconds...");
            
            // Simulate capturing keystrokes
            let keystrokes = vec![
                (1, "[CTRL+ALT+T]"), 
                (1, "ssh admin@server.example.com\n"),
                (2, "P@ssw0rd123!\n"),
                (1, "sudo -i\n"),
                (1, "SuperSecretR00tPW!\n"),
                (2, "mysql -u dbadmin -p\n"),
                (1, "dbP@ssw0rd!\n"),
                (1, "[ALT+TAB]"),
                (1, "[BROWSER URL] https://admin.example.com\n"),
                (1, "[FORM FIELD] username: admin\n"),
                (2, "[FORM FIELD] password: Ex@mpleAdm1nPW\n"),
                (1, "[MOUSE CLICK] Login\n"),
            ];
            
            let mut total_delay = 0;
            
            for (delay, keystroke) in keystrokes {
                if total_delay >= duration {
                    break;
                }
                
                let timestamp = chrono::Local::now().format("%H:%M:%S%.3f").to_string();
                writeln!(file, "[{timestamp}] {keystroke}")
                    .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
                
                sleep(Duration::from_secs(delay)).await;
                total_delay += delay;
            }
            
            // Write footer
            writeln!(file)
                .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
            writeln!(file, "Ended: {}", chrono::Local::now().to_rfc3339())
                .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
            writeln!(file, "=== Keylogger Stopped ===")
                .map_err(|e| format!("Failed to write to keylogger log: {e}"))?;
            
            info!("Keylogger simulation complete, log saved to: {log_file}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully simulated keylogger for {duration} seconds and captured credentials"),
                artifacts: vec![log_file],
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

pub struct CredentialsInFiles {}

#[async_trait]
impl AttackTechnique for CredentialsInFiles {
    fn info(&self) -> Technique {
        Technique {
            id: "T1552.001".to_string(),
            name: "Credentials in Files".to_string(),
            description: "Harvesting hardcoded passwords, API tokens, or service credentials from config files (/etc/, .env)".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_file".to_string(),
                    description: "File to save discovered credentials".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_discovered_credentials.log".to_string()),
                },
            ],
            detection: "Monitor for processes accessing configuration files, unusual file access patterns, or credential harvesting tools".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_file = config.parameters.get("output_file").unwrap_or(&"/tmp/signalbench_discovered_credentials.log".to_string()).clone();
            
            if dry_run {
                info!("[DRY RUN] Would search for credentials in config files");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would search for credentials in config files".to_string(),
                    artifacts: vec![output_file],
                    cleanup_required: false,
                });
            }

            let test_dir = "/tmp/signalbench_cred_test";
            if !Path::new(test_dir).exists() {
                fs::create_dir_all(test_dir).map_err(|e| format!("Failed to create test directory: {e}"))?;
            }

            let test_env_file = format!("{test_dir}/.env");
            let env_content = "DATABASE_URL=postgresql://testuser:testpass123@localhost:5432/testdb\nAPI_KEY=sk_test_1234567890abcdef\n";
            let mut env_file = File::create(&test_env_file).map_err(|e| format!("Failed to create test file: {e}"))?;
            env_file.write_all(env_content.as_bytes()).map_err(|e| format!("Failed to write test content: {e}"))?;

            let mut output = File::create(&output_file).map_err(|e| format!("Failed to create output file: {e}"))?;
            writeln!(output, "=== SIGNALBENCH CREDENTIAL DISCOVERY ===").map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(output, "Found test credentials in: {test_env_file}").map_err(|e| format!("Failed to write: {e}"))?;
            writeln!(output, "NOTE: Harmless simulation for EDR testing.").map_err(|e| format!("Failed to write: {e}"))?;

            info!("Credential discovery simulation complete");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: "Successfully discovered test credentials (harmless simulation)".to_string(),
                artifacts: vec![output_file, test_env_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    let _ = fs::remove_file(artifact);
                }
            }
            let _ = fs::remove_dir_all("/tmp/signalbench_cred_test");
            Ok(())
        })
    }
}

// ======================================
// T1003.007 - OS Credential Dumping: Proc Filesystem
// ======================================
pub struct ProcFilesystemCredentialDumping {}

#[async_trait]
impl AttackTechnique for ProcFilesystemCredentialDumping {
    fn info(&self) -> Technique {
        Technique {
            id: "T1003.007".to_string(),
            name: "OS Credential Dumping: Proc Filesystem".to_string(),
            description: "Uses dd utility and /proc filesystem to analyze process memory for credential patterns".to_string(),
            category: "credential_access".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "target_processes".to_string(),
                    description: "Comma-separated list of process names to target".to_string(),
                    required: false,
                    default: Some("firefox,chrome,ssh,sshd,apache2,nginx".to_string()),
                },
                TechniqueParameter {
                    name: "memory_dump_size".to_string(),
                    description: "Size of memory to extract per process (bytes)".to_string(),
                    required: false,
                    default: Some("4096".to_string()),
                },
                TechniqueParameter {
                    name: "max_processes".to_string(),
                    description: "Maximum number of processes to analyze".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save detailed analysis logs".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_proc_dump.log".to_string()),
                },
                TechniqueParameter {
                    name: "search_patterns".to_string(),
                    description: "Credential patterns to search for (password,token,key)".to_string(),
                    required: false,
                    default: Some("password,token,key,auth,credential".to_string()),
                },
            ],
            detection: "Monitor dd command usage on /proc/<PID>/mem files, excessive /proc filesystem access, memory mapping enumeration, and process memory analysis".to_string(),
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
            let target_processes = config
                .parameters
                .get("target_processes")
                .unwrap_or(&"firefox,chrome,ssh,sshd,apache2,nginx".to_string())
                .clone();
                
            let memory_dump_size = config
                .parameters
                .get("memory_dump_size")
                .unwrap_or(&"4096".to_string())
                .parse::<usize>()
                .unwrap_or(4096);
                
            let max_processes = config
                .parameters
                .get("max_processes")
                .unwrap_or(&"5".to_string())
                .parse::<usize>()
                .unwrap_or(5);
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_proc_dump.log".to_string())
                .clone();
                
            let search_patterns = config
                .parameters
                .get("search_patterns")
                .unwrap_or(&"password,token,key,auth,credential".to_string())
                .clone();

            let session_id = Uuid::new_v4().to_string().split('-').next().unwrap_or("signalbench").to_string();
            let dump_dir = format!("/tmp/signalbench_proc_dumps_{session_id}");
            
            if dry_run {
                info!("[DRY RUN] Would analyze /proc filesystem for credentials");
                info!("[DRY RUN] Target processes: {target_processes}");
                info!("[DRY RUN] Memory dump size per process: {memory_dump_size} bytes");
                info!("[DRY RUN] Would create dumps in: {dump_dir}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would analyze /proc filesystem for {max_processes} target processes"),
                    artifacts: vec![log_file, dump_dir],
                    cleanup_required: false,
                });
            }

            // Create dump directory
            fs::create_dir_all(&dump_dir)
                .map_err(|e| format!("Failed to create dump directory: {e}"))?;

            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            writeln!(log_file_handle, "# SignalBench /proc Filesystem Credential Dumping").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK: T1003.007").unwrap();
            writeln!(log_file_handle, "# Target Processes: {}", target_processes).unwrap();
            writeln!(log_file_handle, "# Memory Dump Size: {} bytes", memory_dump_size).unwrap();
            writeln!(log_file_handle, "# Search Patterns: {}", search_patterns).unwrap();
            writeln!(log_file_handle, "# Session ID: {}", session_id).unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();

            // Enumerate processes from /proc
            writeln!(log_file_handle, "\n## Process Enumeration").unwrap();
            
            let proc_entries = fs::read_dir("/proc")
                .map_err(|e| format!("Failed to read /proc directory: {e}"))?;
                
            let target_process_list: Vec<&str> = target_processes.split(',').collect();
            let mut found_processes = Vec::new();
            
            for entry in proc_entries {
                if found_processes.len() >= max_processes {
                    break;
                }
                
                if let Ok(entry) = entry {
                    if let Ok(file_name) = entry.file_name().into_string() {
                        if let Ok(pid) = file_name.parse::<u32>() {
                            // Try to read process name
                            let comm_path = format!("/proc/{}/comm", pid);
                            if let Ok(comm_content) = fs::read_to_string(&comm_path) {
                                let process_name = comm_content.trim();
                                
                                // Check if this process is in our target list
                                if target_process_list.iter().any(|&target| process_name.contains(target)) {
                                    found_processes.push((pid, process_name.to_string()));
                                    writeln!(log_file_handle, "Found target process: {} (PID: {})", process_name, pid).unwrap();
                                }
                            }
                        }
                    }
                }
            }

            writeln!(log_file_handle, "Total target processes found: {}", found_processes.len()).unwrap();

            // If no target processes found, use current process for simulation
            if found_processes.is_empty() {
                let current_pid = std::process::id();
                found_processes.push((current_pid, "signalbench".to_string()));
                writeln!(log_file_handle, "No target processes found, using current process: signalbench (PID: {})", current_pid).unwrap();
            }

            let search_pattern_list: Vec<&str> = search_patterns.split(',').collect();
            let mut total_credentials_found = 0;

            // Analyze each process
            for (pid, process_name) in &found_processes {
                writeln!(log_file_handle, "\n## Analyzing Process: {} (PID: {})", process_name, pid).unwrap();
                
                // Read memory maps
                let maps_path = format!("/proc/{}/maps", pid);
                let maps_result = fs::read_to_string(&maps_path);
                
                match maps_result {
                    Ok(maps_content) => {
                        writeln!(log_file_handle, "Successfully read memory maps for PID {}", pid).unwrap();
                        
                        // Parse readable memory regions
                        let readable_regions: Vec<_> = maps_content
                            .lines()
                            .filter(|line| line.contains(" r"))
                            .take(3) // Limit to first 3 readable regions
                            .collect();
                            
                        writeln!(log_file_handle, "Found {} readable memory regions", readable_regions.len()).unwrap();
                        
                        for (index, region) in readable_regions.iter().enumerate() {
                            writeln!(log_file_handle, "Memory region {}: {}", index + 1, region).unwrap();
                            
                            // Extract memory address range
                            if let Some(addr_range) = region.split_whitespace().next() {
                                if let Some(dash_pos) = addr_range.find('-') {
                                    let start_addr = &addr_range[..dash_pos];
                                    
                                    if let Ok(start_offset) = u64::from_str_radix(start_addr, 16) {
                                        // Use dd to copy memory segment
                                        let mem_dump_file = format!("{}/proc_{}_region_{}.dump", dump_dir, pid, index);
                                        
                                        writeln!(log_file_handle, "Attempting dd memory extraction from offset 0x{:x}", start_offset).unwrap();
                                        
                                        let dd_command = Command::new("dd")
                                            .arg(format!("if=/proc/{}/mem", pid))
                                            .arg(format!("of={}", mem_dump_file))
                                            .arg(format!("bs={}", memory_dump_size))
                                            .arg("count=1")
                                            .arg(format!("skip={}", start_offset / memory_dump_size as u64))
                                            .arg("conv=noerror")
                                            .output()
                                            .await;
                                            
                                        match dd_command {
                                            Ok(output) => {
                                                let exit_code = output.status.code().unwrap_or(-1);
                                                writeln!(log_file_handle, "dd command exit code: {}", exit_code).unwrap();
                                                
                                                if exit_code == 0 && Path::new(&mem_dump_file).exists() {
                                                    // Read the dumped memory and search for patterns
                                                    if let Ok(mut dump_content) = fs::read(&mem_dump_file) {
                                                        // Truncate to readable size for pattern matching
                                                        dump_content.truncate(memory_dump_size);
                                                        let content_str = String::from_utf8_lossy(&dump_content);
                                                        
                                                        // Search for credential patterns
                                                        for pattern in &search_pattern_list {
                                                            if content_str.to_lowercase().contains(pattern) {
                                                                total_credentials_found += 1;
                                                                writeln!(log_file_handle, "CREDENTIAL PATTERN FOUND: '{}' in memory region {}", pattern, index + 1).unwrap();
                                                                
                                                                // Create simulated credential finding
                                                                let cred_context = match pattern.trim() {
                                                                    "password" => "username=testuser password=SimulatedP@ss123",
                                                                    "token" => "auth_token=sim_tk_1234567890abcdef",
                                                                    "key" => "api_key=sim_key_abcdef1234567890",
                                                                    "auth" => "basic_auth=dGVzdDpwYXNzd29yZA==",
                                                                    _ => "credential_data=simulation_value"
                                                                };
                                                                writeln!(log_file_handle, "Context: {}", cred_context).unwrap();
                                                            }
                                                        }
                                                        
                                                        // Log memory dump details
                                                        writeln!(log_file_handle, "Memory dump saved: {} ({} bytes)", mem_dump_file, dump_content.len()).unwrap();
                                                    }
                                                } else {
                                                    writeln!(log_file_handle, "dd command failed or produced no output").unwrap();
                                                }
                                            },
                                            Err(e) => {
                                                writeln!(log_file_handle, "Failed to execute dd command: {}", e).unwrap();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                        writeln!(log_file_handle, "Failed to read memory maps for PID {}: {}", pid, e).unwrap();
                    }
                }
                
                // Small delay between processes
                sleep(Duration::from_millis(500)).await;
            }

            // Generate summary
            writeln!(log_file_handle, "\n## Analysis Summary").unwrap();
            writeln!(log_file_handle, "Processes analyzed: {}", found_processes.len()).unwrap();
            writeln!(log_file_handle, "Total credential patterns found: {}", total_credentials_found).unwrap();
            writeln!(log_file_handle, "Memory dumps stored in: {}", dump_dir).unwrap();
            writeln!(log_file_handle, "\nNOTE: All credential findings are simulated for telemetry generation").unwrap();

            info!("/proc filesystem credential analysis complete. Found {} credential patterns.", total_credentials_found);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully analyzed {} processes and found {} credential patterns using /proc filesystem", found_processes.len(), total_credentials_found),
                artifacts: vec![log_file, dump_dir],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    if artifact.contains("signalbench_proc_dumps_") {
                        // Remove dump directory and all contents
                        if let Err(e) = fs::remove_dir_all(artifact) {
                            warn!("Failed to remove dump directory {artifact}: {e}");
                        } else {
                            info!("Removed dump directory: {artifact}");
                        }
                    } else {
                        // Remove single file
                        if let Err(e) = fs::remove_file(artifact) {
                            warn!("Failed to remove artifact {artifact}: {e}");
                        } else {
                            info!("Removed artifact: {artifact}");
                        }
                    }
                }
            }
            Ok(())
        })
    }
}
