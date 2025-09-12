// SNELLEN - EDR Testing Framework
// Obfuscated Files or Information (T1027)
// 
// This module implements file and code obfuscation techniques
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
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// ======================================
// T1027 - Obfuscated Files or Information
// ======================================
pub struct ObfuscatedFilesAndInformation {}

#[async_trait]
impl AttackTechnique for ObfuscatedFilesAndInformation {
    fn info(&self) -> Technique {
        Technique {
            id: "T1027".to_string(),
            name: "Obfuscated Files or Information".to_string(),
            description: "Employs various obfuscation techniques to evade detection mechanisms".to_string(),
            category: "DEFENSE_EVASION".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "obfuscation_type".to_string(),
                    description: "Type of obfuscation to perform (encoding, encryption, packing, string)".to_string(),
                    required: false,
                    default: Some("encoding".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory to save obfuscated files".to_string(),
                    required: false,
                    default: Some("/tmp/snellen_obfuscation".to_string()),
                },
                TechniqueParameter {
                    name: "log_file".to_string(),
                    description: "Path to save obfuscation log".to_string(),
                    required: false,
                    default: Some("/tmp/snellen_obfuscation.log".to_string()),
                },
                TechniqueParameter {
                    name: "execute_after".to_string(),
                    description: "Whether to attempt execution of obfuscated files".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Heuristic analysis can sometimes detect obfuscated files, code, or unusual encoding patterns".to_string(),
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
            let technique_info = self.info();
            
            // Get parameters from config or use defaults
            let obfuscation_type = config
                .parameters
                .get("obfuscation_type")
                .unwrap_or(&"encoding".to_string())
                .clone()
                .to_lowercase();
                
            let output_dir = config
                .parameters
                .get("output_dir")
                .unwrap_or(&"/tmp/snellen_obfuscation".to_string())
                .clone();
                
            let log_file = config
                .parameters
                .get("log_file")
                .unwrap_or(&"/tmp/snellen_obfuscation.log".to_string())
                .clone();
                
            let execute_after = config
                .parameters
                .get("execute_after")
                .unwrap_or(&"true".to_string())
                .clone()
                .to_lowercase() == "true";
            
            // Create artifact list for cleanup
            let mut artifacts = vec![log_file.clone(), output_dir.clone()];
            
            if dry_run {
                return Ok(SimulationResult {
                    technique_id: technique_info.id,
                    success: true,
                    message: format!("Would perform {obfuscation_type} obfuscation and save to {output_dir}, execute after: {execute_after}"),
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
            writeln!(log_file_handle, "# SNELLEN Obfuscated Files and Information Simulation").unwrap();
            writeln!(log_file_handle, "# MITRE ATT&CK Technique: T1027").unwrap();
            writeln!(log_file_handle, "# Obfuscation Type: {obfuscation_type}").unwrap();
            writeln!(log_file_handle, "# Output Directory: {output_dir}").unwrap();
            writeln!(log_file_handle, "# Execute After Obfuscation: {execute_after}").unwrap();
            writeln!(log_file_handle, "# Timestamp: {}", chrono::Local::now()).unwrap();
            writeln!(log_file_handle, "# --------------------------------------------------------").unwrap();
            
            // Different techniques based on obfuscation type
            match obfuscation_type.as_str() {
                "encoding" => {
                    writeln!(log_file_handle, "\n## Encoding Obfuscation Techniques").unwrap();
                    
                    // 1. Base64 encoding of a shell script
                    writeln!(log_file_handle, "\n1. Base64 Encoding a Shell Script").unwrap();
                    
                    // Create a test script
                    let script_file = format!("{output_dir}/original_script.sh");
                    let test_script = r#"#!/bin/bash
# This is a test script that would be obfuscated
echo "Snellen Obfuscation Test - Base64 Encoding" > /tmp/snellen_b64_decoded_executed
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
echo "Hostname: $(hostname)"
# In a real scenario, this could be a malicious payload
"#;
                    
                    if let Err(e) = std::fs::write(&script_file, test_script) {
                        writeln!(log_file_handle, "Failed to write test script: {e}").unwrap();
                    } else {
                        artifacts.push(script_file.clone());
                        artifacts.push("/tmp/snellen_b64_decoded_executed".to_string());
                        
                        // Encode the script with base64
                        let encoded_script = BASE64.encode(test_script);
                        let encoded_file = format!("{output_dir}/encoded_script.b64");
                        
                        if let Err(e) = std::fs::write(&encoded_file, &encoded_script) {
                            writeln!(log_file_handle, "Failed to write encoded script: {e}").unwrap();
                        } else {
                            artifacts.push(encoded_file.clone());
                            
                            writeln!(log_file_handle, "Original script: {script_file}").unwrap();
                            writeln!(log_file_handle, "Encoded script: {encoded_file}").unwrap();
                            
                            // Create a loader script that decodes and executes
                            let loader_file = format!("{output_dir}/b64_loader.sh");
                            let loader_script = format!(r#"#!/bin/bash
# This script decodes and executes a base64 encoded payload
# In real attacks, this could be used to evade detection

# Encoded payload
B64_PAYLOAD="{encoded_script}"

# Decode and execute
echo "$B64_PAYLOAD" | base64 -d | bash

echo "Base64 loader executed successfully"
"#);
                            
                            if let Err(e) = std::fs::write(&loader_file, loader_script) {
                                writeln!(log_file_handle, "Failed to write loader script: {e}").unwrap();
                            } else {
                                artifacts.push(loader_file.clone());
                                
                                // Make executable
                                let chmod_cmd = format!("chmod +x {loader_file}");
                                let _ = Command::new("bash")
                                    .arg("-c")
                                    .arg(&chmod_cmd)
                                    .output()
                                    .await;
                                
                                writeln!(log_file_handle, "Loader script created: {loader_file}").unwrap();
                                
                                // Execute if requested
                                if execute_after {
                                    writeln!(log_file_handle, "Executing loader script...").unwrap();
                                    
                                    let exec_output = Command::new("bash")
                                        .arg("-c")
                                        .arg(&loader_file)
                                        .output()
                                        .await;
                                        
                                    match exec_output {
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
                                }
                            }
                        }
                    }
                    
                    // 2. Hex encoding of a script
                    writeln!(log_file_handle, "\n2. Hex Encoding a Shell Script").unwrap();
                    
                    // Create another test script
                    let script_file = format!("{output_dir}/original_script2.sh");
                    let test_script = r#"#!/bin/bash
# This is another test script for hex encoding
echo "Snellen Obfuscation Test - Hex Encoding" > /tmp/snellen_hex_decoded_executed
echo "Current time: $(date)"
echo "Operating system: $(uname -a)"
# In a real scenario, this could be malicious code
"#;
                    
                    if let Err(e) = std::fs::write(&script_file, test_script) {
                        writeln!(log_file_handle, "Failed to write test script: {e}").unwrap();
                    } else {
                        artifacts.push(script_file.clone());
                        artifacts.push("/tmp/snellen_hex_decoded_executed".to_string());
                        
                        // Encode the script with hex
                        let encoded_script = hex::encode(test_script);
                        let encoded_file = format!("{output_dir}/encoded_script.hex");
                        
                        if let Err(e) = std::fs::write(&encoded_file, &encoded_script) {
                            writeln!(log_file_handle, "Failed to write hex encoded script: {e}").unwrap();
                        } else {
                            artifacts.push(encoded_file.clone());
                            
                            writeln!(log_file_handle, "Original script: {script_file}").unwrap();
                            writeln!(log_file_handle, "Hex encoded script: {encoded_file}").unwrap();
                            
                            // Create a loader script that decodes and executes
                            let loader_file = format!("{output_dir}/hex_loader.sh");
                            let loader_script = format!(r#"#!/bin/bash
# This script decodes and executes a hex encoded payload

# Encoded payload
HEX_PAYLOAD="{encoded_script}"

# Decode and execute
echo "$HEX_PAYLOAD" | xxd -r -p | bash

echo "Hex loader executed successfully"
"#);
                            
                            if let Err(e) = std::fs::write(&loader_file, loader_script) {
                                writeln!(log_file_handle, "Failed to write hex loader script: {e}").unwrap();
                            } else {
                                artifacts.push(loader_file.clone());
                                
                                // Make executable
                                let chmod_cmd = format!("chmod +x {loader_file}");
                                let _ = Command::new("bash")
                                    .arg("-c")
                                    .arg(&chmod_cmd)
                                    .output()
                                    .await;
                                
                                writeln!(log_file_handle, "Hex loader script created: {loader_file}").unwrap();
                                
                                // Execute if requested
                                if execute_after {
                                    writeln!(log_file_handle, "Executing hex loader script...").unwrap();
                                    
                                    let exec_output = Command::new("bash")
                                        .arg("-c")
                                        .arg(&loader_file)
                                        .output()
                                        .await;
                                        
                                    match exec_output {
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
                                }
                            }
                        }
                    }
                },
                "encryption" => {
                    writeln!(log_file_handle, "\n## Encryption Obfuscation Techniques").unwrap();
                    
                    // Create a test executable
                    let bin_file = format!("{output_dir}/original_executable");
                    let test_executable = r#"#!/bin/bash
echo "Snellen Obfuscation Test - Encrypted Executable" > /tmp/snellen_decrypted_executed
echo "This simulates a decrypted and executed payload"
echo "Current user: $(whoami)"
echo "Date and time: $(date)"
"#;
                    
                    if let Err(e) = std::fs::write(&bin_file, test_executable) {
                        writeln!(log_file_handle, "Failed to write test executable: {e}").unwrap();
                    } else {
                        artifacts.push(bin_file.clone());
                        artifacts.push("/tmp/snellen_decrypted_executed".to_string());
                        
                        // Make it executable
                        let chmod_cmd = format!("chmod +x {bin_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                        
                        // "Encrypt" the executable with password (simulated using OpenSSL)
                        let encrypted_file = format!("{output_dir}/encrypted_executable.enc");
                        let encryption_password = "snellen-test-password";
                        
                        let encrypt_cmd = format!("openssl enc -aes-256-cbc -salt -in {bin_file} -out {encrypted_file} -k {encryption_password}");
                        
                        let encrypt_output = Command::new("bash")
                            .arg("-c")
                            .arg(&encrypt_cmd)
                            .output()
                            .await;
                            
                        match encrypt_output {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(-1);
                                
                                if exit_code == 0 {
                                    artifacts.push(encrypted_file.clone());
                                    
                                    writeln!(log_file_handle, "Original executable: {bin_file}").unwrap();
                                    writeln!(log_file_handle, "Encrypted executable: {encrypted_file}").unwrap();
                                    writeln!(log_file_handle, "Encryption password: {encryption_password}").unwrap();
                                    
                                    // Create a loader script that decrypts and executes
                                    let loader_file = format!("{output_dir}/decrypt_and_execute.sh");
                                    let loader_script = format!(r#"#!/bin/bash
# This script decrypts and executes an encrypted payload
# In real attacks, this could be used to bypass AV/EDR detection

# Encrypted file path
ENCRYPTED_FILE="{encrypted_file}"
# Decrypted output path
DECRYPTED_FILE="{output_dir}/decrypted_executable"
# Encryption password
PASSWORD="{encryption_password}"

# Decrypt the file
openssl enc -aes-256-cbc -d -in "$ENCRYPTED_FILE" -out "$DECRYPTED_FILE" -k "$PASSWORD"

# Make executable
chmod +x "$DECRYPTED_FILE"

# Execute
"$DECRYPTED_FILE"

# Clean up (optional in real attacks)
rm "$DECRYPTED_FILE"

echo "Decryption and execution completed"
"#);
                                    
                                    if let Err(e) = std::fs::write(&loader_file, loader_script) {
                                        writeln!(log_file_handle, "Failed to write decrypt loader: {e}").unwrap();
                                    } else {
                                        artifacts.push(loader_file.clone());
                                        artifacts.push(format!("{output_dir}/decrypted_executable"));
                                        
                                        // Make executable
                                        let chmod_cmd = format!("chmod +x {loader_file}");
                                        let _ = Command::new("bash")
                                            .arg("-c")
                                            .arg(&chmod_cmd)
                                            .output()
                                            .await;
                                        
                                        writeln!(log_file_handle, "Decrypt and execute script created: {loader_file}").unwrap();
                                        
                                        // Execute if requested
                                        if execute_after {
                                            writeln!(log_file_handle, "Executing decrypt and execute script...").unwrap();
                                            
                                            let exec_output = Command::new("bash")
                                                .arg("-c")
                                                .arg(&loader_file)
                                                .output()
                                                .await;
                                                
                                            match exec_output {
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
                                        }
                                    }
                                } else {
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    writeln!(log_file_handle, "Encryption failed: {exit_code} ({stderr})").unwrap();
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "Encryption Error: {e}").unwrap();
                            }
                        }
                    }
                },
                "string" => {
                    writeln!(log_file_handle, "\n## String Obfuscation Techniques").unwrap();
                    
                    // 1. String splitting and concatenation
                    writeln!(log_file_handle, "\n1. String Splitting and Concatenation").unwrap();
                    
                    let obfuscated_script_file = format!("{output_dir}/string_obfuscated.sh");
                    let obfuscated_script = r#"#!/bin/bash
# This script demonstrates string obfuscation techniques

# Split command string into variables
A="ec"
B="ho"
C=" \"Snel"
D="len String"
E=" Obfu"
F="scation Te"
G="st\" > /tmp/sn"
H="ellen_stri"
I="ng_obfu"
J="scation"

# Concatenate and execute
$(eval "${A}${B}${C}${D}${E}${F}${G}${H}${I}${J}")

# Another form of obfuscation with arrays
cmd=(
  "cat"
  "/etc"
  "/ho"
  "st"
  "name"
)

# Execute with array indices
${cmd[0]} ${cmd[1]}${cmd[2]}${cmd[3]}${cmd[4]}

# Character encoding obfuscation
$(printf "w%s\n" "hoami")

# Execution through multiple layers
ev""al "ec""ho \"Layer 2 obfuscation test\""

echo "String obfuscation test completed"
"#;
                    
                    if let Err(e) = std::fs::write(&obfuscated_script_file, obfuscated_script) {
                        writeln!(log_file_handle, "Failed to write string obfuscated script: {e}").unwrap();
                    } else {
                        artifacts.push(obfuscated_script_file.clone());
                        artifacts.push("/tmp/snellen_string_obfuscation".to_string());
                        
                        // Make executable
                        let chmod_cmd = format!("chmod +x {obfuscated_script_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                        
                        writeln!(log_file_handle, "String obfuscated script created: {obfuscated_script_file}").unwrap();
                        
                        // Execute if requested
                        if execute_after {
                            writeln!(log_file_handle, "Executing string obfuscated script...").unwrap();
                            
                            let exec_output = Command::new("bash")
                                .arg("-c")
                                .arg(&obfuscated_script_file)
                                .output()
                                .await;
                                
                            match exec_output {
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
                        }
                    }
                    
                    // 2. Variable name obfuscation
                    writeln!(log_file_handle, "\n2. Variable Name Obfuscation").unwrap();
                    
                    let var_obfuscated_file = format!("{output_dir}/var_obfuscated.sh");
                    let var_obfuscated_script = r#"#!/bin/bash
# This script demonstrates variable name obfuscation

# Using confusing and misleading variable names
__SYSTEM_PATH_CONFIG123="echo"
__SYSTEM_CONF_001="Snellen Variable Obfuscation Test"
__SYSTEM__REG=">"
__SYSTEM_TMP_FILE="/tmp/snellen_var_obfuscation"

# Execute through variables
$__SYSTEM_PATH_CONFIG123 "$__SYSTEM_CONF_001" $__SYSTEM__REG $__SYSTEM_TMP_FILE

# Using special characters in variable names
va\u{AD}r$1="whoami"
va\u{AD}r$2="hostname"

# Execute 
$(eval $va\u{AD}r$1)
$(eval $va\u{AD}r$2)

echo "Variable obfuscation test completed"
"#;
                    
                    if let Err(e) = std::fs::write(&var_obfuscated_file, var_obfuscated_script) {
                        writeln!(log_file_handle, "Failed to write variable obfuscated script: {e}").unwrap();
                    } else {
                        artifacts.push(var_obfuscated_file.clone());
                        artifacts.push("/tmp/snellen_var_obfuscation".to_string());
                        
                        // Make executable
                        let chmod_cmd = format!("chmod +x {var_obfuscated_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                        
                        writeln!(log_file_handle, "Variable obfuscated script created: {var_obfuscated_file}").unwrap();
                        
                        // Execute if requested
                        if execute_after {
                            writeln!(log_file_handle, "Executing variable obfuscated script...").unwrap();
                            
                            let exec_output = Command::new("bash")
                                .arg("-c")
                                .arg(&var_obfuscated_file)
                                .output()
                                .await;
                                
                            match exec_output {
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
                        }
                    }
                },
                "packing" => {
                    writeln!(log_file_handle, "\n## Binary Packing and Compression Simulation").unwrap();
                    
                    // Create a simple test executable
                    let test_bin_file = format!("{output_dir}/original_binary");
                    let test_binary = r#"#!/bin/bash
echo "Snellen Packing Test - Unpacked Binary" > /tmp/snellen_unpacked_executed
echo "This simulates an unpacked and executed binary payload"
echo "Current system: $(uname -a)"
echo "Current user: $(whoami)"
"#;
                    
                    if let Err(e) = std::fs::write(&test_bin_file, test_binary) {
                        writeln!(log_file_handle, "Failed to write test binary: {e}").unwrap();
                    } else {
                        artifacts.push(test_bin_file.clone());
                        artifacts.push("/tmp/snellen_unpacked_executed".to_string());
                        
                        // Make executable
                        let chmod_cmd = format!("chmod +x {test_bin_file}");
                        let _ = Command::new("bash")
                            .arg("-c")
                            .arg(&chmod_cmd)
                            .output()
                            .await;
                        
                        // "Pack" the binary (simulated with compression)
                        let packed_file = format!("{output_dir}/packed_binary.gz");
                        
                        let pack_cmd = format!("cat {test_bin_file} | gzip -9 > {packed_file}");
                        
                        let pack_output = Command::new("bash")
                            .arg("-c")
                            .arg(&pack_cmd)
                            .output()
                            .await;
                            
                        match pack_output {
                            Ok(output) => {
                                let exit_code = output.status.code().unwrap_or(-1);
                                
                                if exit_code == 0 {
                                    artifacts.push(packed_file.clone());
                                    
                                    writeln!(log_file_handle, "Original binary: {test_bin_file}").unwrap();
                                    writeln!(log_file_handle, "Packed binary: {packed_file}").unwrap();
                                    
                                    // Create an unpacker and executor
                                    let unpacker_file = format!("{output_dir}/unpack_and_execute.sh");
                                    let unpacker_script = format!(r#"#!/bin/bash
# This script unpacks and executes a compressed payload
# In real attacks, this could be used to bypass signature-based detection

# Packed file path
PACKED_FILE="{packed_file}"
# Unpacked output path
UNPACKED_FILE="{output_dir}/unpacked_binary"

# Unpack the file
cat "$PACKED_FILE" | gunzip > "$UNPACKED_FILE"

# Make executable
chmod +x "$UNPACKED_FILE"

# Execute
"$UNPACKED_FILE"

# Clean up (optional in real attacks)
rm "$UNPACKED_FILE"

echo "Unpacking and execution completed"
"#);
                                    
                                    if let Err(e) = std::fs::write(&unpacker_file, unpacker_script) {
                                        writeln!(log_file_handle, "Failed to write unpacker script: {e}").unwrap();
                                    } else {
                                        artifacts.push(unpacker_file.clone());
                                        artifacts.push(format!("{output_dir}/unpacked_binary"));
                                        
                                        // Make executable
                                        let chmod_cmd = format!("chmod +x {unpacker_file}");
                                        let _ = Command::new("bash")
                                            .arg("-c")
                                            .arg(&chmod_cmd)
                                            .output()
                                            .await;
                                        
                                        writeln!(log_file_handle, "Unpack and execute script created: {unpacker_file}").unwrap();
                                        
                                        // Execute if requested
                                        if execute_after {
                                            writeln!(log_file_handle, "Executing unpack and execute script...").unwrap();
                                            
                                            let exec_output = Command::new("bash")
                                                .arg("-c")
                                                .arg(&unpacker_file)
                                                .output()
                                                .await;
                                                
                                            match exec_output {
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
                                        }
                                    }
                                } else {
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    writeln!(log_file_handle, "Packing failed: {exit_code} ({stderr})").unwrap();
                                }
                            },
                            Err(e) => {
                                writeln!(log_file_handle, "Packing Error: {e}").unwrap();
                            }
                        }
                    }
                },
                _ => {
                    writeln!(log_file_handle, "\n## ERROR: Unsupported obfuscation type '{obfuscation_type}'").unwrap();
                    writeln!(log_file_handle, "Supported types: encoding, encryption, string, packing").unwrap();
                }
            }
            
            // Close log file
            drop(log_file_handle);
            
            info!("Obfuscated files and information test complete, logs saved to {log_file}");
            
            Ok(SimulationResult {
                technique_id: technique_info.id,
                success: true,
                message: format!("Obfuscated files and information ({obfuscation_type}) test completed. Logs: {log_file}"),
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