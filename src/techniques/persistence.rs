use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{ExecuteFuture, CleanupFuture};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tokio::process::Command;
use uuid::Uuid;


pub struct StartupFolder {}

#[async_trait]
impl AttackTechnique for StartupFolder {
    fn info(&self) -> Technique {
        Technique {
            id: "T1547.002".to_string(),
            name: "Startup Folder".to_string(),
            description: "Generates telemetry for Linux desktop autostart persistence".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "app_name".to_string(),
                    description: "Name of the desktop application entry".to_string(),
                    required: false,
                    default: Some("SignalBench Persistence".to_string()),
                },
                TechniqueParameter {
                    name: "command".to_string(),
                    description: "Command to execute at startup (shell features will be wrapped with /bin/sh -c)".to_string(),
                    required: false,
                    default: Some("echo 'SignalBench startup executed' >> /tmp/signalbench_startup.log".to_string()),
                },
            ],
            detection: "Monitor .desktop file creation in ~/.config/autostart directory".to_string(),
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
            let app_name = config.parameters.get("app_name").unwrap_or(&"SignalBench Persistence".to_string()).clone();
            let raw_command = config.parameters.get("command").unwrap_or(&"echo 'SignalBench startup executed' >> /tmp/signalbench_startup.log".to_string()).clone();
            // Wrap command with shell to handle shell features like redirection
            let command = format!("/bin/sh -c \"{}\"", raw_command.replace("\"", "\\\""));
            
            // Generate unique desktop file name to avoid conflicts
            let desktop_filename = format!("signalbench-{}.desktop", Uuid::new_v4().simple());
            let autostart_dir = format!("{}/.config/autostart", std::env::var("HOME").unwrap_or_else(|_| ".".to_string()));
            let desktop_file_path = format!("{autostart_dir}/{desktop_filename}");
            
            if dry_run {
                info!("[DRY RUN] Would create desktop autostart file at: {desktop_file_path}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would create desktop autostart file at {desktop_file_path}"),
                    artifacts: vec![desktop_file_path],
                    cleanup_required: false,
                });
            }

            // Ensure autostart directory exists
            if !Path::new(&autostart_dir).exists() {
                fs::create_dir_all(&autostart_dir).map_err(|e| format!("Failed to create autostart directory: {e}"))?;
            }

            // Create proper desktop file content for Linux autostart
            let desktop_content = format!(
                "[Desktop Entry]\n\
                Type=Application\n\
                Name={app_name}\n\
                Exec={command}\n\
                Terminal=false\n\
                Hidden=false\n\
                NoDisplay=false\n\
                X-GNOME-Autostart-enabled=true\n\
                TryExec=/bin/sh\n\
                Comment=SignalBench Persistence Technique T1547.002\n\
                Categories=System;\n"
            );

            // Create the desktop file
            let mut file = File::create(&desktop_file_path)
                .map_err(|e| format!("Failed to create desktop file: {e}"))?;
            
            file.write_all(desktop_content.as_bytes())
                .map_err(|e| format!("Failed to write to desktop file: {e}"))?;
            
            info!("Created desktop autostart file at: {desktop_file_path}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully created desktop autostart file at {desktop_file_path}"),
                artifacts: vec![desktop_file_path],
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
            
            // Try to remove autostart directory if it's empty
            if let Ok(home_dir) = std::env::var("HOME") {
                let autostart_dir = format!("{home_dir}/.config/autostart");
                if Path::new(&autostart_dir).exists() {
                    match std::fs::read_dir(&autostart_dir) {
                        Ok(entries) => {
                            if entries.count() == 0 {
                                if let Err(e) = std::fs::remove_dir(&autostart_dir) {
                                    debug!("Could not remove empty autostart directory: {e}");
                                } else {
                                    info!("Removed empty autostart directory");
                                }
                            }
                        }
                        Err(e) => debug!("Could not read autostart directory: {e}"),
                    }
                }
            }
            
            Ok(())
        })
    }
}

pub struct CronJob {}

#[async_trait]
impl AttackTechnique for CronJob {
    fn info(&self) -> Technique {
        Technique {
            id: "T1053.003".to_string(),
            name: "Cron Job".to_string(),
            description: "Generates telemetry for cron job persistence techniques".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "cron_expression".to_string(),
                    description: "Cron expression for scheduling".to_string(),
                    required: false,
                    default: Some("*/30 * * * *".to_string()),
                },
                TechniqueParameter {
                    name: "command".to_string(),
                    description: "Command to execute in cron job".to_string(),
                    required: false,
                    default: Some("/usr/bin/echo 'SignalBench Cron Job Test (GoCortex.io)' > /tmp/signalbench_test_cron".to_string()),
                },
            ],
            detection: "Monitor crontab modifications".to_string(),
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
            let cron_expression = config.parameters.get("cron_expression").unwrap_or(&"*/30 * * * *".to_string()).clone();
            let command = config.parameters.get("command").unwrap_or(&"/usr/bin/echo 'SignalBench Cron Job Test (GoCortex.io)' > /tmp/signalbench_test_cron".to_string()).clone();
            
            // Generate a unique identifier for this cron job
            let id = Uuid::new_v4().to_string().split('-').next().unwrap_or("signalbenchtest").to_string();
            let temp_cron_file = format!("/tmp/signalbench_test_cron_{id}");
            
            if dry_run {
                info!("[DRY RUN] Would add cron job: {cron_expression} {command}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would add cron job: {cron_expression} {command}"),
                    artifacts: vec![temp_cron_file.clone()],
                    cleanup_required: false,
                });
            }

            // Create a temporary file with the existing crontab
            let status = Command::new("crontab")
                .args(["-l"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output()
                .await
                .map_err(|e| format!("Failed to get current crontab: {e}"))?;
            
            let mut crontab_content = String::from_utf8_lossy(&status.stdout).to_string();
            // Add our test cron job
            crontab_content.push_str(&format!("\n# SignalBench Test Cron Job (GoCortex.io) - {id}\n"));
            crontab_content.push_str(&format!("{cron_expression} {command}\n"));
            
            // Write to temporary file
            let mut file = File::create(&temp_cron_file)
                .map_err(|e| format!("Failed to create temporary cron file: {e}"))?;
            
            file.write_all(crontab_content.as_bytes())
                .map_err(|e| format!("Failed to write to temporary cron file: {e}"))?;
            
            // Install the new crontab
            let status = Command::new("crontab")
                .args([&temp_cron_file])
                .status()
                .await
                .map_err(|e| format!("Failed to install crontab: {e}"))?;
                
            if !status.success() {
                return Err("Failed to install crontab".to_string());
            }
            
            info!("Added cron job: {cron_expression} {command}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully added cron job with ID {id}"),
                artifacts: vec![format!("cron_job_{id}"), temp_cron_file],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            // Cleanup the temporary file
            for artifact in artifacts {
                if artifact.starts_with("/tmp/signalbench_test_cron_") && Path::new(artifact).exists() {
                    if let Err(e) = fs::remove_file(artifact) {
                        warn!("Failed to remove temporary cron file {artifact}: {e}");
                    }
                }
                
                if artifact.starts_with("cron_job_") {
                    let id = artifact.trim_start_matches("cron_job_");
                    
                    // Get current crontab
                    let output = Command::new("crontab")
                        .args(["-l"])
                        .output()
                        .await
                        .map_err(|e| format!("Failed to get current crontab: {e}"))?;
                    
                    let crontab_content = String::from_utf8_lossy(&output.stdout).to_string();
                    
                    // Filter out our test cron job
                    let new_crontab = crontab_content
                        .lines()
                        .filter(|line| !line.contains(&format!("SignalBench Cron Job Test - {id}")))
                        .filter(|line| !line.starts_with("# SignalBench Test Cron Job (GoCortex.io)"))
                        .collect::<Vec<&str>>()
                        .join("\n");
                    
                    // Write to temporary file
                    let temp_file = format!("/tmp/signalbench_test_cron_cleanup_{}", Uuid::new_v4());
                    let mut file = File::create(&temp_file)
                        .map_err(|e| format!("Failed to create temporary cron file: {e}"))?;
                    
                    file.write_all(new_crontab.as_bytes())
                        .map_err(|e| format!("Failed to write to temporary cron file: {e}"))?;
                    
                    // Install the new crontab
                    let status = Command::new("crontab")
                        .args([&temp_file])
                        .status()
                        .await
                        .map_err(|e| format!("Failed to install crontab: {e}"))?;
                        
                    if !status.success() {
                        return Err("Failed to install crontab".to_string());
                    }
                    
                    // Cleanup temporary file
                    if let Err(e) = fs::remove_file(&temp_file) {
                        warn!("Failed to remove temporary cron file {temp_file}: {e}");
                    }
                    
                    info!("Removed cron job with ID {id}");
                }
            }
            
            // Remove the output file created by the cron job command
            let output_file = "/tmp/signalbench_test_cron";
            if Path::new(output_file).exists() {
                if let Err(e) = fs::remove_file(output_file) {
                    warn!("Failed to remove cron job output file {output_file}: {e}");
                } else {
                    info!("Removed cron job output file: {output_file}");
                }
            }
            
            Ok(())
        })
    }
}

pub struct WebShellDeployment {}

#[async_trait]
impl AttackTechnique for WebShellDeployment {
    fn info(&self) -> Technique {
        Technique {
            id: "T1505.003".to_string(),
            name: "Web Shell Deployment".to_string(),
            description: "Deploys malicious web shells on Linux-based web servers (PHP, JSP, or custom backdoors) for long-term access".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "web_root".to_string(),
                    description: "Web server document root directory".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_webshell_test".to_string()),
                },
                TechniqueParameter {
                    name: "shell_type".to_string(),
                    description: "Type of web shell (php, jsp, aspx)".to_string(),
                    required: false,
                    default: Some("php".to_string()),
                },
                TechniqueParameter {
                    name: "shell_name".to_string(),
                    description: "Filename for the web shell".to_string(),
                    required: false,
                    default: Some("signalbench_test.php".to_string()),
                },
            ],
            detection: "Monitor web directories for suspicious script files, unexpected file creation in web directories, or unusual web server process behaviour".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["www-data".to_string(), "root".to_string()],
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let web_root = config
                .parameters
                .get("web_root")
                .unwrap_or(&"/tmp/signalbench_webshell_test".to_string())
                .clone();
                
            let shell_type = config
                .parameters
                .get("shell_type")
                .unwrap_or(&"php".to_string())
                .clone();
                
            let shell_name = config
                .parameters
                .get("shell_name")
                .unwrap_or(&"signalbench_test.php".to_string())
                .clone();
            
            let shell_path = format!("{web_root}/{shell_name}");
            
            if dry_run {
                info!("[DRY RUN] Would deploy {} web shell at: {shell_path}", shell_type.to_uppercase());
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!("DRY RUN: Would deploy {} web shell at {shell_path}", shell_type.to_uppercase()),
                    artifacts: vec![shell_path],
                    cleanup_required: false,
                });
            }

            // Ensure web root directory exists (for testing purposes)
            if !Path::new(&web_root).exists() {
                fs::create_dir_all(&web_root).map_err(|e| format!("Failed to create web root directory: {e}"))?;
            }

            // Create web shell content based on type - HARMLESS TESTING ONLY
            let shell_content = match shell_type.to_lowercase().as_str() {
                "php" => {
                    "<?php\n\
                    // SIGNALBENCH TEST WEB SHELL - NOT FOR PRODUCTION USE\n\
                    // Developed by GoCortex.io for security testing purposes\n\
                    // This is a harmless test file for web shell telemetry\n\
                    \n\
                    if(isset($_GET['cmd'])) {\n\
                        echo '<pre>SignalBench Test: Would execute command: ' . htmlspecialchars($_GET['cmd']) . '</pre>';\n\
                        echo '<pre>Status: SignalBench Telemetry Generator by GoCortex.io</pre>';\n\
                    } else {\n\
                        echo '<h1>SignalBench Test Web Shell</h1>';\n\
                        echo '<p>This is a test file created by the SignalBench EDR testing tool.</p>';\n\
                        echo '<p>Developed by GoCortex.io - https://gocortex.io</p>';\n\
                        echo '<form>Command: <input name=\"cmd\" type=\"text\"><input type=\"submit\" value=\"Test\"></form>';\n\
                    }\n\
                    ?>"
                },
                "jsp" => {
                    "<%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\" pageEncoding=\"UTF-8\"%>\n\
                    <!DOCTYPE html>\n\
                    <html><head><title>SignalBench Test</title></head><body>\n\
                    <h1>SignalBench Test JSP Shell</h1>\n\
                    <p>This is a test file created by the SignalBench EDR testing tool.</p>\n\
                    <p>Developed by GoCortex.io - https://gocortex.io</p>\n\
                    <%\n\
                        String cmd = request.getParameter(\"cmd\");\n\
                        if(cmd != null) {\n\
                            out.println(\"<pre>SignalBench Test: Would execute command: \" + cmd + \"</pre>\");\n\
                            out.println(\"<pre>Status: SignalBench Telemetry Generator by GoCortex.io</pre>\");\n\
                        } else {\n\
                            out.println(\"<form>Command: <input name='cmd' type='text'><input type='submit' value='Test'></form>\");\n\
                        }\n\
                    %>\n\
                    </body></html>"
                },
                _ => {
                    "#!/bin/bash\n\
                    # SIGNALBENCH TEST SHELL SCRIPT - NOT FOR PRODUCTION USE\n\
                    # Developed by GoCortex.io for security testing purposes\n\
                    echo \"SignalBench Test Shell\"\n\
                    echo \"This is a test file created by the SignalBench EDR testing tool.\"\n\
                    echo \"Developed by GoCortex.io - https://gocortex.io\"\n\
                    echo \"Query string: $QUERY_STRING\"\n\
                    echo \"Status: SignalBench Telemetry Generator by GoCortex.io\""
                }
            };

            // Create the web shell file
            let mut file = File::create(&shell_path)
                .map_err(|e| format!("Failed to create web shell file: {e}"))?;
            
            file.write_all(shell_content.as_bytes())
                .map_err(|e| format!("Failed to write web shell content: {e}"))?;
            
            info!("Deployed {} web shell at: {}", shell_type.to_uppercase(), shell_path);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully deployed {} web shell at {}", shell_type.to_uppercase(), shell_path),
                artifacts: vec![shell_path],
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed web shell artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove web shell artifact {artifact}: {e}"),
                    }
                    
                    // Try to remove parent directory if empty
                    if let Some(parent) = Path::new(artifact).parent() {
                        if parent.exists() {
                            match std::fs::read_dir(parent) {
                                Ok(entries) => {
                                    if entries.count() == 0 {
                                        if let Err(e) = std::fs::remove_dir(parent) {
                                            debug!("Could not remove empty web root directory: {e}");
                                        } else {
                                            info!("Removed empty web root directory: {}", parent.display());
                                        }
                                    }
                                }
                                Err(e) => debug!("Could not read web root directory: {e}"),
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }
}