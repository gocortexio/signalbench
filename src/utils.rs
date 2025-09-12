use std::fs::{self, File};
use std::io::{Read, Write};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use uuid::Uuid;

/// Generate a random string of specified length
#[allow(dead_code)]
pub fn random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a unique ID for tracking attacks
#[allow(dead_code)]
pub fn generate_unique_id() -> String {
    Uuid::new_v4().to_string()
}

/// Create a temporary file with specified content
#[allow(dead_code)]
pub fn create_temp_file(content: &str) -> Result<String, String> {
    let temp_dir = std::env::temp_dir();
    let filename = format!("signalbench_test_{}.tmp", generate_unique_id());
    let path = temp_dir.join(filename);
    
    let mut file = File::create(&path)
        .map_err(|e| format!("Failed to create temporary file: {e}"))?;
    
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write to temporary file: {e}"))?;
    
    Ok(path.to_string_lossy().to_string())
}

/// Read a file's content
#[allow(dead_code)]
pub fn read_file(path: &str) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {e}"))?;
    
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read file: {e}"))?;
    
    Ok(content)
}

/// Check if current user has root privileges
#[allow(dead_code)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Get current username
#[allow(dead_code)]
pub fn get_username() -> String {
    whoami::username()
}

/// Check if a command is available on the system
#[allow(dead_code)]
pub async fn is_command_available(command: &str) -> bool {
    let status = tokio::process::Command::new("which")
        .arg(command)
        .output()
        .await;
        
    match status {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Format file size for display
#[allow(dead_code)]
pub fn format_file_size(size: u64) -> String {
    const KILO: u64 = 1024;
    const MEGA: u64 = KILO * 1024;
    const GIGA: u64 = MEGA * 1024;
    
    if size >= GIGA {
        format!("{:.2} GB", size as f64 / GIGA as f64)
    } else if size >= MEGA {
        format!("{:.2} MB", size as f64 / MEGA as f64)
    } else if size >= KILO {
        format!("{:.2} KB", size as f64 / KILO as f64)
    } else {
        format!("{size} bytes")
    }
}

/// Get file permissions as an octal string
#[allow(dead_code)]
pub fn get_file_permissions(path: &str) -> Result<String, String> {
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {e}"))?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        Ok(format!("{:o}", mode & 0o777))
    }
    
    #[cfg(not(unix))]
    {
        Ok("unknown".to_string())
    }
}
