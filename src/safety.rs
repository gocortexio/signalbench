use log::{debug, warn};
use std::path::Path;

/// Check if the environment is safe for running attack simulations
pub fn check_environment() -> Result<(), String> {
    debug!("Performing safety checks before execution");
    
    // Check for the presence of sensitive files
    check_for_sensitive_files()?;
    
    // Everything looks good
    debug!("Safety checks passed");
    Ok(())
}



/// Check for the presence of sensitive files that might indicate a production system
fn check_for_sensitive_files() -> Result<(), String> {
    // Basic safety check - only warn about obvious production indicators
    let critical_paths = [
        "/etc/kubernetes/admin.conf",
        "/var/lib/docker/swarm/docker-state.json",
    ];
    
    for path in &critical_paths {
        if Path::new(path).exists() {
            warn!("Detected critical system file: {path}");
        }
    }
    
    Ok(())
}

/// Check if the user has confirmed they want to proceed
#[allow(dead_code)]
pub fn confirm_execution(technique_id: &str, dry_run: bool) -> Result<(), String> {
    if dry_run {
        // No confirmation needed for dry runs
        return Ok(());
    }
    
    println!("You are about to execute attack technique {technique_id} which may modify your system.");
    println!("This is intended for security testing in controlled environments.");
    println!("Do you want to proceed? (y/N): ");
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(|e| format!("Failed to read input: {e}"))?;
    
    if input.trim().to_lowercase() != "y" {
        return Err("Execution cancelled by user".to_string());
    }
    
    Ok(())
}
