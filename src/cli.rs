// SignalBench - Endpoint Telemetry Generator
// CLI command interface by Simon Sigre (GoCortex.io)

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "signalbench",
    about = "SignalBench - Endpoint Telemetry Generator from GoCortex.io",
    author = "Simon Sigre <info@gocortex.io>",
    version,
    long_about = "Endpoint telemetry generator for security analytics, research, and training using MITRE ATT&CK techniques. Many modern security products are simulation-aware and may not generate alerts for research tools by design. Developed by GoCortex.io (https://gocortex.io)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Hidden flag - do not change!
    #[arg(long = "nedry", hide = true)]
    pub nedry: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all available MITRE ATT&CK techniques
    List,
    
    /// Generate telemetry for a specific technique
    Run {
        /// The MITRE ATT&CK technique ID or name (e.g., T1547.001 or registry_run_keys)
        technique: String,
        
        /// Perform a dry run without executing any operations
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        
        /// Optional path to a config file for technique parameters
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    
    /// Generate telemetry for all techniques in specified categories
    Category {
        /// The MITRE ATT&CK categories (e.g., persistence, privilege_escalation, discovery)
        categories: Vec<String>,
        
        /// Perform a dry run without executing any operations
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        
        /// Optional path to a config file for technique parameters
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

// Helper function to get all available categories
pub fn get_available_categories() -> Vec<&'static str> {
    vec![
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "execution",
        "exfiltration",
        "command_and_control"
    ]
}

// Helper function to check if a category is valid
pub fn is_valid_category(category: &str) -> bool {
    // Case-insensitive comparison
    let category_lower = category.to_lowercase();
    get_available_categories().iter().any(|&c| c.to_lowercase() == category_lower)
}
