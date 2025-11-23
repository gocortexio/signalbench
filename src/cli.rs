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
        
        /// Skip cleanup after technique execution (preserve artifacts for debugging)
        #[arg(long, default_value_t = false)]
        no_cleanup: bool,
        
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
        
        /// Skip cleanup after technique execution (preserve artifacts for debugging)
        #[arg(long, default_value_t = false)]
        no_cleanup: bool,
        
        /// Optional path to a config file for technique parameters
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    
    /// Voltron Mode - Multi-host MITRE ATT&CK simulation with peer-to-peer hive architecture
    #[command(subcommand)]
    Voltron(VoltronCommands),
}

#[derive(Subcommand)]
pub enum VoltronCommands {
    /// Generate pre-shared key for Voltron encryption
    Keygen {
        /// Output path for the key file (default: voltron.key)
        #[arg(short, long, default_value = "voltron.key")]
        output: PathBuf,
        
        /// Deprecated: hostname is no longer used with PSK model
        #[arg(long, hide = true)]
        hostname: Option<String>,
    },
    
    /// Start Voltron server (coordinator node)
    Server {
        /// Path to pre-shared key file (from keygen)
        #[arg(short, long, default_value = "voltron.key")]
        psk: PathBuf,
        
        /// Path to SQLite journal database
        #[arg(short, long, default_value = "voltron.db")]
        journal: PathBuf,
        
        /// Enable debug logging (verbose output to stderr)
        #[arg(short, long, default_value_t = false)]
        debug: bool,
    },
    
    /// Start Voltron client (endpoint node)
    Client {
        /// Server address (IP:PORT, default port: 16969)
        #[arg(short, long)]
        server: String,
        
        /// Path to pre-shared key file (shared with server)
        #[arg(short, long, default_value = "voltron.key")]
        psk: PathBuf,
        
        /// Client hostname (default: auto-detected)
        #[arg(long)]
        hostname: Option<String>,
        
        /// Enable debug logging (verbose output to stderr)
        #[arg(short, long, default_value_t = false)]
        debug: bool,
    },
    
    /// Dispatch technique to connected clients (run from server console)
    Run {
        /// Server address for coordination (IP:PORT)
        #[arg(short, long)]
        server: String,
        
        /// Path to pre-shared key file
        #[arg(short, long, default_value = "voltron.key")]
        psk: PathBuf,
        
        /// MITRE ATT&CK technique ID (e.g., T1003.001)
        #[arg(short, long)]
        technique: String,
        
        /// Attacker hostname(s) - comma-separated for multiple
        #[arg(short, long)]
        attacker: String,
        
        /// Victim hostname (optional - defaults to same as attacker for single-host techniques, required for multi-host lateral movement)
        #[arg(short, long)]
        victim: Option<String>,
        
        /// Custom parameters as JSON (optional)
        #[arg(long)]
        params: Option<String>,
        
        /// Enable debug logging (verbose output to stderr)
        #[arg(short, long, default_value_t = false)]
        debug: bool,
    },
    
    /// List Voltron-compatible techniques (multi-host/NETWORK category)
    List,
    
    /// Show connected clients and formation status
    Formed {
        /// Server address (IP:PORT, default port: 16969)
        #[arg(short, long)]
        server: String,
        
        /// Path to pre-shared key file (shared with server)
        #[arg(short, long, default_value = "voltron.key")]
        psk: PathBuf,
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
        "command_and_control",
        "collection",
        "impact",
        "software"
    ]
}

// Helper function to check if a category is valid
pub fn is_valid_category(category: &str) -> bool {
    // Case-insensitive comparison
    let category_lower = category.to_lowercase();
    get_available_categories().iter().any(|&c| c.to_lowercase() == category_lower)
}
