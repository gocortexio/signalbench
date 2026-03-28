// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

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

    /// Enable debug logging (verbose output to stderr, replaces RUST_LOG=debug)
    #[arg(long, short = 'd', global = true, default_value_t = false)]
    pub debug: bool,

    /// Force execution of all technique operations regardless of pre-check results.
    /// Security products detect the ATTEMPT, not the success - bypassing guards
    /// generates maximum telemetry even when prerequisites are missing.
    #[arg(long, short = 'f', global = true, default_value_t = false)]
    pub force: bool,

    /// Hidden flag - do not change!
    #[arg(long = "nedry", hide = true)]
    pub nedry: bool,

    /// Delay in seconds before cleanup (detection window for security tools)
    #[arg(long, global = true, default_value_t = 0)]
    pub delay_cleanup: u64,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all available MITRE ATT&CK techniques
    List,

    /// Generate telemetry for one or more specified techniques
    Run {
        /// One or more MITRE ATT&CK technique IDs or names (e.g., T1082 T1016 T1049)
        #[arg(num_args = 1.., required = true)]
        techniques: Vec<String>,

        /// Perform a dry run without executing any operations
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Skip cleanup after technique execution (preserve artifacts for debugging)
        #[arg(long, default_value_t = false)]
        no_cleanup: bool,

        /// Optional path to a config file for technique parameters
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Chain execution mode: each TTP runs as a child process of the previous one,
        /// building a realistic parent/child process tree (local execution only)
        #[arg(long, default_value_t = false)]
        chain: bool,
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

        /// Chain execution mode: each TTP runs as a child process of the previous one,
        /// building a realistic parent/child process tree (local execution only)
        #[arg(long, default_value_t = false)]
        chain: bool,
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
        "software",
    ]
}

// Special meta-category that runs ALL techniques with force mode
pub const ALL_CAPS_CATEGORY: &str = "ALL_CAPS";

// Helper function to check if a category is valid
pub fn is_valid_category(category: &str) -> bool {
    // Case-insensitive comparison
    let category_lower = category.to_lowercase();
    get_available_categories()
        .iter()
        .any(|&c| c.to_lowercase() == category_lower)
}
