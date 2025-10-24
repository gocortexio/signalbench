// SignalBench - Endpoint Telemetry Generator
// Developed by Simon Sigre at GoCortex.io
// https://gocortex.io
//
// This tool provides a framework for generating endpoint telemetry
// aligned with MITRE ATT&CK techniques for security analytics, research, and training

mod cli;
mod config;
mod easter_egg;
mod logger;
mod runner;
mod safety;
mod techniques;
mod utils;

use cli::{Cli, Commands};
use clap::Parser;
use log::{error, info};
use std::{env, process};

#[tokio::main]
async fn main() {
    // Check for the easter egg flag before normal parsing
    if env::args().any(|arg| arg == "--nedry") {
        easter_egg::jurassic_park_animation();
        return;
    }

    // Initialize the logger
    logger::init_logger();

    info!("Starting SignalBench v{} - Endpoint Telemetry Generator by GoCortex.io", env!("CARGO_PKG_VERSION"));
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Run the appropriate command
    match run_command(cli).await {
        Ok(_) => {
            info!("SignalBench v{} completed successfully", env!("CARGO_PKG_VERSION"));
            process::exit(0);
        }
        Err(e) => {
            error!("SignalBench failed: {e}");
            process::exit(1);
        }
    }
}

async fn run_command(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::List => {
            runner::list_techniques()
        },
        Commands::Run { technique, dry_run, no_cleanup, config } => {
            // Check safety before execution
            safety::check_environment()?;
            
            // Run the specified technique
            runner::run_technique(&technique, dry_run, no_cleanup, config).await
        },
        Commands::Category { categories, dry_run, no_cleanup, config } => {
            // Check safety before execution
            safety::check_environment()?;
            
            // Run all techniques in the specified categories
            runner::run_categories(&categories, dry_run, no_cleanup, config).await
        },
    }
}