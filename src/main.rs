// SignalBench - Endpoint Telemetry Generator
// Developed by Simon Sigre at GoCortex.io
// https://gocortex.io
//
// This tool provides a framework for generating endpoint telemetry
// aligned with MITRE ATT&CK techniques for security analytics, research, and training

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::question_mark)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::collapsible_if)]

mod cli;
mod config;
mod easter_egg;
mod logger;
mod runner;
mod safety;
mod techniques;
mod utils;
mod voltron;

use cli::{Cli, Commands, VoltronCommands};
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

    // Parse command line arguments first to extract debug flag
    let cli = Cli::parse();
    
    // Determine if debug mode is enabled from Voltron commands
    let debug_enabled = match &cli.command {
        Commands::Voltron(VoltronCommands::Server { debug, .. }) => *debug,
        Commands::Voltron(VoltronCommands::Client { debug, .. }) => *debug,
        Commands::Voltron(VoltronCommands::Run { debug, .. }) => *debug,
        _ => false,
    };
    
    // Initialize the logger with appropriate level
    logger::init_logger(debug_enabled);

    info!("Starting SignalBench v{} - Endpoint Telemetry Generator by GoCortex.io", env!("CARGO_PKG_VERSION"));
    
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
        Commands::Voltron(voltron_cmd) => {
            match voltron_cmd {
                VoltronCommands::Keygen { output, hostname } => {
                    voltron::keygen_command(output, hostname)
                }
                VoltronCommands::Server { psk, journal, debug } => {
                    voltron::server_command(psk, journal, debug).await
                }
                VoltronCommands::Client { server, psk, hostname, debug } => {
                    voltron::client_command(server, psk, hostname, debug).await
                }
                VoltronCommands::Run { server, psk, technique, attacker, victim, params, debug } => {
                    voltron::run_command(server, psk, technique, attacker, victim, params, debug).await
                }
                VoltronCommands::List => {
                    voltron::list_command()
                }
                VoltronCommands::Formed { server, psk } => {
                    voltron::formed_command(server, psk).await
                }
            }
        },
    }
}