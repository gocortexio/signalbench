// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

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

mod chain;
mod cli;
mod config;
mod easter_egg;
mod logger;
mod runner;
mod safety;
mod techniques;
mod utils;
mod voltron;

use clap::Parser;
use cli::{Cli, Commands, VoltronCommands};
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

    // Determine if debug mode is enabled - check global flag first, then Voltron subcommands
    let debug_enabled = cli.debug
        || match &cli.command {
            Commands::Voltron(VoltronCommands::Server { debug, .. }) => *debug,
            Commands::Voltron(VoltronCommands::Client { debug, .. }) => *debug,
            Commands::Voltron(VoltronCommands::Run { debug, .. }) => *debug,
            _ => false,
        };

    // Initialise the logger with appropriate level
    logger::init_logger(debug_enabled);

    // Log force mode activation
    if cli.force {
        info!("[FORCE] Force mode enabled - bypassing pre-checks, maximum telemetry generation");
    }

    info!(
        "Starting SignalBench v{} - Endpoint Telemetry Generator by GoCortex.io",
        env!("CARGO_PKG_VERSION")
    );

    // Spawn a background task that listens for SIGINT/SIGTERM (Unix) and cleans up
    // any chain file before exiting.  Tokio signal handling runs in normal async
    // context, so it is safe to call env::var and filesystem ops here.
    #[cfg(unix)]
    tokio::spawn(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
        chain::cleanup_chain_file_from_env();
        process::exit(130); // 128 + SIGINT(2)
    });

    // Run the appropriate command
    match run_command(cli).await {
        Ok(_) => {
            info!(
                "SignalBench v{} completed successfully",
                env!("CARGO_PKG_VERSION")
            );
            process::exit(0);
        }
        Err(e) => {
            error!("SignalBench failed: {e}");
            process::exit(1);
        }
    }
}

async fn run_command(cli: Cli) -> Result<(), String> {
    let force = cli.force;
    let debug = cli.debug;
    let delay_cleanup = cli.delay_cleanup;

    match cli.command {
        Commands::List => runner::list_techniques(),
        Commands::Run {
            techniques,
            dry_run,
            no_cleanup,
            config,
            chain,
        } => {
            // Check safety before execution
            safety::check_environment()?;

            // Run the specified technique(s)
            runner::run_techniques(
                &techniques,
                runner::RunOptions {
                    dry_run,
                    no_cleanup,
                    config_path: config,
                    force,
                    debug,
                    delay_cleanup,
                    chain,
                },
            )
            .await
        }
        Commands::Category {
            categories,
            dry_run,
            no_cleanup,
            config,
            chain,
        } => {
            // Check safety before execution
            safety::check_environment()?;

            // Run all techniques in the specified categories
            runner::run_categories(
                &categories,
                runner::RunOptions {
                    dry_run,
                    no_cleanup,
                    config_path: config,
                    force,
                    debug,
                    delay_cleanup,
                    chain,
                },
            )
            .await
        }
        Commands::Voltron(voltron_cmd) => match voltron_cmd {
            VoltronCommands::Keygen { output, hostname } => {
                voltron::keygen_command(output, hostname)
            }
            VoltronCommands::Server {
                psk,
                journal,
                debug,
            } => voltron::server_command(psk, journal, debug).await,
            VoltronCommands::Client {
                server,
                psk,
                hostname,
                debug,
            } => voltron::client_command(server, psk, hostname, debug).await,
            VoltronCommands::Run {
                server,
                psk,
                technique,
                attacker,
                victim,
                params,
                debug,
            } => {
                voltron::run_command(server, psk, technique, attacker, victim, params, debug).await
            }
            VoltronCommands::List => voltron::list_command(),
            VoltronCommands::Formed { server, psk } => voltron::formed_command(server, psk).await,
        },
    }
}
