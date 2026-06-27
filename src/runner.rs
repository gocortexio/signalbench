// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::chain;
use crate::cli::is_valid_category;
use crate::config::{get_technique_config, load_config};
use crate::techniques::{
    get_all_techniques, get_technique_by_id_or_name, get_techniques_by_category,
};
use colored::*;
use log::{error, info, warn};
use std::collections::HashMap;

/// Execution options shared by `run_technique` and `run_categories`.
/// Grouping these into a struct keeps function argument counts within clippy limits.
pub struct RunOptions {
    pub dry_run: bool,
    pub no_cleanup: bool,
    pub config_path: Option<std::path::PathBuf>,
    pub force: bool,
    pub debug: bool,
    pub delay_cleanup: u64,
    pub step_delay: u64,
    pub chain: bool,
}

/// List all available MITRE ATT&CK techniques
/// Developed by Simon Sigre for GoCortex.io
pub fn list_techniques() -> Result<(), String> {
    println!(
        "\n{}",
        format!(
            "SIGNALBENCH v{} - Endpoint Telemetry Generator",
            env!("CARGO_PKG_VERSION")
        )
        .bold()
        .green()
    );
    println!(
        "{}",
        "Developed by GoCortex.io | https://gocortex.io".italic()
    );
    println!(
        "\n{}",
        "Available MITRE ATT&CK Techniques".bold().underline()
    );

    // Get all techniques and organise by category
    let all_techniques = get_all_techniques();

    // Group techniques by category (normalized to ensure consistent capitalization)
    // Filter out voltron_only techniques as they require multi-host coordination
    let mut techniques_by_category: HashMap<String, Vec<_>> = HashMap::new();
    for technique in all_techniques {
        let info = technique.info();

        // Skip Voltron-only techniques (they require multi-host coordination)
        if info.voltron_only {
            continue;
        }

        let category = info.category.to_lowercase();
        techniques_by_category
            .entry(category)
            .or_insert_with(Vec::new)
            .push(technique);
    }

    // Sort categories
    let mut categories: Vec<_> = techniques_by_category.keys().collect();
    categories.sort();

    // Print techniques by category (grep-friendly format)
    for category in categories {
        println!(
            "\n{}",
            format!("CATEGORY: {}", category.to_uppercase())
                .bold()
                .green()
        );

        let techniques = techniques_by_category.get(category).unwrap();
        for technique in techniques {
            let info = technique.info();
            println!(
                "  {} | {} | Platforms: {}",
                info.id.yellow(),
                info.name,
                info.platforms.join(", ")
            );
        }
    }

    println!("\n{}", "Usage:".bold());
    println!("  signalbench run <technique_id_or_name> [technique2 ...] [--dry-run] [--force] [--debug] [--config <config_file>]");
    println!("  signalbench category <category1> [category2] ... [--dry-run] [--force] [--debug] [--config <config_file>]");
    println!("  signalbench category ALL_CAPS  [--dry-run]   # Run ALL techniques with FORCE mode");
    println!("  signalbench suite <suite_name>  [--dry-run] [--force] [--step-delay N]");
    println!("\n{}", "Flags:".bold());
    println!("  -d, --debug          Enable debug logging (verbose output to stderr)");
    println!("  -f, --force          Bypass pre-checks, attempt all operations for maximum telemetry");
    println!("      --step-delay N   Seconds between techniques in a batch (default 5)");
    println!("\n{}", "Note:".bold());
    println!(
        "  For techniques with the same MITRE ATT&CK ID, use the exact technique name in quotes"
    );
    println!(
        "\n{}",
        "Visit https://gocortex.io for documentation and support".italic()
    );

    Ok(())
}

/// Pre-flight dependency gate.
///
/// Returns `Some(detail)` when the technique declares `required_tools()` that
/// are missing from this host and `force` is not set — the caller should then
/// report the technique as SKIPPED (not FAILED) rather than executing it.
/// Returns `None` when the technique can run (deps present, none declared, or
/// `--force` is in effect, which deliberately bypasses pre-checks).
async fn missing_required_tools(
    technique: &dyn crate::techniques::AttackTechnique,
    force: bool,
    dry_run: bool,
) -> Option<String> {
    // `--force` deliberately bypasses pre-checks; `--dry-run` never invokes the
    // tool, so it should still show the technique's plan rather than skip.
    if force || dry_run {
        return None;
    }
    let required = technique.required_tools();
    if required.is_empty() {
        return None;
    }
    let missing = crate::utils::missing_tools(&required).await;
    if missing.is_empty() {
        return None;
    }
    Some(
        missing
            .iter()
            .map(|bin| format!("{bin} (install {})", crate::utils::tool_package(bin)))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Generate telemetry for a specific technique with custom parameters (for Voltron mode)
pub async fn run_technique_with_params(
    technique_id: &str,
    custom_params: std::collections::HashMap<String, String>,
    dry_run: bool,
    no_cleanup: bool,
) -> Result<(), String> {
    use crate::config::TechniqueConfig;

    // Find the technique
    let technique = match get_technique_by_id_or_name(technique_id) {
        Some(t) => t,
        None => return Err(format!("Technique '{technique_id}' not found")),
    };

    let _technique_info = technique.info();

    // Build technique config with custom parameters
    // Check for force parameter in custom_params
    let force = custom_params
        .get("force")
        .map(|v| v == "true")
        .unwrap_or(false);
    let technique_config = TechniqueConfig {
        parameters: custom_params,
        timeout_seconds: Some(300), // Default 5 minutes
        cleanup_after: Some(!no_cleanup),
        force,
    };

    // Pre-flight: a missing hard dependency is a SKIP, not a failure.
    if let Some(detail) = missing_required_tools(technique.as_ref(), force, dry_run).await {
        warn!("Technique '{technique_id}' skipped -- dependency missing: {detail}");
        return Ok(());
    }

    // Execute the technique
    let result = match technique.execute(&technique_config, dry_run).await {
        Ok(result) => result,
        Err(e) => {
            return Err(format!("Failed to execute technique: {e}"));
        }
    };

    // Cleanup if necessary
    if !no_cleanup && technique_config.cleanup_after.unwrap_or(false) && result.cleanup_required {
        let _ = technique.cleanup(&result.artifacts).await;
    }

    if result.success {
        Ok(())
    } else {
        Err(result.message)
    }
}

/// Generate telemetry for a specific technique
pub async fn run_technique(
    technique_id: &str,
    opts: RunOptions,
) -> Result<(), String> {
    let RunOptions { dry_run, no_cleanup, config_path, force, debug, delay_cleanup, step_delay: _, chain } = opts;
    // Load configuration
    let config = load_config(config_path.as_deref())?;

    // Find the technique
    let technique = match get_technique_by_id_or_name(technique_id) {
        Some(t) => t,
        None => return Err(format!("Technique '{technique_id}' not found")),
    };

    let technique_info = technique.info();

    // In chain mode, rename the current process to the MITRE ID (dots→dashes)
    // so it appears correctly in `ps`/`pstree` for this hop, regardless of whether
    // we were invoked by ID or by name.
    if chain {
        chain::rename_current_process(&technique_info.id);
    }

    // Print technique information
    println!("\n{}", "Generating Technique Telemetry".bold().underline());
    println!("{}: {}", "Technique ID".bold(), technique_info.id.yellow());
    println!("{}: {}", "Name".bold(), technique_info.name);
    println!("{}: {}", "Category".bold(), technique_info.category);
    println!("{}: {}", "Description".bold(), technique_info.description);

    if dry_run {
        println!("\n{}", "[DRY RUN MODE]".bold().blue());
    }

    if force {
        println!(
            "{}",
            "[FORCE MODE] Bypassing pre-checks - maximum telemetry"
                .yellow()
                .bold()
        );
    }

    // Get technique-specific configuration with force flag
    let mut technique_config = get_technique_config(&technique_info.id, &config);
    technique_config.force = force;
    if no_cleanup {
        technique_config.cleanup_after = Some(false);
    }

    // Execute the technique
    println!("\n{}", "Executing...".bold());

    // In chain mode a technique-level failure (Err from execute, or result.success == false)
    // is non-fatal: log a warning and continue the chain.  A true crash (non-zero child exit)
    // is handled separately in spawn_next_chain_child and does abort the chain.
    // Pre-flight: a missing hard dependency is reported as SKIPPED (naming the
    // package) rather than a misleading FAILED. In chain mode we still fall
    // through to spawn the next child so the chain is not broken.
    let result = if let Some(detail) = missing_required_tools(technique.as_ref(), force, dry_run).await
    {
        println!("\n{}", "Execution Skipped".bold().yellow());
        println!("{} Dependency missing: {}", "[SKIP]".yellow(), detail);
        if chain {
            warn!(
                "[CHAIN] Technique '{}' skipped (missing dependency) -- continuing chain",
                technique_id
            );
        }
        None
    } else {
        match technique.execute(&technique_config, dry_run).await {
            Ok(result) => {
                // Print result
                if result.success {
                    println!("\n{}", "Execution Successful".bold().green());
                } else {
                    println!("\n{}", "Execution Failed".bold().red());
                    if chain {
                        warn!(
                            "[CHAIN] Technique '{}' reported failure -- continuing chain",
                            technique_id
                        );
                    }
                }
                println!("{}", result.message);
                if !result.artifacts.is_empty() {
                    println!("\n{}", "Created Artifacts:".bold());
                    for artifact in &result.artifacts {
                        println!("  - {artifact}");
                    }
                }
                Some(result)
            }
            Err(e) => {
                error!("Failed to execute technique: {e}");
                if chain {
                    warn!(
                        "[CHAIN] Technique '{}' errored -- continuing chain",
                        technique_id
                    );
                    None
                } else {
                    return Err(format!("Failed to execute technique: {e}"));
                }
            }
        }
    };

    // Cleanup if necessary (only when we have a result)
    if let Some(ref result) = result {
        if no_cleanup {
            println!(
                "\n{}",
                "Skipping cleanup (--no-cleanup flag set)".yellow().bold()
            );
            if !result.artifacts.is_empty() {
                println!("{}", "Artifacts preserved for debugging:".yellow());
                for artifact in &result.artifacts {
                    println!("  - {artifact}");
                }
            }
        } else if result.cleanup_required
            && !dry_run
            && technique_config.cleanup_after.unwrap_or(true)
        {
            if delay_cleanup > 0 {
                println!(
                    "{}",
                    format!(
                        "Waiting {}s before cleanup (detection window)...",
                        delay_cleanup
                    )
                    .yellow()
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay_cleanup)).await;
            }
            println!("\n{}", "Cleaning up...".bold());
            if let Err(e) = technique.cleanup(&result.artifacts).await {
                warn!("Cleanup failed: {e}");
                println!("{}: {}", "Cleanup Warning".yellow().bold(), e);
            } else {
                println!("{}", "Cleanup completed successfully".green());
            }
        } else if result.cleanup_required && !technique_config.cleanup_after.unwrap_or(true) {
            println!(
                "\n{}",
                "Artifacts left on system (cleanup_after = false)"
                    .yellow()
                    .bold()
            );
        }
    }

    // ── Chain mode: spawn the next child in the chain ────────────────────────
    if chain {
        if let Ok(chain_file_str) = std::env::var(chain::CHAIN_FILE_ENV) {
            let chain_file = std::path::Path::new(&chain_file_str).to_path_buf();

            // Check if there are more entries; if empty, delete and we're done.
            let remaining = chain::peek_chain_entries(&chain_file);

            if remaining.is_empty() {
                info!("[CHAIN] Last technique in chain finished -- deleting chain file");
                chain::delete_chain_file(&chain_file);
            } else {
                // Attempt to spawn next child; skip unknown techniques.
                let mut skipped = 0;
                loop {
                    let peek = chain::peek_chain_entries(&chain_file);
                    if peek.is_empty() {
                        chain::delete_chain_file(&chain_file);
                        break;
                    }
                    // Validate the next entry exists as a technique before popping.
                    let next_id = &peek[0];
                    if get_technique_by_id_or_name(next_id).is_none() {
                        warn!("[CHAIN] Unknown technique '{}' -- skipping", next_id);
                        // Pop and discard.
                        let _ = chain::pop_chain_entry(&chain_file);
                        skipped += 1;
                        if skipped > 500 {
                            // Safety valve to prevent infinite loop.
                            warn!("[CHAIN] Too many consecutive unknown techniques -- aborting chain");
                            chain::delete_chain_file(&chain_file);
                            break;
                        }
                        continue;
                    }
                    // Valid technique — spawn the child.
                    if let Err(e) = chain::spawn_next_chain_child(
                        &chain_file,
                        dry_run,
                        no_cleanup,
                        config_path.as_deref(),
                        force,
                        debug,
                        delay_cleanup,
                    ) {
                        return Err(e);
                    }
                    break;
                }
            }
        } else {
            info!("[CHAIN] Chain of one -- process renamed, no child spawned");
        }
    }

    Ok(())
}

/// Look up a suite by name and execute its technique list via `run_techniques`.
pub async fn run_suite(suite_name: &str, opts: RunOptions) -> Result<(), String> {
    let suite = match crate::suites::get_suite_by_name(suite_name) {
        Some(s) => s,
        None => {
            return Err(format!(
                "Suite '{}' not found. Run 'signalbench list' to see available suites.",
                suite_name
            ))
        }
    };

    println!(
        "\n{}",
        format!("[SUITE] {}", suite.name).bold().cyan()
    );
    println!("{}", suite.description.italic());
    println!(
        "{}",
        format!("[SUITE] {} techniques in sequence:", suite.technique_ids.len()).dimmed()
    );
    for id in suite.technique_ids {
        println!("  -> {}", id.yellow());
    }

    let technique_ids: Vec<String> = suite.technique_ids.iter().map(|s| s.to_string()).collect();
    run_techniques(&technique_ids, opts).await
}

/// Generate telemetry for one or more explicitly specified techniques.
/// A single technique delegates directly to `run_technique` (identical behaviour to before).
/// Multiple techniques run in sequence, or build a process chain in chain mode
/// (mirroring the pattern used by `run_categories`).
pub async fn run_techniques(
    techniques: &[String],
    opts: RunOptions,
) -> Result<(), String> {
    if techniques.is_empty() {
        return Err("No techniques specified".to_string());
    }

    // Single technique: delegate directly — identical to the old single-argument behaviour.
    if techniques.len() == 1 {
        return run_technique(&techniques[0], opts).await;
    }

    let RunOptions { dry_run, no_cleanup, config_path, force, debug, delay_cleanup, step_delay, chain } = opts;

    // Validate all IDs up front so the user gets a clear error before anything runs.
    for id in techniques {
        if get_technique_by_id_or_name(id).is_none() {
            return Err(format!("Technique '{id}' not found"));
        }
    }

    // ── Chain mode ────────────────────────────────────────────────────────────
    if chain {
        let all_ids: Vec<String> = techniques.to_vec();

        println!(
            "\n{}",
            format!("[CHAIN] Building process chain with {} techniques", all_ids.len())
                .bold()
                .cyan()
        );
        for id in &all_ids {
            println!("  -> {}", id.yellow());
        }

        chain::write_chain_file(&all_ids)
            .map_err(|e| format!("Failed to initialise chain file: {e}"))?;

        let first_id = match chain::pop_chain_entry(std::path::Path::new(
            &std::env::var(chain::CHAIN_FILE_ENV)
                .map_err(|e| format!("Chain env var missing: {e}"))?,
        ))? {
            Some(id) => id,
            None => return Err("Chain file was empty immediately after writing".to_string()),
        };

        return run_technique(
            &first_id,
            RunOptions {
                dry_run,
                no_cleanup,
                config_path,
                force,
                debug,
                delay_cleanup,
                step_delay,
                chain: true,
            },
        )
        .await;
    }

    // ── Sequential (no chain) ─────────────────────────────────────────────────
    println!(
        "\n{}",
        format!(
            "[RUN] Executing {} techniques: {}",
            techniques.len(),
            techniques.join(", ")
        )
        .bold()
        .cyan()
    );

    if step_delay > 0 {
        println!(
            "{}",
            format!("[STEP] {}s delay between techniques", step_delay).yellow()
        );
    }

    let mut success_count: u32 = 0;
    let mut failure_count: u32 = 0;

    for (idx, technique_id) in techniques.iter().enumerate() {
        match run_technique(
            technique_id,
            RunOptions {
                dry_run,
                no_cleanup,
                config_path: config_path.clone(),
                force,
                debug,
                delay_cleanup,
                step_delay,
                chain: false,
            },
        )
        .await
        {
            Ok(()) => success_count += 1,
            Err(e) => {
                failure_count += 1;
                error!("Technique {technique_id} failed: {e}");
                println!("{}: {}", "Failed".red().bold(), e);
            }
        }
        // Apply step delay between techniques, not after the last one.
        if step_delay > 0 && idx + 1 < techniques.len() {
            println!(
                "{}",
                format!("[STEP] Waiting {}s before next technique...", step_delay).dimmed()
            );
            tokio::time::sleep(std::time::Duration::from_secs(step_delay)).await;
        }
    }

    println!("\n{}", "Run Summary".bold().underline());
    println!("Techniques: {}", techniques.len());
    println!("Successful: {}", success_count.to_string().green());
    println!(
        "Failed: {}",
        if failure_count > 0 {
            failure_count.to_string().red()
        } else {
            failure_count.to_string().normal()
        }
    );

    Ok(())
}

/// Generate telemetry for all techniques in multiple specified categories
/// Developed by Simon Sigre for GoCortex.io
pub async fn run_categories(
    categories: &[String],
    opts: RunOptions,
) -> Result<(), String> {
    let RunOptions { dry_run, no_cleanup, config_path, force, debug, delay_cleanup, step_delay, chain } = opts;
    use crate::cli::{get_available_categories, ALL_CAPS_CATEGORY};

    println!(
        "\n{}",
        format!(
            "SIGNALBENCH v{} - Endpoint Telemetry Generator",
            env!("CARGO_PKG_VERSION")
        )
        .bold()
        .green()
    );
    println!(
        "{}",
        "Developed by GoCortex.io | https://gocortex.io".italic()
    );

    if categories.is_empty() {
        return Err("No categories specified".to_string());
    }

    // Check for ALL_CAPS meta-category (MF DOOM tribute)
    let (effective_categories, effective_force, effective_delay, effective_step_delay) =
        if categories.len() == 1 && categories[0].to_uppercase() == ALL_CAPS_CATEGORY {
            // MF DOOM tribute
            println!("\n{}", "=".repeat(60).cyan());
            println!(
                "{}",
                "  ALL CAPS - MITRE ATT&CK FULL SPECTRUM EXECUTION"
                    .bold()
                    .cyan()
            );
            println!("{}", "=".repeat(60).cyan());
            println!();
            println!(
                "  {}",
                "JUST REMEMBER ALL CAPS WHEN YOU SPELL THE MAN NAME".italic()
            );
            println!("  {}", "-- MF DOOM (1971-2020)".italic());
            println!();
            println!("{}", "=".repeat(60).cyan());
            println!();
            println!(
                "{}",
                "[ALL_CAPS] Running ALL techniques across ALL categories with FORCE mode"
                    .yellow()
                    .bold()
            );
            println!(
                "{}",
                "[ALL_CAPS] Maximum telemetry generation - no guards, no mercy".yellow()
            );
            println!();

            // Get all categories
            let all_cats: Vec<String> = get_available_categories()
                .iter()
                .map(|s| s.to_string())
                .collect();
            // ALL_CAPS uses 5s delay by default if not specified
            let delay = if delay_cleanup == 0 { 5 } else { delay_cleanup };
            let sdel = if step_delay == 0 { 5 } else { step_delay };
            (all_cats, true, delay, sdel)
        } else {
            (categories.to_vec(), force, delay_cleanup, step_delay)
        };

    // Validate all categories first
    for category in &effective_categories {
        if !is_valid_category(category) {
            return Err(format!(
                "Invalid category: {category}. Use 'signalbench list' to see available categories."
            ));
        }
    }

    if effective_force {
        println!(
            "{}",
            "[FORCE MODE] Bypassing all pre-checks - maximum telemetry generation"
                .yellow()
                .bold()
        );
    }

    if effective_delay > 0 {
        println!(
            "{}",
            format!(
                "[DELAY] {}s pause before cleanup (detection window)",
                effective_delay
            )
            .yellow()
        );
    }

    if effective_step_delay > 0 {
        println!(
            "{}",
            format!(
                "[STEP] {}s delay between techniques",
                effective_step_delay
            )
            .yellow()
        );
    }

    // ── Chain mode: build flat ordered list, write chain file, delegate ────────
    if chain {
        // Expand all categories into a flat ordered list of TTP IDs.
        // Where multiple techniques share the same MITRE ID, the chain will execute
        // the first registered matching technique per ID (consistent with how
        // get_technique_by_id_or_name resolves IDs across the codebase).
        let mut all_ids: Vec<String> = Vec::new();
        for category in &effective_categories {
            let techniques = get_techniques_by_category(category);
            for technique in &techniques {
                all_ids.push(technique.info().id.clone());
            }
        }

        if all_ids.is_empty() {
            return Err("No techniques found for the specified categories".to_string());
        }

        println!(
            "\n{}",
            format!("[CHAIN] Building process chain with {} techniques", all_ids.len())
                .bold()
                .cyan()
        );
        for id in &all_ids {
            println!("  -> {}", id.yellow());
        }

        // Per spec: write ALL TTP IDs to the chain file up front (including the
        // first), then each generation pops its own entry before executing.
        chain::write_chain_file(&all_ids)
            .map_err(|e| format!("Failed to initialise chain file: {e}"))?;

        // Pop the first entry and run it in the current process.
        let first_id = match chain::pop_chain_entry(std::path::Path::new(
            &std::env::var(chain::CHAIN_FILE_ENV)
                .map_err(|e| format!("Chain env var missing: {e}"))?,
        ))? {
            Some(id) => id,
            None => return Err("Chain file was empty immediately after writing".to_string()),
        };

        // Run the first technique (it will spawn the rest via chain mode).
        return run_technique(
            &first_id,
            RunOptions {
                dry_run,
                no_cleanup,
                config_path,
                force: effective_force,
                debug,
                delay_cleanup: effective_delay,
                step_delay: effective_step_delay,
                chain: true,
            },
        )
        .await;
    }

    // Load configuration if provided
    let config = if let Some(ref config_path) = config_path {
        Some(load_config(Some(config_path))?)
    } else {
        None
    };

    let mut total_success = 0;
    let mut total_failure = 0;
    let mut total_skipped = 0;
    let mut total_techniques = 0;

    // Process each category
    for category in &effective_categories {
        println!(
            "\n{}",
            format!("Processing Category: {}", category.to_uppercase())
                .bold()
                .cyan()
        );
        println!("{}", "=".repeat(50));

        // Get techniques for this category
        let techniques = get_techniques_by_category(category);

        if techniques.is_empty() {
            println!(
                "{}: No techniques found for category {}",
                "Warning".yellow().bold(),
                category
            );
            continue;
        }

        let mut success_count = 0;
        let mut failure_count = 0;
        let mut skipped_count = 0;
        let mut first_executed = true;

        // Execute each technique in the category
        for technique in &techniques {
            let info = technique.info();

            // Voltron-only techniques require multi-host coordination and
            // cannot run in single-host or ALL_CAPS context.
            if info.voltron_only {
                println!(
                    "\n{} {} | {} - requires Voltron multi-host coordination",
                    "[SKIP]".yellow(),
                    info.id.yellow(),
                    info.name
                );
                warn!(
                    "[SKIP] {} | {} requires Voltron multi-host coordination",
                    info.id, info.name
                );
                continue;
            }

            total_techniques += 1;

            // Apply step delay between techniques (not before the first one executed).
            if !first_executed && effective_step_delay > 0 {
                println!(
                    "{}",
                    format!("[STEP] Waiting {}s before next technique...", effective_step_delay).dimmed()
                );
                tokio::time::sleep(std::time::Duration::from_secs(effective_step_delay)).await;
            }
            first_executed = false;

            println!(
                "\n{} {}",
                "Executing:".bold(),
                format!("{} | {}", info.id.yellow(), info.name).bold()
            );
            if dry_run {
                println!(
                    "{}",
                    "(DRY RUN MODE - No actual execution)".yellow().italic()
                );
            }

            // Get technique-specific config with force flag
            let mut technique_config = if let Some(ref config) = config {
                get_technique_config(&info.id, config)
            } else {
                Default::default()
            };
            technique_config.force = effective_force;
            if no_cleanup {
                technique_config.cleanup_after = Some(false);
            }

            // Pre-flight: skip (don't fail) when a declared hard dependency is absent.
            if let Some(detail) =
                missing_required_tools(technique.as_ref(), effective_force, dry_run).await
            {
                skipped_count += 1;
                total_skipped += 1;
                println!(
                    "{}: {} - dependency missing: {}",
                    "Skipped".yellow().bold(),
                    info.name,
                    detail
                );
                continue;
            }

            // Execute the technique
            match technique.execute(&technique_config, dry_run).await {
                Ok(result) => {
                    success_count += 1;
                    total_success += 1;
                    println!(
                        "{}: {} completed successfully",
                        "Success".green().bold(),
                        info.name
                    );

                    // Print artifacts if any
                    if !result.artifacts.is_empty() {
                        println!("Artifacts created:");
                        for artifact in &result.artifacts {
                            println!("  - {artifact}");
                        }
                    }

                    // Cleanup if necessary
                    if no_cleanup {
                        if !result.artifacts.is_empty() {
                            println!("{}", "Skipping cleanup (--no-cleanup flag set)".yellow());
                        }
                    } else if result.cleanup_required
                        && !dry_run
                        && technique_config.cleanup_after.unwrap_or(true)
                    {
                        if effective_delay > 0 {
                            println!(
                                "{}",
                                format!("Waiting {}s before cleanup...", effective_delay).dimmed()
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(effective_delay))
                                .await;
                        }
                        println!("{}", "Cleaning up...".bold());
                        if let Err(e) = technique.cleanup(&result.artifacts).await {
                            warn!("Cleanup failed: {e}");
                            println!("{}: {}", "Cleanup Warning".yellow().bold(), e);
                        }
                    }
                }
                Err(e) => {
                    failure_count += 1;
                    total_failure += 1;
                    error!("Technique {} failed: {e}", info.id);
                    println!("{}: {} - {}", "Failed".red().bold(), info.name, e);
                }
            }
        }

        // Print category summary
        println!(
            "\n{}",
            format!("Category {} Summary", category.to_uppercase())
                .bold()
                .underline()
        );
        println!("Techniques: {}", techniques.len());
        println!("Successful: {}", success_count.to_string().green());
        println!("Skipped: {}", skipped_count.to_string().yellow());
        println!(
            "Failed: {}",
            if failure_count > 0 {
                failure_count.to_string().red()
            } else {
                failure_count.to_string().normal()
            }
        );
    }

    // Print overall summary
    println!("\n{}", "Overall Execution Summary".bold().underline());
    println!("Categories Processed: {}", effective_categories.len());
    println!("Total Techniques: {total_techniques}");
    println!("Total Successful: {}", total_success.to_string().green());
    println!("Total Skipped: {}", total_skipped.to_string().yellow());
    println!(
        "Total Failed: {}",
        if total_failure > 0 {
            total_failure.to_string().red()
        } else {
            total_failure.to_string().normal()
        }
    );
    if effective_force {
        println!(
            "{}",
            "[FORCE MODE] All operations attempted regardless of pre-checks".yellow()
        );
    }

    Ok(())
}
