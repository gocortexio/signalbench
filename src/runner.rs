use crate::cli::is_valid_category;
use crate::config::{load_config, get_technique_config};
use crate::techniques::{get_all_techniques, get_technique_by_id_or_name, get_techniques_by_category};
use log::{error, warn};
use colored::*;
use std::collections::HashMap;

/// List all available MITRE ATT&CK techniques
/// Developed by Simon Sigre for GoCortex.io
pub fn list_techniques() -> Result<(), String> {
    println!("\n{}", format!("SIGNALBENCH v{} - Endpoint Telemetry Generator", env!("CARGO_PKG_VERSION")).bold().green());
    println!("{}", "Developed by GoCortex.io | https://gocortex.io".italic());
    println!("\n{}", "Available MITRE ATT&CK Techniques".bold().underline());
    
    // Get all techniques and organise by category
    let all_techniques = get_all_techniques();
    
    // Group techniques by category (normalized to ensure consistent capitalization)
    let mut techniques_by_category: HashMap<String, Vec<_>> = HashMap::new();
    for technique in all_techniques {
        let category = technique.info().category.to_lowercase();
        techniques_by_category.entry(category).or_insert_with(Vec::new).push(technique);
    }
    
    // Sort categories
    let mut categories: Vec<_> = techniques_by_category.keys().collect();
    categories.sort();
    
    // Print techniques by category
    for category in categories {
        println!("\n{}", category.to_uppercase().bold().green());
        println!("{}", "-".repeat(category.len()));
        
        let techniques = techniques_by_category.get(category).unwrap();
        for technique in techniques {
            let info = technique.info();
            println!("  {} | {}", info.id.yellow(), info.name);
            println!("    {}", info.description);
            println!("    {}", format!("Platforms: {}", info.platforms.join(", ")).dimmed());
        }
    }
    
    println!("\n{}", "Usage:".bold());
    println!("  signalbench run <technique_id_or_name> [--dry-run] [--config <config_file>]");
    println!("  signalbench category <category1> [category2] [category3] ... [--dry-run] [--config <config_file>]");
    println!("\n{}", "Note:".bold());
    println!("  For techniques with the same MITRE ATT&CK ID, use the exact technique name in quotes");
    println!("\n{}", "Visit https://gocortex.io for documentation and support".italic());
    
    Ok(())
}

/// Generate telemetry for a specific technique
pub async fn run_technique(
    technique_id: &str, 
    dry_run: bool,
    config_path: Option<std::path::PathBuf>,
) -> Result<(), String> {
    // Load configuration
    let config = load_config(config_path.as_deref())?;
    
    // Find the technique
    let technique = match get_technique_by_id_or_name(technique_id) {
        Some(t) => t,
        None => return Err(format!("Technique '{technique_id}' not found")),
    };
    
    let technique_info = technique.info();
    
    // Print technique information
    println!("\n{}", "Generating Technique Telemetry".bold().underline());
    println!("{}: {}", "Technique ID".bold(), technique_info.id.yellow());
    println!("{}: {}", "Name".bold(), technique_info.name);
    println!("{}: {}", "Category".bold(), technique_info.category);
    println!("{}: {}", "Description".bold(), technique_info.description);
    
    if dry_run {
        println!("\n{}", "[DRY RUN MODE]".bold().blue());
    }
    
    // Get technique-specific configuration
    let technique_config = get_technique_config(&technique_info.id, &config);
    
    // Execute the technique
    println!("\n{}", "Executing...".bold());
    
    let result = match technique.execute(&technique_config, dry_run).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to execute technique: {e}");
            return Err(format!("Failed to execute technique: {e}"));
        }
    };
    
    // Print result
    if result.success {
        println!("\n{}", "Execution Successful".bold().green());
    } else {
        println!("\n{}", "Execution Failed".bold().red());
    }
    
    println!("{}", result.message);
    
    if !result.artifacts.is_empty() {
        println!("\n{}", "Created Artifacts:".bold());
        for artifact in &result.artifacts {
            println!("  - {artifact}");
        }
    }
    
    // Cleanup if necessary
    if result.cleanup_required && !dry_run && technique_config.cleanup_after.unwrap_or(true) {
        println!("\n{}", "Cleaning up...".bold());
        if let Err(e) = technique.cleanup(&result.artifacts).await {
            warn!("Cleanup failed: {e}");
            println!("{}: {}", "Cleanup Warning".yellow().bold(), e);
        } else {
            println!("{}", "Cleanup completed successfully".green());
        }
    } else if result.cleanup_required && !technique_config.cleanup_after.unwrap_or(true) {
        println!("\n{}", "Artifacts left on system (cleanup_after = false)".yellow().bold());
    }
    
    Ok(())
}



/// Generate telemetry for all techniques in multiple specified categories
/// Developed by Simon Sigre for GoCortex.io
pub async fn run_categories(categories: &[String], dry_run: bool, config_path: Option<std::path::PathBuf>) -> Result<(), String> {
    println!("\n{}", format!("SIGNALBENCH v{} - Endpoint Telemetry Generator", env!("CARGO_PKG_VERSION")).bold().green());
    println!("{}", "Developed by GoCortex.io | https://gocortex.io".italic());
    
    if categories.is_empty() {
        return Err("No categories specified".to_string());
    }
    
    // Validate all categories first
    for category in categories {
        if !is_valid_category(category) {
            return Err(format!("Invalid category: {category}. Use 'signalbench list' to see available categories."));
        }
    }
    
    // Load configuration if provided
    let config = if let Some(config_path) = config_path {
        Some(load_config(Some(&config_path))?)
    } else {
        None
    };
    
    let mut total_success = 0;
    let mut total_failure = 0;
    let mut total_techniques = 0;
    
    // Process each category
    for category in categories {
        println!("\n{}", format!("Processing Category: {}", category.to_uppercase()).bold().cyan());
        println!("{}", "=".repeat(50));
        
        // Get techniques for this category
        let techniques = get_techniques_by_category(category);
        
        if techniques.is_empty() {
            println!("{}: No techniques found for category {}", "Warning".yellow().bold(), category);
            continue;
        }
        
        let mut success_count = 0;
        let mut failure_count = 0;
        
        // Execute each technique in the category
        for technique in &techniques {
            total_techniques += 1;
            let info = technique.info();
            
            println!("\n{} {}", "Executing:".bold(), format!("{} | {}", info.id.yellow(), info.name).bold());
            if dry_run {
                println!("{}", "(DRY RUN MODE - No actual execution)".yellow().italic());
            }
            
            // Get technique-specific config
            let technique_config = if let Some(ref config) = config {
                get_technique_config(&info.id, config)
            } else {
                Default::default()
            };
            
            // Execute the technique
            match technique.execute(&technique_config, dry_run).await {
                Ok(result) => {
                    success_count += 1;
                    total_success += 1;
                    println!("{}: {} completed successfully", "Success".green().bold(), info.name);
                    
                    // Print artifacts if any
                    if !result.artifacts.is_empty() {
                        println!("Artifacts created:");
                        for artifact in &result.artifacts {
                            println!("  - {artifact}");
                        }
                    }
                    
                    // Cleanup if necessary
                    if result.cleanup_required && !dry_run && technique_config.cleanup_after.unwrap_or(true) {
                        println!("{}", "Cleaning up...".bold());
                        if let Err(e) = technique.cleanup(&result.artifacts).await {
                            warn!("Cleanup failed: {e}");
                            println!("{}: {}", "Cleanup Warning".yellow().bold(), e);
                        }
                    }
                },
                Err(e) => {
                    failure_count += 1;
                    total_failure += 1;
                    error!("Technique {} failed: {e}", info.id);
                    println!("{}: {} - {}", "Failed".red().bold(), info.name, e);
                }
            }
        }
        
        // Print category summary
        println!("\n{}", format!("Category {} Summary", category.to_uppercase()).bold().underline());
        println!("Techniques: {}", techniques.len());
        println!("Successful: {}", success_count.to_string().green());
        println!("Failed: {}", if failure_count > 0 { 
            failure_count.to_string().red()
        } else { 
            failure_count.to_string().normal()
        });
    }
    
    // Print overall summary
    println!("\n{}", "Overall Execution Summary".bold().underline());
    println!("Categories Processed: {}", categories.len());
    println!("Total Techniques: {total_techniques}");
    println!("Total Successful: {}", total_success.to_string().green());
    println!("Total Failed: {}", if total_failure > 0 { 
        total_failure.to_string().red()
    } else { 
        total_failure.to_string().normal()
    });
    
    Ok(())
}
