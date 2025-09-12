use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use log::debug;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TechniqueConfig {
    pub parameters: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub cleanup_after: Option<bool>,
}

impl Default for TechniqueConfig {
    fn default() -> Self {
        TechniqueConfig {
            parameters: HashMap::new(),
            timeout_seconds: Some(30),
            cleanup_after: Some(true),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct SimulatorConfig {
    pub techniques: HashMap<String, TechniqueConfig>,
    pub global: GlobalConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub dry_run: Option<bool>,
    pub default_timeout_seconds: Option<u64>,
    pub default_cleanup_after: Option<bool>,
    pub log_level: Option<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        GlobalConfig {
            dry_run: Some(false),
            default_timeout_seconds: Some(30),
            default_cleanup_after: Some(true),
            log_level: Some("info".to_string()),
        }
    }
}


pub fn load_config(path: Option<&Path>) -> Result<SimulatorConfig, String> {
    match path {
        Some(config_path) => {
            if !config_path.exists() {
                return Err(format!("Config file not found: {config_path:?}"));
            }
            
            let config_content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(e) => return Err(format!("Failed to read config file: {e}")),
            };
            
            match serde_json::from_str(&config_content) {
                Ok(config) => {
                    debug!("Loaded configuration from {config_path:?}");
                    Ok(config)
                },
                Err(e) => Err(format!("Failed to parse config file: {e}")),
            }
        },
        None => {
            debug!("No config file provided, using default configuration");
            Ok(SimulatorConfig::default())
        }
    }
}

pub fn get_technique_config(
    technique_id: &str, 
    config: &SimulatorConfig
) -> TechniqueConfig {
    match config.techniques.get(technique_id) {
        Some(technique_config) => technique_config.clone(),
        None => {
            let default_config = TechniqueConfig {
                parameters: HashMap::new(),
                timeout_seconds: config.global.default_timeout_seconds,
                cleanup_after: config.global.default_cleanup_after,
            };
            debug!("No configuration found for technique {technique_id}, using defaults");
            default_config
        }
    }
}

// Save a configuration to a file
#[allow(dead_code)]
pub fn save_config(config: &SimulatorConfig, path: &Path) -> Result<(), String> {
    let config_json = match serde_json::to_string_pretty(config) {
        Ok(json) => json,
        Err(e) => return Err(format!("Failed to serialize config: {e}")),
    };
    
    match fs::write(path, config_json) {
        Ok(_) => {
            debug!("Configuration saved to {path:?}");
            Ok(())
        },
        Err(e) => Err(format!("Failed to write config file: {e}")),
    }
}
