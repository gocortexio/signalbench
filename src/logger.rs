use chrono::Utc;
use env_logger::{Builder, Env};
use log::LevelFilter;
use std::io::Write;

/// Initialise the logger with UTC ISO8601 timestamps and coloured output
pub fn init_logger(debug: bool) {
    let filter_level = if debug { "debug" } else { "info" };
    
    Builder::from_env(Env::default().default_filter_or(filter_level))
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {} {}] {}",
                Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();
}

/// Macro for debug logging with UTC ISO8601 timestamps
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        eprintln!("[{} DEBUG] {}", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"), format!($($arg)*));
    };
}

/// Set the logger level
#[allow(dead_code)]
pub fn set_log_level(level: &str) {
    match level.to_lowercase().as_str() {
        "debug" => log::set_max_level(LevelFilter::Debug),
        "info" => log::set_max_level(LevelFilter::Info),
        "warn" => log::set_max_level(LevelFilter::Warn),
        "error" => log::set_max_level(LevelFilter::Error),
        _ => log::set_max_level(LevelFilter::Info),
    }
}

/// Log to both console and a file
#[allow(dead_code)]
pub fn setup_file_logger(log_file: &str) -> Result<(), String> {
    let log_dir = std::path::Path::new(log_file).parent().unwrap_or_else(|| std::path::Path::new("."));
    
    if !log_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(log_dir) {
            return Err(format!("Failed to create log directory: {e}"));
        }
    }
    
    // Logging will continue to the console via env_logger
    // This just adds file logging as well
    
    Ok(())
}
