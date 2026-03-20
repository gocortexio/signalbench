// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

// SignalBench - Chain Execution Mode
// Implements file-based TTP chaining so each technique runs as a child process
// of the previous one, building a genuine parent/child process tree.

use log::{info, warn};
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// Environment variable that stores the path to the chain session file.
/// Child processes read this to locate the shared chain state.
pub const CHAIN_FILE_ENV: &str = "SIGNALBENCH_CHAIN_FILE";

/// Write a list of TTP IDs to a new session-scoped chain file at
/// `<temp_dir>/signalbench_chain_<uuid>.txt` and export `SIGNALBENCH_CHAIN_FILE`
/// into the current process's environment so child processes inherit it.
pub fn write_chain_file(ttp_ids: &[String]) -> Result<PathBuf, String> {
    let id = uuid::Uuid::new_v4().to_string().replace('-', "");
    let path = env::temp_dir().join(format!("signalbench_chain_{id}.txt"));

    let mut file = fs::File::create(&path)
        .map_err(|e| format!("Failed to create chain file {:?}: {e}", path))?;

    for ttp_id in ttp_ids {
        writeln!(file, "{ttp_id}").map_err(|e| format!("Failed to write chain file: {e}"))?;
    }

    // Export into current process so inherited child environment picks it up.
    env::set_var(CHAIN_FILE_ENV, &path);

    info!("[CHAIN] Chain file created: {:?} ({} entries)", path, ttp_ids.len());
    Ok(path)
}

/// Read and atomically remove the first entry from the chain file.
/// Returns `None` when the file is empty or missing.
pub fn pop_chain_entry(chain_file: &Path) -> Result<Option<String>, String> {
    if !chain_file.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(chain_file)
        .map_err(|e| format!("Failed to read chain file: {e}"))?;

    let mut lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() {
        return Ok(None);
    }

    let first = lines.remove(0).to_string();

    // Write remaining lines back atomically (write to .tmp then rename).
    let tmp_path = chain_file.with_extension("tmp");
    {
        let mut tmp = fs::File::create(&tmp_path)
            .map_err(|e| format!("Failed to create tmp chain file: {e}"))?;
        for line in &lines {
            writeln!(tmp, "{line}").map_err(|e| format!("Failed to write tmp chain file: {e}"))?;
        }
    }
    fs::rename(&tmp_path, chain_file)
        .map_err(|e| format!("Failed to atomically update chain file: {e}"))?;

    Ok(Some(first))
}

/// Peek at all remaining entries in the chain file without modifying it.
/// Errors are logged as warnings and an empty list is returned so the chain
/// can continue rather than silently masking I/O failures.
pub fn peek_chain_entries(chain_file: &Path) -> Vec<String> {
    if !chain_file.exists() {
        return vec![];
    }
    match fs::File::open(chain_file) {
        Err(e) => {
            warn!("[CHAIN] Failed to open chain file for peek {:?}: {e}", chain_file);
            vec![]
        }
        Ok(f) => io::BufReader::new(f)
            .lines()
            .filter_map(|l| match l {
                Ok(line) if !line.is_empty() => Some(line),
                Err(e) => {
                    warn!("[CHAIN] Error reading chain file line: {e}");
                    None
                }
                _ => None,
            })
            .collect(),
    }
}

/// Delete the chain file.  Always called by the last process in a chain.
/// Ignores errors if the file is already gone.
pub fn delete_chain_file(chain_file: &Path) {
    if chain_file.exists() {
        if let Err(e) = fs::remove_file(chain_file) {
            warn!("[CHAIN] Failed to delete chain file {:?}: {e}", chain_file);
        } else {
            info!("[CHAIN] Chain file deleted: {:?}", chain_file);
        }
    }
}

/// If `SIGNALBENCH_CHAIN_FILE` env var is set, delete that file.
/// Used by the Tokio SIGINT/SIGTERM handler to clean up on Ctrl+C.
pub fn cleanup_chain_file_from_env() {
    if let Ok(path) = env::var(CHAIN_FILE_ENV) {
        let p = Path::new(&path);
        delete_chain_file(p);
    }
}

/// Spawn the next `signalbench` child process.
///
/// * Pops the next TTP ID from the chain file.
/// * Sets `argv[0]` to the TTP ID with dots replaced by dashes (Unix only; no-op on Windows).
/// * Explicitly propagates `SIGNALBENCH_CHAIN_FILE` into the child environment.
/// * Inherits all relevant parent flags.
/// * Blocks (waits) until the child exits.
/// * If the child exits non-zero, cleans up the chain file and returns an error.
///
/// Returns `Ok(())` when there are no more entries (chain finished cleanly).
pub fn spawn_next_chain_child(
    chain_file: &Path,
    dry_run: bool,
    no_cleanup: bool,
    config: Option<&std::path::Path>,
    force: bool,
    debug: bool,
    delay_cleanup: u64,
) -> Result<(), String> {
    let next_id = match pop_chain_entry(chain_file)? {
        Some(id) => id,
        None => {
            // No more entries — this process was the last in the chain.
            delete_chain_file(chain_file);
            return Ok(());
        }
    };

    info!("[CHAIN] Spawning child for technique: {next_id}");

    // Build argv[0] alias: dots replaced by dashes (e.g. T1003-001).
    let child_name = next_id.replace('.', "-");

    // Determine the binary path (our own executable).
    let exe = env::current_exe()
        .map_err(|e| format!("Failed to determine current executable path: {e}"))?;

    // Build the argument list for the child process.
    // Child will execute:  <alias> run <id> [flags] --chain
    let mut args: Vec<String> = vec![
        child_name.clone(), // argv[0] — the TTP alias
        "run".to_string(),
        next_id.clone(),
    ];

    if dry_run {
        args.push("--dry-run".to_string());
    }
    if no_cleanup {
        args.push("--no-cleanup".to_string());
    }
    if force {
        args.push("--force".to_string());
    }
    if debug {
        args.push("--debug".to_string());
    }
    if delay_cleanup > 0 {
        args.push("--delay-cleanup".to_string());
        args.push(delay_cleanup.to_string());
    }
    if let Some(cfg) = config {
        args.push("--config".to_string());
        args.push(cfg.to_string_lossy().to_string());
    }
    args.push("--chain".to_string());

    // Spawn the child.  Explicitly set SIGNALBENCH_CHAIN_FILE on the child's
    // environment in addition to inheriting it, so the handoff is unambiguous
    // even if the parent's environment has been modified since the file was created.
    let status = spawn_with_argv0(&exe, &args, &child_name, chain_file)
        .map_err(|e| format!("Failed to spawn chain child '{next_id}': {e}"))?;

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        warn!("[CHAIN] Child process '{next_id}' exited with code {code} — aborting chain");
        delete_chain_file(chain_file);
        return Err(format!(
            "Chain aborted: child '{next_id}' exited with non-zero code {code}"
        ));
    }

    Ok(())
}

/// Rename the current process so it appears under the TTP ID in `ps`/`pstree`.
///
/// On Linux: uses `prctl(PR_SET_NAME)` (16-char limit including NUL).
/// On macOS: uses `pthread_setname_np()` to set the main thread name.
/// On Windows: no-op (process hollowing would be required — deferred per spec).
pub fn rename_current_process(ttp_id: &str) {
    // Replace dots with dashes: T1003.001 → T1003-001
    let alias = ttp_id.replace('.', "-");
    // prctl(PR_SET_NAME) on Linux enforces a 15-char + NUL limit.
    let trimmed: &str = if alias.len() > 15 { &alias[..15] } else { &alias };

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        if let Ok(name) = CString::new(trimmed.as_bytes()) {
            unsafe {
                libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        if let Ok(name) = CString::new(trimmed.as_bytes()) {
            unsafe {
                // macOS pthread_setname_np sets the name of the calling thread.
                libc::pthread_setname_np(name.as_ptr());
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = trimmed;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Platform-specific process spawning with argv[0] manipulation
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn spawn_with_argv0(
    exe: &Path,
    args: &[String],
    argv0: &str,
    chain_file: &Path,
) -> io::Result<std::process::ExitStatus> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(exe);
    // Skip args[0] (our alias) — real arguments start at index 1.
    cmd.args(&args[1..]);
    // Override argv[0] so `ps` shows the TTP ID for this child.
    cmd.arg0(argv0);
    // Explicitly set the chain file env var so the child can locate it even
    // if the inherited environment was modified after write_chain_file() ran.
    cmd.env(CHAIN_FILE_ENV, chain_file);
    cmd.status()
}

#[cfg(not(unix))]
fn spawn_with_argv0(
    exe: &Path,
    args: &[String],
    _argv0: &str,
    chain_file: &Path,
) -> io::Result<std::process::ExitStatus> {
    // Windows: argv[0] manipulation is not supported; spawn normally.
    // Chain execution still works — only process renaming is a no-op.
    let mut cmd = std::process::Command::new(exe);
    cmd.args(&args[1..]);
    cmd.env(CHAIN_FILE_ENV, chain_file);
    cmd.status()
}
