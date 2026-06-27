// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

use rand::distr::Alphanumeric;
use rand::Rng;
use std::fs::{self, File};
use std::io::{Read, Write};
use uuid::Uuid;

/// Generate a random string of specified length
#[allow(dead_code)]
pub fn random_string(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a unique ID for tracking attacks
#[allow(dead_code)]
pub fn generate_unique_id() -> String {
    Uuid::new_v4().to_string()
}

/// Create a temporary file with specified content
#[allow(dead_code)]
pub fn create_temp_file(content: &str) -> Result<String, String> {
    let temp_dir = std::env::temp_dir();
    let filename = format!("signalbench_test_{}.tmp", generate_unique_id());
    let path = temp_dir.join(filename);

    let mut file =
        File::create(&path).map_err(|e| format!("Failed to create temporary file: {e}"))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write to temporary file: {e}"))?;

    Ok(path.to_string_lossy().to_string())
}

/// Read a file's content
#[allow(dead_code)]
pub fn read_file(path: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {e}"))?;

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read file: {e}"))?;

    Ok(content)
}

/// Check if current user has root privileges
#[allow(dead_code)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Get current username
#[allow(dead_code)]
pub fn get_username() -> String {
    whoami::username()
}

/// Check if a command is available on the system.
///
/// Scans `$PATH` for an executable file directly rather than shelling out to
/// `which`/`command -v` — those helpers are themselves frequently absent on the
/// lean / container hosts this check exists to protect, which would make every
/// lookup spuriously report "missing".
#[allow(dead_code)]
pub async fn is_command_available(command: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let is_exec = |p: &std::path::Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };

    // An explicit path is checked as-is rather than searched on PATH.
    if command.contains('/') {
        return is_exec(std::path::Path::new(command));
    }

    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|dir| is_exec(&dir.join(command)))
}

/// Map a binary name to a human-readable install hint (Debian / RHEL style).
///
/// Turns a missing-tool condition into actionable operator output, e.g.
/// "install dnsutils / bind-utils". Unknown binaries echo their own name.
#[allow(dead_code)]
pub fn tool_package(bin: &str) -> String {
    match bin {
        "dig" | "nslookup" | "host" => "dnsutils / bind-utils",
        "nc" | "ncat" => "netcat-openbsd / nmap-ncat",
        "socat" => "socat",
        "nmap" => "nmap",
        "hydra" => "hydra",
        "sshpass" => "sshpass",
        "gcc" | "cc" => "gcc / build-essential",
        "gcore" | "gdb" => "gdb",
        "strace" => "strace",
        "setfattr" | "getfattr" => "attr",
        "getcap" | "capsh" => "libcap2-bin / libcap",
        "brctl" => "bridge-utils",
        "arp" | "netstat" | "route" => "net-tools",
        "nft" => "nftables",
        "iptables" => "iptables",
        "lsof" => "lsof",
        "docker" => "docker.io / docker-ce",
        "kubectl" => "kubernetes-client / kubectl",
        "containerd" | "runc" | "crictl" => "containerd",
        "python3" | "python" => "python3",
        "perl" => "perl",
        "ruby" => "ruby",
        "php" => "php-cli",
        "crontab" => "cron / cronie",
        "auditctl" => "auditd",
        "modprobe" | "modinfo" | "lsmod" => "kmod",
        "ssh" | "ssh-keygen" | "scp" => "openssh-client",
        "wipe" => "wipe",
        "debugfs" => "e2fsprogs",
        "ldconfig" => "libc-bin",
        _ => return bin.to_string(),
    }
    .to_string()
}

/// Return the subset of `bins` that are NOT available on this host.
#[allow(dead_code)]
pub async fn missing_tools(bins: &[&str]) -> Vec<String> {
    let mut missing = Vec::new();
    for bin in bins {
        if !is_command_available(bin).await {
            missing.push((*bin).to_string());
        }
    }
    missing
}

/// Build a `bash -c "<cmd>"` invocation for Bucket-A "the attempt is the signal"
/// techniques.
///
/// Calling `Command::new("tool")` directly means a missing binary returns
/// `ENOENT` and no process is ever created — so an EDR sees nothing. Routing the
/// attempt through the shell guarantees a `bash` process whose command line
/// carries the IoC (the argv that brute-force / LOLBin / suspicious-download
/// rules actually match) even when the tool is absent; the shell simply exits
/// 127. `bash` is treated as always present (it is the project's baseline shell).
#[allow(dead_code)]
pub fn shell_attempt(argv: &[&str]) -> tokio::process::Command {
    let line = argv
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd = tokio::process::Command::new("bash");
    cmd.arg("-c").arg(line);
    cmd
}

/// POSIX single-quote a shell argument so it survives `bash -c` unmodified.
fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    let safe = arg.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '=' | ',' | '+')
    });
    if safe {
        return arg.to_string();
    }
    // Close the quote, emit an escaped literal quote, reopen — the POSIX idiom.
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Format file size for display
#[allow(dead_code)]
pub fn format_file_size(size: u64) -> String {
    const KILO: u64 = 1024;
    const MEGA: u64 = KILO * 1024;
    const GIGA: u64 = MEGA * 1024;

    if size >= GIGA {
        format!("{:.2} GB", size as f64 / GIGA as f64)
    } else if size >= MEGA {
        format!("{:.2} MB", size as f64 / MEGA as f64)
    } else if size >= KILO {
        format!("{:.2} KB", size as f64 / KILO as f64)
    } else {
        format!("{size} bytes")
    }
}

/// Get file permissions as an octal string
#[allow(dead_code)]
pub fn get_file_permissions(path: &str) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("Failed to get file metadata: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        Ok(format!("{:o}", mode & 0o777))
    }

    #[cfg(not(unix))]
    {
        Ok("unknown".to_string())
    }
}
