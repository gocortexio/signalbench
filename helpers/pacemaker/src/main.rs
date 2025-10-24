use std::env;
use std::fs::File;
use std::io::{Write, Read};
use std::thread;
use std::time::Duration;

// YARA signature strings - MUST match FE_APT_Trojan_Linux_PACEMAKER rule exactly
// These strings MUST be embedded in the binary and survive compiler optimization
static CRED_FORMAT_STR: &[u8] = b"\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00";
static PROC_MEM_STR: &[u8] = b"\x00/proc/%d/mem\x00";
static PROC_MAPS_STR: &[u8] = b"\x00/proc/%s/maps\x00";
static PROC_CMDLINE_STR: &[u8] = b"\x00/proc/%s/cmdline\x00";

fn main() {
    // Parse command line arguments to mimic memread launcher
    // Based on Mandiant report: /home/bin/memread -t $1 -m 16 -s 2 &
    let args: Vec<String> = env::args().collect();
    let mut timeout_secs = 10;
    let mut mem_size_mb = 16;
    let mut scan_interval = 2;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" => {
                if i + 1 < args.len() {
                    timeout_secs = args[i + 1].parse().unwrap_or(10);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-m" => {
                if i + 1 < args.len() {
                    mem_size_mb = args[i + 1].parse().unwrap_or(16);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "-s" => {
                if i + 1 < args.len() {
                    scan_interval = args[i + 1].parse().unwrap_or(2);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    // CRITICAL: Force the compiler to include YARA signature strings in the binary
    // Using std::hint::black_box() prevents the optimiser from removing these strings
    // This ensures the binary will trigger FE_APT_Trojan_Linux_PACEMAKER YARA detection
    std::hint::black_box(CRED_FORMAT_STR);
    std::hint::black_box(PROC_MEM_STR);
    std::hint::black_box(PROC_MAPS_STR);
    std::hint::black_box(PROC_CMDLINE_STR);
    
    // Additionally, actually use the strings to guarantee their presence
    let _ = consume_signature_strings();

    // Simulate PACEMAKER credential stealing behaviour based on Mandiant APT report
    // This mimics the behaviour described in the FE_APT_Trojan_Linux_PACEMAKER malware
    simulate_credential_harvesting(timeout_secs, mem_size_mb, scan_interval);
}

/// Consume the YARA signature strings to prevent compiler optimisation
/// This function uses the strings in a way that the compiler cannot eliminate
#[inline(never)]
fn consume_signature_strings() -> usize {
    let mut consumed: usize = 0;
    
    // Touch each byte to ensure the strings are actually used
    for &byte in CRED_FORMAT_STR {
        consumed = consumed.wrapping_add(byte as usize);
    }
    for &byte in PROC_MEM_STR {
        consumed = consumed.wrapping_add(byte as usize);
    }
    for &byte in PROC_MAPS_STR {
        consumed = consumed.wrapping_add(byte as usize);
    }
    for &byte in PROC_CMDLINE_STR {
        consumed = consumed.wrapping_add(byte as usize);
    }
    
    std::hint::black_box(consumed)
}

/// Simulate PACEMAKER credential harvesting behaviour
/// Based on Mandiant report: https://www.mandiant.com/resources/blog/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day
fn simulate_credential_harvesting(timeout_secs: u64, mem_size_mb: u64, scan_interval: u64) {
    // Credential files matching Mandiant APT report and RADIALPULSE YARA rules
    // Real PACEMAKER writes to: /tmp/dsactiveuser.statementcounters, etc.
    let cred_files = [
        "/tmp/signalbench_sim_dsactiveuser.statementcounters",
        "/tmp/signalbench_sim_dsstartssh.statementcounters",
        "/tmp/signalbench_sim_dsserver-check.statementcounters",
    ];

    // Simulate process inspection via /proc filesystem (safe simulation)
    simulate_proc_inspection();

    // Simulate memory scanning behaviour
    simulate_memory_scanning(mem_size_mb, scan_interval);

    // Create credential files with harvested data format
    // Real PACEMAKER uses format: "Name:%s || Pwd:%s || AuthNum:%s"
    create_credential_files(&cred_files, mem_size_mb, scan_interval);

    // Simulate the memread process running for the specified timeout
    // This mimics: /home/bin/memread -t $1 -m 16 -s 2 &
    thread::sleep(Duration::from_secs(timeout_secs));
}

/// Simulate /proc filesystem inspection
/// PACEMAKER reads /proc/%s/maps and /proc/%s/cmdline to locate credentials in memory
fn simulate_proc_inspection() {
    // Try to read our own process maps (safe simulation)
    let pid = std::process::id();
    let maps_path = format!("/proc/{pid}/maps");
    let cmdline_path = format!("/proc/{pid}/cmdline");
    
    // Attempt to read maps file (simulates credential location in memory)
    if let Ok(mut file) = File::open(&maps_path) {
        let mut buffer = String::new();
        let _ = file.read_to_string(&mut buffer);
        // In real PACEMAKER, this locates credential memory regions
    }
    
    // Attempt to read cmdline (simulates process identification)
    if let Ok(mut file) = File::open(&cmdline_path) {
        let mut buffer = Vec::new();
        let _ = file.read_to_end(&mut buffer);
        // In real PACEMAKER, this identifies target Pulse Secure processes
    }
}

/// Simulate memory scanning behaviour
/// PACEMAKER reads from /proc/%d/mem to extract credentials from running processes
fn simulate_memory_scanning(_mem_size_mb: u64, _scan_interval: u64) {
    // Real PACEMAKER would:
    // 1. Open /proc/<target_pid>/mem
    // 2. Scan memory regions identified from /proc/<target_pid>/maps
    // 3. Search for credential patterns (usernames, passwords, auth tokens)
    // 4. Extract credentials matching authentication realms (LDAP, RADIUS, ACE)
    
    // We simulate this safely without actually accessing other processes
    let pid = std::process::id();
    let mem_path = format!("/proc/{pid}/mem");
    
    // Attempt to open (will fail with permission denied on most systems, which is expected)
    let _ = File::open(&mem_path);
    // In real PACEMAKER, this extracts Pulse Secure VPN credentials from memory
}

/// Create credential files with harvested data
/// Real PACEMAKER writes credentials in format: "Name:%s || Pwd:%s || AuthNum:%s"
fn create_credential_files(files: &[&str], mem_size_mb: u64, scan_interval: u64) {
    for path in files {
        if let Ok(mut file) = File::create(path) {
            // Simulate credential data format from Mandiant report
            // Real PACEMAKER would write actual harvested credentials here
            let _ = writeln!(
                file,
                "=== SignalBench PACEMAKER Simulation ===\n\
                Credential Harvesting Simulation\n\
                Target: Pulse Secure VPN Authentication\n\
                Memory size scanned: {mem_size_mb}MB\n\
                Scan interval: {scan_interval}s\n\
                Authentication Realms: LDAP, RADIUS, ACE\n\
                \n\
                Simulated Credential Format:\n\
                Name:simulated_user || Pwd:simulated_pass || AuthNum:simulated_token\n\
                \n\
                Note: This is a benign simulation for security analytics testing\n\
                Real PACEMAKER malware harvests actual VPN credentials from memory"
            );
        }
    }
}
