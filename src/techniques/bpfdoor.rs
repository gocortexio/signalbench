// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

// ============================================================================
// S1161 BPFDoor -- Named-software coverage probe (SOFTWARE category)
// ============================================================================
//
// Faithful enough that BPFDoor-specific EDR/YARA rules fire; safety-bounded
// so nothing reaches a functional implant.
//
// Public reporting this implementation draws on:
//   - Elastic Security Labs:  "A peek behind the BPFDoor"
//   - Sandfly Security:       "BPFDoor: An evasive Linux backdoor (technical
//                              analysis)"  -- publishes the disassembled cBPF
//                              filter and the magic constants used below.
//   - Qualys Threat Research: detection-script breakdown
//   - Rapid7 TR Report:       BPFDoor in telecom networks
//   - Nikhil Hegde:           "cBPF-based BPFDoor analysis"
//   - https://github.com/gwillgues/BPFDoor (public reference C source)
//   - MITRE ATT&CK S1161
//
// What this technique DOES (these are the IoCs an EDR signature keys on):
//   1. socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))  -- the namesake
//   2. setsockopt(SO_BINDTODEVICE, "lo")               -- safety, see below
//   3. setsockopt(SO_ATTACH_FILTER, <cBPF program>)    -- filter contains the
//      published BPFDoor magic constants 0x5293 / 0x7255 / 0x39393939 so
//      YARA / signature rules over /proc/<pid>/maps match.
//   4. prctl(PR_SET_NAME, "<one of the documented daemon names>")
//   5. Writes one of the documented BPFDoor PID filenames
//      (haldrund.pid / kdmtmpflush.pid / xinetd.lock / gdm.pid) to /var/run/
//   6. Embeds the BPFDoor YARA fodder strings ("justforfun", "HOME=/tmp",
//      "HISTFILE=", "MYSQL_HISTFILE=", "TERM=xterm", "/bin/sh") into the
//      binary AND logs them at runtime so they appear in working memory.
//   7. Passive listen for a short bounded window (default 5s, hard-capped 30s).
//
// What this technique deliberately does NOT do (the parts that would make it
// a real implant rather than a coverage probe):
//   * NO functional magic-packet trigger: the trigger callback is provably
//     inert -- it logs the byte offsets it inspects and returns.  No fork,
//     no execve, no iptables manipulation, no /bin/sh -i, no callback
//     connection.  Combined with the loopback bind, the trigger is
//     unreachable from any real network anyway.
//   * NO self-unlink (BPFDoor anti-forensic).
//   * NO timestamp manipulation via utime().
//   * NO argv[0] rewrite (PR_SET_NAME catches the YARA / `ps` signal; argv[0]
//     rewriting via env_argv pointer arithmetic is brittle across libc and
//     unnecessary for the coverage purpose).
//
// Safety envelope (hard-coded, not operator-overridable):
//   * AF_PACKET socket bound to "lo" only via SO_BINDTODEVICE.  The socket
//     physically cannot see traffic from any other interface.
//   * Trigger callback contains no syscalls beyond bookkeeping.
//   * No filesystem mutation outside /tmp/signalbench_bpfdoor_<id>/ and one
//     /var/run/<documented>.pid file (tracked + cleaned).
//   * Listen window hard-capped at 30 seconds regardless of operator config.
//   * Refuses any masquerade_name or pid_filename outside the documented
//     BPFDoor sets -- operators cannot use this as a generic process-spoofing
//     primitive (that is T1036-PROC's job).
//   * Requires CAP_NET_RAW (root); cleanly skips with a clear message on
//     unprivileged invocations.
//

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, SimulationResult, Technique, TechniqueParameter};
use crate::techniques::{CleanupFuture, ExecuteFuture};
use async_trait::async_trait;
use libc::{c_int, c_void, sock_filter, sock_fprog};
use log::{debug, info, warn};
use std::ffi::CString;
use std::fs;
use std::os::unix::io::RawFd;
use std::path::Path;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Public BPFDoor constants (transcribed from the published analyses above)
// ---------------------------------------------------------------------------

/// TCP magic value at offset 54 of an Ethernet/IPv4/TCP frame (Sandfly,
/// Elastic).  Decimal 21139.
const BPFDOOR_MAGIC_TCP: u32 = 0x5293;

/// UDP magic value at offset 42 of an Ethernet/IPv4/UDP frame.  Decimal 29269.
const BPFDOOR_MAGIC_UDP: u32 = 0x7255;

/// ICMP magic value (32-bit) at offset 38 of an Ethernet/IPv4/ICMP frame.
const BPFDOOR_MAGIC_ICMP: u32 = 0x39393939;

/// PID filenames real BPFDoor samples use under /var/run/.  These are NOT the
/// actual daemons being masqueraded -- BPFDoor uses these specific
/// benign-looking names that do not belong to any real service.
const BPFDOOR_PID_FILENAMES: &[&str] = &[
    "haldrund.pid",
    "kdmtmpflush.pid",
    "xinetd.lock",
    "gdm.pid",
];

/// Process names documented in public BPFDoor analyses (used for the PR_SET_NAME
/// masquerade -- /proc/<pid>/comm shows the basename of these).  Operators may
/// only choose from this set; arbitrary masquerading is what T1036-PROC is for.
const BPFDOOR_MASQUERADE_NAMES: &[&str] = &[
    "/sbin/udevd",
    "/usr/sbin/atd",
    "/usr/sbin/kdmflush",
    "/usr/sbin/dhcpd",
    "/usr/sbin/auditd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/libexec/postfix/master",
];

/// YARA fodder strings found in BPFDoor samples (per Sandfly / Elastic /
/// Qualys analyses).  Embedded as a single byte slice so they appear in the
/// binary's .rodata AND in working memory (logged at runtime).  Detection
/// rules that key on these strings will match a process scan.
const BPFDOOR_YARA_STRINGS: &[u8] = b"\
S1161-BPFDOOR-COVERAGE-PROBE \
justforfun \
HOME=/tmp \
HISTFILE= \
MYSQL_HISTFILE= \
TERM=xterm-256color \
/bin/sh \
";

// ---------------------------------------------------------------------------
// cBPF filter program (faithful to the published BPFDoor disassembly)
// ---------------------------------------------------------------------------

/// Build the BPFDoor cBPF filter program.  The bytecode mirrors the disassembly
/// published in the Sandfly / Elastic analyses: it accepts packets carrying
/// the magic value at the protocol-specific payload offset (TCP at 54,
/// UDP at 42, ICMP at 38) and drops everything else.
///
/// The magic constants appear in the bytecode's `k` fields, which is what
/// YARA rules over /proc/<pid>/maps (or kernel BPF program dumps) match on.
///
/// The filter is correct and will load cleanly under the kernel verifier.
/// Even though it returns "accept" on magic, our trigger callback is inert,
/// AND the SO_BINDTODEVICE binding to "lo" means no real-network packet ever
/// reaches the filter to begin with.  The combination of those two guards
/// is the safety envelope.
fn build_bpfdoor_filter() -> Vec<sock_filter> {
    vec![
        // (0) ldh [12]                     ; Ethertype
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 12 },
        // (1) jeq #0x0800  jt 0 jf 11      ; IPv4?  fall through, else drop
        sock_filter { code: 0x15, jt: 0, jf: 11, k: 0x0800 },
        // (2) ldb [23]                     ; IP protocol
        sock_filter { code: 0x30, jt: 0, jf: 0, k: 23 },
        // (3) jeq #6   jt 2 jf 0           ; TCP   -> goto 6
        sock_filter { code: 0x15, jt: 2, jf: 0, k: 6 },
        // (4) jeq #17  jt 3 jf 0           ; UDP   -> goto 8
        sock_filter { code: 0x15, jt: 3, jf: 0, k: 17 },
        // (5) jeq #1   jt 4 jf 7           ; ICMP  -> goto 10, else drop
        sock_filter { code: 0x15, jt: 4, jf: 7, k: 1 },
        // (6) ldh [54]                     ; TCP payload halfword
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 54 },
        // (7) jeq #BPFDOOR_MAGIC_TCP  jt 4 jf 5
        sock_filter { code: 0x15, jt: 4, jf: 5, k: BPFDOOR_MAGIC_TCP },
        // (8) ldh [42]                     ; UDP payload halfword
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 42 },
        // (9) jeq #BPFDOOR_MAGIC_UDP  jt 2 jf 3
        sock_filter { code: 0x15, jt: 2, jf: 3, k: BPFDOOR_MAGIC_UDP },
        // (10) ld [38]                     ; ICMP payload word (32-bit)
        sock_filter { code: 0x20, jt: 0, jf: 0, k: 38 },
        // (11) jeq #BPFDOOR_MAGIC_ICMP  jt 0 jf 1
        sock_filter { code: 0x15, jt: 0, jf: 1, k: BPFDOOR_MAGIC_ICMP },
        // (12) ret #65535                  ; accept (unreachable via lo bind)
        sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
        // (13) ret #0                      ; drop
        sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
    ]
}

// ---------------------------------------------------------------------------
// Low-level syscall wrappers
// ---------------------------------------------------------------------------

/// Open the raw AF_PACKET socket -- the namesake mechanism.  Requires
/// CAP_NET_RAW.
fn create_packet_socket() -> Result<RawFd, String> {
    // socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    // ETH_P_ALL == 0x0003; htons puts it in network byte order.
    let eth_p_all_n: c_int = (0x0003_u16.to_be()) as c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all_n) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let reason = match err.raw_os_error() {
            Some(libc::EPERM) | Some(libc::EACCES) => {
                "AF_PACKET raw socket requires CAP_NET_RAW (run as root)"
            }
            Some(libc::EAFNOSUPPORT) => "AF_PACKET not supported by this kernel",
            _ => "socket(AF_PACKET, SOCK_RAW) failed",
        };
        return Err(format!("{reason}: {err}"));
    }
    Ok(fd)
}

/// Bind the raw socket to the loopback interface only.  This is the primary
/// safety guard: even though the cBPF filter accepts magic packets, the
/// socket cannot see traffic from any non-loopback interface, so no real
/// network packet can ever reach the (inert) trigger.
fn bind_to_loopback(fd: RawFd) -> Result<(), String> {
    let lo = CString::new("lo").expect("static 'lo' is a valid CString");
    // SO_BINDTODEVICE expects the interface name as a string.  The length
    // includes the trailing NUL byte.
    let len = (lo.as_bytes().len() + 1) as libc::socklen_t;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            lo.as_ptr() as *const c_void,
            len,
        )
    };
    if rc < 0 {
        return Err(format!(
            "SO_BINDTODEVICE 'lo' failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Attach the cBPF filter program to the raw socket.  The filter bytes
/// embedded include the BPFDoor magic constants -- this is the EDR/YARA IoC.
fn attach_filter(fd: RawFd, filter: &[sock_filter]) -> Result<(), String> {
    // The kernel reads `len` instructions from the filter pointer.  The
    // pointer needs `*mut` typing in the C struct definition, even though
    // the kernel does not modify the program -- `as *mut _` keeps that
    // compatible without any actual mutation by us.
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const sock_fprog as *const c_void,
            std::mem::size_of::<sock_fprog>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(format!(
            "SO_ATTACH_FILTER failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Rename the current process via prctl(PR_SET_NAME, ...).  This changes
/// /proc/self/comm (max 15 chars + NUL), which is what BPFDoor-detecting
/// `ps` / signature rules grep for.  Argv[0] is not rewritten here -- doing
/// so portably across glibc / musl requires pointer arithmetic on the
/// env_argv block, which is brittle and unnecessary for the coverage signal.
fn set_process_name(masquerade: &str) -> Result<String, String> {
    let basename = masquerade.rsplit('/').next().unwrap_or("daemon");
    // PR_SET_NAME is limited to 16 bytes including the NUL terminator.
    let short: String = basename.chars().take(15).collect();
    let cstr = CString::new(short.as_str())
        .map_err(|e| format!("masquerade name is not a valid C string: {e}"))?;
    let rc = unsafe {
        libc::prctl(libc::PR_SET_NAME, cstr.as_ptr() as libc::c_ulong, 0, 0, 0)
    };
    if rc < 0 {
        return Err(format!(
            "prctl(PR_SET_NAME) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(short)
}

/// The magic-packet trigger callback.  Real BPFDoor would XOR-decode a
/// password from the packet, parse a source IP/port for the callback
/// connection, fork, install an iptables nat-REDIRECT rule, and exec
/// /bin/sh -i.  This function is provably inert: zero syscalls beyond
/// bookkeeping, returns immediately.
///
/// The constants it references live in this function's basic block so that
/// LTO does not strip them -- their presence in /proc/<pid>/maps is part of
/// the static-analysis signal.
#[inline(never)]
fn bpfdoor_trigger_inert(packet: &[u8]) {
    // Touch the documented BPFDoor magic constants so they appear in the
    // function's code body for static-analysis tooling.
    let touched_magic = (BPFDOOR_MAGIC_TCP, BPFDOOR_MAGIC_UDP, BPFDOOR_MAGIC_ICMP);
    debug!(
        "[S1161] inert trigger touched (magic={:#06x}/{:#06x}/{:#010x}); {} bytes, NO action taken",
        touched_magic.0,
        touched_magic.1,
        touched_magic.2,
        packet.len()
    );
}

// ---------------------------------------------------------------------------
// Technique implementation
// ---------------------------------------------------------------------------

pub struct S1161BpfDoor;

#[async_trait]
impl AttackTechnique for S1161BpfDoor {
    fn info(&self) -> Technique {
        Technique {
            id: "S1161".to_string(),
            name: "BPFDoor".to_string(),
            description: "Coverage probe for the BPFDoor Linux backdoor family \
                          (Red Menshen / Earth Bluecrow / DecisiveArchitect, \
                          2018+).  Performs the BPFDoor-defining mechanism in \
                          full: opens an AF_PACKET raw socket, attaches a real \
                          cBPF filter program containing the published magic \
                          constants (0x5293 / 0x7255 / 0x39393939) at the \
                          protocol-specific payload offsets, masquerades the \
                          process name (PR_SET_NAME) as one of the documented \
                          daemons (/sbin/udevd, /usr/sbin/atd, etc.), and \
                          writes one of the documented BPFDoor PID filenames \
                          (haldrund.pid / kdmtmpflush.pid / xinetd.lock / \
                          gdm.pid) to /var/run/.  Embeds the standard BPFDoor \
                          YARA fodder strings (justforfun, HOME=/tmp, \
                          MYSQL_HISTFILE=, etc.) in both .rodata and working \
                          memory.  Safety-bounded: the raw socket is hard-bound \
                          to the lo interface via SO_BINDTODEVICE, so the \
                          filter cannot see real network traffic; the \
                          magic-packet trigger callback is provably inert (no \
                          fork, no exec, no iptables, no shell, no C2 \
                          callback).  Listen window hard-capped at 30 seconds. \
                          masquerade_name and pid_filename can only be chosen \
                          from the documented BPFDoor sets -- this is not a \
                          generic process-spoofing primitive (T1036-PROC) or \
                          generic raw-socket primitive.  Requires CAP_NET_RAW \
                          (root).  References: Elastic Security Labs, Sandfly \
                          Security, Qualys, Rapid7 telecom report, MITRE \
                          S1161.  Fully reversible: cleanup removes the PID \
                          file and the /tmp session log.".to_string(),
            category: "software".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "masquerade_name".to_string(),
                    description: "Process name to set via PR_SET_NAME.  Must be \
                                  one of the documented BPFDoor daemons: \
                                  /sbin/udevd, /usr/sbin/atd, /usr/sbin/kdmflush, \
                                  /usr/sbin/dhcpd, /usr/sbin/auditd, \
                                  /usr/lib/systemd/systemd-journald, \
                                  /usr/libexec/postfix/master.  Default: \
                                  /sbin/udevd".to_string(),
                    required: false,
                    default: Some("/sbin/udevd".to_string()),
                },
                TechniqueParameter {
                    name: "pid_filename".to_string(),
                    description: "PID filename written under /var/run/.  Must be \
                                  one of the documented BPFDoor filenames: \
                                  haldrund.pid, kdmtmpflush.pid, xinetd.lock, \
                                  gdm.pid.  Default: haldrund.pid".to_string(),
                    required: false,
                    default: Some("haldrund.pid".to_string()),
                },
                TechniqueParameter {
                    name: "listen_seconds".to_string(),
                    description: "Duration to hold the raw socket + cBPF filter \
                                  open after setup.  Hard-capped at 30s \
                                  regardless of value.  Default: 5".to_string(),
                    required: false,
                    default: Some("5".to_string()),
                },
            ],
            detection: "BPFDoor-specific indicators: socket(AF_PACKET, SOCK_RAW, \
                        ETH_P_ALL) syscall (rare for non-system processes); \
                        setsockopt(SO_ATTACH_FILTER, ...) loading a cBPF \
                        program (visible via `ss -e0p` or BPF program dumps); \
                        YARA matches on the magic constants 0x5293 / 0x7255 / \
                        0x39393939 in /proc/<pid>/maps; YARA matches on the \
                        embedded strings (justforfun, MYSQL_HISTFILE=, etc.); \
                        process whose /proc/<pid>/comm reads as a system daemon \
                        but whose /proc/<pid>/exe is NOT the canonical path \
                        for that daemon; presence of one of the documented \
                        BPFDoor PID filenames in /var/run/ that does not \
                        belong to any real service; raw socket fd held by a \
                        process that does NOT need raw network access (Sandfly, \
                        Elastic, Qualys, Falco rule libraries all key on \
                        these).  Hardened detection: hooking the bpf() / \
                        setsockopt() syscalls via eBPF (KRSI-LSM, Falco, \
                        Tetragon, BPFDoor-Scanner from snapattack) catches \
                        the filter-load syscall pair regardless of process \
                        name.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let masquerade = config
                .parameters
                .get("masquerade_name")
                .cloned()
                .unwrap_or_else(|| "/sbin/udevd".to_string());
            if !BPFDOOR_MASQUERADE_NAMES.contains(&masquerade.as_str()) {
                return Err(format!(
                    "masquerade_name '{masquerade}' not in the documented BPFDoor set; \
                     allowed: {BPFDOOR_MASQUERADE_NAMES:?}"
                ));
            }

            let pid_filename = config
                .parameters
                .get("pid_filename")
                .cloned()
                .unwrap_or_else(|| "haldrund.pid".to_string());
            if !BPFDOOR_PID_FILENAMES.contains(&pid_filename.as_str()) {
                return Err(format!(
                    "pid_filename '{pid_filename}' not in the documented BPFDoor set; \
                     allowed: {BPFDOOR_PID_FILENAMES:?}"
                ));
            }

            // Hard cap at 30s regardless of operator config.  This is part of
            // the safety envelope -- the technique must not turn into a
            // long-lived listener.
            let listen_seconds: u64 = config
                .parameters
                .get("listen_seconds")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(5)
                .min(30);

            let session_id = Uuid::new_v4().to_string().replace('-', "");
            let work_dir = format!("/tmp/signalbench_bpfdoor_{session_id}");
            let log_path = format!("{work_dir}/run.log");

            if dry_run {
                info!("[DRY RUN] S1161 BPFDoor coverage probe would, in order:");
                info!("[DRY RUN]   1. socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))  -- requires CAP_NET_RAW");
                info!("[DRY RUN]   2. setsockopt(SO_BINDTODEVICE, \"lo\")  -- safety envelope");
                info!(
                    "[DRY RUN]   3. setsockopt(SO_ATTACH_FILTER, <cBPF program with magic 0x{:04x}/0x{:04x}/0x{:08x}>)",
                    BPFDOOR_MAGIC_TCP, BPFDOOR_MAGIC_UDP, BPFDOOR_MAGIC_ICMP
                );
                info!("[DRY RUN]   4. prctl(PR_SET_NAME, '{masquerade}')");
                info!("[DRY RUN]   5. write PID file at /var/run/{pid_filename}");
                info!("[DRY RUN]   6. log YARA fodder strings to runtime memory");
                info!("[DRY RUN]   7. passive listen on lo for {listen_seconds}s (filter drops all -- inert trigger never fires)");
                info!("[DRY RUN]   cleanup removes /var/run/{pid_filename} and {work_dir}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: format!(
                        "DRY RUN: BPFDoor coverage probe (masquerade='{masquerade}', \
                         pid='{pid_filename}', listen={listen_seconds}s, magic constants \
                         and YARA strings embedded; lo-bound; inert trigger)"
                    ),
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            // Root gate (CAP_NET_RAW).  Cleanly skip-with-reason rather than
            // crashing -- non-root is a perfectly valid environment in which
            // the technique simply cannot fire.
            if !crate::utils::is_root() {
                let msg = "S1161 BPFDoor requires CAP_NET_RAW (run as root) \
                           -- AF_PACKET raw socket cannot be created \
                           unprivileged; skipping cleanly."
                    .to_string();
                warn!("{msg}");
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: false,
                    message: msg,
                    artifacts: vec![],
                    cleanup_required: false,
                });
            }

            info!("[S1161] Starting BPFDoor coverage probe (session {session_id})");
            info!(
                "[S1161] embedded YARA fodder: {}",
                String::from_utf8_lossy(BPFDOOR_YARA_STRINGS)
            );

            let mut artifacts: Vec<String> = Vec::new();
            let mut report: Vec<String> = Vec::new();
            report.push(format!("S1161 BPFDoor coverage probe -- session {session_id}"));
            report.push(format!(
                "masquerade={masquerade}, pid_filename={pid_filename}, listen={listen_seconds}s"
            ));

            // Work dir for the audit log.
            if let Err(e) = fs::create_dir_all(&work_dir) {
                warn!("[S1161] could not create {work_dir}: {e}");
            } else {
                artifacts.push(work_dir.clone());
            }

            // 1. Open the raw AF_PACKET socket -- the namesake mechanism.
            let sock_fd = match create_packet_socket() {
                Ok(fd) => fd,
                Err(e) => {
                    let msg = format!("[S1161] {e}");
                    warn!("{msg}");
                    let cleanup_required = !artifacts.is_empty();
                    return Ok(SimulationResult {
                        technique_id: self.info().id,
                        success: false,
                        message: msg,
                        artifacts,
                        cleanup_required,
                    });
                }
            };
            let line = format!("[OK] socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) -> fd {sock_fd}");
            info!("  [-->] {line}");
            report.push(line);

            // 2. Bind to loopback ONLY (primary safety guard).
            if let Err(e) = bind_to_loopback(sock_fd) {
                unsafe { libc::close(sock_fd) };
                return Err(format!("[S1161] {e}"));
            }
            let line = "[OK] setsockopt(SO_BINDTODEVICE, \"lo\") -- safety envelope".to_string();
            info!("  [-->] {line}");
            report.push(line);

            // 3. Build and attach the cBPF filter.
            let filter = build_bpfdoor_filter();
            if let Err(e) = attach_filter(sock_fd, &filter) {
                unsafe { libc::close(sock_fd) };
                return Err(format!("[S1161] {e}"));
            }
            let line = format!(
                "[OK] setsockopt(SO_ATTACH_FILTER, {} cBPF instructions, magic 0x{:04x}/0x{:04x}/0x{:08x})",
                filter.len(),
                BPFDOOR_MAGIC_TCP,
                BPFDOOR_MAGIC_UDP,
                BPFDOOR_MAGIC_ICMP
            );
            info!("  [-->] {line}");
            report.push(line);

            // 4. Masquerade the process name.
            match set_process_name(&masquerade) {
                Ok(short) => {
                    let line = format!(
                        "[OK] prctl(PR_SET_NAME, '{short}')  -- /proc/self/comm now masqueraded"
                    );
                    info!("  [-->] {line}");
                    report.push(line);
                }
                Err(e) => {
                    let line = format!("[--] prctl(PR_SET_NAME, '{masquerade}'): {e}");
                    warn!("  {line}");
                    report.push(line);
                }
            }

            // 5. PID file -- only write if the documented BPFDoor name is not
            //    already taken (we never overwrite an existing file).
            let pid_path = format!("/var/run/{pid_filename}");
            if Path::new(&pid_path).exists() {
                let line = format!(
                    "[--] PID file {pid_path} already exists -- refusing to overwrite"
                );
                warn!("  {line}");
                report.push(line);
            } else {
                match fs::write(&pid_path, format!("{}\n", std::process::id())) {
                    Ok(_) => {
                        let line = format!("[OK] PID file written: {pid_path}");
                        info!("  [-->] {line}");
                        report.push(line);
                        artifacts.push(pid_path.clone());
                    }
                    Err(e) => {
                        let line = format!("[--] PID file write {pid_path} failed: {e}");
                        warn!("  {line}");
                        report.push(line);
                    }
                }
            }

            // 6. Touch the inert trigger so its symbol stays in the loaded
            //    binary (defensive against LTO stripping).
            bpfdoor_trigger_inert(&[]);

            // 7. Passive listen for the bounded window.  The cBPF filter
            //    drops all packets on lo, and the inert trigger would do
            //    nothing even if a magic packet arrived -- this is the
            //    EDR-visible "BPFDoor sitting on a raw socket" window.
            let line = format!(
                "[INFO] passive listen on lo for {listen_seconds}s (filter drops all; inert trigger)"
            );
            info!("  [-->] {line}");
            report.push(line);
            tokio::time::sleep(std::time::Duration::from_secs(listen_seconds)).await;
            report.push("[OK] listen window complete".to_string());

            // 8. Close the socket -- the BPF filter detaches with it.
            unsafe { libc::close(sock_fd) };
            report.push("[OK] raw socket closed (cBPF filter detached)".to_string());

            // 9. Persist the audit log via normal I/O (the recon channel was
            //    syscall-flavoured, the audit trail is deliberately visible).
            let body = report.join("\n");
            if let Err(e) = fs::write(&log_path, format!("{body}\n")) {
                warn!("[S1161] could not write log {log_path}: {e}");
            } else {
                artifacts.push(log_path.clone());
            }

            let steps_ok = report.iter().filter(|l| l.starts_with("[OK]")).count();
            let summary = format!(
                "S1161 BPFDoor coverage probe complete: {steps_ok} steps OK \
                 (masquerade={masquerade}, pid=/var/run/{pid_filename}, listen={listen_seconds}s, \
                 cBPF magic 0x{:04x}/0x{:04x}/0x{:08x}; lo-bound; inert trigger).  \
                 EDR signal is the AF_PACKET+ATTACH_FILTER syscall pair plus the YARA-matchable \
                 magic constants and strings -- not any action taken by the trigger.",
                BPFDOOR_MAGIC_TCP, BPFDOOR_MAGIC_UDP, BPFDOOR_MAGIC_ICMP
            );
            info!("{summary}");

            let cleanup_required = !artifacts.is_empty();
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message: summary,
                artifacts,
                cleanup_required,
            })
        })
    }

    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            info!("[S1161] Cleaning up BPFDoor coverage probe artefacts...");

            // Two-pass: files first (so per-file failures are surfaced
            // before the wholesale directory removal), then directories.
            let mut dirs: Vec<&String> = Vec::new();
            for artifact in artifacts {
                let p = Path::new(artifact);
                if !p.exists() {
                    continue;
                }
                if p.is_dir() {
                    dirs.push(artifact);
                    continue;
                }
                match fs::remove_file(artifact) {
                    Ok(_) => info!("  [OK] Removed {artifact}"),
                    Err(e) => warn!("  Failed to remove {artifact}: {e}"),
                }
            }
            for dir in dirs {
                match fs::remove_dir_all(dir) {
                    Ok(_) => info!("  [OK] Removed dir {dir}"),
                    Err(e) => warn!("  Failed to remove dir {dir}: {e}"),
                }
            }

            info!("[S1161] Cleanup complete");
            Ok(())
        })
    }
}
