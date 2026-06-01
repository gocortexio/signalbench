// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

use log::{debug, warn};
use std::path::Path;

/// Check if the environment is safe for running attack simulations
pub fn check_environment() -> Result<(), String> {
    debug!("Performing safety checks before execution");

    // Check for the presence of sensitive files
    check_for_sensitive_files()?;

    // Everything looks good
    debug!("Safety checks passed");
    Ok(())
}

/// Check for the presence of sensitive files that might indicate a production system
fn check_for_sensitive_files() -> Result<(), String> {
    // Basic safety check - only warn about obvious production indicators
    let critical_paths = [
        "/etc/kubernetes/admin.conf",
        "/var/lib/docker/swarm/docker-state.json",
    ];

    for path in &critical_paths {
        if Path::new(path).exists() {
            warn!("Detected critical system file: {path}");
        }
    }

    // Detect signs of a prior incomplete PamBackdoor (T1556.003) run.
    // If any of the following are present, the previous run either
    // crashed before cleanup or hit a guarded-refusal: leftover
    // artefacts that an operator should investigate before launching
    // anything else.
    let pam_backup_glob = std::fs::read_dir("/etc/pam.d").ok();
    if let Some(entries) = pam_backup_glob {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("sshd.signalbench-backup") {
                warn!(
                    "Detected leftover PamBackdoor SSH backup: \
                     /etc/pam.d/{name} (prior run did not complete \
                     cleanup; review /etc/pam.d/sshd for stray \
                     backdoor lines)"
                );
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("signalbench_pam_") && name.ends_with(".so") {
                warn!(
                    "Detected leftover PamBackdoor fake module: /tmp/{name} \
                     (prior run did not clean up)"
                );
            }
            if name.starts_with("signalbench_pam_backdoor_") && name.ends_with(".json") {
                warn!(
                    "Detected leftover PamBackdoor metadata: /tmp/{name} \
                     (run `signalbench cleanup` or inspect this file to \
                     understand what state remains)"
                );
            }
        }
    }

    // Catastrophic post-incident detector: if pam_unix.so is missing
    // from every PAM module directory on a Linux host, authentication
    // is broken and signalbench should refuse to run anything that
    // touches PAM further until the host is repaired.
    #[cfg(target_os = "linux")]
    {
        let pam_module_dirs = [
            "/lib/security/",
            "/lib/x86_64-linux-gnu/security/",
            "/lib64/security/",
            "/usr/lib/security/",
            "/usr/lib/x86_64-linux-gnu/security/",
        ];
        let mut any_exists = false;
        let mut pam_unix_present = false;
        for dir in pam_module_dirs {
            if Path::new(dir).exists() {
                any_exists = true;
                if Path::new(&format!("{dir}pam_unix.so")).exists() {
                    pam_unix_present = true;
                }
            }
        }
        if any_exists && !pam_unix_present {
            warn!(
                "[CRITICAL] pam_unix.so is missing from every PAM module \
                 directory on this host.  Authentication is broken.  \
                 Repair with: apt-get install --reinstall libpam-modules \
                 libpam0g libpam-runtime  (Debian/Ubuntu)  or  \
                 dnf reinstall pam pam-libs  (RHEL/Fedora)."
            );
        }
    }

    Ok(())
}

/// Check if the user has confirmed they want to proceed
#[allow(dead_code)]
pub fn confirm_execution(technique_id: &str, dry_run: bool) -> Result<(), String> {
    if dry_run {
        // No confirmation needed for dry runs
        return Ok(());
    }

    println!(
        "You are about to execute attack technique {technique_id} which may modify your system."
    );
    println!("This is intended for security testing in controlled environments.");
    println!("Do you want to proceed? (y/N): ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {e}"))?;

    if input.trim().to_lowercase() != "y" {
        return Err("Execution cancelled by user".to_string());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Destructive-write safety chokepoint
// ---------------------------------------------------------------------------
//
// Every technique that writes to a system path MUST consult these helpers
// before performing the write.  Post-incident root-cause for the
// PamBackdoor (T1556.003) lockout was: the technique cp'd a fake .so over
// the real /lib/x86_64-linux-gnu/security/pam_unix.so as root with no
// pre-flight check that the destination was a critical system file, no
// backup of the original, and a cleanup path that fs::remove_file'd the
// destination -- leaving the host with no pam_unix.so and total
// auth-lockout for all users.
//
// The contract enforced here is: signalbench will refuse to overwrite a
// path that is either (a) under a protected directory or matches a
// protected filename, OR (b) already exists.  Both conditions are
// independent gates; bypassing one does not bypass the other.
//
// **These guards are NOT overridable by --force.**  --force is for
// production-safety speed bumps (e.g. "this looks like a prod host, do
// you really want to continue").  It is not for "yes, please brick the
// host's authentication stack".  Two different concerns.
//
// Design principle: the EDR detection signal is the syscall trace of the
// attempt, not the success of the overwrite.  Refusing the write at the
// guard layer preserves the technique's logged-attempt audit trail
// without producing real damage.
//
pub mod destructive_write {
    use std::path::Path;

    /// Directory prefixes under which NO file may be created or
    /// overwritten by signalbench.  Each entry must end with a trailing
    /// slash so `starts_with` does what we mean.
    pub const PROTECTED_DIRS: &[&str] = &[
        // Auth modules -- overwriting any of these breaks PAM for every
        // login service on the host (sshd, login, sudo, su, cron, gdm).
        // This is the directory tree where the PamBackdoor lockout
        // originated.
        "/lib/security/",
        "/lib/x86_64-linux-gnu/security/",
        "/lib64/security/",
        "/usr/lib/security/",
        "/usr/lib/x86_64-linux-gnu/security/",
        "/usr/lib64/security/",
        // Init system core unit files -- replacing these breaks boot.
        "/lib/systemd/system/",
        "/usr/lib/systemd/system/",
        // Boot artefacts (initramfs, kernel, GRUB).
        "/boot/",
        // System binaries that every login path depends on.  Each
        // critical login binary is also enumerated in PROTECTED_FILES.
        "/sbin/",
        "/usr/sbin/",
    ];

    /// Exact file paths or basenames that NO technique may overwrite.
    /// Matched against the basename of the destination, then against
    /// the full path, in that order.
    pub const PROTECTED_FILES: &[&str] = &[
        // User database -- corruption equals lockout.
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        // PAM stacks beyond sshd.  /etc/pam.d/sshd is intentionally
        // allowed for the PamBackdoor technique (with backup/restore
        // discipline); modifying any other PAM stack would propagate
        // the failure to console / sudo / su simultaneously.
        "/etc/pam.d/login",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-account",
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/su",
        "/etc/pam.d/sudo",
        // Core login shells / authentication binaries.  Listed
        // explicitly because PROTECTED_DIRS doesn't cover /bin/.
        "/bin/sh",
        "/bin/bash",
        "/bin/dash",
        "/bin/login",
        "/bin/su",
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/login",
        // C library and its critical siblings.  An overwrite of any
        // of these takes down every dynamically-linked binary on the
        // host instantly.
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/lib/x86_64-linux-gnu/libdl.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/lib64/libc.so.6",
        "/lib64/ld-linux-x86-64.so.2",
    ];

    /// Real PAM module filenames.  Any destination whose basename
    /// matches one of these is refused as a destination regardless of
    /// the parent directory -- belt-and-braces against PROTECTED_DIRS
    /// missing a path on an exotic distribution layout.
    pub const PROTECTED_PAM_MODULES: &[&str] = &[
        "pam_unix.so",
        "pam_systemd.so",
        "pam_deny.so",
        "pam_permit.so",
        "pam_env.so",
        "pam_cap.so",
        "pam_limits.so",
        "pam_loginuid.so",
        "pam_mail.so",
        "pam_motd.so",
        "pam_namespace.so",
        "pam_nologin.so",
        "pam_pwhistory.so",
        "pam_rootok.so",
        "pam_securetty.so",
        "pam_selinux.so",
        "pam_shells.so",
        "pam_succeed_if.so",
        "pam_time.so",
        "pam_userdb.so",
        "pam_warn.so",
        "pam_wheel.so",
        "pam_xauth.so",
        "pam_lastlog.so",
        "pam_keyinit.so",
        "pam_faillock.so",
        "pam_faildelay.so",
        "pam_tally.so",
        "pam_tally2.so",
        "pam_listfile.so",
        "pam_access.so",
        "pam_filter.so",
        "pam_group.so",
        "pam_localuser.so",
        "pam_pwquality.so",
        "pam_passwdqc.so",
        "pam_cracklib.so",
        "pam_gnome_keyring.so",
        "pam_ecryptfs.so",
        "pam_kwallet5.so",
        "pam_sss.so",
        "pam_winbind.so",
        "pam_ldap.so",
        "pam_krb5.so",
        "pam_mkhomedir.so",
        "pam_oddjob_mkhomedir.so",
    ];

    /// Reasons a write may be refused.  Returned by `guarded_can_write`
    /// so callers can log a specific cause -- useful for the
    /// post-incident audit trail.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RefusalReason {
        /// Destination is under a hardcoded protected directory.
        ProtectedDirectory(&'static str),
        /// Destination matches a hardcoded protected file path.
        ProtectedFile(&'static str),
        /// Destination basename matches a real PAM module name.
        ProtectedPamModule(&'static str),
        /// Destination already exists.  Signalbench refuses to
        /// overwrite pre-existing files at any path; backup/restore
        /// discipline lives at the technique layer (e.g.
        /// /etc/pam.d/sshd is allowed with explicit backup).
        DestinationExists,
    }

    impl std::fmt::Display for RefusalReason {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RefusalReason::ProtectedDirectory(d) => {
                    write!(f, "destination is under protected directory {d}")
                }
                RefusalReason::ProtectedFile(p) => {
                    write!(f, "destination matches protected file {p}")
                }
                RefusalReason::ProtectedPamModule(name) => {
                    write!(
                        f,
                        "destination basename '{name}' is a real PAM module \
                         (overwriting would break authentication)"
                    )
                }
                RefusalReason::DestinationExists => {
                    write!(
                        f,
                        "destination already exists; signalbench will not \
                         overwrite existing files in system locations"
                    )
                }
            }
        }
    }

    /// Pre-flight check: return Ok(()) if the destination may be
    /// written to, Err(RefusalReason) otherwise.  Callers should log
    /// the refusal reason and skip the write -- the attempted-write
    /// audit log line is itself a useful detection signal.
    ///
    /// NOT overridable by --force.  See module docstring.
    pub fn guarded_can_write(dest: &Path) -> Result<(), RefusalReason> {
        let dest_str = dest.to_string_lossy();

        // 1. Match against protected directory prefixes.
        for protected_dir in PROTECTED_DIRS {
            if dest_str.starts_with(protected_dir) {
                return Err(RefusalReason::ProtectedDirectory(protected_dir));
            }
        }

        // 2. Match against full protected file paths.
        for protected_file in PROTECTED_FILES {
            if dest_str == *protected_file {
                return Err(RefusalReason::ProtectedFile(protected_file));
            }
        }

        // 3. Match the basename against PAM module names.  Catches
        //    exotic library layouts where the parent dir didn't match
        //    PROTECTED_DIRS but the file would still be a real PAM
        //    module if PAM ever looked here.
        if let Some(basename) = dest.file_name().and_then(|n| n.to_str()) {
            for protected_module in PROTECTED_PAM_MODULES {
                if basename.eq_ignore_ascii_case(protected_module) {
                    return Err(RefusalReason::ProtectedPamModule(protected_module));
                }
            }
        }

        // 4. Refuse if destination already exists.  This is the
        //    catch-all guard: even if a future destructive technique
        //    targets a path not in the lists above, it cannot
        //    overwrite a pre-existing file.
        if dest.exists() {
            return Err(RefusalReason::DestinationExists);
        }

        Ok(())
    }

    /// True if a path is structurally a protected destination
    /// (regardless of whether it currently exists).  Use this when a
    /// technique needs to decide UP FRONT (before any side effects)
    /// whether a target is impossible.  For per-write decisions use
    /// `guarded_can_write` which also checks existence.
    #[allow(dead_code)]
    pub fn is_protected_path(dest: &Path) -> bool {
        let dest_str = dest.to_string_lossy();
        for protected_dir in PROTECTED_DIRS {
            if dest_str.starts_with(protected_dir) {
                return true;
            }
        }
        for protected_file in PROTECTED_FILES {
            if dest_str == *protected_file {
                return true;
            }
        }
        if let Some(basename) = dest.file_name().and_then(|n| n.to_str()) {
            for protected_module in PROTECTED_PAM_MODULES {
                if basename.eq_ignore_ascii_case(protected_module) {
                    return true;
                }
            }
        }
        false
    }

    /// Cleanup-side safety: refuse to remove a path that is structurally
    /// protected.  If a technique's cleanup is asked to delete something
    /// at a protected path, it almost certainly indicates a bug --
    /// either the technique tracked a stale artifact, or the destination
    /// pre-existed and was misclassified.  Refuse rather than risk
    /// blowing away a real system file.
    pub fn guarded_can_remove(target: &Path) -> Result<(), RefusalReason> {
        let target_str = target.to_string_lossy();
        for protected_dir in PROTECTED_DIRS {
            if target_str.starts_with(protected_dir) {
                return Err(RefusalReason::ProtectedDirectory(protected_dir));
            }
        }
        for protected_file in PROTECTED_FILES {
            if target_str == *protected_file {
                return Err(RefusalReason::ProtectedFile(protected_file));
            }
        }
        if let Some(basename) = target.file_name().and_then(|n| n.to_str()) {
            for protected_module in PROTECTED_PAM_MODULES {
                if basename.eq_ignore_ascii_case(protected_module) {
                    return Err(RefusalReason::ProtectedPamModule(protected_module));
                }
            }
        }
        Ok(())
    }
}
