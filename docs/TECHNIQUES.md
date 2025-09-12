# SignalBench - Technique Documentation

This document provides detailed information about each MITRE ATT&CK technique implemented in SignalBench, explaining how they work, what telemetry they generate, and what artefacts they create.

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

SignalBench executes **actual OS commands** that emulate technique-aligned activity patterns whilst remaining safe and non-destructive. This approach generates realistic endpoint telemetry for security analytics:

- Execute actual system commands to generate realistic telemetry
- Establish real network connections for network-based techniques
- Manipulate real files and processes on the system (within controlled parameters)
- Clean up after themselves to leave the system in its original state

This approach generates more realistic endpoint telemetry compared to simple simulations. When running these techniques in an environment with security products, generated signals may be observable depending on sensor configuration and coverage. Many modern security products are simulation-aware and may not generate alerts for research tools by design.

## DISCOVERY Techniques

### T1082 - System Information Discovery

**Description:**  
Emulates system information discovery activities that generate telemetry patterns associated with reconnaissance behavior.

**How it works:**
1. Executes various system information commands
2. Collects details about the operating system, hardware, kernel, and installed packages
3. Saves all gathered information to a log file for telemetry analysis

**Parameters:**
- `output_file`: Path to save the system information
- `commands`: Comma-separated list of commands to run

**Artefacts:** 
- System information output file (cleaned up automatically after execution)

**Observable patterns:**
- Multiple system information commands executed in rapid succession
- Creation of files containing comprehensive system details

### T1016 - System Network Configuration Discovery

**Description:**  
Simulates collection of network configuration information to map out the target network.

**How it works:**
1. Runs various network configuration commands (ip addr, ip route, ifconfig, netstat)
2. Collects information about network interfaces, routing tables, and open ports
3. Creates a comprehensive log file of network information

**Parameters:**
- `output_file`: Path to save the network information
- `commands`: Comma-separated list of network commands to run

**Artefacts:**
- Network information output file (cleaned up automatically after execution)

**Detection opportunities:**
- Multiple network discovery commands in short succession
- Creation of files containing network configuration details

### T1016 - DNS reconnaissance or enumeration via DNSRecon

**Description:**  
Creates and executes a benign DNS reconnaissance script to simulate enumeration of domain information.

**How it works:**
1. Creates a Python script named "signalbench-dnsrecon.py" in the /tmp directory
2. The script performs DNS lookups on common subdomains for a target domain
3. Results are logged to a file showing discovered DNS records
4. This is a simulated technique that doesn't use aggressive scanning tools

**Parameters:**
- `target_domain`: Domain to target for reconnaissance (default: example.com)
- `output_file`: Path to save the reconnaissance results
- `subdomain_list`: List of subdomains to check (comma-separated)

**Artefacts:**
- Python DNS reconnaissance script (cleaned up automatically after execution)
- DNS scan results file (cleaned up automatically after execution)

**Detection opportunities:**
- Creation and execution of DNS query scripts
- Multiple DNS queries in rapid succession
- Pattern of subdomain enumeration activities

### T1046 - Network Service Discovery

**Description:**  
Simulates scanning for network services to identify open ports and running services on the target network.

**How it works:**
1. Creates a log file for scan results
2. For localhost targets, performs real (but safe) port checks on specified ports
3. For non-localhost targets, simulates port scanning results without actual network traffic
4. Documents open/closed ports and potential services running

**Parameters:**
- `target_hosts`: Target hosts to scan (comma-separated IPs or CIDR)
- `ports`: Ports to scan (e.g., 22,80,443 or 1-1000)
- `output_file`: Path to save scan results

**Artefacts:**
- Port scan results file (cleaned up automatically after execution)

**Detection opportunities:**
- Network monitoring tools can detect port scanning activity
- Multiple connection attempts to different ports in rapid succession

### T1049 - System Network Connections Discovery

**Description:**  
Simulates discovering active network connections to understand data flow and potential lateral movement paths.

**How it works:**
1. Executes various connection-gathering commands (netstat, ss, lsof)
2. Logs all current network connections, listening ports, and associated processes
3. Creates a comprehensive network connections map

**Parameters:**
- `output_file`: Path to save connection discovery results
- `commands`: Comma-separated list of commands to run for connection discovery

**Artefacts:**
- Network connections log file (cleaned up automatically after execution)

**Detection opportunities:**
- Process monitoring can detect network connection discovery commands
- Multiple network-related commands executed in sequence

## CREDENTIAL_ACCESS Techniques

### T1003.001 - Memory Dumping

**Description:**  
Simulates the process of dumping memory from a running process to extract credentials, a common technique used by attackers to steal passwords and tokens from memory.

**How it works:**
1. Creates a simulated memory dump file in the specified location
2. Generates fake memory content that appears to contain sensitive information
3. Simulates a delay to mimic the process of memory extraction
4. Creates an "Extracted Credentials" section that appears to contain credentials harvested from memory

**Parameters:**
- `target_pid`: PID of process to dump memory from (0 = self)
- `dump_file`: Path to save the memory dump file

**Artefacts:** 
- Memory dump file (cleaned up automatically after execution)

**Detection opportunities:**
- Suspicious process accessing memory of other processes
- Reading of process memory files
- Creation of large memory dump files

### T1056.001 - Keylogging

**Description:**  
Simulates a keylogger that captures user keystrokes to steal credentials and sensitive information.

**How it works:**
1. Creates a log file to simulate keylogger output
2. Simulates capturing of keystrokes over a specified duration
3. Records simulated sensitive information like SSH logins, passwords, and web credentials
4. Timestamps each simulated keystroke to appear realistic

**Parameters:**
- `log_file`: Path to save the keylogger output
- `duration`: Duration in seconds to run the keylogger simulation

**Artefacts:**
- Keylogger log file (cleaned up automatically after execution)

**Detection opportunities:**
- Processes reading from keyboard device files
- Suspicious keyboard hook API calls
- File creation with credential-like content

### T1552.001 - Credentials in Files

**Description:**  
Harvesting hardcoded passwords, API tokens, or service credentials from config files (/etc/, .env).

**How it works:**
1. Creates test credential files with realistic content (.env, config.json, etc.)
2. Searches for credential patterns in configuration files
3. Simulates credential discovery and harvesting
4. Reports findings in detailed logs

**Parameters:**
- `search_paths`: Paths to search for credential files
- `file_patterns`: File patterns to search for credentials
- `output_file`: File to save discovered credentials

**Artefacts:**
- Test credential files (cleaned up automatically after execution)
- Credential discovery logs (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor for processes accessing configuration files
- Unusual file access patterns
- Credential harvesting tools

### T1003.007 - OS Credential Dumping: Proc Filesystem

**Description:**  
Uses dd utility and /proc filesystem to analyze process memory for credential patterns, simulating memory dumping techniques commonly used to extract credentials from running processes.

**How it works:**
1. Enumerates running processes from /proc directory targeting common applications (firefox, chrome, ssh, sshd, apache2, nginx)
2. Reads memory maps from /proc/<PID>/maps to identify readable memory regions  
3. Uses dd utility to extract memory segments from /proc/<PID>/mem files
4. Searches extracted memory for credential patterns (password, token, key, auth, credential)
5. Logs all analysis activities and findings for telemetry generation
6. Creates session-specific dump directories for realistic artifact simulation

**Parameters:**
- `target_processes`: Comma-separated list of process names to target (default: firefox,chrome,ssh,sshd,apache2,nginx)
- `memory_dump_size`: Size of memory to extract per process in bytes (default: 4096)
- `max_processes`: Maximum number of processes to analyze (default: 5)
- `log_file`: Path to save detailed analysis logs (default: /tmp/signalbench_proc_dump.log)
- `search_patterns`: Credential patterns to search for (default: password,token,key,auth,credential)

**Artefacts:**
- Process memory dump files in session directory (cleaned up automatically after execution)
- Detailed analysis log file with enumeration and search results (cleaned up automatically after execution)
- Session-specific dump directory with unique identifier (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor dd command usage on /proc/<PID>/mem files
- Excessive /proc filesystem access patterns
- Memory mapping enumeration activities
- Process memory analysis and credential extraction attempts
- Creation of memory dump files in temporary directories

## DEFENSE_EVASION Techniques

### T1027 - Obfuscated Files or Information

**Description:**  
Employs various obfuscation techniques to evade detection mechanisms and hide malicious content.

**How it works:**
1. Implements multiple obfuscation methods:
   - Base64 encoding/decoding
   - XOR encryption with custom keys
   - Text string manipulation and concatenation
   - Binary packing/compression
   - Script obfuscation techniques
2. Creates obfuscated files and demonstrates deobfuscation
3. Executes deobfuscated content to trigger detection
4. Logs all obfuscation operations for review

**Parameters:**
- `obfuscation_type`: Type of obfuscation to perform (encoding, encryption, packing, string)
- `output_dir`: Directory to save obfuscated files
- `log_file`: Path to save obfuscation log
- `execute_after`: Whether to attempt execution of obfuscated files

**Artefacts:**
- Obfuscated files (cleaned up automatically after execution)
- Deobfuscated files (cleaned up automatically)
- Obfuscation log file (cleaned up automatically)

**Detection opportunities:**
- Files containing encoded/obfuscated content
- Use of encoding/decoding functions
- Execution of decoded content
- Suspicious patterns in obfuscated files

### T1055 - Process Injection

**Description:**  
Injects code into running processes to evade detection and execute malicious code in the context of legitimate processes.

**How it works:**
1. Supports multiple injection techniques:
   - Ptrace-based code injection
   - LD_PRELOAD dynamic library loading
   - Shared library injection
2. Creates actual C code for injection
3. Compiles injection code on the target system
4. Performs real (but controlled) process injection
5. Logs all injection attempts and results

**Parameters:**
- `technique`: Specific injection technique (ptrace, ld_preload, shared_library)
- `target_process`: Target process name or PID (for ptrace)
- `output_dir`: Directory to save injection artefacts
- `log_file`: Path to save injection log

**Artefacts:**
- Injection source code files (cleaned up automatically)
- Compiled injection binaries (cleaned up automatically)
- Injected libraries (cleaned up automatically)
- Target process scripts (cleaned up automatically)
- Injection logs (cleaned up automatically)

**Detection opportunities:**
- Suspicious ptrace calls
- LD_PRELOAD manipulations
- Creation of shared libraries
- Process memory modifications
- Unusual process relationships

### T1562.002 - Disable Linux Audit Logs

**Description:**  
Simulates an attempt to disable or manipulate audit logs to avoid detection.

**How it works:**
1. Creates a file that simulates rules to disable Linux audit logging
2. Contains rules that would disable key system call auditing in a real attack
3. Does not actually modify system audit configuration

**Parameters:**
- `audit_rules_file`: Path to save the simulated audit rules

**Artefacts:**
- Audit rules file (cleaned up automatically after execution)

**Detection opportunities:**
- Modification of audit configuration files
- Commands that disable audit functionality

### T1070.003 - Clear Command History

**Description:**  
Simulates clearing of bash command history to remove evidence of attacker activity.

**How it works:**
1. Creates a backup of the current user's bash history
2. Simulates clearing the history by creating an empty file
3. Restores the original history during cleanup

**Parameters:**
- `history_backup`: Path to save the backup of bash history

**Artefacts:**
- History backup file (cleaned up automatically after execution)

**Detection opportunities:**
- Unusual modifications to history files
- Commands that clear or manipulate bash history

### T1574.007 - Path Interception

**Description:**  
Simulates path interception by modifying environment variables to control which binaries are executed.

**How it works:**
1. Documents current PATH and LD_LIBRARY_PATH variables
2. Simulates adding a malicious directory to the beginning of PATH
3. Creates a log file showing how a legitimate command could be intercepted

**Parameters:**
- `custom_path`: Directory to add to PATH variable
- `env_log_file`: Path to save the log file

**Artefacts:**
- Environment variable log file (cleaned up automatically after execution)

**Detection opportunities:**
- Unusual modifications to PATH or LD_LIBRARY_PATH
- Creation of executable files in non-standard locations

## EXECUTION Techniques

### T1059 - Advanced Command and Scripting Interpreter

**Description:**  
Executes malicious commands using various obfuscation techniques and scripting languages to test detection capabilities.

**How it works:**
1. Supports multiple interpreter types (bash, python, perl)
2. Implements various command obfuscation techniques:
   - Base64 encoding/decoding
   - Hex encoding/decoding
   - Variable concatenation
   - IFS (Internal Field Separator) manipulation
   - Command substitution
3. Creates and executes scripts with suspicious behaviours
4. Logs all command executions and their outputs

**Parameters:**
- `interpreter`: Type of interpreter to use (bash, python, perl)
- `obfuscation`: Obfuscation technique to apply (base64, hex, variable, none)
- `command`: Command to execute (if not specified, uses reconnaissance commands)
- `output_dir`: Directory to save execution artefacts
- `log_file`: Path to save execution logs

**Artefacts:**
- Temporary script files (cleaned up automatically after execution)
- Command output logs (cleaned up automatically)
- Execution history logs (cleaned up automatically)

**Detection opportunities:**
- Execution of encoded/obfuscated commands
- Use of suspicious command patterns
- Commands that access sensitive system information
- Use of eval or other execution functions in scripts
- Multiple command interpreter or encoding techniques in sequence

### T1059 - Possible C2 via dnscat2

**Description:**  
Downloads and executes a test file named dnscat2 to simulate command and control communications over DNS.

**How it works:**
1. Uses curl or wget to download a file from the Palo Alto Networks API
2. The downloaded file is a test file designed to look like dnscat2, a known C2 tool
3. The file is executed with basic C2 parameters to simulate a command and control session
4. This test intentionally triggers EDR/AV alerts as it uses a real-world C2 simulation file

**Parameters:**
- `download_url`: URL to download the file from (default uses a Palo Alto Networks test file)
- `output_file`: Path to save the downloaded file
- `log_file`: Path to save execution logs
- `c2_domain`: Domain to use for simulated C2 communications

**Artefacts:**
- Downloaded dnscat2 executable (cleaned up automatically after execution)
- C2 execution log file (cleaned up automatically after execution)

**Detection opportunities:**
- Download of known malicious or suspicious filenames
- Execution of tools known to be used for C2 communications
- DNS traffic patterns consistent with command and control channels
- Creation and execution of files with signatures matching known C2 tools

### T1059.004 - Unix Shell Execution

**Description:**  
Executes suspicious commands via Unix shell.

**How it works:**
1. Executes a specified command through a shell
2. Creates a log file documenting the command execution
3. Captures standard output and error from the command

**Parameters:**
- `shell`: Shell to use for command execution
- `command`: Command to execute
- `log_file`: Path to save execution log

**Artefacts:**
- Command execution log file (cleaned up automatically after execution)
- Any output file created by the executed command

**Detection opportunities:**
- Execution of unusual or suspicious shell commands
- Shell commands that create files in temporary directories

### T1059.006 - Python Script Execution

**Description:**  
Executes a potentially malicious Python script.

**How it works:**
1. Creates a Python script file with simulated malicious content
2. Script includes various suspicious behaviours like system reconnaissance, file operations
3. Executes the Python script and logs output

**Parameters:**
- `script_file`: Path to create and save the Python script
- `log_file`: Path to save execution log

**Artefacts:**
- Python script file (cleaned up automatically after execution)
- Script execution log file (cleaned up automatically after execution)
- Script output file (cleaned up automatically after execution)

**Detection opportunities:**
- Creation and execution of Python scripts with suspicious content
- Scripts that collect system information or simulate data exfiltration

## LATERAL_MOVEMENT Techniques

### T1021.004 - SSH Lateral Movement

**Description:**  
Simulates attempts to move laterally through a network using SSH.

**How it works:**
1. Attempts SSH connections to specified target hosts
2. Uses key-based authentication to avoid password prompts
3. Creates a log file documenting connection attempts and results

**Parameters:**
- `targets`: Comma-separated list of IPs or hostnames to target
- `username`: Username to use for SSH connections
- `log_file`: Path to save the log file

**Artefacts:**
- SSH connection log file (cleaned up automatically after execution)

**Detection opportunities:**
- Multiple SSH connection attempts in rapid succession
- SSH connections to unusual or varied destinations

## PERSISTENCE Techniques


### T1547.002 - Startup Folder

**Description:**  
Generates telemetry for Linux desktop autostart persistence using proper .desktop files.

**How it works:**
1. Creates a .desktop file in the user's autostart directory (~/.config/autostart/)
2. Uses proper desktop entry format that Linux desktop environments recognise
3. Configures the application to execute a specified command at user login
4. Generates realistic persistence telemetry that EDR systems can detect

**Parameters:**
- `app_name`: Name of the desktop application entry (default: SignalBench Persistence)
- `command`: Command to execute at startup (shell features automatically wrapped with /bin/sh -c) (default: echo 'SignalBench startup executed' >> /tmp/signalbench_startup.log)

**Artefacts:**
- .desktop file in ~/.config/autostart directory (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor .desktop file creation in ~/.config/autostart directory
- Desktop entry modifications with suspicious Exec commands
- Autostart persistence mechanisms in Linux environments

### T1053.003 - Cron Job

**Description:**  
Simulates creating a cron job for persistence.

**How it works:**
1. Gets the current user's crontab
2. Adds a new cron job entry with a scheduled command
3. Installs the modified crontab

**Parameters:**
- `cron_expression`: Cron expression for scheduling
- `command`: Command to execute in cron job

**Artefacts:**
- Temporary crontab file (cleaned up automatically after execution)
- Cron job entry (removed during cleanup)

**Detection opportunities:**
- Modifications to crontab files
- Unusual or suspicious cron job entries

### T1543 - Create or Modify System Process

**Description:**  
Creates or modifies system services and processes to establish persistence on the system.

**How it works:**
1. Supports multiple service types:
   - systemd service units
   - init.d scripts
   - rc.local entries
2. Creates actual service definition files
3. Installs services (if permissions allow) or simulates installation
4. Attempts to start the service (controlled environment)
5. Logs all service creation operations

**Parameters:**
- `service_type`: Type of service to create (systemd, init.d, rc_local)
- `service_name`: Name for the service
- `command`: Command to execute when service runs
- `output_dir`: Directory to save service files
- `install`: Whether to attempt installation (requires privileges)

**Artefacts:**
- Service definition files (cleaned up automatically)
- Service installation logs (cleaned up automatically)
- Installed services (removed during cleanup if installed)

**Detection opportunities:**
- Creation of new service files
- Modifications to startup processes
- Services executing suspicious commands
- Services with unusual configurations or permissions

### T1505.003 - Web Shell Deployment

**Description:**  
Deploys malicious web shells on Linux-based web servers (PHP, JSP, or custom backdoors) for long-term access.

**How it works:**
1. Creates realistic web shell files in specified directories
2. Supports multiple web shell types (PHP, JSP, ASPX)
3. Includes proper web shell functionality for testing
4. Creates files that would trigger web application security scanners

**Parameters:**
- `web_root`: Web server document root directory
- `shell_type`: Type of web shell (php, jsp, aspx)
- `shell_name`: Filename for the web shell

**Artefacts:**
- Web shell files (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor web directories for suspicious script files
- Unexpected file creation in web directories
- Unusual web server process behaviour

## PRIVILEGE_ESCALATION Techniques

### T1548.003 - Sudoers Modification

**Description:**  
Simulates modifying the sudoers file to grant elevated privileges.

**How it works:**
1. Creates a temporary sudoers file in the /etc/sudoers.d/ directory
2. Grants specified privileges to a user
3. Validates syntax of the sudoers file before installation

**Parameters:**
- `username`: User to grant elevated privileges
- `privileges`: Privileges to grant (e.g., "ALL=(ALL:ALL) NOPASSWD: ALL")

**Artefacts:**
- Sudoers file in /etc/sudoers.d/ (cleaned up automatically after execution)

**Detection opportunities:**
- Creation or modification of files in /etc/sudoers.d/
- Changes to sudo privileges

### T1548.003.001 - Sudo Unsigned Integer Privilege Escalation

**Description:**  
Exploits CVE-2019-14287 sudo vulnerability using negative or large unsigned integer user IDs to bypass sudo restrictions and execute commands as root.

**How it works:**
1. Exploits a vulnerability in sudo versions < 1.8.28 where negative user IDs (-u#-1) or large unsigned integers (-u#4294967295) are interpreted as UID 0 (root)
2. Attempts to execute a specified command using both exploitation variants
3. Tests the vulnerability by running commands that would normally be restricted
4. Logs all exploitation attempts and results for analysis

**Parameters:**
- `command`: Command to execute via sudo exploitation (default: "id")
- `test_both_variants`: Whether to test both -u#-1 and -u#4294967295 methods (default: "true")
- `log_file`: Path to save exploitation log (default: "/tmp/signalbench_sudo_exploit.log")

**Artefacts:**
- Sudo exploitation log file (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor for sudo commands with negative user IDs (-u#-1)
- Watch for sudo commands with large unsigned integers (-u#4294967295)
- Unusual sudo activity from non-privileged users attempting root access
- CVE-2019-14287 exploitation patterns in authentication logs

### T1548.001 - SUID Binary

**Description:**  
Simulates setting the SUID bit on a binary for privilege escalation.

**How it works:**
1. Creates a small executable file
2. Sets the SUID bit on the file
3. Simulates how this could be used for privilege escalation

**Parameters:**
- `target_binary`: Path to create the SUID binary

**Artefacts:**
- SUID binary file (cleaned up automatically after execution)

**Detection opportunities:**
- Creation of new SUID binaries
- Modification of file permissions to add SUID bit

### T1136.001 - Local Account Creation

**Description:**  
Adding new privileged users (e.g., via useradd, passwd, or direct /etc/passwd modification).

**How it works:**
1. Simulates creating new user accounts with elevated privileges
2. Creates harmless test files that represent user account entries
3. Does not modify actual system files for safety
4. Simulates /etc/passwd and /etc/shadow modifications

**Parameters:**
- `username`: Username for the new account
- `groups`: Groups to add the user to  
- `shell`: Default shell for the user

**Artefacts:**
- Test user account files (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor for new user account creation
- Changes to /etc/passwd, /etc/shadow
- Unusual useradd/usermod commands

### T1068 - Exploitation for Privilege Escalation

**Description:**  
Using local privilege escalation exploits (e.g., Dirty Pipe, Dirty COW, kernel module exploits).

**How it works:**
1. Simulates common privilege escalation exploits
2. Creates realistic simulation logs based on exploit type
3. Detects kernel version for realistic testing
4. Completely harmless - only creates test files, no actual exploitation

**Parameters:**
- `exploit_type`: Type of privilege escalation exploit to simulate (dirty_pipe, dirty_cow, generic)
- `target_file`: Target file for the simulated exploit

**Artefacts:**
- Privilege escalation simulation files (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor for unusual kernel module loading
- Suspicious process behaviour
- Exploitation indicators
- Privilege escalation attempts

## EXFILTRATION Techniques

### T1048 - Exfiltration Over Alternative Protocol

**Description:**  
Simulates data exfiltration using alternative protocols such as DNS, ICMP, or HTTP.

**How it works:**
1. Creates a file with simulated sensitive data for exfiltration
2. Encodes and formats data for the chosen protocol (base64 for DNS/HTTP, hex for ICMP)
3. Simulates the exfiltration process by showing the commands that would be executed
4. Creates detailed logs of the exfiltration process

**Parameters:**
- `protocol`: Protocol to use for exfiltration (dns, icmp, http)
- `data_file`: Path to save simulated data to be exfiltrated
- `log_file`: Path to save exfiltration log
- `target`: Target for exfiltration (domain for DNS, IP for ICMP, URL for HTTP)

**Artefacts:**
- Exfiltration data file (cleaned up automatically after execution)
- Exfiltration log file (cleaned up automatically after execution)

**Detection opportunities:**
- Unusual DNS queries with encoded data in subdomains
- ICMP packets with custom data payloads
- HTTP requests with encoded data in parameters
- High volume of network traffic using a single protocol

## COMMAND_AND_CONTROL Techniques

### T1095 - Non-Application Layer Protocol

**Description:**  
Executes actual command and control communications using non-application layer protocols (TCP, UDP, ICMP).

**How it works:**
1. Creates a file with C2 commands to be executed
2. Establishes actual communication channels using the chosen protocol
3. Transmits encoded commands and receives responses over the network
4. Uses netcat (nc) for TCP/UDP communications and ping for ICMP
5. Creates detailed logs of all C2 communication operations

**Parameters:**
- `protocol`: Protocol to use (icmp, tcp, udp)
- `target`: Target IP address
- `port`: Target port (for TCP/UDP)
- `log_file`: Path to save C2 simulation log
- `command_file`: Path to save C2 commands

**Artefacts:**
- C2 command file (cleaned up automatically after execution)
- C2 simulation log file (cleaned up automatically after execution)
- Temporary network socket files (cleaned up automatically)

**Detection opportunities:**
- Unusual protocol usage patterns
- Base64 or hex-encoded data in network traffic
- Regular beaconing or communication intervals
- Communication with unusual or suspicious external endpoints
- Use of netcat or similar networking tools

### T1205 - Traffic Signaling

**Description:**  
Uses cron to install TCP filters on network interfaces for covert signaling and command and control communications.

**How it works:**
1. Creates cron jobs to periodically install network traffic filters
2. Supports multiple filter types including iptables rules and tc (traffic control) filters
3. Configures filters to monitor specific TCP ports for incoming signals
4. Uses realistic cron scheduling to simulate persistent monitoring
5. Creates filter rules that could be used for covert C2 channel activation
6. Logs all cron job creation and filter installation activities

**Parameters:**
- `interface`: Network interface to install filter on (default: eth0)
- `filter_type`: Type of TCP filter - iptables or tc_filter (default: iptables)
- `target_port`: TCP port to filter for signaling (default: 8443)
- `cron_schedule`: Cron expression for filter installation (default: */15 * * * *)
- `log_file`: Path to save traffic signaling log (default: /tmp/signalbench_traffic_signaling.log)

**Artefacts:**
- Temporary cron job entries (cleaned up automatically after execution)
- Network filter rules and scripts (cleaned up automatically after execution)
- Traffic signaling log file (cleaned up automatically after execution)
- Filter installation scripts (cleaned up automatically after execution)

**Detection opportunities:**
- Monitor cron job modifications for network-related tasks
- Detect iptables or tc filter rule changes
- Monitor network interface configuration changes
- Unusual traffic patterns on filtered ports
- Periodic network filter installation activities
- Cron jobs executing network commands

### T1105 - Ingress Tool Transfer

**Description:**  
Downloads actual test files from external sources and attempts to execute them to test EDR/AV detection capabilities.

**How it works:**
1. Downloads files using curl or wget from specified URLs
2. Downloads include publicly available test files designed for security testing
3. Makes downloaded files executable and attempts to run them
4. Creates detailed logs of download operations and execution attempts
5. Default source is the Palo Alto Networks test file URL

**Parameters:**
- `url`: URL to download the malicious file from
- `output_dir`: Directory to save downloaded files
- `download_tool`: Tool to use for downloading (curl or wget)
- `execution_attempt`: Whether to attempt execution of downloaded files

**Artefacts:**
- Downloaded test files (cleaned up automatically after execution)
- Download and execution log file (cleaned up automatically)

**Detection opportunities:**
- File downloads from known security testing URLs
- Executable files being downloaded and made executable
- Attempt to execute recently downloaded files
- Suspicious file characteristics in downloaded content