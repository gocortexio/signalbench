# Acknowledgements

SignalBench builds upon the research, tools, and techniques developed by the security community. We gratefully acknowledge the following projects and researchers whose work has informed and inspired SignalBench's capabilities.

## Core Technique Sources

### GTFOBins
- Project: https://gtfobins.github.io/
- Description: A curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems
- Used in: T1548-GTFOBINS privilege escalation probe
- Licence: GPL-3.0

### Traitor
- Author: Liam Galvin (liamg)
- Project: https://github.com/liamg/traitor
- Description: Automatic Linux privilege escalation via exploitation of low-hanging fruit (GTFOBins, CVEs, Docker socket, etc.)
- Used in: GTFOBins shell escape sequences, Docker socket exploitation patterns, CVE exploitation techniques
- Licence: MIT

### LinPEAS / PEASS-ng
- Author: Carlos Polop
- Project: https://github.com/peass-ng/PEASS-ng
- Description: Linux Privilege Escalation Awesome Script - comprehensive enumeration for privilege escalation vectors
- Used in: Container breakout enumeration patterns, capability checks, namespace escape detection, kernel vulnerability mapping
- Licence: LGPL-3.0

### ttp-bench
- Author: Thomas Stromberg
- Project: https://github.com/tstromberg/ttp-bench
- Description: TTP benchmark suite for evaluating security product detection capabilities
- Used in: Process masquerading patterns, self-deleting binary techniques, suspicious domain IOCs, defanged sample approach
- Licence: Apache-2.0

### deepce
- Author: stealthcopter
- Project: https://github.com/stealthcopter/deepce
- Description: Docker Enumeration, Escalation of Privileges and Container Escapes
- Used in: Container detection logic, Docker socket checks, capability enumeration, cgroup analysis
- Licence: MIT

### Atomic Red Team
- Organisation: Red Canary
- Project: https://github.com/redcanaryco/atomic-red-team
- Description: Library of tests mapped to the MITRE ATT&CK framework for validating security controls
- Used in: Technique implementation patterns, test methodology, ATT&CK technique coverage validation
- Licence: MIT

### CALDERA
- Organisation: The MITRE Corporation
- Project: https://github.com/mitre/caldera
- Description: Automated adversary emulation system for testing security operations
- Used in: Adversary emulation patterns, technique chaining concepts, operational security testing methodology
- Licence: Apache-2.0

## Research and Documentation

### Unit42 Container Escape Research
- Organisation: Palo Alto Networks Unit42
- Publication: Container Escape Techniques for Cloud Environments
- Used in: T1611 container escape techniques, cgroup release_agent exploitation, privileged container breakouts

### MITRE ATT&CK Framework
- Organisation: The MITRE Corporation
- Project: https://attack.mitre.org/
- Description: Globally-accessible knowledge base of adversary tactics and techniques
- Used in: All technique IDs, tactic categorisation, detection recommendations

### HackTricks
- Author: Carlos Polop
- Project: https://book.hacktricks.wiki/
- Description: Comprehensive hacking methodology and techniques reference
- Used in: Privilege escalation vectors, container breakout techniques, Linux security bypass methods

## Runtime and CVE References

### CVE-2022-0847 (Dirty Pipe)
- Researcher: Max Kellermann
- Description: Linux kernel vulnerability allowing privilege escalation via pipe buffer manipulation
- Used in: Kernel vulnerability detection and version mapping

### CVE-2016-5195 (Dirty COW)
- Researcher: Phil Oester
- Description: Linux kernel race condition vulnerability in copy-on-write mechanism
- Used in: Kernel vulnerability detection and version mapping

### CVE-2019-5736 (runc)
- Researchers: Adam Iwaniuk and Borys Popławski
- Description: Container runtime vulnerability allowing host escape via /proc/self/exe overwrite
- Used in: Runtime CVE version checks

### CVE-2020-15257 (containerd)
- Organisation: NCC Group
- Description: Containerd privilege escalation via exposed abstract unix sockets
- Used in: Runtime CVE version checks

### CVE-2024-1086 (nftables UAF)
- Researcher: David Bouman ("Notselwyn")
- Publication: "Nftables Adventures: bug hunting and N-day exploitation (CVE-2024-1086)"
  https://pwning.tech/nftables/
- Description: Linux kernel nftables use-after-free in `nft_verdict_init()` allowing local
  privilege escalation via crafted nft rule manipulation under an unprivileged user
  namespace.
- Used in: T1068.001 nftables exploit pattern (kernel_exploits.rs)

### CVE-2025-38352 (POSIX CPU Timer Race)
- Description: Linux kernel race condition in POSIX CPU timer handling allowing local
  privilege escalation via ptrace + timer signal delivery.
- Used in: T1068.002 POSIX CPU timer race pattern (kernel_exploits.rs)

### CVE-2025-40190 (Ext4 Xattr Underflow)
- Description: Linux kernel ext4 extended attribute integer underflow allowing local
  privilege escalation via crafted xattr operations.
- Used in: T1068.003 ext4 xattr exploit pattern (kernel_exploits.rs)

### CVE-2025-31133 (runC Masked Path Escape)
- Description: runC container escape via symlink manipulation of masked /proc paths.
- Used in: T1611.012 runC masked path escape (container_escape.rs)

### CVE-2025-52565 (runC Console Escape)
- Description: runC container escape via console device handling, exploiting /dev/pts
  bind-mount semantics to break out of the container PTS namespace.
- Used in: T1611.013 runC console escape (container_escape.rs)

### CVE-2026-31431 (CopyFail)
- Description: Linux kernel privilege escalation chain combining AF_ALG + splice + recv
  syscalls against setuid binaries.
- Used in: T1068.004 CopyFail privilege escalation (kernel_exploits.rs)

### CVE-2023-2163 (eBPF Verifier Branch Pruning)
- Reference: Google Security Research
  https://github.com/google/security-research/tree/master/pocs/linux/cve-2023-2163
  https://nvd.nist.gov/vuln/detail/CVE-2023-2163
- Description: Linux kernel eBPF verifier branch-pruning flaw allowing crafted eBPF
  programs to bypass safety checks; requires CAP_BPF or CAP_SYS_ADMIN.
- Used in: Future-work reference (PRIVATE_DOCS/FUTURE.md)

## Named-Software Simulations

### T1106-IOURING - RingReaper (io_uring evasion)
- Organisation: AhnLab Security Emergency Response Center (ASEC), August 2025
- Description: Original public reporting on the RingReaper post-exploitation agent, which
  drives recon and C2 entirely through io_uring submission/completion rings, bypassing
  EDR sensors that hook the classic openat / read / connect / recvfrom / statx / write
  syscalls. The reporting documented the opcode set (OpenAt / Read / Close / Statx /
  Connect / Send / Recv) and the SQPOLL-mode stealth profile.
- Used in: T1106-IOURING (defense_evasion.rs) -- faithful EDR coverage probe of the
  RingReaper pattern, plus the v2 SQPOLL ring / linked SQE chain / IORING_OP_WRITE /
  command-via-ring extensions.

### S1161 - BPFDoor

BPFDoor's attribution rests on a substantial body of defender research. The S1161 coverage
probe in SignalBench draws on the following sources:

- **Elastic Security Labs** -- "A peek behind the BPFDoor"
  https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor
  Provides the most detailed published walkthrough of the BPFDoor binary internals,
  including the cBPF filter structure and the masquerade name set.

- **Sandfly Security** -- "BPFDoor: An evasive Linux backdoor (technical analysis)"
  https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis
  Publishes the disassembled cBPF filter program with the magic constants
  (0x5293 / 0x7255 / 0x39393939) at the protocol-specific payload offsets -- the
  authoritative reference for the bytecode that YARA rules key on.

- **Qualys Threat Research** -- "Here's a simple script to detect the stealthy
  nation-state BPFDoor"
  https://blog.qualys.com/vulnerabilities-threat-research/2022/08/01/heres-a-simple-script-to-detect-the-stealthy-nation-state-bpfdoor
  Detection-script analysis; documents the BPFDoor PID-file naming convention and the
  string artefacts that survive in the running process.

- **Rapid7 Threat Research** -- "BPFDoor in telecom networks: sleeper-cells threat
  research report"
  https://www.rapid7.com/blog/post/tr-bpfdoor-telecom-networks-sleeper-cells-threat-research-report/
  Campaign-level reporting linking BPFDoor to long-running operations against
  telecommunications targets across the Middle East and Asia.

- **Nikhil Hegde** -- "cBPF-based BPFDoor analysis"
  https://nikhilh-20.github.io/blog/cbpf_bpfdoor/
  Independent technical analysis of the cBPF filter mechanism.

- **gwillgues** -- public reference C source
  https://github.com/gwillgues/BPFDoor
  A widely-referenced reimplementation that has become the de-facto reference for the
  TTP cluster; informs the masquerade-name set and the trigger-callback shape (which
  S1161 implements as an inert no-op).

- **snapattack** -- bpfdoor-scanner (defensive tool)
  https://github.com/snapattack/bpfdoor-scanner
  Active network probe for BPFDoor implants; demonstrates the detectable
  request/response side of the magic-packet protocol and informs the safety envelope
  design (loopback-only bind, inert trigger).

- **MITRE ATT&CK Software entry S1161**
  https://attack.mitre.org/software/S1161/

Used in: S1161 BPFDoor coverage probe (bpfdoor.rs).

### T1620 / Symbiote-class fileless ELF execution
- Description: The memfd_create + fexecve pattern documented across BPFDoor variants,
  Symbiote, and virtually every modern Linux implant family. The technique runs an ELF
  entirely from anonymous memory, bypassing file-based detection (YARA scans, AV
  signature checks, inotify watches on disk-write paths).
- Used in: T1620 Reflective Code Loading (defense_evasion.rs)

## Tool References

### Docker
- Project: https://www.docker.com/
- Used in: Container escape techniques, socket API interaction

### Kubernetes
- Project: https://kubernetes.io/
- Used in: Container environment detection, cloud-native security testing

### runc
- Project: https://github.com/opencontainers/runc
- Used in: Container runtime vulnerability detection

### containerd
- Project: https://containerd.io/
- Used in: Container runtime vulnerability detection

## Community

Special thanks to the broader security research community whose open-source contributions make tools like SignalBench possible. The collaborative nature of security research allows defenders to better understand and prepare for real-world threats.

---

If you believe your work has been used in SignalBench and should be acknowledged here, please open an issue at https://github.com/gocortexio/signalbench/issues with details of your contribution.
