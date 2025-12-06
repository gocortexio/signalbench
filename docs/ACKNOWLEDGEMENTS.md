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
