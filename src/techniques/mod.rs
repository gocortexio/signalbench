// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

// SIGNALBENCH - Technique Modules
// Techniques module configuration
//
// This module organises attack techniques according to the MITRE ATT&CK framework
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

pub mod bpfdoor;
pub mod collection;
pub mod command_and_control;
pub mod command_interpreter;
pub mod container_escape;
pub mod credential_access;
pub mod defense_evasion;
pub mod discovery;
pub mod dns_recon;
pub mod dnscat_c2;
pub mod execution;
pub mod gtfobins;
pub mod impact;
pub mod kernel_exploits;
pub mod lateral_movement;
pub mod network;
pub mod persistence;
pub mod persistence_system_process;
pub mod privilege_escalation;
pub mod protocol_lateral_movement;
pub mod sharepoint_exfil;
pub mod software;

use crate::config::TechniqueConfig;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,                          // MITRE ATT&CK ID (e.g., T1547.001)
    pub name: String,                        // Human-readable name
    pub description: String,                 // Brief description
    pub category: String,                    // Attack category
    pub parameters: Vec<TechniqueParameter>, // Parameters needed for this technique
    pub detection: String,                   // How this technique can be detected
    pub cleanup_support: bool,               // Whether this technique supports cleanup
    pub platforms: Vec<String>,              // Supported platforms (e.g., ["Linux"])
    pub permissions: Vec<String>,            // Required permissions (e.g., ["root"])
    #[serde(default)]
    pub voltron_only: bool, // Whether this technique can only run in Voltron mode
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueParameter {
    pub name: String,            // Parameter name
    pub description: String,     // Parameter description
    pub required: bool,          // Whether this parameter is required
    pub default: Option<String>, // Default value, if any
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub technique_id: String,
    pub success: bool,
    pub message: String,
    pub artifacts: Vec<String>,
    pub cleanup_required: bool,
}

impl fmt::Display for Technique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}| {}", self.id, self.name)
    }
}

// Define a type alias for our async function return types to make the code cleaner
pub type ExecuteFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SimulationResult, String>> + Send + 'a>>;
pub type CleanupFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

#[async_trait]
pub trait AttackTechnique: Send + Sync {
    /// Returns the technique information
    fn info(&self) -> Technique;

    /// External binaries without which this technique produces essentially no
    /// signal AND for which it has no native/shell fallback.
    ///
    /// Only HARD, all-or-nothing dependencies belong here (e.g. `gcc` for a
    /// compile-and-run exploit). The runner pre-checks these and reports the
    /// technique as SKIPPED — naming the missing package — instead of a
    /// misleading FAILED, unless `--force` is set. Techniques that degrade
    /// per-section, or that fall back to a native/shell implementation, must
    /// NOT list their tools here.
    fn required_tools(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Executes the technique with the given configuration
    fn execute<'a>(&'a self, config: &'a TechniqueConfig, dry_run: bool) -> ExecuteFuture<'a>;

    /// Cleans up any artifacts created by the technique
    fn cleanup<'a>(&'a self, artifacts: &'a [String]) -> CleanupFuture<'a>;
}

// Register all techniques to be available in the simulator
pub fn get_all_techniques() -> Vec<Box<dyn AttackTechnique>> {
    vec![
        // Persistence techniques
        Box::new(persistence::StartupFolder {}),
        Box::new(persistence::CronJob {}),
        Box::new(persistence::WebShellDeployment {}),
        Box::new(persistence::AccountManipulation {}),
        // Privilege escalation techniques
        Box::new(privilege_escalation::SudoersModification {}),
        Box::new(privilege_escalation::SuidBinary {}),
        Box::new(privilege_escalation::LocalAccountCreation {}),
        Box::new(privilege_escalation::PrivilegeEscalationExploit {}),
        Box::new(privilege_escalation::SudoUnsignedIntegerEscalation {}),
        Box::new(gtfobins::GtfobinsProbe {}),
        Box::new(gtfobins::LolbinAbuseExecution {}),
        Box::new(kernel_exploits::NftablesExploit {}),
        Box::new(kernel_exploits::PosixCpuTimerRace {}),
        Box::new(kernel_exploits::Ext4XattrUnderflow {}),
        Box::new(kernel_exploits::CopyFail {}),
        // Container escape techniques (T1611)
        Box::new(container_escape::DockerSocketEscape {}),
        Box::new(container_escape::PrivilegedContainerEscape {}),
        Box::new(container_escape::SensitiveMountEscape {}),
        Box::new(container_escape::CgroupReleaseAgentEscape {}),
        Box::new(container_escape::KernelModuleEscape {}),
        Box::new(container_escape::ContainerReconnaissance {}),
        Box::new(container_escape::HostPidNamespaceEscape {}),
        Box::new(container_escape::SuidPrivilegeEscape {}),
        Box::new(container_escape::AdvancedContainerBreakout {}),
        Box::new(container_escape::RuntimeCveCheck {}),
        Box::new(container_escape::NamespaceEscapeDetection {}),
        Box::new(container_escape::RunCMaskedPathEscape {}),
        Box::new(container_escape::RunCConsoleEscape {}),
        Box::new(container_escape::RunCProcfsEscape {}),
        // Defense evasion techniques
        Box::new(defense_evasion::DisableAuditLogs {}),
        Box::new(defense_evasion::ClearBashHistory {}),
        Box::new(defense_evasion::ModifyEnvironmentVariable {}),
        Box::new(defense_evasion::MasqueradingAsCrond {}),
        Box::new(defense_evasion::FileDeletion {}),
        Box::new(defense_evasion::ProcessMasquerading {}),
        Box::new(defense_evasion::SelfDeletingBinary {}),
        Box::new(defense_evasion::DisableSecurityTools {}),
        Box::new(defense_evasion::ReflectiveCodeLoading {}),
        Box::new(defense_evasion::IoUringEvasion {}),
        // Credential access techniques
        Box::new(credential_access::MemoryDumping {}),
        Box::new(credential_access::KeyloggerSimulation {}),
        Box::new(credential_access::CredentialsInFiles {}),
        Box::new(credential_access::ProcFilesystemCredentialDumping {}),
        Box::new(credential_access::SSHBruteForce {}),
        Box::new(credential_access::EtcPasswdShadow {}),
        Box::new(credential_access::PamBackdoor {}),
        // Discovery techniques
        Box::new(discovery::SystemInformationDiscovery {}),
        Box::new(discovery::NetworkDiscovery {}),
        Box::new(discovery::NetworkConnectionsDiscovery {}),
        Box::new(network::NetworkScanCommon {}),
        Box::new(network::NetworkScanHighValue {}),
        // Lateral movement techniques
        Box::new(lateral_movement::SshLateralMovement {}),
        Box::new(lateral_movement::VncLateralMovement {}),
        Box::new(protocol_lateral_movement::VncProtoLateralMovement {}),
        Box::new(protocol_lateral_movement::SshProtoLateralMovement {}),
        // Execution techniques
        Box::new(execution::CommandLineInterface {}),
        Box::new(execution::ScriptExecution {}),
        Box::new(execution::UncommonRemoteShellCommands {}),
        // Exfiltration techniques
        Box::new(network::ExfiltrationOverAlternativeProtocol {}),
        Box::new(sharepoint_exfil::SharePointExfil {}),
        // Command and Control techniques
        Box::new(network::NonApplicationLayerProtocol {}),
        Box::new(command_and_control::IngressToolTransfer {}),
        Box::new(command_and_control::TrafficSignaling {}),
        Box::new(command_and_control::SuspiciousGitHubToolTransfer {}),
        Box::new(command_and_control::SuspiciousDomainsHttp {}),
        Box::new(command_and_control::SuspiciousDomainsStratum {}),
        Box::new(command_and_control::SuspiciousDomainsAsyncRat {}),
        Box::new(command_and_control::SuspiciousDomainsDns {}),
        Box::new(command_and_control::SuspiciousDomainsSoftEther {}),
        // Advanced Command Interpreter
        Box::new(command_interpreter::AdvancedCommandExecution {}),
        // System Process Persistence
        Box::new(persistence_system_process::CreateOrModifySystemProcess {}),
        // DNS reconnaissance via DNSRecon
        Box::new(dns_recon::DNSReconTest {}),
        // Possible C2 via dnscat2
        Box::new(dnscat_c2::DnscatC2Test {}),
        // Software simulations
        Box::new(software::S1109Pacemaker {}),
        Box::new(bpfdoor::S1161BpfDoor {}),
        // Collection techniques
        Box::new(collection::AutomatedCollection {}),
        // Impact techniques
        Box::new(impact::ResourceHijacking {}),
    ]
}

// Helper function to get a technique by ID or name
pub fn get_technique_by_id_or_name(id_or_name: &str) -> Option<Box<dyn AttackTechnique>> {
    // First try to find by exact name match - this will ensure unique techniques are found
    let exact_name_match = get_all_techniques().into_iter().find(|t| {
        let info = t.info();
        info.name.to_lowercase() == id_or_name.to_lowercase().replace("_", " ")
    });

    if exact_name_match.is_some() {
        return exact_name_match;
    }

    // If no exact name match, try ID or slugified name as before
    get_all_techniques().into_iter().find(|t| {
        let info = t.info();
        info.id.to_lowercase() == id_or_name.to_lowercase()
            || info.name.to_lowercase().replace(" ", "_") == id_or_name.to_lowercase()
    })
}

// Helper function to get all techniques in a category
pub fn get_techniques_by_category(category: &str) -> Vec<Box<dyn AttackTechnique>> {
    get_all_techniques()
        .into_iter()
        .filter(|t| t.info().category.to_lowercase() == category.to_lowercase())
        .collect()
}

// Sinkhole resolution shared helper
// Resolves sinkhole.signalbench.sigre.xyz via the system resolver (honours /etc/hosts).
// Falls back to SINKHOLE_IP_FALLBACK when DNS is unavailable.
pub const SINKHOLE_LOOKUP_DOMAIN: &str = "sinkhole.signalbench.sigre.xyz";
pub const SINKHOLE_IP_FALLBACK: &str = "198.135.184.22";

pub async fn resolve_sinkhole_ip() -> String {
    use tokio::net::lookup_host;
    match lookup_host(format!("{}:80", SINKHOLE_LOOKUP_DOMAIN)).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                return addr.ip().to_string();
            }
            SINKHOLE_IP_FALLBACK.to_string()
        }
        Err(_) => SINKHOLE_IP_FALLBACK.to_string(),
    }
}
