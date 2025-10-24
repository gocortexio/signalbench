// SIGNALBENCH - Technique Modules
// Techniques module configuration
// 
// This module organises attack techniques according to the MITRE ATT&CK framework
// Developed by Simon Sigre (simon@gocortex.io)
// Part of the GoCortex.io platform for security testing and validation

pub mod persistence;
pub mod privilege_escalation;
pub mod defense_evasion;
pub mod credential_access;
pub mod discovery;
pub mod lateral_movement;
pub mod execution;
pub mod network;
pub mod command_and_control;
pub mod command_interpreter;
pub mod defense_evasion_obfuscation;
pub mod persistence_system_process;
pub mod process_injection;
pub mod dnscat_c2;
pub mod dns_recon;
pub mod software;

use crate::config::TechniqueConfig;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,           // MITRE ATT&CK ID (e.g., T1547.001)
    pub name: String,         // Human-readable name
    pub description: String,  // Brief description
    pub category: String,     // Attack category
    pub parameters: Vec<TechniqueParameter>,  // Parameters needed for this technique
    pub detection: String,    // How this technique can be detected
    pub cleanup_support: bool, // Whether this technique supports cleanup
    pub platforms: Vec<String>, // Supported platforms (e.g., ["Linux"])
    pub permissions: Vec<String>, // Required permissions (e.g., ["root"])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueParameter {
    pub name: String,         // Parameter name
    pub description: String,  // Parameter description
    pub required: bool,       // Whether this parameter is required
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
pub type ExecuteFuture<'a> = Pin<Box<dyn Future<Output = Result<SimulationResult, String>> + Send + 'a>>;
pub type CleanupFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

#[async_trait]
pub trait AttackTechnique: Send + Sync {
    /// Returns the technique information
    fn info(&self) -> Technique;
    
    /// Executes the technique with the given configuration
    fn execute<'a>(
        &'a self,
        config: &'a TechniqueConfig,
        dry_run: bool,
    ) -> ExecuteFuture<'a>;
    
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
        
        // Privilege escalation techniques
        Box::new(privilege_escalation::SudoersModification {}),
        Box::new(privilege_escalation::SuidBinary {}),
        Box::new(privilege_escalation::LocalAccountCreation {}),
        Box::new(privilege_escalation::PrivilegeEscalationExploit {}),
        Box::new(privilege_escalation::SudoUnsignedIntegerEscalation {}),
        
        // Defense evasion techniques
        Box::new(defense_evasion::DisableAuditLogs {}),
        Box::new(defense_evasion::ClearBashHistory {}),
        Box::new(defense_evasion::ModifyEnvironmentVariable {}),
        Box::new(defense_evasion::MasqueradingAsCrond {}),
        
        // Credential access techniques
        Box::new(credential_access::MemoryDumping {}),
        Box::new(credential_access::KeyloggerSimulation {}),
        Box::new(credential_access::CredentialsInFiles {}),
        Box::new(credential_access::ProcFilesystemCredentialDumping {}),
        Box::new(credential_access::HydraBruteForceSimulation {}),
        
        // Discovery techniques
        Box::new(discovery::SystemInformationDiscovery {}),
        Box::new(discovery::NetworkDiscovery {}),
        Box::new(network::NetworkServiceDiscovery {}),
        Box::new(network::SystemNetworkConnectionsDiscovery {}),
        
        // Lateral movement techniques
        Box::new(lateral_movement::SshLateralMovement {}),
        
        // Execution techniques
        Box::new(execution::CommandLineInterface {}),
        Box::new(execution::ScriptExecution {}),
        Box::new(execution::UncommonRemoteShellCommands {}),
        
        // Exfiltration techniques
        Box::new(network::ExfiltrationOverAlternativeProtocol {}),
        
        // Command and Control techniques
        Box::new(network::NonApplicationLayerProtocol {}),
        Box::new(command_and_control::IngressToolTransfer {}),
        Box::new(command_and_control::TrafficSignaling {}),
        Box::new(command_and_control::SuspiciousGitHubToolTransfer {}),
        
        // Advanced Command Interpreter
        Box::new(command_interpreter::AdvancedCommandExecution {}),
        
        // Defense Evasion - Obfuscation
        Box::new(defense_evasion_obfuscation::ObfuscatedFilesAndInformation {}),
        
        // Process Injection
        Box::new(process_injection::ProcessInjection {}),
        
        // System Process Persistence
        Box::new(persistence_system_process::CreateOrModifySystemProcess {}),
        
        // DNS reconnaissance via DNSRecon
        Box::new(dns_recon::DNSReconTest {}),
        
        // Possible C2 via dnscat2
        Box::new(dnscat_c2::DnscatC2Test {}),
        
        // Software simulations
        Box::new(software::S1109Pacemaker {}),
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
        info.id.to_lowercase() == id_or_name.to_lowercase() || 
        info.name.to_lowercase().replace(" ", "_") == id_or_name.to_lowercase()
    })
}

// Helper function to get all techniques in a category
pub fn get_techniques_by_category(category: &str) -> Vec<Box<dyn AttackTechnique>> {
    get_all_techniques().into_iter()
        .filter(|t| t.info().category.to_lowercase() == category.to_lowercase())
        .collect()
}
