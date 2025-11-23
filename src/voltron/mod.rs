pub mod client;
pub mod encrypted_channel;
pub mod handshake;
pub mod protocol;
pub mod psk;
pub mod scenario;
pub mod server;
pub mod state;
pub mod watchdog;

pub use client::VoltronClient;
pub use server::VoltronServer;
pub use protocol::VoltronError;
pub use psk::PreSharedKey;
pub use state::TechniqueJournal;

use std::path::PathBuf;

pub fn keygen_command(output: PathBuf, _hostname: Option<String>) -> Result<(), String> {
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║         SignalBench Voltron - Pre-Shared Key Generation              ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    println!("Generating 256-bit pre-shared key...");
    let psk = PreSharedKey::generate();
    
    println!("  [OK] Random key generated");
    println!("  [OK] Fingerprint: {}", psk.fingerprint());
    
    println!("\nSaving key to: {}", output.display());
    psk.save_to_file(&output)
        .map_err(|e| format!("Failed to save PSK: {}", e))?;
    
    println!("  [OK] Key saved successfully (permissions: 0600)");
    
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║                         USAGE INSTRUCTIONS                            ║");
    println!("╠═══════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                       ║");
    println!("║  IMPORTANT: Copy {} to all servers and clients          ║", output.display());
    println!("║             All endpoints must use the SAME key file.                 ║");
    println!("║                                                                       ║");
    println!("║  Start Voltron Server:                                                ║");
    println!("║    signalbench voltron server --psk {}                   ║", output.display());
    println!("║                                                                       ║");
    println!("║  Connect Client:                                                      ║");
    println!("║    signalbench voltron client --server <IP>:16969 \\                  ║");
    println!("║                               --psk {}                    ║", output.display());
    println!("║                                                                       ║");
    println!("║  Enable Debug Logging:                                                ║");
    println!("║    Add --debug flag to see all handshake and encryption details      ║");
    println!("║                                                                       ║");
    println!("╠═══════════════════════════════════════════════════════════════════════╣");
    println!("║  Key Details:                                                         ║");
    println!("║    Algorithm:    ChaCha20-Poly1305 AEAD                               ║");
    println!("║    Key Size:     256 bits (32 bytes)                                  ║");
    
    let fingerprint = psk.fingerprint();
    if fingerprint.len() <= 68 {
        println!("║    Fingerprint:  {:<54} ║", fingerprint);
    } else {
        let mid_point = fingerprint.len() / 2;
        let (line1, line2) = fingerprint.split_at(mid_point);
        println!("║    Fingerprint:  {:<54} ║", line1);
        println!("║                  {:<54} ║", line2);
    }
    
    println!("║    File:         {:<54} ║", output.display().to_string());
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    println!("[OK] Key generation complete! Copy this file to all endpoints.");
    
    Ok(())
}

pub async fn server_command(psk_path: PathBuf, journal_path: PathBuf, debug: bool) -> Result<(), String> {
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║                 SignalBench Voltron Server                           ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    if debug {
        println!("[DEBUG MODE ENABLED] Verbose logging to stderr");
        log::debug!(" Server starting with debug logging enabled");
    }
    
    println!("Loading pre-shared key from: {}", psk_path.display());
    let psk = PreSharedKey::load_from_file(&psk_path)
        .map_err(|e| format!("Failed to load PSK: {}", e))?;
    
    println!("  [OK] PSK loaded successfully");
    println!("  [OK] Fingerprint: {}", psk.fingerprint());
    
    println!("\nInitialising technique journal: {}", journal_path.display());
    let journal = TechniqueJournal::new(&journal_path)
        .map_err(|e| format!("Failed to create journal: {}", e))?;
    
    println!("  [OK] Journal database ready");
    
    println!("\nStarting Voltron server on 0.0.0.0:16969...");
    let mut server = VoltronServer::new_with_psk(psk, journal, debug);
    
    println!("  [OK] PSK encryption enabled (ChaCha20-Poly1305)");
    println!("  [OK] JSON-RPC 2.0 control channel active");
    println!("  [OK] Heartbeat monitor running (60s timeout)");
    
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║  Server is ready. Clients can connect using:                         ║");
    println!("║    signalbench voltron client --server <IP>:16969                    ║");
    println!("║                                                                       ║");
    println!("║  Press Ctrl+C to stop the server                                     ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    server.start().await
        .map_err(|e| format!("Server error: {}", e))?;
    
    Ok(())
}

pub async fn client_command(server_addr: String, psk_path: PathBuf, hostname: Option<String>, debug: bool) -> Result<(), String> {
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║           SignalBench Voltron Client - Endpoint Node                 ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    if debug {
        println!("[DEBUG MODE ENABLED] Verbose logging to stderr");
        log::debug!(" Client starting with debug logging enabled");
    }
    
    let server_addr = if !server_addr.contains(':') {
        format!("{}:16969", server_addr)
    } else {
        server_addr
    };
    
    println!("Loading pre-shared key from: {}", psk_path.display());
    let psk = PreSharedKey::load_from_file(&psk_path)
        .map_err(|e| format!("Failed to load PSK: {}", e))?;
    
    let hostname = hostname.unwrap_or_else(|| {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "voltron-client".to_string())
    });
    
    println!("  [OK] PSK loaded successfully");
    println!("  [OK] Fingerprint: {}", psk.fingerprint());
    println!("  [OK] Hostname: {}", hostname);
    
    println!("\nConnecting to Voltron server at {}...", server_addr);
    let mut client = VoltronClient::new_with_psk(server_addr.clone(), hostname.clone(), psk, debug);
    
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║  Voltron Client - Auto-reconnect Mode                                ║");
    println!("║    Hostname: {:<58}║", hostname);
    println!("║    Server:   {:<58}║", server_addr);
    println!("║                                                                       ║");
    println!("║  Reconnection: Exponential backoff 1s-30s on disconnect              ║");
    println!("║  Press Ctrl+C to stop                                                ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    client.run_with_reconnect().await
        .map_err(|e| format!("Client error: {}", e))?;
    
    Ok(())
}

pub async fn run_command(
    server_addr: String,
    psk_path: PathBuf,
    technique: String,
    attacker: String,
    victim: Option<String>,
    params: Option<String>,
    debug: bool,
) -> Result<(), String> {
    use tokio::net::TcpStream;
    use crate::voltron::protocol::{JsonRpcRequest, RunTechniqueParams, RunTechniqueResult};
    use crate::voltron::encrypted_channel::EncryptedChannel;
    
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║           SignalBench Voltron Run - Technique Dispatch              ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    if debug {
        eprintln!("[DEBUG MODE ENABLED] Verbose logging to stderr");
        log::debug!(" Run command starting");
    }
    
    println!("Loading pre-shared key from: {}", psk_path.display());
    let psk = PreSharedKey::load_from_file(&psk_path)
        .map_err(|e| format!("Failed to load PSK: {}", e))?;
    println!("  [OK] PSK loaded successfully");
    println!("  [OK] Fingerprint: {}", psk.fingerprint());
    
    let params_json = if let Some(p) = params {
        Some(serde_json::from_str(&p)
            .map_err(|e| format!("Invalid JSON params: {}", e))?)
    } else {
        None
    };
    
    println!("\nDispatching technique:");
    println!("  [OK] Technique:  {}", technique);
    println!("  [OK] Attacker:   {}", attacker);
    if let Some(ref v) = victim {
        println!("  [OK] Victim:     {}", v);
    }
    if params_json.is_some() {
        println!("  [OK] Custom parameters provided");
    }
    
    let server_addr = if !server_addr.contains(':') {
        format!("{}:16969", server_addr)
    } else {
        server_addr
    };
    
    println!("\nConnecting to server at {}...", server_addr);
    
    let mut stream = TcpStream::connect(&server_addr).await
        .map_err(|e| format!("Failed to connect to server: {}", e))?;
    
    println!("  [OK] Connected to server");
    
    if debug {
        log::debug!(" Starting client-side handshake");
    }
    
    let handshake = crate::voltron::handshake::Handshake::new(psk, debug);
    let session_key = handshake.client_handshake(&mut stream).await
        .map_err(|e| format!("Handshake failed: {}", e))?;
    
    println!("  [OK] Handshake complete");
    
    let channel = EncryptedChannel::new(&session_key, debug);
    
    let run_params = RunTechniqueParams {
        technique: technique.clone(),
        attacker: attacker.clone(),
        victim: victim.clone(),
        params: params_json,
    };
    
    let request = JsonRpcRequest::new(
        "technique.run",
        Some(serde_json::to_value(&run_params)
            .map_err(|e| format!("Failed to serialize params: {}", e))?),
        1,
    );
    
    if debug {
        log::debug!(" Sending technique.run request");
    }
    
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;
    
    channel.send(&mut stream, &request_bytes).await
        .map_err(|e| format!("Failed to send request: {}", e))?;
    
    println!("  [OK] Dispatch request sent");
    println!("\nWaiting for server response...");
    
    let response_bytes = channel.recv(&mut stream).await
        .map_err(|e| format!("Failed to receive response: {}", e))?;
    
    let response: crate::voltron::protocol::JsonRpcResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    if let Some(error) = response.error {
        return Err(format!("Server error: {} (code: {})", error.message, error.code));
    }
    
    let result: RunTechniqueResult = serde_json::from_value(response.result.unwrap_or(serde_json::Value::Null))
        .map_err(|e| format!("Failed to parse result: {}", e))?;
    
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║                      Dispatch Successful                             ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    println!("  Technique ID:  {}", result.technique_id);
    println!("  Group ID:      {}", result.group_id);
    println!("  Status:        {}", result.status);
    println!("\nThe technique has been dispatched to the specified clients.");
    println!("Check the server console for execution progress.\n");
    
    Ok(())
}

pub async fn formed_command(server_addr: String, psk_path: PathBuf) -> Result<(), String> {
    use tokio::net::TcpStream;
    use std::time::SystemTime;
    use crate::voltron::protocol::{JsonRpcRequest, JsonRpcResponse};
    
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║                 Voltron Formation Status                             ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    let server_addr = if server_addr.contains(':') {
        server_addr
    } else {
        format!("{}:16969", server_addr)
    };
    
    println!("Connecting to server at {}...", server_addr);
    
    let psk = PreSharedKey::load_from_file(&psk_path)
        .map_err(|e| format!("Failed to load PSK: {}", e))?;
    
    let mut stream = TcpStream::connect(&server_addr).await
        .map_err(|e| format!("Connection failed: {}", e))?;
    
    println!("  [OK] Connected to server");
    
    let handshake = crate::voltron::handshake::Handshake::new(psk, false);
    let session_key = handshake.client_handshake(&mut stream).await
        .map_err(|e| format!("Handshake failed: {}", e))?;
    
    println!("  [OK] Handshake complete\n");
    
    let channel = crate::voltron::encrypted_channel::EncryptedChannel::new(&session_key, false);
    
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "clients.list".to_string(),
        params: None,
        id: Some(serde_json::json!(1)),
    };
    
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;
    
    channel.send(&mut stream, &request_bytes).await
        .map_err(|e| format!("Failed to send request: {}", e))?;
    
    let response_bytes = channel.recv(&mut stream).await
        .map_err(|e| format!("Failed to receive response: {}", e))?;
    
    let response: JsonRpcResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    if let Some(error) = response.error {
        return Err(format!("Server error: {} (code: {})", error.message, error.code));
    }
    
    #[derive(serde::Deserialize)]
    struct ClientListResult {
        clients: Vec<server::ClientInfo>,
    }
    
    let result: ClientListResult = serde_json::from_value(response.result.unwrap_or(serde_json::Value::Null))
        .map_err(|e| format!("Failed to parse result: {}", e))?;
    
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║  Connected Clients                                                    ║");
    println!("╠═══════════════════════════════════════════════════════════════════════╣");
    println!("║  Hostname           IP Address        Version    Status        Seen  ║");
    println!("╠═══════════════════════════════════════════════════════════════════════╣");
    
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    for client in &result.clients {
        let age_secs = now - client.last_seen;
        let age_str = if age_secs < 60 {
            format!("{}s", age_secs)
        } else {
            format!("{}m", age_secs / 60)
        };
        
        let status_str = match client.status {
            server::ClientConnectionStatus::Connected => "Connected",
            server::ClientConnectionStatus::Timeout => "Timeout",
            server::ClientConnectionStatus::Disconnected => "Disconnected",
        };
        
        println!("║  {:<18} {:<17} {:<9} {:<13} {:<5} ║",
            client.hostname,
            client.ip,
            client.version,
            status_str,
            age_str);
    }
    
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    println!("Total clients: {}\n", result.clients.len());
    
    Ok(())
}
pub fn list_command() -> Result<(), String> {
    use crate::techniques::get_all_techniques;
    use colored::Colorize;
    use std::collections::HashMap;
    
    println!("\n╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║       SignalBench Voltron - Multi-Host MITRE ATT&CK Techniques      ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝\n");
    
    let all_techniques = get_all_techniques();
    let total_count = all_techniques.len();
    
    // Group techniques by category (matching regular list format)
    let mut techniques_by_category: HashMap<String, Vec<_>> = HashMap::new();
    for technique in all_techniques {
        let info = technique.info();
        // Normalize category to lowercase with underscores for consistent grouping
        let category = info.category.to_lowercase().replace(" ", "_");
        techniques_by_category.entry(category).or_insert_with(Vec::new).push(technique);
    }
    
    // Sort categories
    let mut categories: Vec<_> = techniques_by_category.keys().collect();
    categories.sort();
    
    // Print techniques by category (matching regular list format)
    for category in categories {
        println!("\n{}", format!("CATEGORY: {}", category.to_uppercase()).bold().green());
        
        let techniques = techniques_by_category.get(category).unwrap();
        for technique in techniques {
            let info = technique.info();
            let suffix = if info.voltron_only {
                " [VOLTRON-ONLY]"
            } else {
                ""
            };
            println!("  {} | {}{} | Platforms: {}", 
                info.id.yellow(), 
                info.name,
                suffix,
                info.platforms.join(", "));
        }
    }
    
    println!("\n{} technique(s) available in Voltron mode", total_count);
    println!("\nNote: [VOLTRON-ONLY] techniques require multi-host coordination");
    println!("\nUsage:");
    println!("  signalbench voltron run -s SERVER:PORT -t TECHNIQUE -a ATTACKER [-v VICTIM]\n");
    
    Ok(())
}
