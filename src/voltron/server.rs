use crate::voltron::protocol::{
    VoltronError, JsonRpcRequest, JsonRpcResponse, JsonRpcError,
    RegisterParams, HeartbeatParams, TechniqueResultParams,
    ExecuteTechniqueParams,
    read_request, write_request, write_response,
};
use crate::voltron::state::{TechniqueJournal, TechniqueState};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{RwLock, Mutex};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

const HEARTBEAT_TIMEOUT_SECS: i64 = 60;
const HEARTBEAT_CHECK_INTERVAL_SECS: u64 = 10;

pub enum OutboundMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ClientInfo {
    pub hostname: String,
    pub ip: String,
    pub version: String,
    pub last_seen: i64,
    pub status: ClientConnectionStatus,
    #[serde(skip)]
    pub outbound_tx: Option<tokio::sync::mpsc::Sender<OutboundMessage>>,
}

impl Clone for ClientInfo {
    fn clone(&self) -> Self {
        ClientInfo {
            hostname: self.hostname.clone(),
            ip: self.ip.clone(),
            version: self.version.clone(),
            last_seen: self.last_seen,
            status: self.status.clone(),
            outbound_tx: self.outbound_tx.clone(),
        }
    }
}

impl std::fmt::Debug for ClientInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientInfo")
            .field("hostname", &self.hostname)
            .field("ip", &self.ip)
            .field("version", &self.version)
            .field("last_seen", &self.last_seen)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ClientConnectionStatus {
    Connected,
    Timeout,
    Disconnected,
}

pub struct VoltronServer {
    port: u16,
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
    journal: Arc<Mutex<TechniqueJournal>>,
    psk: Option<crate::voltron::PreSharedKey>,
    debug: bool,
}

impl VoltronServer {
    pub fn new_with_psk(psk: crate::voltron::PreSharedKey, journal: TechniqueJournal, debug: bool) -> Self {
        VoltronServer {
            port: 16969,
            clients: Arc::new(RwLock::new(HashMap::new())),
            journal: Arc::new(Mutex::new(journal)),
            psk: Some(psk),
            debug,
        }
    }

    pub async fn start(&mut self) -> Result<(), VoltronError> {
        if self.debug {
            log::debug!(" Server startup - binding TCP listener on 0.0.0.0:{}", self.port);
        }
        
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
            .await
            .map_err(VoltronError::Io)?;
        
        log::info!(" Voltron server listening on 0.0.0.0:{}", self.port);
        
        if self.debug {
            log::debug!(" TCP listener configured: local_addr={:?}", listener.local_addr());
        }
        
        let clients = self.clients.clone();
        let journal = self.journal.clone();
        let debug = self.debug;
        
        tokio::spawn(async move {
            if debug {
                log::debug!(" Heartbeat monitor thread started");
            }
            Self::heartbeat_monitor(clients, journal, debug).await;
            if debug {
                log::debug!(" Heartbeat monitor thread exiting");
            }
        });
        
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::error!(" Accept error: {}", e);
                    continue;
                }
            };
            
            if self.debug {
                log::debug!(" Accepted connection from {}, spawning client handler", peer_addr);
            }
            
            log::info!(" New connection from {}", peer_addr);
            
            let clients = self.clients.clone();
            let journal = self.journal.clone();
            let psk = self.psk.clone();
            let debug = self.debug;
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, clients, journal, psk, debug).await {
                    log::error!(" Client handler error: {}", e);
                }
            });
        }
    }

    async fn handle_client(
        mut stream: TcpStream,
        clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
        journal: Arc<Mutex<TechniqueJournal>>,
        psk: Option<crate::voltron::PreSharedKey>,
        debug: bool,
    ) -> Result<(), VoltronError> {
        let peer_addr = stream.peer_addr()
            .map_err(VoltronError::Io)?;
        
        let channel = if let Some(psk) = psk {
            if debug {
                log::debug!(" [{}] Starting server-side handshake", peer_addr);
            }
            
            let handshake = crate::voltron::handshake::Handshake::new(psk, debug);
            let session_key = handshake.server_handshake(&mut stream).await?;
            
            if debug {
                log::debug!(" [{}] Handshake complete, creating encrypted channel", peer_addr);
            }
            
            let ch = crate::voltron::encrypted_channel::EncryptedChannel::new(&session_key, debug);
            log::info!(" [{}] Encrypted channel established", peer_addr);
            Some(ch)
        } else {
            None
        };
        
        let (read_half, write_half) = tokio::io::split(stream);
        
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel::<OutboundMessage>(100);
        
        let writer_task = Self::writer_task(write_half, outbound_rx, channel.clone(), debug);
        let writer_handle = tokio::spawn(writer_task);
        
        let reader_result = Self::reader_task(
            read_half, 
            channel, 
            clients.clone(), 
            journal.clone(),
            outbound_tx.clone(),
            peer_addr.to_string(), 
            debug
        ).await;
        
        if debug {
            log::debug!(" [{}] Reader task finished, aborting writer task", peer_addr);
        }
        
        writer_handle.abort();
        
        if debug {
            match &reader_result {
                Ok(_) => log::debug!(" [{}] Connection closed gracefully", peer_addr),
                Err(e) => log::debug!(" [{}] Connection closed with error: {}", peer_addr, e),
            }
        }
        
        reader_result
    }

    async fn writer_task(
        mut write_half: WriteHalf<TcpStream>,
        mut outbound_rx: tokio::sync::mpsc::Receiver<OutboundMessage>,
        channel: Option<crate::voltron::encrypted_channel::EncryptedChannel>,
        debug: bool,
    ) {
        if debug {
            log::debug!(" Writer task started");
        }
        
        while let Some(message) = outbound_rx.recv().await {
            let result = if let Some(ref ch) = channel {
                let bytes = match &message {
                    OutboundMessage::Request(req) => match serde_json::to_vec(req) {
                        Ok(b) => b,
                        Err(e) => {
                            log::error!(" Failed to serialize request: {}", e);
                            continue;
                        }
                    },
                    OutboundMessage::Response(resp) => match serde_json::to_vec(resp) {
                        Ok(b) => b,
                        Err(e) => {
                            log::error!(" Failed to serialize response: {}", e);
                            continue;
                        }
                    },
                };
                ch.send(&mut write_half, &bytes).await
            } else {
                match message {
                    OutboundMessage::Request(request) => write_request(&mut write_half, &request).await,
                    OutboundMessage::Response(response) => write_response(&mut write_half, &response).await,
                }
            };
            
            if let Err(e) = result {
                log::error!(" Failed to send message: {}", e);
                break;
            }
        }
        
        if debug {
            log::debug!(" Writer task exited");
        }
    }

    async fn reader_task(
        mut read_half: ReadHalf<TcpStream>,
        channel: Option<crate::voltron::encrypted_channel::EncryptedChannel>,
        clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
        journal: Arc<Mutex<TechniqueJournal>>,
        outbound_tx: tokio::sync::mpsc::Sender<OutboundMessage>,
        peer_addr: String,
        debug: bool,
    ) -> Result<(), VoltronError> {
        if debug {
            log::debug!(" [{}] Reader task started", peer_addr);
        }
        
        let mut client_hostname: Option<String> = None;
        
        loop {
            let request = if let Some(ref ch) = channel {
                let plaintext = match ch.recv(&mut read_half).await {
                    Ok(data) => data,
                    Err(e) => {
                        log::info!(" [{}] Client disconnected: {}", peer_addr, e);
                        break;
                    }
                };
                
                if debug {
                    log::debug!(" [{}] Received {} bytes (decrypted)", peer_addr, plaintext.len());
                }
                
                match serde_json::from_slice(&plaintext) {
                    Ok(req) => req,
                    Err(e) => {
                        log::error!(" [{}] Invalid JSON-RPC: {}", peer_addr, e);
                        continue;
                    }
                }
            } else {
                match read_request(&mut read_half).await {
                    Ok(req) => req,
                    Err(e) => {
                        log::info!(" [{}] Client disconnected: {}", peer_addr, e);
                        break;
                    }
                }
            };
            
            if debug {
                log::debug!(" [{}] Received request: method={}, id={:?}", 
                    peer_addr, request.method, request.id);
            }
            
            match request.method.as_str() {
                "client.register" => {
                    let params: RegisterParams = match request.params.as_ref() {
                        Some(p) => match serde_json::from_value(p.clone()) {
                            Ok(params) => params,
                            Err(e) => {
                                log::error!(" [{}] Invalid registration params: {}", peer_addr, e);
                                continue;
                            }
                        },
                        None => {
                            log::error!(" [{}] Missing registration params", peer_addr);
                            continue;
                        }
                    };
                    
                    if debug {
                        log::debug!(" Registration request: hostname={}, ip={}, version={}, capabilities={:?}",
                            params.hostname, peer_addr, params.version, params.capabilities);
                    }
                    
                    client_hostname = Some(params.hostname.clone());
                    
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    
                    let info = ClientInfo {
                        hostname: params.hostname.clone(),
                        ip: peer_addr.clone(),
                        version: params.version.clone(),
                        last_seen: now,
                        status: ClientConnectionStatus::Connected,
                        outbound_tx: Some(outbound_tx.clone()),
                    };
                    
                    clients.write().await.insert(params.hostname.clone(), info);
                    
                    log::info!(" Client registered: {} ({})", params.hostname, peer_addr);
                    
                    if debug {
                        log::debug!(" Clients map now contains {} clients", clients.read().await.len());
                    }
                    
                    // Note: Response to registration is not implemented in async refactor
                    // Original client doesn't wait for registration response
                },
                "client.heartbeat" => {
                    let params: HeartbeatParams = match request.params.as_ref() {
                        Some(p) => match serde_json::from_value(p.clone()) {
                            Ok(params) => params,
                            Err(e) => {
                                log::error!(" [{}] Invalid heartbeat params: {}", peer_addr, e);
                                continue;
                            }
                        },
                        None => continue,
                    };
                    
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    
                    if let Some(client) = clients.write().await.get_mut(&params.hostname) {
                        let elapsed = now - client.last_seen;
                        
                        if debug {
                            log::debug!(" Heartbeat from {} (seq={}): last_seen updated from {} to {} (elapsed={}s)",
                                params.hostname, params.sequence, client.last_seen, now, elapsed);
                        }
                        
                        client.last_seen = now;
                        client.status = ClientConnectionStatus::Connected;
                    }
                    
                    if debug {
                        log::debug!(" [{}] Notification received ({}), no response sent", peer_addr, request.method);
                    }
                },
                "technique.result" => {
                    let params: TechniqueResultParams = match request.params.as_ref() {
                        Some(p) => match serde_json::from_value(p.clone()) {
                            Ok(p) => p,
                            Err(e) => {
                                log::error!(" [{}] Invalid technique.result params: {}", peer_addr, e);
                                continue;
                            }
                        },
                        None => {
                            log::error!(" [{}] Missing technique.result params", peer_addr);
                            continue;
                        }
                    };
                    
                    if debug {
                        log::debug!(" [{}] Technique result: technique_id={}, status={:?}", 
                            peer_addr, params.technique_id, params.status);
                    }
                    
                    let state = match params.status {
                        crate::voltron::protocol::ExecutionStatus::Success => TechniqueState::Done,
                        crate::voltron::protocol::ExecutionStatus::Failed => TechniqueState::Failed,
                        crate::voltron::protocol::ExecutionStatus::Aborted => TechniqueState::Aborted,
                        crate::voltron::protocol::ExecutionStatus::Partial => TechniqueState::Done,
                    };
                    
                    if let Err(e) = journal.lock().await.update_state(&params.technique_id, state.clone()) {
                        log::warn!(" [{}] Failed to update technique state (technique_id={}, state={:?}): {} - continuing", 
                            peer_addr, params.technique_id, state, e);
                    } else {
                        log::info!(" Technique {} completed with status {:?}", params.technique_id, params.status);
                    }
                },
                "clients.list" => {
                    if debug {
                        log::debug!(" [{}] Clients list request", peer_addr);
                    }
                    
                    let clients_snapshot: Vec<ClientInfo> = clients.read().await
                        .values()
                        .cloned()
                        .collect();
                    
                    #[derive(serde::Serialize)]
                    struct ClientListResult {
                        clients: Vec<ClientInfo>,
                    }
                    
                    let result = ClientListResult {
                        clients: clients_snapshot,
                    };
                    
                    let response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: Some(serde_json::to_value(&result).unwrap()),
                        error: None,
                        id: request.id.clone(),
                    };
                    
                    if outbound_tx.send(OutboundMessage::Response(response)).await.is_ok() {
                        if debug {
                            log::debug!(" [{}] Sent clients.list response: {} clients", peer_addr, result.clients.len());
                        }
                    }
                },
                "technique.run" => {
                    use crate::voltron::protocol::RunTechniqueParams;
                    use uuid::Uuid;
                    
                    let params: RunTechniqueParams = match request.params.as_ref() {
                        Some(p) => match serde_json::from_value(p.clone()) {
                            Ok(params) => params,
                            Err(e) => {
                                log::error!(" [{}] Invalid technique.run params: {}", peer_addr, e);
                                
                                let error_response = JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    result: None,
                                    error: Some(JsonRpcError {
                                        code: -32602,
                                        message: format!("Invalid params: {}", e),
                                        data: None,
                                    }),
                                    id: request.id.clone(),
                                };
                                
                                let _ = outbound_tx.send(OutboundMessage::Response(error_response)).await;
                                continue;
                            }
                        },
                        None => {
                            log::error!(" [{}] Missing technique.run params", peer_addr);
                            continue;
                        }
                    };
                    
                    if debug {
                        log::debug!(" Technique run request: technique={}, attacker={}, victim={:?}",
                            params.technique, params.attacker, params.victim);
                    }
                    
                    let technique_id = Uuid::new_v4().to_string();
                    let group_id = Uuid::new_v4().to_string();
                    
                    let clients_lock = clients.read().await;
                    
                    let attacker_client = match clients_lock.get(&params.attacker) {
                        Some(c) => c,
                        None => {
                            log::error!(" Attacker client '{}' not found", params.attacker);
                            
                            let error_response = JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                result: None,
                                error: Some(JsonRpcError {
                                    code: -32001,
                                    message: format!("Attacker client '{}' not found", params.attacker),
                                    data: None,
                                }),
                                id: request.id.clone(),
                            };
                            
                            let _ = outbound_tx.send(OutboundMessage::Response(error_response)).await;
                            continue;
                        }
                    };
                    
                    let victim_client = if let Some(ref victim_hostname) = params.victim {
                        match clients_lock.get(victim_hostname) {
                            Some(c) => Some(c),
                            None => {
                                log::error!(" Victim client '{}' not found", victim_hostname);
                                
                                let error_response = JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    result: None,
                                    error: Some(JsonRpcError {
                                        code: -32001,
                                        message: format!("Victim client '{}' not found", victim_hostname),
                                        data: None,
                                    }),
                                    id: request.id.clone(),
                                };
                                
                                let _ = outbound_tx.send(OutboundMessage::Response(error_response)).await;
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    
                    let attacker_tx = attacker_client.outbound_tx.clone();
                    let victim_tx = victim_client.as_ref().and_then(|c| c.outbound_tx.clone());
                    let victim_ip = victim_client.as_ref().map(|c| {
                        c.ip.rsplit_once(':').map(|(ip, _port)| ip).unwrap_or(&c.ip).to_string()
                    });
                    
                    if debug && victim_ip.is_some() {
                        log::debug!(" [DISPATCH] Extracted victim IP: {}", victim_ip.as_ref().unwrap());
                    }
                    
                    drop(clients_lock);
                    
                    if let Err(e) = journal.lock().await.add_technique(&technique_id, &params.technique, Some(&group_id)) {
                        log::error!(" [{}] Failed to create journal entry: {}", peer_addr, e);
                        
                        let error_response = JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32003,
                                message: format!("Failed to create journal entry: {}", e),
                                data: None,
                            }),
                            id: request.id.clone(),
                        };
                        
                        let _ = outbound_tx.send(OutboundMessage::Response(error_response)).await;
                        continue;
                    }
                    
                    if debug {
                        log::debug!(" [JOURNAL] Created entry: technique_id={}, technique={}, group_id={}", 
                            technique_id, params.technique, group_id);
                    }
                    
                    let mut attacker_params = serde_json::json!({
                        "technique_id": technique_id.clone(),
                        "technique": params.technique.clone(),
                        "role": "attacker",
                        "params": params.params.clone().unwrap_or(serde_json::json!({})),
                        "group_id": group_id.clone(),
                    });
                    
                    if let Some(ref vip) = victim_ip {
                        attacker_params["victim_ip"] = serde_json::json!(vip);
                    }
                    
                    let attacker_execute = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        method: "execute_technique".to_string(),
                        params: Some(attacker_params),
                        id: None,
                    };
                    
                    let mut dispatch_failed = false;
                    let mut failed_role = String::new();
                    let mut attacker_sent = false;
                    
                    if let Some(ref tx) = attacker_tx {
                        if tx.send(OutboundMessage::Request(attacker_execute)).await.is_err() {
                            log::error!(" [{}] Failed to send technique to attacker - channel closed", peer_addr);
                            dispatch_failed = true;
                            failed_role = "attacker".to_string();
                        } else {
                            attacker_sent = true;
                            if debug {
                                log::debug!(" Dispatched technique to attacker {}", params.attacker);
                            }
                        }
                    }
                    
                    if !dispatch_failed {
                        if let Some(ref tx) = victim_tx {
                            let victim_execute = JsonRpcRequest {
                                jsonrpc: "2.0".to_string(),
                                method: "execute_technique".to_string(),
                                params: Some(serde_json::json!({
                                    "technique_id": technique_id.clone(),
                                    "technique": params.technique.clone(),
                                    "role": "victim",
                                    "params": params.params.clone().unwrap_or(serde_json::json!({})),
                                    "group_id": group_id.clone(),
                                })),
                                id: None,
                            };
                            
                            if tx.send(OutboundMessage::Request(victim_execute)).await.is_err() {
                                log::error!(" [{}] Failed to send technique to victim - channel closed", peer_addr);
                                dispatch_failed = true;
                                failed_role = "victim".to_string();
                                
                                if attacker_sent {
                                    if let Some(ref atx) = attacker_tx {
                                        let abort = JsonRpcRequest {
                                            jsonrpc: "2.0".to_string(),
                                            method: "abort_technique".to_string(),
                                            params: Some(serde_json::json!({
                                                "technique_id": technique_id.clone(),
                                            })),
                                            id: None,
                                        };
                                        let _ = atx.send(OutboundMessage::Request(abort)).await;
                                        log::info!(" [{}] Sent abort to attacker due to victim dispatch failure", peer_addr);
                                    }
                                }
                            } else if debug {
                                log::debug!(" Dispatched technique to victim {:?}", params.victim);
                            }
                        }
                    }
                    
                    if dispatch_failed {
                        if let Err(e) = journal.lock().await.update_state(&technique_id, TechniqueState::Failed) {
                            log::error!(" [{}] Failed to update journal to FAILED state: {}", peer_addr, e);
                        }
                        
                        let error_response = JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32004,
                                message: format!("Failed to dispatch technique to {} - connection closed", failed_role),
                                data: None,
                            }),
                            id: request.id.clone(),
                        };
                        
                        let _ = outbound_tx.send(OutboundMessage::Response(error_response)).await;
                        continue;
                    }
                    
                    if let Err(e) = journal.lock().await.update_state(&technique_id, TechniqueState::Dispatched) {
                        log::error!(" [{}] Failed to update journal to DISPATCHED state: {} - continuing", peer_addr, e);
                    }
                    
                    if debug {
                        log::debug!(" [JOURNAL] Updated state: technique_id={} -> DISPATCHED", technique_id);
                    }
                    
                    use crate::voltron::protocol::RunTechniqueResult;
                    let result = RunTechniqueResult {
                        technique_id: technique_id.clone(),
                        group_id: group_id.clone(),
                        status: "dispatched".to_string(),
                        attacker_result: None,
                        victim_result: None,
                    };
                    
                    let response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: Some(serde_json::to_value(&result).unwrap()),
                        error: None,
                        id: request.id.clone(),
                    };
                    
                    if outbound_tx.send(OutboundMessage::Response(response)).await.is_ok() {
                        if debug {
                            log::debug!(" [{}] Sent technique.run response: technique_id={}", peer_addr, technique_id);
                        }
                    }
                    
                    log::info!(" Technique {} dispatched: {} (attacker={}, victim={:?})",
                        technique_id, params.technique, params.attacker, params.victim);
                },
                _ => {
                    if debug {
                        log::debug!(" [{}] Unknown method: {}", peer_addr, request.method);
                    }
                }
            }
        }
        
        if let Some(hostname) = client_hostname {
            if let Some(client) = clients.write().await.get_mut(&hostname) {
                client.status = ClientConnectionStatus::Disconnected;
                client.outbound_tx = None;
            }
            log::info!(" Client {} disconnected", hostname);
        }
        
        if debug {
            log::debug!(" [{}] Reader task exited", peer_addr);
        }
        
        Ok(())
    }

    async fn heartbeat_monitor(
        clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
        journal: Arc<Mutex<TechniqueJournal>>,
        debug: bool,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_CHECK_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            interval.tick().await;
            
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            
            let mut clients_guard = clients.write().await;
            let client_count = clients_guard.len();
            
            if debug {
                log::debug!(" Heartbeat monitor check: {} clients registered, threshold={}s",
                    client_count, HEARTBEAT_TIMEOUT_SECS);
            }
            
            for (hostname, client) in clients_guard.iter_mut() {
                let age = now - client.last_seen;
                
                if debug {
                    log::debug!(" Client {} last_seen={}s ago, status={:?}", 
                        hostname, age, client.status);
                }
                
                if age > HEARTBEAT_TIMEOUT_SECS && client.status == ClientConnectionStatus::Connected {
                    log::warn!(" Client {} heartbeat timeout ({}s > {}s)", 
                        hostname, age, HEARTBEAT_TIMEOUT_SECS);
                    client.status = ClientConnectionStatus::Timeout;
                    client.outbound_tx = None;
                    
                    let mut j = journal.lock().await;
                    let running_techniques = j.get_running_techniques_for_client(hostname);
                    for technique_id in running_techniques {
                        if let Err(e) = j.update_state(&technique_id, TechniqueState::Aborted) {
                            log::error!(" Failed to abort technique {} for {}: {}", technique_id, hostname, e);
                        }
                    }
                    drop(j);
                }
                
                if age > 30 && age < HEARTBEAT_TIMEOUT_SECS && client.status == ClientConnectionStatus::Connected {
                    if debug {
                        log::debug!(" Client {} approaching timeout ({}s > 30s warning threshold)", hostname, age);
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn get_clients(&self) -> Vec<ClientInfo> {
        self.clients.read().await.values().cloned().collect()
    }

    #[allow(dead_code)]
    pub async fn dispatch_technique(
        &self,
        technique: &str,
        attacker: &str,
        victim: Option<&str>,
        params: Option<serde_json::Value>,
    ) -> Result<String, VoltronError> {
        let clients_guard = self.clients.read().await;
        
        let attacker_client = clients_guard.get(attacker)
            .ok_or_else(|| VoltronError::ClientNotFound(attacker.to_string()))?;
        
        if attacker_client.status != ClientConnectionStatus::Connected {
            return Err(VoltronError::Protocol(format!("Attacker {} not connected", attacker)));
        }
        
        let attacker_outbound = attacker_client.outbound_tx.clone()
            .ok_or_else(|| VoltronError::Protocol("Attacker has no outbound channel".to_string()))?;
        let attacker_ip = attacker_client.ip.clone();
        
        let victim_info = if let Some(victim_name) = victim {
            let victim_client = clients_guard.get(victim_name)
                .ok_or_else(|| VoltronError::ClientNotFound(victim_name.to_string()))?;
            
            if victim_client.status != ClientConnectionStatus::Connected {
                return Err(VoltronError::Protocol(format!("Victim {} not connected", victim_name)));
            }
            
            let victim_outbound = victim_client.outbound_tx.clone()
                .ok_or_else(|| VoltronError::Protocol("Victim has no outbound channel".to_string()))?;
            Some((victim_client.clone(), victim_outbound))
        } else {
            None
        };
        
        drop(clients_guard);
        
        let technique_id = uuid::Uuid::new_v4().to_string();
        let group_id = uuid::Uuid::new_v4().to_string();
        
        let mut j = self.journal.lock().await;
        j.add_technique(&technique_id, technique, Some(&group_id))
            .map_err(|e| VoltronError::Protocol(format!("Journal error: {}", e)))?;
        drop(j);
        
        let attacker_params = ExecuteTechniqueParams {
            technique_id: technique_id.clone(),
            technique: technique.to_string(),
            role: crate::voltron::protocol::Role::Attacker,
            params: params.unwrap_or(serde_json::json!({})),
            target_info: victim_info.as_ref().map(|(info, _)| {
                crate::voltron::protocol::TargetInfo {
                    hostname: info.hostname.clone(),
                    ip: info.ip.clone(),
                    port: None,
                }
            }),
            group_id: Some(group_id.clone()),
            target_peers: vec![],
        };
        
        let attacker_request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "technique.execute".to_string(),
            params: Some(serde_json::to_value(&attacker_params)?),
            id: Some(serde_json::Value::Number(1.into())),
        };
        
        attacker_outbound.send(OutboundMessage::Request(attacker_request)).await
            .map_err(|e| VoltronError::Protocol(format!("Failed to send to attacker: {}", e)))?;
        
        if let Some((victim_client, victim_outbound)) = victim_info {
            let victim_params = ExecuteTechniqueParams {
                technique_id: technique_id.clone(),
                technique: technique.to_string(),
                role: crate::voltron::protocol::Role::Victim,
                params: serde_json::json!({}),
                target_info: Some(crate::voltron::protocol::TargetInfo {
                    hostname: attacker.to_string(),
                    ip: attacker_ip.clone(),
                    port: None,
                }),
                group_id: Some(group_id.clone()),
                target_peers: vec![],
            };
            
            let victim_request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "technique.execute".to_string(),
                params: Some(serde_json::to_value(&victim_params)?),
                id: Some(serde_json::Value::Number(2.into())),
            };
            
            victim_outbound.send(OutboundMessage::Request(victim_request)).await
                .map_err(|e| VoltronError::Protocol(format!("Failed to send to victim: {}", e)))?;
            
            log::info!(" Dispatched {} to attacker {} and victim {}", technique, attacker, victim_client.hostname);
        } else {
            log::info!(" Dispatched {} to attacker {}", technique, attacker);
        }
        
        Ok(technique_id)
    }
}
