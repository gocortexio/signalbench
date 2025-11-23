use crate::voltron::protocol::{
    VoltronError, JsonRpcRequest, JsonRpcResponse,
    RegisterParams, HeartbeatParams, TechniqueResultParams,
    ClientStatus, ExecutionStatus, ExecuteTechniqueParams,
    read_request, write_request, Role, TargetInfo,
};
use crate::runner;
use tokio::net::TcpStream;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const HEARTBEAT_INTERVAL_SECS: u64 = 30;

enum OutboundMessage {
    Request(JsonRpcRequest),
    #[allow(dead_code)]
    Shutdown,
}

pub struct VoltronClient {
    server_addr: String,
    hostname: String,
    psk: Option<crate::voltron::PreSharedKey>,
    debug: bool,
    outbound_tx: Option<mpsc::Sender<OutboundMessage>>,
    running_techniques: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    tasks: Vec<JoinHandle<()>>,
}

impl VoltronClient {
    pub fn new_with_psk(server_addr: String, hostname: String, psk: crate::voltron::PreSharedKey, debug: bool) -> Self {
        VoltronClient {
            server_addr,
            hostname,
            psk: Some(psk),
            debug,
            outbound_tx: None,
            running_techniques: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx: None,
            tasks: Vec::new(),
        }
    }

    pub async fn connect(&mut self) -> Result<(), VoltronError> {
        if self.debug {
            log::debug!(" [CONNECT] Starting connection sequence to {}", self.server_addr);
        }
        
        let tcp_stream = TcpStream::connect(&self.server_addr)
            .await
            .map_err(VoltronError::Io)?;
        
        log::info!(" Connected to Voltron server at {}", self.server_addr);
        
        let mut stream = tcp_stream;
        let channel = if let Some(ref psk) = self.psk {
            if self.debug {
                log::debug!(" [CONNECT] Starting client-side handshake");
            }
            
            let handshake = crate::voltron::handshake::Handshake::new(psk.clone(), self.debug);
            let session_key = handshake.client_handshake(&mut stream).await?;
            
            if self.debug {
                log::debug!(" [CONNECT] Handshake complete, creating encrypted channel");
            }
            
            let ch = crate::voltron::encrypted_channel::EncryptedChannel::new(&session_key, self.debug);
            log::info!(" Encrypted channel established");
            Some(ch)
        } else {
            log::warn!(" PSK not configured - using unencrypted channel");
            None
        };
        
        if self.debug {
            log::debug!(" [CONNECT] Splitting TCP stream into read/write halves");
        }
        
        let (read_half, write_half) = tokio::io::split(stream);
        
        if self.debug {
            log::debug!(" [CONNECT] Creating outbound channel (capacity=100)");
        }
        
        let (outbound_tx, outbound_rx) = mpsc::channel::<OutboundMessage>(100);
        self.outbound_tx = Some(outbound_tx.clone());
        
        if self.debug {
            log::debug!(" [CONNECT] Creating shutdown broadcast channel");
        }
        
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);
        
        let hostname = self.hostname.clone();
        let debug = self.debug;
        let techniques = self.running_techniques.clone();
        
        if debug {
            log::debug!(" [CONNECT] Spawning writer task...");
        }
        let writer_task = Self::writer_task(write_half, outbound_rx, channel.clone(), debug);
        self.tasks.push(tokio::spawn(writer_task));
        if debug {
            log::debug!(" [CONNECT] Writer task spawned (task count: {})", self.tasks.len());
        }
        
        if debug {
            log::debug!(" [CONNECT] Spawning reader task...");
        }
        let reader_task = Self::reader_task(read_half, channel.clone(), outbound_tx.clone(), techniques, debug, shutdown_rx.clone());
        self.tasks.push(tokio::spawn(reader_task));
        if debug {
            log::debug!(" [CONNECT] Reader task spawned (task count: {})", self.tasks.len());
        }
        
        if debug {
            log::debug!(" [CONNECT] Spawning heartbeat task...");
        }
        let heartbeat_task = Self::heartbeat_task(hostname.clone(), outbound_tx.clone(), debug, shutdown_rx);
        self.tasks.push(tokio::spawn(heartbeat_task));
        if debug {
            log::debug!(" [CONNECT] Heartbeat task spawned (task count: {})", self.tasks.len());
        }
        
        if debug {
            log::debug!(" [CONNECT] All tasks spawned, sending registration via outbound channel");
        }
        
        self.send_registration_via_channel(&hostname, &outbound_tx).await?;
        
        if debug {
            log::debug!(" [CONNECT] Connection sequence complete, {} tasks running", self.tasks.len());
        }
        
        Ok(())
    }

    async fn send_registration_via_channel(&self, hostname: &str, outbound_tx: &mpsc::Sender<OutboundMessage>) -> Result<(), VoltronError> {
        let capabilities = vec!["attacker".to_string(), "victim".to_string()];
        
        let params = RegisterParams {
            hostname: hostname.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities,
        };
        
        if self.debug {
            log::debug!(" [REGISTRATION] Queuing registration: hostname={}, version={}, capabilities={:?}", 
                params.hostname, params.version, params.capabilities);
        }
        
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "client.register".to_string(),
            params: Some(serde_json::to_value(&params)?),
            id: Some(serde_json::Value::Number(1.into())),
        };
        
        outbound_tx.send(OutboundMessage::Request(request))
            .await
            .map_err(|_| VoltronError::Protocol("Failed to queue registration - channel closed".to_string()))?;
        
        if self.debug {
            log::debug!(" [REGISTRATION] Registration queued successfully (fire-and-forget, no response expected)");
        }
        
        Ok(())
    }

    async fn writer_task(
        mut write_half: WriteHalf<TcpStream>,
        mut outbound_rx: mpsc::Receiver<OutboundMessage>,
        channel: Option<crate::voltron::encrypted_channel::EncryptedChannel>,
        debug: bool,
    ) {
        if debug {
            log::debug!(" [WRITER] Task starting, waiting for outbound messages...");
        }
        
        let mut message_count = 0u64;
        
        while let Some(msg) = outbound_rx.recv().await {
            message_count += 1;
            
            match msg {
                OutboundMessage::Request(request) => {
                    if debug {
                        log::debug!(" [WRITER] Received outbound request #{}: method={}, id={:?}", 
                            message_count, request.method, request.id);
                    }
                    
                    let result = if let Some(ref ch) = channel {
                        let bytes = match serde_json::to_vec(&request) {
                            Ok(b) => b,
                            Err(e) => {
                                log::error!(" [WRITER] Failed to serialize request: {}", e);
                                continue;
                            }
                        };
                        
                        if debug {
                            log::debug!(" [WRITER] Encrypting and sending {} bytes for method={}", bytes.len(), request.method);
                        }
                        
                        ch.send(&mut write_half, &bytes).await
                    } else {
                        if debug {
                            log::debug!(" [WRITER] Sending plaintext request for method={}", request.method);
                        }
                        write_request(&mut write_half, &request).await
                    };
                    
                    if let Err(e) = result {
                        log::error!(" [WRITER] Failed to send request: {}", e);
                        break;
                    }
                    
                    if debug {
                        log::debug!(" [WRITER] Request sent successfully (method={})", request.method);
                    }
                },
                OutboundMessage::Shutdown => {
                    if debug {
                        log::debug!(" [WRITER] Received shutdown signal, exiting...");
                    }
                    break;
                }
            }
        }
        
        if debug {
            log::debug!(" [WRITER] Task exiting (sent {} messages total)", message_count);
        }
    }

    async fn reader_task(
        mut read_half: ReadHalf<TcpStream>,
        channel: Option<crate::voltron::encrypted_channel::EncryptedChannel>,
        outbound_tx: mpsc::Sender<OutboundMessage>,
        running_techniques: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
        debug: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        if debug {
            log::debug!(" [READER] Task starting, listening for server commands...");
        }
        
        let mut message_count = 0u64;
        
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        if debug {
                            log::debug!(" [READER] Received shutdown signal, exiting...");
                        }
                        break;
                    }
                }
                result = Self::read_message(&mut read_half, &channel, debug) => {
                    message_count += 1;
                    
                    match result {
                        Ok(request) => {
                            if debug {
                                log::debug!(" [READER] Received message #{}: method={}", message_count, request.method);
                            }
                            
                            if let Err(e) = Self::handle_request(request, &outbound_tx, &running_techniques, debug).await {
                                log::error!(" [READER] Failed to handle request: {}", e);
                            }
                        },
                        Err(e) => {
                            log::error!(" [READER] Connection error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        
        if debug {
            log::debug!(" [READER] Task exiting (received {} messages total)", message_count);
        }
    }

    async fn read_message(
        read_half: &mut ReadHalf<TcpStream>,
        channel: &Option<crate::voltron::encrypted_channel::EncryptedChannel>,
        debug: bool,
    ) -> Result<JsonRpcRequest, VoltronError> {
        if let Some(ref ch) = channel {
            let plaintext = ch.recv(read_half).await?;
            if debug {
                log::debug!(" Received {} bytes (decrypted)", plaintext.len());
            }
            let request: JsonRpcRequest = serde_json::from_slice(&plaintext)?;
            if debug {
                log::debug!(" Parsed request: method={}, id={:?}", request.method, request.id);
            }
            Ok(request)
        } else {
            read_request(read_half).await
        }
    }

    async fn handle_request(
        request: JsonRpcRequest,
        outbound_tx: &mpsc::Sender<OutboundMessage>,
        running_techniques: &Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
        debug: bool,
    ) -> Result<(), VoltronError> {
        match request.method.as_str() {
            "technique.execute" => {
                let params: ExecuteTechniqueParams = match request.params.as_ref() {
                    Some(p) => serde_json::from_value(p.clone())?,
                    None => return Err(VoltronError::Protocol("Missing params".to_string())),
                };
                
                if debug {
                    log::debug!(" Execute request: technique={}, role={:?}", params.technique, params.role);
                }
                
                let technique_id = params.technique_id.clone();
                let tx = outbound_tx.clone();
                let tech = running_techniques.clone();
                
                let task = tokio::spawn(async move {
                    if let Err(e) = Self::execute_technique(params, tx, debug).await {
                        log::error!(" Technique execution error: {}", e);
                    }
                });
                
                tech.lock().await.insert(technique_id, task);
                
                let response = JsonRpcResponse::success(
                    serde_json::json!({"status": "started"}),
                    request.id,
                );
                outbound_tx.send(OutboundMessage::Request(JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    method: "technique.ack".to_string(),
                    params: Some(serde_json::to_value(&response)?),
                    id: None,
                })).await.ok();
            },
            "technique.cleanup" => {
                if debug {
                    log::debug!(" Cleanup request received");
                }
                let response = JsonRpcResponse::success(
                    serde_json::json!({"status": "ok"}),
                    request.id,
                );
                outbound_tx.send(OutboundMessage::Request(JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    method: "cleanup.response".to_string(),
                    params: Some(serde_json::to_value(&response)?),
                    id: None,
                })).await.ok();
            },
            "execute_technique" => {
                let params: serde_json::Value = match request.params.as_ref() {
                    Some(p) => p.clone(),
                    None => return Err(VoltronError::Protocol("Missing params".to_string())),
                };
                
                let technique_id = params.get("technique_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| VoltronError::Protocol("Missing technique_id".to_string()))?
                    .to_string();
                
                let technique = params.get("technique")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| VoltronError::Protocol("Missing technique".to_string()))?
                    .to_string();
                
                let role_str = params.get("role")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| VoltronError::Protocol("Missing role".to_string()))?;
                
                let role = match role_str {
                    "attacker" => Role::Attacker,
                    "victim" => Role::Victim,
                    _ => return Err(VoltronError::Protocol(format!("Invalid role: {}", role_str))),
                };
                
                let victim_ip = params.get("victim_ip").and_then(|v| v.as_str()).map(|s| s.to_string());
                let technique_params = params.get("params").cloned().unwrap_or(serde_json::json!({}));
                let group_id = params.get("group_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                
                if debug {
                    log::debug!(" [EXECUTOR] Received execute_technique: id={}, technique={}, role={:?}", technique_id, technique, role);
                }
                
                let execute_params = ExecuteTechniqueParams {
                    technique_id: technique_id.clone(),
                    technique: technique.clone(),
                    role,
                    target_info: victim_ip.map(|ip| {
                        let hostname = ip.clone();
                        TargetInfo {
                            hostname,
                            ip,
                            port: None,
                        }
                    }),
                    params: technique_params,
                    group_id,
                    target_peers: vec![],
                };
                
                let tx = outbound_tx.clone();
                let tech = running_techniques.clone();
                let technique_id_clone = technique_id.clone();
                
                let task = tokio::spawn(async move {
                    if debug {
                        log::debug!(" [EXECUTOR] Starting technique execution: {}", technique_id_clone);
                    }
                    if let Err(e) = Self::execute_technique(execute_params, tx, debug).await {
                        log::error!(" [EXECUTOR] Technique execution error: {}", e);
                    }
                    if debug {
                        log::debug!(" [EXECUTOR] Technique execution completed: {}", technique_id_clone);
                    }
                });
                
                tech.lock().await.insert(technique_id.clone(), task);
                
                if debug {
                    log::debug!(" [EXECUTOR] Technique task spawned: {}", technique_id);
                }
            },
            "technique.abort" | "abort_technique" => {
                let technique_id: String = match request.params.as_ref()
                    .and_then(|p| p.get("technique_id"))
                    .and_then(|v| v.as_str()) {
                    Some(id) => id.to_string(),
                    None => return Err(VoltronError::Protocol("Missing technique_id".to_string())),
                };
                
                log::warn!(" Abort requested for technique: {}", technique_id);
                
                let mut tech = running_techniques.lock().await;
                if let Some(handle) = tech.remove(&technique_id) {
                    handle.abort();
                    log::info!(" Technique {} aborted", technique_id);
                    
                    let abort_params = TechniqueResultParams {
                        technique_id: technique_id.clone(),
                        status: ExecutionStatus::Aborted,
                        artifacts: vec![],
                        telemetry: serde_json::json!({}),
                        error: Some("Aborted by server request".to_string()),
                    };
                    
                    outbound_tx.send(OutboundMessage::Request(JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        method: "technique.result".to_string(),
                        params: Some(serde_json::to_value(&abort_params)?),
                        id: None,
                    })).await.ok();
                }
            },
            _ => {
                if debug {
                    log::debug!(" Unknown method: {}", request.method);
                }
            }
        }
        
        Ok(())
    }

    async fn execute_technique(
        params: ExecuteTechniqueParams,
        outbound_tx: mpsc::Sender<OutboundMessage>,
        debug: bool,
    ) -> Result<(), VoltronError> {
        if debug {
            log::debug!(" Executing technique: {}", params.technique);
        }
        
        let mut technique_params: HashMap<String, String> = serde_json::from_value(params.params.clone()).unwrap_or_default();
        
        technique_params.insert("__voltron_role".to_string(), format!("{:?}", params.role));
        
        if let Some(ref target) = params.target_info {
            technique_params.insert("__voltron_target_ip".to_string(), target.ip.clone());
            if let Some(port) = target.port {
                technique_params.insert("__voltron_target_port".to_string(), port.to_string());
            }
        }
        
        if debug {
            log::debug!(" Full parameter set for technique {}:", params.technique);
            for (key, value) in &technique_params {
                log::debug!("   {}={}", key, value);
            }
        }
        
        let result = runner::run_technique_with_params(&params.technique, technique_params, false, false).await;
        
        let (status, artifacts, telemetry, error) = match result {
            Ok(_) => {
                (ExecutionStatus::Success, vec![], serde_json::json!({}), None)
            },
            Err(e) => {
                (ExecutionStatus::Failed, vec![], serde_json::json!({}), Some(e))
            },
        };
        
        let result_params = TechniqueResultParams {
            technique_id: params.technique_id,
            status,
            artifacts,
            telemetry,
            error,
        };
        
        outbound_tx.send(OutboundMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "technique.result".to_string(),
            params: Some(serde_json::to_value(&result_params)?),
            id: None,
        })).await.ok();
        
        Ok(())
    }

    async fn heartbeat_task(
        hostname: String,
        outbound_tx: mpsc::Sender<OutboundMessage>,
        debug: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        if debug {
            log::debug!(" [HEARTBEAT] Task starting for hostname={} (interval={}s)", hostname, HEARTBEAT_INTERVAL_SECS);
        }
        
        let mut sequence = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        if debug {
            log::debug!(" [HEARTBEAT] Consuming initial tick...");
        }
        
        interval.tick().await;
        
        if debug {
            log::debug!(" [HEARTBEAT] Initial tick consumed, entering heartbeat loop");
        }
        
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        if debug {
                            log::debug!(" [HEARTBEAT] Received shutdown signal, exiting...");
                        }
                        break;
                    }
                }
                _ = interval.tick() => {
                    sequence += 1;
                    
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    
                    let params = HeartbeatParams {
                        hostname: hostname.clone(),
                        sequence,
                        timestamp: now,
                        status: ClientStatus::Ready,
                        running_techniques: vec![],
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    };
                    
                    if debug {
                        log::debug!(" [HEARTBEAT] Interval tick #{}, queuing heartbeat: seq={}, timestamp={}, status={:?}", 
                            sequence, sequence, now, params.status);
                    }
                    
                    let request = JsonRpcRequest {
                        jsonrpc: "2.0".to_string(),
                        method: "client.heartbeat".to_string(),
                        params: serde_json::to_value(&params).ok(),
                        id: None,
                    };
                    
                    if debug {
                        log::debug!(" [HEARTBEAT] Sending to outbound channel...");
                    }
                    
                    if outbound_tx.send(OutboundMessage::Request(request)).await.is_err() {
                        log::error!(" [HEARTBEAT] Failed to send - outbound channel closed");
                        break;
                    }
                    
                    if debug {
                        log::debug!(" [HEARTBEAT] Queued successfully (seq={})", sequence);
                    }
                }
            }
        }
        
        if debug {
            log::debug!(" [HEARTBEAT] Task exiting (sent {} heartbeats total)", sequence);
        }
    }

    pub async fn run(&mut self) -> Result<(), VoltronError> {
        log::info!(" Voltron client running. Listening for server commands...");
        log::info!(" Press Ctrl+C to stop.");
        
        let tasks = std::mem::take(&mut self.tasks);
        let _ = futures::future::join_all(tasks).await;
        
        Ok(())
    }
    
    pub async fn run_with_reconnect(&mut self) -> Result<(), VoltronError> {
        const MAX_BACKOFF_SECS: u64 = 30;
        const INITIAL_BACKOFF_SECS: u64 = 1;
        
        let mut backoff_secs = INITIAL_BACKOFF_SECS;
        
        loop {
            match self.connect().await {
                Ok(_) => {
                    log::info!(" Connected successfully");
                    backoff_secs = INITIAL_BACKOFF_SECS;
                    
                    if let Err(e) = self.run().await {
                        log::error!(" Client error: {}", e);
                    }
                    
                    log::info!(" Attempting reconnection in {} seconds...", backoff_secs);
                },
                Err(e) => {
                    log::error!(" Connection failed: {}", e);
                    log::info!(" Retrying in {} seconds...", backoff_secs);
                }
            }
            
            tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
            backoff_secs = std::cmp::min(backoff_secs * 2, MAX_BACKOFF_SECS);
            
            self.outbound_tx = None;
            self.shutdown_tx = None;
            self.tasks.clear();
        }
    }

    #[allow(dead_code)]
    pub async fn stop(&mut self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
        
        if let Some(tx) = &self.outbound_tx {
            let _ = tx.send(OutboundMessage::Shutdown).await;
        }
        
        for task in &mut self.tasks {
            task.abort();
        }
        
        self.running_techniques.lock().await.clear();
    }
}

impl Drop for VoltronClient {
    fn drop(&mut self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
    }
}
