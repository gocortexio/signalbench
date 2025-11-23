use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

pub const RPC_VERSION: &str = "2.0";

#[allow(dead_code)]
pub const METHOD_REGISTER: &str = "client.register";
#[allow(dead_code)]
pub const METHOD_HEARTBEAT: &str = "client.heartbeat";
#[allow(dead_code)]
pub const METHOD_EXECUTE_TECHNIQUE: &str = "technique.execute";
#[allow(dead_code)]
pub const METHOD_TECHNIQUE_RESULT: &str = "technique.result";
#[allow(dead_code)]
pub const METHOD_RUN_TECHNIQUE: &str = "technique.run";
#[allow(dead_code)]
pub const METHOD_CLEANUP: &str = "technique.cleanup";
#[allow(dead_code)]
pub const METHOD_CANCEL: &str = "technique.cancel";
#[allow(dead_code)]
pub const METHOD_PAUSE: &str = "server.pause";
#[allow(dead_code)]
pub const METHOD_RESUME: &str = "server.resume";
#[allow(dead_code)]
pub const METHOD_SHUTDOWN: &str = "server.shutdown";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterParams {
    pub hostname: String,
    pub version: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegisterResult {
    pub server_version: String,
    pub assigned_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatParams {
    pub hostname: String,
    pub sequence: u64,
    pub timestamp: i64,
    pub status: ClientStatus,
    pub running_techniques: Vec<String>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct HeartbeatResult {
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteTechniqueParams {
    pub technique_id: String,
    pub technique: String,
    pub role: Role,
    pub params: serde_json::Value,
    pub target_info: Option<TargetInfo>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub target_peers: Vec<TargetInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueResultParams {
    pub technique_id: String,
    pub status: ExecutionStatus,
    pub artifacts: Vec<String>,
    pub telemetry: serde_json::Value,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CleanupParams {
    pub technique_id: String,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CleanupResult {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTechniqueParams {
    pub technique: String,
    pub attacker: String,
    pub victim: Option<String>,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunTechniqueResult {
    pub technique_id: String,
    pub group_id: String,
    pub status: String,
    pub attacker_result: Option<TechniqueResultParams>,
    pub victim_result: Option<TechniqueResultParams>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientStatus {
    Ready,
    Busy,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Role {
    Attacker,
    Victim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub hostname: String,
    pub ip: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Success,
    Partial,
    Failed,
    Aborted,
}

#[derive(Debug, thiserror::Error)]
pub enum VoltronError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Message too large: {0} bytes (max 1MB)")]
    MessageTooLarge(usize),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[allow(dead_code)]
    #[error("Client not found: {0}")]
    ClientNotFound(String),
    #[error("Invalid JSON-RPC request: {0}")]
    InvalidJsonRpc(String),
    #[error("Certificate generation failed: {0}")]
    #[allow(dead_code)]
    CertificateGeneration(String),
    #[error("Invalid key file: {0}")]
    #[allow(dead_code)]
    InvalidKeyFile(String),
    #[error("Certificate parsing failed: {0}")]
    #[allow(dead_code)]
    CertificateParsing(String),
}

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

impl JsonRpcRequest {
    #[allow(dead_code)]
    pub fn new(method: &str, params: Option<serde_json::Value>, id: u64) -> Self {
        JsonRpcRequest {
            jsonrpc: RPC_VERSION.to_string(),
            method: method.to_string(),
            params,
            id: Some(serde_json::Value::Number(id.into())),
        }
    }

    #[allow(dead_code)]
    pub fn notification(method: &str, params: Option<serde_json::Value>) -> Self {
        JsonRpcRequest {
            jsonrpc: RPC_VERSION.to_string(),
            method: method.to_string(),
            params,
            id: None,
        }
    }
}

impl JsonRpcResponse {
    pub fn success(result: serde_json::Value, id: Option<serde_json::Value>) -> Self {
        JsonRpcResponse {
            jsonrpc: RPC_VERSION.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    #[allow(dead_code)]
    pub fn error(code: i32, message: String, id: Option<serde_json::Value>) -> Self {
        JsonRpcResponse {
            jsonrpc: RPC_VERSION.to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
            id,
        }
    }
}

pub async fn write_request<W>(writer: &mut W, req: &JsonRpcRequest) -> Result<(), VoltronError>
where
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_vec(req)?;
    
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(VoltronError::MessageTooLarge(json.len()));
    }
    
    let len = json.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    
    Ok(())
}

#[allow(dead_code)]
pub async fn write_response<W>(writer: &mut W, resp: &JsonRpcResponse) -> Result<(), VoltronError>
where
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_vec(resp)?;
    
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(VoltronError::MessageTooLarge(json.len()));
    }
    
    let len = json.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    
    Ok(())
}

pub async fn read_request<R>(reader: &mut R) -> Result<JsonRpcRequest, VoltronError>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    
    if len > MAX_MESSAGE_SIZE {
        return Err(VoltronError::MessageTooLarge(len));
    }
    
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await?;
    
    let req: JsonRpcRequest = serde_json::from_slice(&buffer)?;
    
    if req.jsonrpc != RPC_VERSION {
        return Err(VoltronError::InvalidJsonRpc(format!(
            "Invalid JSON-RPC version: expected '{}', got '{}'",
            RPC_VERSION, req.jsonrpc
        )));
    }
    
    if let Some(ref id) = req.id {
        if !id.is_string() && !id.is_number() && !id.is_null() {
            return Err(VoltronError::InvalidJsonRpc(
                "Request id must be string, number, or null".to_string()
            ));
        }
    }
    
    if let Some(ref params) = req.params {
        if !params.is_object() && !params.is_array() {
            return Err(VoltronError::InvalidJsonRpc(
                "Request params must be an object or array".to_string()
            ));
        }
    }
    
    Ok(req)
}

#[allow(dead_code)]
pub async fn read_response<R>(reader: &mut R) -> Result<JsonRpcResponse, VoltronError>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    
    if len > MAX_MESSAGE_SIZE {
        return Err(VoltronError::MessageTooLarge(len));
    }
    
    let mut buffer = vec![0u8; len];
    reader.read_exact(&mut buffer).await?;
    
    let resp: JsonRpcResponse = serde_json::from_slice(&buffer)?;
    
    if resp.jsonrpc != RPC_VERSION {
        return Err(VoltronError::InvalidJsonRpc(format!(
            "Invalid JSON-RPC version: expected '{}', got '{}'",
            RPC_VERSION, resp.jsonrpc
        )));
    }
    
    if let Some(ref id) = resp.id {
        if !id.is_string() && !id.is_number() && !id.is_null() {
            return Err(VoltronError::InvalidJsonRpc(
                "Response id must be string, number, or null".to_string()
            ));
        }
    }
    
    match (&resp.result, &resp.error) {
        (Some(_), Some(_)) => {
            return Err(VoltronError::InvalidJsonRpc(
                "Response cannot have both result and error".to_string()
            ));
        }
        (None, None) => {
            return Err(VoltronError::InvalidJsonRpc(
                "Response must have either result or error".to_string()
            ));
        }
        _ => {}
    }
    
    if resp.error.is_some() || resp.result.is_some() {
        if resp.id.is_none() {
            return Err(VoltronError::InvalidJsonRpc(
                "Response to request must include id field".to_string()
            ));
        }
    }
    
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_json_rpc_request_framing() {
        let params = serde_json::json!({
            "hostname": "test-host",
            "version": "1.6.0"
        });
        let req = JsonRpcRequest::new(METHOD_REGISTER, Some(params), 1);

        let mut buffer = Vec::new();
        write_request(&mut buffer, &req).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = read_request(&mut cursor).await.unwrap();

        assert_eq!(decoded.jsonrpc, "2.0");
        assert_eq!(decoded.method, METHOD_REGISTER);
        assert_eq!(decoded.id, Some(serde_json::Value::Number(1.into())));
    }
    
    #[tokio::test]
    async fn test_json_rpc_request_without_params() {
        let req = JsonRpcRequest::new(METHOD_HEARTBEAT, None, 2);

        let mut buffer = Vec::new();
        write_request(&mut buffer, &req).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = read_request(&mut cursor).await.unwrap();

        assert_eq!(decoded.jsonrpc, "2.0");
        assert_eq!(decoded.method, METHOD_HEARTBEAT);
        assert!(decoded.params.is_none());
    }
    
    #[tokio::test]
    async fn test_invalid_json_rpc_version_request() {
        let bad_json = r#"{"jsonrpc":"1.0","method":"test","id":1}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_request(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_invalid_json_rpc_version_response() {
        let bad_json = r#"{"jsonrpc":"1.0","result":true,"id":1}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_response(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_response_with_both_result_and_error() {
        let bad_json = r#"{"jsonrpc":"2.0","result":true,"error":{"code":-32600,"message":"err"},"id":1}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_response(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_response_with_neither_result_nor_error() {
        let bad_json = r#"{"jsonrpc":"2.0","id":1}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_response(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_message_too_large() {
        let huge_len = (2 * 1024 * 1024u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&huge_len);
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_request(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::MessageTooLarge(_)));
    }
    
    #[tokio::test]
    async fn test_invalid_request_id_array() {
        let bad_json = r#"{"jsonrpc":"2.0","method":"test","id":[1,2,3]}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_request(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_invalid_request_id_object() {
        let bad_json = r#"{"jsonrpc":"2.0","method":"test","id":{"foo":"bar"}}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_request(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_invalid_response_id_array() {
        let bad_json = r#"{"jsonrpc":"2.0","result":true,"id":[1,2,3]}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_response(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_invalid_params_string() {
        let bad_json = r#"{"jsonrpc":"2.0","method":"test","params":"invalid","id":1}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_request(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }
    
    #[tokio::test]
    async fn test_invalid_params_number() {
        let bad_json = r#"{"jsonrpc":"2.0","method":"test","params":42,"id":1}"#;
        let len = (bad_json.len() as u32).to_be_bytes();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&len);
        buffer.extend_from_slice(bad_json.as_bytes());
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result = read_request(&mut cursor).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::InvalidJsonRpc(_)));
    }

    #[tokio::test]
    async fn test_json_rpc_response_framing() {
        let result = serde_json::json!({"success": true});
        let resp = JsonRpcResponse::success(result, Some(serde_json::Value::Number(1.into())));

        let mut buffer = Vec::new();
        write_response(&mut buffer, &resp).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = read_response(&mut cursor).await.unwrap();

        assert_eq!(decoded.jsonrpc, "2.0");
        assert!(decoded.result.is_some());
        assert!(decoded.error.is_none());
    }

    #[test]
    fn test_json_rpc_error() {
        let resp = JsonRpcResponse::error(-32600, "Invalid Request".to_string(), Some(serde_json::Value::Number(1.into())));
        
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32600);
    }
}
