use crate::voltron::{VoltronError, PreSharedKey};
use rand::Rng;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SALT_SIZE: usize = 32;
const HMAC_SIZE: usize = 32;

/// Handshake protocol for PSK authentication
/// 
/// Protocol flow:
/// 1. Client generates random salt (32 bytes)
/// 2. Client sends salt to server
/// 3. Server computes HMAC-SHA256(salt, psk) and sends to client
/// 4. Client verifies HMAC matches expected value
/// 5. Both derive session key using HKDF-SHA256(psk, salt)
pub struct Handshake {
    psk: PreSharedKey,
    debug: bool,
}

impl Handshake {
    pub fn new(psk: PreSharedKey, debug: bool) -> Self {
        Handshake { psk, debug }
    }
    
    /// Client-side handshake: initiate challenge/response (async)
    pub async fn client_handshake<S>(&self, stream: &mut S) -> Result<[u8; 32], VoltronError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if self.debug {
            log::debug!(" Client handshake starting...");
        }
        
        // Generate random salt
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_SIZE];
        rng.fill(&mut salt);
        
        if self.debug {
            log::debug!(" Generated salt: {}", hex::encode(&salt));
        }
        
        // Send salt to server
        stream.write_all(&salt)
            .await
            .map_err(VoltronError::Io)?;
        
        if self.debug {
            log::debug!(" Sent salt to server");
        }
        
        // Compute expected HMAC
        let expected_hmac = compute_hmac(&salt, self.psk.secret_bytes());
        
        if self.debug {
            log::debug!(" Expected HMAC: {}", hex::encode(&expected_hmac));
        }
        
        // Receive server's HMAC response
        let mut server_hmac = [0u8; HMAC_SIZE];
        stream.read_exact(&mut server_hmac)
            .await
            .map_err(VoltronError::Io)?;
        
        if self.debug {
            log::debug!(" Received server HMAC: {}", hex::encode(&server_hmac));
        }
        
        // Verify HMAC matches
        if server_hmac != expected_hmac {
            if self.debug {
                log::debug!(" HMAC verification FAILED!");
            }
            return Err(VoltronError::AuthenticationFailed(
                "Server HMAC verification failed - incorrect PSK".to_string()
            ));
        }
        
        if self.debug {
            log::debug!(" HMAC verification SUCCESS");
        }
        
        // Derive session key using HKDF
        let session_key = derive_session_key(self.psk.secret_bytes(), &salt);
        
        if self.debug {
            log::debug!(" Session key derived: {}", hex::encode(&session_key));
            log::debug!(" Client handshake completed successfully");
        }
        
        Ok(session_key)
    }
    
    /// Server-side handshake: respond to challenge (async)
    pub async fn server_handshake<S>(&self, stream: &mut S) -> Result<[u8; 32], VoltronError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if self.debug {
            log::debug!(" Server handshake starting...");
        }
        
        // Receive salt from client
        let mut salt = [0u8; SALT_SIZE];
        stream.read_exact(&mut salt)
            .await
            .map_err(VoltronError::Io)?;
        
        if self.debug {
            log::debug!(" Received salt from client: {}", hex::encode(&salt));
        }
        
        // Compute HMAC
        let hmac = compute_hmac(&salt, self.psk.secret_bytes());
        
        if self.debug {
            log::debug!(" Computed HMAC: {}", hex::encode(&hmac));
        }
        
        // Send HMAC to client
        stream.write_all(&hmac)
            .await
            .map_err(VoltronError::Io)?;
        
        if self.debug {
            log::debug!(" Sent HMAC to client");
        }
        
        // Derive session key using HKDF
        let session_key = derive_session_key(self.psk.secret_bytes(), &salt);
        
        if self.debug {
            log::debug!(" Session key derived: {}", hex::encode(&session_key));
            log::debug!(" Server handshake completed successfully");
        }
        
        Ok(session_key)
    }
}

/// Compute HMAC-SHA256(message, key)
fn compute_hmac(message: &[u8], key: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

/// Derive session key using HKDF-SHA256
fn derive_session_key(psk: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), psk);
    let mut session_key = [0u8; 32];
    hkdf.expand(b"voltron-session-key", &mut session_key)
        .expect("32 bytes is valid HKDF output length");
    
    session_key
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_successful_handshake() {
        let psk = PreSharedKey::generate();
        
        // Simulate bidirectional stream using tokio duplex
        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);
        
        let psk_clone = psk.clone();
        
        // Spawn server task
        let server_task = tokio::spawn(async move {
            let server_hs = Handshake::new(psk_clone, false);
            server_hs.server_handshake(&mut server_stream).await
        });
        
        // Run client handshake
        let client_hs = Handshake::new(psk, false);
        let client_key = client_hs.client_handshake(&mut client_stream).await.unwrap();
        
        // Wait for server handshake
        let server_key = server_task.await.unwrap().unwrap();
        
        // Both should derive same session key
        assert_eq!(client_key, server_key);
    }
    
    #[tokio::test]
    async fn test_wrong_psk_fails() {
        let client_psk = PreSharedKey::generate();
        let server_psk = PreSharedKey::generate();
        
        // Simulate bidirectional stream using tokio duplex
        let (mut client_stream, mut server_stream) = tokio::io::duplex(1024);
        
        // Spawn server task with different PSK
        let server_task = tokio::spawn(async move {
            let server_hs = Handshake::new(server_psk, false);
            server_hs.server_handshake(&mut server_stream).await
        });
        
        // Run client handshake
        let client_hs = Handshake::new(client_psk, false);
        let result = client_hs.client_handshake(&mut client_stream).await;
        
        // Client should fail authentication
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VoltronError::AuthenticationFailed(_)));
        
        // Server will complete but client rejected
        let _server_result = server_task.await;
    }
    
    #[test]
    fn test_hmac_computation() {
        let message = b"test message";
        let key = b"test key";
        
        let hmac1 = compute_hmac(message, key);
        let hmac2 = compute_hmac(message, key);
        
        // Same inputs should produce same HMAC
        assert_eq!(hmac1, hmac2);
        
        // Different message should produce different HMAC
        let hmac3 = compute_hmac(b"different message", key);
        assert_ne!(hmac1, hmac3);
    }
    
    #[test]
    fn test_session_key_derivation() {
        let psk = [42u8; 32];
        let salt = [99u8; 32];
        
        let key1 = derive_session_key(&psk, &salt);
        let key2 = derive_session_key(&psk, &salt);
        
        // Same inputs should produce same key
        assert_eq!(key1, key2);
        
        // Different salt should produce different key
        let salt2 = [100u8; 32];
        let key3 = derive_session_key(&psk, &salt2);
        assert_ne!(key1, key3);
    }
}
