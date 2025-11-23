use crate::voltron::VoltronError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NONCE_SIZE: usize = 12; // ChaCha20-Poly1305 nonce size
const TAG_SIZE: usize = 16;    // Authentication tag size

/// Encrypted channel wrapper for JSON-RPC communication
/// Uses ChaCha20-Poly1305 AEAD for confidentiality and integrity
/// 
/// Wire format: [length: u32][nonce: 12 bytes][encrypted_payload + tag]
pub struct EncryptedChannel {
    cipher: ChaCha20Poly1305,
    send_counter: AtomicU64,
    recv_counter: AtomicU64,
    debug: bool,
}

impl Clone for EncryptedChannel {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            send_counter: AtomicU64::new(self.send_counter.load(Ordering::SeqCst)),
            recv_counter: AtomicU64::new(self.recv_counter.load(Ordering::SeqCst)),
            debug: self.debug,
        }
    }
}

impl EncryptedChannel {
    /// Create new encrypted channel from session key
    pub fn new(session_key: &[u8; 32], debug: bool) -> Self {
        let cipher = ChaCha20Poly1305::new(session_key.into());
        
        if debug {
            log::debug!(" EncryptedChannel initialised");
        }
        
        EncryptedChannel {
            cipher,
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            debug,
        }
    }
    
    /// Encrypt and send message (async)
    pub async fn send<W>(&self, stream: &mut W, plaintext: &[u8]) -> Result<(), VoltronError>
    where
        W: AsyncWriteExt + Unpin,
    {
        // Get monotonic nonce
        let counter = self.send_counter.fetch_add(1, Ordering::SeqCst);
        let nonce = counter_to_nonce(counter);
        
        if self.debug {
            log::debug!(" Encrypting message: {} bytes, counter: {}", plaintext.len(), counter);
            log::debug!(" Nonce: {}", hex::encode(&nonce));
        }
        
        // Encrypt plaintext
        let ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| VoltronError::Protocol(format!("Encryption failed: {}", e)))?;
        
        if self.debug {
            log::debug!(" Ciphertext: {} bytes (includes {} byte tag)", 
                ciphertext.len(), TAG_SIZE);
        }
        
        // Wire format: [length: u32][nonce: 12 bytes][ciphertext + tag]
        let total_len = (NONCE_SIZE + ciphertext.len()) as u32;
        
        stream.write_all(&total_len.to_be_bytes())
            .await
            .map_err(VoltronError::Io)?;
        stream.write_all(&nonce)
            .await
            .map_err(VoltronError::Io)?;
        stream.write_all(&ciphertext)
            .await
            .map_err(VoltronError::Io)?;
        stream.flush()
            .await
            .map_err(VoltronError::Io)?;
        
        if self.debug {
            log::debug!(" Sent encrypted message: {} total bytes", 
                4 + NONCE_SIZE + ciphertext.len());
        }
        
        Ok(())
    }
    
    /// Receive and decrypt message (async)
    pub async fn recv<R>(&self, stream: &mut R) -> Result<Vec<u8>, VoltronError>
    where
        R: AsyncReadExt + Unpin,
    {
        // Read length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)
            .await
            .map_err(VoltronError::Io)?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        
        if self.debug {
            log::debug!(" Receiving encrypted message: {} bytes", total_len);
        }
        
        if total_len < NONCE_SIZE + TAG_SIZE {
            return Err(VoltronError::Protocol(format!(
                "Invalid message length: {}", total_len
            )));
        }
        
        // Read nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        stream.read_exact(&mut nonce_bytes)
            .await
            .map_err(VoltronError::Io)?;
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        if self.debug {
            log::debug!(" Nonce: {}", hex::encode(&nonce_bytes));
        }
        
        // Read ciphertext
        let ciphertext_len = total_len - NONCE_SIZE;
        let mut ciphertext = vec![0u8; ciphertext_len];
        stream.read_exact(&mut ciphertext)
            .await
            .map_err(VoltronError::Io)?;
        
        if self.debug {
            log::debug!(" Ciphertext: {} bytes", ciphertext.len());
        }
        
        // Decrypt and verify
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| VoltronError::Protocol(format!("Decryption failed: {}", e)))?;
        
        let counter = self.recv_counter.fetch_add(1, Ordering::SeqCst);
        
        if self.debug {
            log::debug!(" Decrypted {} bytes, counter: {}", plaintext.len(), counter);
        }
        
        Ok(plaintext)
    }
}

/// Convert counter to nonce (12 bytes, big-endian)
fn counter_to_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    // Put counter in last 8 bytes (big-endian)
    nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
    #[allow(deprecated)]
    {
        *Nonce::from_slice(&nonce_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let session_key = [42u8; 32];
        let channel = EncryptedChannel::new(&session_key, false);
        
        let plaintext = b"Hello, Voltron!";
        let mut buffer = Vec::new();
        
        // Encrypt
        channel.send(&mut buffer, plaintext).await.unwrap();
        
        // Decrypt
        let mut cursor = std::io::Cursor::new(buffer);
        let decrypted = channel.recv(&mut cursor).await.unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[tokio::test]
    async fn test_multiple_messages() {
        let session_key = [99u8; 32];
        let channel = EncryptedChannel::new(&session_key, false);
        
        let messages = vec![
            b"Message 1".to_vec(),
            b"Message 2 is longer".to_vec(),
            b"3".to_vec(),
        ];
        
        let mut buffer = Vec::new();
        
        // Encrypt all messages
        for msg in &messages {
            channel.send(&mut buffer, msg).await.unwrap();
        }
        
        // Decrypt all messages
        let mut cursor = std::io::Cursor::new(buffer);
        for expected in &messages {
            let decrypted = channel.recv(&mut cursor).await.unwrap();
            assert_eq!(expected, &decrypted);
        }
    }
    
    #[test]
    fn test_nonce_monotonicity() {
        let counter1 = 0u64;
        let counter2 = 1u64;
        let counter3 = u64::MAX;
        
        let nonce1 = counter_to_nonce(counter1);
        let nonce2 = counter_to_nonce(counter2);
        let nonce3 = counter_to_nonce(counter3);
        
        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
    }
    
    #[tokio::test]
    async fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        
        let channel1 = EncryptedChannel::new(&key1, false);
        let channel2 = EncryptedChannel::new(&key2, false);
        
        let plaintext = b"Secret message";
        let mut buffer = Vec::new();
        
        // Encrypt with key1
        channel1.send(&mut buffer, plaintext).await.unwrap();
        
        // Try to decrypt with key2 (should fail)
        let mut cursor = std::io::Cursor::new(buffer);
        let result = channel2.recv(&mut cursor).await;
        
        assert!(result.is_err());
    }
}
