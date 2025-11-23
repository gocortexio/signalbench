use crate::voltron::VoltronError;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Pre-shared key for Voltron Mode encryption
/// Uses 32-byte (256-bit) symmetric key for ChaCha20-Poly1305
#[derive(Clone)]
pub struct PreSharedKey {
    secret: [u8; 32],
}

impl PreSharedKey {
    /// Generate a new random pre-shared key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        
        PreSharedKey { secret }
    }
    
    /// Load pre-shared key from hex-encoded file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, VoltronError> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(VoltronError::Io)?;
        
        // Remove whitespace and newlines
        let hex_str = content.trim().replace("\n", "").replace(" ", "");
        
        // Decode hex string
        let bytes = hex::decode(&hex_str)
            .map_err(|e| VoltronError::Protocol(format!("Invalid hex in PSK file: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(VoltronError::Protocol(format!(
                "PSK must be exactly 32 bytes, got {}", bytes.len()
            )));
        }
        
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        
        Ok(PreSharedKey { secret })
    }
    
    /// Save pre-shared key to hex-encoded file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), VoltronError> {
        let hex_str = hex::encode(&self.secret);
        
        fs::write(path.as_ref(), hex_str.as_bytes())
            .map_err(VoltronError::Io)?;
        
        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path.as_ref())
                .map_err(VoltronError::Io)?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path.as_ref(), perms)
                .map_err(VoltronError::Io)?;
        }
        
        Ok(())
    }
    
    /// Get the raw secret bytes (for cryptographic operations)
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
    
    /// Compute SHA-256 fingerprint of the PSK for verification/display
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.secret);
        let result = hasher.finalize();
        hex::encode(result)
    }
    
    /// Verify that two PSKs match by comparing fingerprints
    #[allow(dead_code)]
    pub fn matches(&self, other: &PreSharedKey) -> bool {
        self.secret == other.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_generate_psk() {
        let psk1 = PreSharedKey::generate();
        let psk2 = PreSharedKey::generate();
        
        // Two random PSKs should be different
        assert!(!psk1.matches(&psk2));
    }
    
    #[test]
    fn test_save_and_load() {
        let psk = PreSharedKey::generate();
        let temp_file = NamedTempFile::new().unwrap();
        
        // Save PSK
        psk.save_to_file(temp_file.path()).unwrap();
        
        // Load PSK
        let loaded_psk = PreSharedKey::load_from_file(temp_file.path()).unwrap();
        
        // Should match
        assert!(psk.matches(&loaded_psk));
    }
    
    #[test]
    fn test_fingerprint() {
        let psk = PreSharedKey::generate();
        let fp1 = psk.fingerprint();
        let fp2 = psk.fingerprint();
        
        // Fingerprint should be deterministic
        assert_eq!(fp1, fp2);
        
        // Should be 64 hex characters (32 bytes * 2)
        assert_eq!(fp1.len(), 64);
    }
    
    #[test]
    fn test_invalid_hex() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), "not_valid_hex").unwrap();
        
        let result = PreSharedKey::load_from_file(temp_file.path());
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_length() {
        let temp_file = NamedTempFile::new().unwrap();
        // Only 16 bytes instead of 32
        let short_hex = hex::encode(&[0u8; 16]);
        fs::write(temp_file.path(), short_hex).unwrap();
        
        let result = PreSharedKey::load_from_file(temp_file.path());
        assert!(result.is_err());
    }
}
