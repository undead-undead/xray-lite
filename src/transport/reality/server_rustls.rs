use anyhow::{anyhow, Result};
/// Reality server implementation using rustls-reality
///
/// This is a simplified version for testing Reality authentication injection.
/// Full implementation will be completed in Phase 5.
use std::sync::Arc;
use tracing::{debug, info};

use rustls::reality::RealityConfig;

pub struct RealityServerRustls {
    reality_config: Arc<RealityConfig>,
}

impl RealityServerRustls {
    /// Create a new Reality server with rustls
    ///
    /// # Arguments
    /// * `private_key` - Reality private key (32 bytes)
    /// * `dest` - Destination server for fallback (e.g., "www.example.com:443")
    pub fn new(private_key: Vec<u8>, dest: Option<String>) -> Result<Self> {
        // Create Reality configuration
        let reality_config = RealityConfig::new(private_key)
            .with_verify_client(false) // Disable for now, will enable in Phase 4b
            .with_dest(dest.unwrap_or_else(|| "www.microsoft.com:443".to_string()));

        reality_config.validate()?;

        Ok(Self {
            reality_config: Arc::new(reality_config),
        })
    }

    /// Get the Reality configuration
    pub fn config(&self) -> &Arc<RealityConfig> {
        &self.reality_config
    }

    /// Test Reality authentication injection
    ///
    /// This function demonstrates how Reality auth is injected into ServerHello.random
    pub fn test_inject_auth(
        &self,
        server_random: &mut [u8; 32],
        client_random: &[u8; 32],
    ) -> Result<()> {
        rustls::reality::inject_auth(server_random, &self.reality_config, client_random)
            .map_err(|e| anyhow!("Failed to inject Reality auth: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_server_creation() {
        let private_key = vec![42u8; 32];
        let server = RealityServerRustls::new(private_key, None);
        assert!(server.is_ok());
    }

    #[test]
    fn test_reality_server_invalid_key() {
        let private_key = vec![42u8; 16]; // Wrong length
        let server = RealityServerRustls::new(private_key, None);
        assert!(server.is_err());
    }

    #[test]
    fn test_inject_auth() {
        let private_key = vec![42u8; 32];
        let server = RealityServerRustls::new(private_key, None).unwrap();

        let mut server_random = [0u8; 32];
        for (i, byte) in server_random.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let client_random = [99u8; 32];

        let original_prefix = server_random[0..20].to_vec();

        let result = server.test_inject_auth(&mut server_random, &client_random);
        assert!(result.is_ok());

        // First 20 bytes should remain unchanged
        assert_eq!(&server_random[0..20], &original_prefix[..]);

        // Last 12 bytes should be modified
        assert_ne!(
            &server_random[20..32],
            &[20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
        );
    }
}
