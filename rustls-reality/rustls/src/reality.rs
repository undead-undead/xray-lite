use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::Error;
use ring::hmac;

#[derive(Clone, Debug)]
pub struct RealityConfig {
    pub private_key: Vec<u8>,
    pub verify_client: bool,
    pub dest: Option<String>,
    pub short_ids: Vec<Vec<u8>>,
}

impl RealityConfig {
    pub fn new(private_key: Vec<u8>) -> Self {
        Self {
            private_key,
            verify_client: true,
            dest: None,
            short_ids: Vec::new(),
        }
    }
    pub fn with_verify_client(mut self, verify: bool) -> Self {
        self.verify_client = verify;
        self
    }
    pub fn with_dest(mut self, dest: String) -> Self {
        self.dest = Some(dest);
        self
    }
    pub fn with_short_ids(mut self, short_ids: Vec<Vec<u8>>) -> Self {
        self.short_ids = short_ids;
        self
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.private_key.len() != 32 {
            return Err(Error::General(
                "Reality private key must be 32 bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Inject Reality authentication into ServerHello.random
/// Standard Reality: HMAC-SHA256(Key=AuthKey, Msg=ServerHello.Random[0..20])
pub fn inject_auth(
    server_random: &mut [u8; 32],
    config: &RealityConfig,
    client_random: &[u8; 32],
) -> Result<(), Error> {
    config.validate()?;

    // The key is the session-specific AuthKey
    let key = hmac::Key::new(hmac::HMAC_SHA256, &config.private_key);

    // Xray-core Reality order: ServerRandomPrefix (20) + ClientRandom (32)
    let mut message = Vec::with_capacity(52);
    message.extend_from_slice(&server_random[0..20]);
    message.extend_from_slice(client_random);

    // HMAC-SHA256 SIGN
    let tag = hmac::sign(&key, &message);

    // Inject first 12 bytes of HMAC into server_random[20..32]
    server_random[20..32].copy_from_slice(&tag.as_ref()[0..12]);

    Ok(())
}

pub fn verify_client(session_id: &[u8], client_random: &[u8; 32], config: &RealityConfig) -> bool {
    if session_id.len() < 8 || config.private_key.len() != 32 {
        return false;
    }

    // The key is the session-specific AuthKey
    let key = hmac::Key::new(hmac::HMAC_SHA256, &config.private_key);

    // Reality client auth: HMAC-SHA256(Key=AuthKey, Msg=ClientRandom)
    let tag = hmac::sign(&key, client_random);

    // Constant-time comparison of the first 8 bytes
    use subtle::ConstantTimeEq;
    tag.as_ref()[..8]
        .ct_eq(&session_id[..8])
        .into()
}
