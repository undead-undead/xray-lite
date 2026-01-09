use hex;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn main() {
    // Inputs from the log
    // PrivateKey (AuthKey candidate)
    let auth_key = [0x22, 0x89, 0xf9, 0xf8];
    // Wait, the log only shows 4 bytes. I can't reconstruct the full key.

    // But I can check if the HMAC of [fd, cb, 44, 3d] + [6c, 08, 1b, 49]...
    // No, I need the full 32 bytes.
}
