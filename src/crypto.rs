use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Generate a new Ed25519 keypair.
/// Returns (signing_key, raw 32-byte public key).
pub fn generate_keypair() -> (SigningKey, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let pub_bytes = signing_key.verifying_key().to_bytes();
    (signing_key, pub_bytes)
}

/// Load a keypair from a hex-encoded 32-byte Ed25519 private seed.
pub fn load_keypair(hex_seed: &str) -> Result<(SigningKey, [u8; 32]), crate::Error> {
    let seed_bytes = hex::decode(hex_seed).map_err(|_| crate::Error::InvalidKey("invalid hex"))?;
    if seed_bytes.len() != 32 {
        return Err(crate::Error::InvalidKey("seed must be 32 bytes"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let signing_key = SigningKey::from_bytes(&seed);
    let pub_bytes = signing_key.verifying_key().to_bytes();
    Ok((signing_key, pub_bytes))
}

/// Convert an Ed25519 private key to an X25519 static secret.
/// Process: SHA-512 the 32-byte seed, clamp per RFC 7748, take first 32 bytes.
pub fn ed25519_private_to_x25519(signing_key: &SigningKey) -> X25519Secret {
    let seed = signing_key.to_bytes();
    let hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // Clamp per RFC 7748
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    X25519Secret::from(scalar)
}

/// Convert an Ed25519 public key to an X25519 public key.
/// Uses the birational map from Edwards to Montgomery coordinates.
pub fn ed25519_public_to_x25519(ed_pub: &[u8; 32]) -> Result<X25519Public, crate::Error> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let point = compressed
        .decompress()
        .ok_or(crate::Error::InvalidKey("invalid Ed25519 public key"))?;
    let montgomery = point.to_montgomery();
    Ok(X25519Public::from(montgomery.to_bytes()))
}

/// Perform X25519 Diffie-Hellman.
pub fn x25519(secret: &X25519Secret, public: &X25519Public) -> [u8; 32] {
    secret.diffie_hellman(public).to_bytes()
}

/// Convert an Ed25519 VerifyingKey to X25519 public key bytes.
pub fn verifying_key_to_x25519(vk: &VerifyingKey) -> Result<X25519Public, crate::Error> {
    ed25519_public_to_x25519(&vk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (key, pub_bytes) = generate_keypair();
        assert_eq!(pub_bytes.len(), 32);
        assert_eq!(key.verifying_key().to_bytes(), pub_bytes);
    }

    #[test]
    fn test_load_keypair() {
        let (key1, pub1) = generate_keypair();
        let hex_seed = hex::encode(key1.to_bytes());
        let (key2, pub2) = load_keypair(&hex_seed).unwrap();
        assert_eq!(pub1, pub2);
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_load_keypair_invalid() {
        assert!(load_keypair("not_hex").is_err());
        assert!(load_keypair("aabb").is_err()); // too short
    }

    #[test]
    fn test_dh_shared_secret() {
        // Client and server should derive the same shared secret
        let (server_sign, server_pub) = generate_keypair();
        let (client_sign, _client_pub) = generate_keypair();

        let server_x25519_priv = ed25519_private_to_x25519(&server_sign);
        let client_x25519_priv = ed25519_private_to_x25519(&client_sign);

        let server_x25519_pub = ed25519_public_to_x25519(&server_pub).unwrap();
        let client_x25519_pub = X25519Public::from(client_x25519_priv.diffie_hellman(&server_x25519_pub).to_bytes());
        // Actually we need the client's X25519 public key from their private
        let client_x25519_pub_real = x25519_dalek::PublicKey::from(&client_x25519_priv);

        let shared_client = x25519(&client_x25519_priv, &server_x25519_pub);
        let shared_server = x25519(&server_x25519_priv, &client_x25519_pub_real);
        assert_eq!(shared_client, shared_server);
    }
}
