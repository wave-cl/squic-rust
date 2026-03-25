use chacha20poly1305::{aead::Aead, aead::KeyInit as AeadKeyInit, XChaCha20Poly1305};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Size of the MAC1 tag in bytes.
pub const MAC_SIZE: usize = 16;

/// Size of an X25519 public key.
pub const CLIENT_KEY_SIZE: usize = 32;

/// Size of the replay-protection timestamp (uint32 epoch seconds).
pub const TIMESTAMP_SIZE: usize = 4;

/// Size of MAC2 tag in bytes.
pub const MAC2_SIZE: usize = 16;

/// Size of the random nonce in bytes.
pub const NONCE_SIZE: usize = 8;

/// Total overhead appended to Initial packets:
/// 32-byte client X25519 public key + 4-byte timestamp + 8-byte nonce + 16-byte MAC1 + 16-byte MAC2.
pub const MAC_OVERHEAD: usize = CLIENT_KEY_SIZE + TIMESTAMP_SIZE + NONCE_SIZE + MAC_SIZE + MAC2_SIZE;

/// First byte of a cookie reply packet.
pub const COOKIE_REPLY_TYPE: u8 = 0x01;

/// Nonce size for XChaCha20-Poly1305.
pub const COOKIE_NONCE_SIZE: usize = 24;

/// Maximum age/future of a timestamp before the server rejects it (seconds).
pub const REPLAY_WINDOW: i64 = 120;

type HmacSha256 = Hmac<Sha256>;

/// Compute MAC1 = HMAC-SHA256(shared_secret, data || timestamp || nonce)[:16]
pub fn compute_mac1(shared_secret: &[u8], data: &[u8], timestamp: u32, nonce: &[u8]) -> [u8; MAC_SIZE] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(shared_secret).expect("HMAC accepts any key size");
    mac.update(data);
    mac.update(&timestamp.to_be_bytes());
    mac.update(nonce);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&result[..MAC_SIZE]);
    tag
}

/// Verify MAC1 with constant-time comparison.
pub fn verify_mac1(shared_secret: &[u8], data: &[u8], timestamp: u32, nonce: &[u8], mac1: &[u8]) -> bool {
    let expected = compute_mac1(shared_secret, data, timestamp, nonce);
    constant_time_eq(&expected, mac1)
}

/// Generate a cryptographically random 8-byte nonce using the kernel CSPRNG.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce).expect("getrandom failed");
    nonce
}

/// Current time as uint32 epoch seconds.
pub fn now_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// Check if a timestamp is within the replay window.
pub fn timestamp_in_window(timestamp: u32, now: u32) -> bool {
    let diff = now as i64 - timestamp as i64;
    diff >= -REPLAY_WINDOW && diff <= REPLAY_WINDOW
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Compute MAC2 = HMAC-SHA256(cookie, packet || mac1)[:16]
pub fn compute_mac2(cookie: &[u8], packet: &[u8], mac1: &[u8]) -> [u8; MAC2_SIZE] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(cookie).expect("HMAC accepts any key size");
    mac.update(packet);
    mac.update(mac1);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC2_SIZE];
    tag.copy_from_slice(&result[..MAC2_SIZE]);
    tag
}

/// Verify MAC2 with constant-time comparison.
pub fn verify_mac2(cookie: &[u8], packet: &[u8], mac1: &[u8], mac2: &[u8]) -> bool {
    let expected = compute_mac2(cookie, packet, mac1);
    constant_time_eq(&expected, mac2)
}

/// Compute a deterministic cookie for a (secret, IP) pair.
/// cookie = HMAC-SHA256(secret, ip)[:16]
pub fn cookie_value(secret: &[u8; 32], client_ip: IpAddr) -> [u8; 16] {
    let ip_bytes = match client_ip {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[10] = 0xff;
            buf[11] = 0xff;
            buf[12..].copy_from_slice(&v4.octets());
            buf
        }
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&ip_bytes);
    let result = mac.finalize().into_bytes();
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(&result[..16]);
    cookie
}

/// Encrypt a cookie for sending to the client.
/// Returns [nonce(24)] [ciphertext(cookie + 16 byte tag)].
pub fn encrypt_cookie(secret: &[u8; 32], cookie: &[u8]) -> Option<Vec<u8>> {
    let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new(secret.into());
    let mut nonce_bytes = [0u8; COOKIE_NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes).ok()?;
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, cookie).ok()?;
    let mut result = Vec::with_capacity(COOKIE_NONCE_SIZE + encrypted.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted);
    Some(result)
}

/// Decrypt a cookie reply to recover the cookie value.
pub fn decrypt_cookie(secret: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < COOKIE_NONCE_SIZE + 16 + 16 {
        return None;
    }
    let cipher = <XChaCha20Poly1305 as AeadKeyInit>::new(secret.into());
    let nonce = chacha20poly1305::XNonce::from_slice(&data[..COOKIE_NONCE_SIZE]);
    let ciphertext = &data[COOKIE_NONCE_SIZE..];
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Check if a packet is a QUIC Initial packet.
/// QUIC Initial: long header (bit 7=1, bit 6=1), packet type 0x00 (bits 5-4).
/// First byte & 0xF0 == 0xC0.
pub fn is_quic_initial(data: &[u8]) -> bool {
    data.len() >= 5 && data[0] & 0xF0 == 0xC0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac1_round_trip() {
        let secret = [0xABu8; 32];
        let data = b"test packet data";
        let ts = now_timestamp();
        let nonce = generate_nonce();
        let mac = compute_mac1(&secret, data, ts, &nonce);
        assert_eq!(mac.len(), MAC_SIZE);
        assert!(verify_mac1(&secret, data, ts, &nonce, &mac));

        // Wrong key
        let wrong = [0xCDu8; 32];
        assert!(!verify_mac1(&wrong, data, ts, &nonce, &mac));

        // Tampered data
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        assert!(!verify_mac1(&secret, &tampered, ts, &nonce, &mac));

        // Wrong timestamp
        assert!(!verify_mac1(&secret, data, ts + 1, &nonce, &mac));

        // Wrong nonce
        let wrong_nonce = generate_nonce();
        assert!(!verify_mac1(&secret, data, ts, &wrong_nonce, &mac));
    }

    #[test]
    fn test_timestamp_replay_window() {
        let now = now_timestamp();
        assert!(timestamp_in_window(now, now));
        assert!(timestamp_in_window(now - 60, now));
        assert!(timestamp_in_window(now - 119, now));
        assert!(!timestamp_in_window(now - 121, now));
        assert!(timestamp_in_window(now + 60, now));
        assert!(!timestamp_in_window(now + 121, now));
    }

    #[test]
    fn test_is_quic_initial() {
        assert!(is_quic_initial(&[0xC0, 0, 0, 0, 0]));
        assert!(is_quic_initial(&[0xCF, 0, 0, 0, 0]));
        assert!(!is_quic_initial(&[0x40, 0, 0, 0, 0])); // short header
        assert!(!is_quic_initial(&[0xD0, 0, 0, 0, 0])); // handshake type
        assert!(!is_quic_initial(&[0xC0])); // too short
    }
}
