use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

/// Size of the MAC1 tag in bytes.
pub const MAC_SIZE: usize = 16;

/// Size of an X25519 public key.
pub const CLIENT_KEY_SIZE: usize = 32;

/// Size of the replay-protection timestamp (uint32 epoch seconds).
pub const TIMESTAMP_SIZE: usize = 4;

/// Total overhead appended to Initial packets:
/// 32-byte client X25519 public key + 4-byte timestamp + 16-byte MAC1.
pub const MAC_OVERHEAD: usize = CLIENT_KEY_SIZE + TIMESTAMP_SIZE + MAC_SIZE;

/// Maximum age/future of a timestamp before the server rejects it (seconds).
pub const REPLAY_WINDOW: i64 = 120;

type HmacSha256 = Hmac<Sha256>;

/// Compute MAC1 = HMAC-SHA256(shared_secret, data || timestamp)[:16]
pub fn compute_mac1(shared_secret: &[u8], data: &[u8], timestamp: u32) -> [u8; MAC_SIZE] {
    let mut mac =
        HmacSha256::new_from_slice(shared_secret).expect("HMAC accepts any key size");
    mac.update(data);
    mac.update(&timestamp.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&result[..MAC_SIZE]);
    tag
}

/// Verify MAC1 with constant-time comparison.
pub fn verify_mac1(shared_secret: &[u8], data: &[u8], timestamp: u32, mac1: &[u8]) -> bool {
    let expected = compute_mac1(shared_secret, data, timestamp);
    constant_time_eq(&expected, mac1)
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
        let mac = compute_mac1(&secret, data, ts);
        assert_eq!(mac.len(), MAC_SIZE);
        assert!(verify_mac1(&secret, data, ts, &mac));

        // Wrong key
        let wrong = [0xCDu8; 32];
        assert!(!verify_mac1(&wrong, data, ts, &mac));

        // Tampered data
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        assert!(!verify_mac1(&secret, &tampered, ts, &mac));

        // Wrong timestamp
        assert!(!verify_mac1(&secret, data, ts + 1, &mac));
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
