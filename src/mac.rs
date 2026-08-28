use chacha20poly1305::{aead::Aead, aead::KeyInit as AeadKeyInit, XChaCha20Poly1305};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Size of the MAC1 tag in bytes.
pub const MAC_SIZE: usize = 16;

/// Size of an X25519 public key.
pub const CLIENT_KEY_SIZE: usize = 32;

/// Size of the carried Ed25519 identity key (SIP-3). All-zero means "no
/// identity asserted".
pub const ED25519_SIZE: usize = 32;

/// Size of the replay-protection timestamp (uint32 epoch seconds).
pub const TIMESTAMP_SIZE: usize = 4;

/// Size of MAC2 tag in bytes.
pub const MAC2_SIZE: usize = 16;

/// Size of the random nonce in bytes.
pub const NONCE_SIZE: usize = 8;

/// Total overhead appended to Initial packets by envelope version 1 (SIP-6):
/// 32-byte client X25519 public key + 32-byte Ed25519 identity + 4-byte
/// timestamp + 8-byte nonce + 16-byte MAC1 + 16-byte MAC2.
pub const MAC_OVERHEAD: usize =
    CLIENT_KEY_SIZE + ED25519_SIZE + TIMESTAMP_SIZE + NONCE_SIZE + MAC_SIZE + MAC2_SIZE;

/// Envelope version 1 (SIP-6): no marker byte on the wire. It is named so that
/// a receiver supporting both has something to call the unmarked form.
pub const ENVELOPE_V1: u8 = 1;

/// Envelope version 2 (SIP-29): version 1 plus a one-byte marker, last.
pub const ENVELOPE_V2: u8 = 2;

/// Size of the version marker.
pub const VERSION_SIZE: usize = 1;

/// Trailer width for envelope version 2.
pub const MAC_OVERHEAD_V2: usize = MAC_OVERHEAD + VERSION_SIZE;

// Static assertions: the version 1 trailer is 108 bytes (32+32+4+8+16+16) and
// version 2 is one more. If either changes, update ClientSocket::try_send(),
// which bypasses quinn-udp for the oversized Initial packet to avoid GSO issues
// on Linux.
const _: () = assert!(MAC_OVERHEAD == 108, "MAC_OVERHEAD changed — update Initial send path in conn.rs");
const _: () = assert!(MAC_OVERHEAD_V2 == 109, "MAC_OVERHEAD_V2 changed — update Initial send path in conn.rs");

/// The trailer width for an envelope version, or `None` if unknown.
///
/// SIP-29: version 0 is reserved and never emitted, so a zero byte is known not
/// to be a marker.
pub fn trailer_len(version: u8) -> Option<usize> {
    match version {
        ENVELOPE_V1 => Some(MAC_OVERHEAD),
        ENVELOPE_V2 => Some(MAC_OVERHEAD_V2),
        _ => None,
    }
}

/// First byte of a cookie reply packet.
pub const COOKIE_REPLY_TYPE: u8 = 0x01;

/// Nonce size for XChaCha20-Poly1305.
pub const COOKIE_NONCE_SIZE: usize = 24;

/// Maximum age/future of a timestamp before the server rejects it (seconds).
pub const REPLAY_WINDOW: i64 = 120;

/// Domain separator for the cookie-reply encryption key.
const COOKIE_KEY_LABEL: &[u8] = b"squic-cookie-v1";

/// How long a cookie secret stays current before rotating.
pub const COOKIE_SECRET_LIFETIME_SECS: u64 = 120;

type HmacSha256 = Hmac<Sha256>;

/// Compute MAC1 = HMAC-SHA256(shared_secret, data || ed25519 || timestamp || nonce)[:16]
///
/// SIP-3: the carried Ed25519 identity field is part of the MAC1 input. This is
/// load-bearing — it does not feed the shared secret, so if it were left
/// unauthenticated an on-path attacker could substitute the sign-conjugate key
/// (which passes the server's derivation check) and flip the reported identity.
/// `ed25519` is the 32-byte field exactly as it appears on the wire (all zeros
/// when no identity is asserted).
pub fn compute_mac1(
    version: u8,
    shared_secret: &[u8],
    data: &[u8],
    ed25519: &[u8],
    timestamp: u32,
    nonce: &[u8],
) -> [u8; MAC_SIZE] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(shared_secret).expect("HMAC accepts any key size");
    // SIP-29: every marked version prefixes its version byte. Version 1
    // predates the marker and prefixes nothing.
    //
    // A prefix rather than a suffix, because it is doing two jobs. It
    // authenticates the marker, which a receiver has to read before it can
    // verify anything. And because it comes first, tags computed under
    // different versions are unrelated even when the remaining input
    // coincides — so a packet valid under one version can never verify under
    // another, whatever an attacker picks for the rest of the envelope.
    if version != ENVELOPE_V1 {
        mac.update(&[version]);
    }
    mac.update(data);
    mac.update(ed25519);
    mac.update(&timestamp.to_be_bytes());
    mac.update(nonce);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&result[..MAC_SIZE]);
    tag
}

/// Verify MAC1 with constant-time comparison.
pub fn verify_mac1(
    version: u8,
    shared_secret: &[u8],
    data: &[u8],
    ed25519: &[u8],
    timestamp: u32,
    nonce: &[u8],
    mac1: &[u8],
) -> bool {
    let expected = compute_mac1(version, shared_secret, data, ed25519, timestamp, nonce);
    constant_time_eq(&expected, mac1)
}

/// Constant-time equality over two byte slices (public helper for the SIP-3
/// identity-derivation check in conn.rs).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
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
    (-REPLAY_WINDOW..=REPLAY_WINDOW).contains(&diff)
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

/// Derive the key that encrypts cookie replies, from the server's X25519
/// public key.
///
/// Both ends can compute this without a Diffie-Hellman: the server holds the
/// matching private key, and any legitimate client already knows the server's
/// public key — that is the premise of a silent server. Keying it off the DH
/// shared secret instead would defeat the purpose, since the cookie exists
/// precisely so the server does not have to do a DH for an unverified caller.
///
/// An attacker who does not hold the server's public key cannot read the
/// cookie, and one who does could already make the server do DH work, so
/// nothing is given away.
pub fn cookie_key(server_x25519_pub: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COOKIE_KEY_LABEL);
    hasher.update(server_x25519_pub);
    hasher.finalize().into()
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
        let ed = [0x11u8; ED25519_SIZE];
        let ts = now_timestamp();
        let nonce = generate_nonce();
        let mac = compute_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &nonce);
        assert_eq!(mac.len(), MAC_SIZE);
        assert!(verify_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &nonce, &mac));

        // Wrong key
        let wrong = [0xCDu8; 32];
        assert!(!verify_mac1(ENVELOPE_V1, &wrong, data, &ed, ts, &nonce, &mac));

        // Tampered data
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        assert!(!verify_mac1(ENVELOPE_V1, &secret, &tampered, &ed, ts, &nonce, &mac));

        // Tampered Ed25519 identity field (SIP-3: it is in the MAC1 input)
        let mut ed2 = ed;
        ed2[0] ^= 0xFF;
        assert!(!verify_mac1(ENVELOPE_V1, &secret, data, &ed2, ts, &nonce, &mac));

        // Wrong timestamp
        assert!(!verify_mac1(ENVELOPE_V1, &secret, data, &ed, ts + 1, &nonce, &mac));

        // Wrong nonce
        let wrong_nonce = generate_nonce();
        assert!(!verify_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &wrong_nonce, &mac));
    }

    /// SIP-29 prefixes the version to the MAC1 input rather than appending it,
    /// so that tags computed under different versions are unrelated even when
    /// everything after the prefix is identical. Without that separation a
    /// packet valid under one version could be made to verify under another.
    #[test]
    fn mac1_is_bound_to_the_envelope_version() {
        let secret = [0xABu8; 32];
        let data = b"one QUIC Initial";
        let ed = [0u8; ED25519_SIZE];
        let ts = now_timestamp();
        let nonce = generate_nonce();

        let v1 = compute_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &nonce);
        let v2 = compute_mac1(ENVELOPE_V2, &secret, data, &ed, ts, &nonce);
        assert_ne!(v1, v2, "the version is not in the MAC1 input");

        // Neither verifies as the other, which is what makes the two forms
        // unambiguous cryptographically and not merely structurally.
        assert!(!verify_mac1(ENVELOPE_V2, &secret, data, &ed, ts, &nonce, &v1));
        assert!(!verify_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &nonce, &v2));
        assert!(verify_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &nonce, &v1));
        assert!(verify_mac1(ENVELOPE_V2, &secret, data, &ed, ts, &nonce, &v2));
    }

    /// Version 1 predates the marker, so its MAC1 must be exactly what SIP-6
    /// specified — no prefix. A peer that started prefixing version 1 would
    /// break every deployment still on it.
    #[test]
    fn version_1_mac1_carries_no_prefix() {
        let secret = [0x11u8; 32];
        let data = b"payload";
        let ed = [0u8; ED25519_SIZE];
        let ts = 1234u32;
        let nonce = [7u8; NONCE_SIZE];

        let mut expected = <HmacSha256 as Mac>::new_from_slice(&secret).unwrap();
        expected.update(data);
        expected.update(&ed);
        expected.update(&ts.to_be_bytes());
        expected.update(&nonce);
        let expected = expected.finalize().into_bytes();

        let got = compute_mac1(ENVELOPE_V1, &secret, data, &ed, ts, &nonce);
        assert_eq!(&got[..], &expected[..MAC_SIZE]);
    }

    #[test]
    fn trailer_len_knows_only_defined_versions() {
        assert_eq!(trailer_len(ENVELOPE_V1), Some(MAC_OVERHEAD));
        assert_eq!(trailer_len(ENVELOPE_V2), Some(MAC_OVERHEAD_V2));
        assert_eq!(trailer_len(ENVELOPE_V2), Some(MAC_OVERHEAD + 1));
        // Version 0 is reserved and never emitted, so a zero byte is known not
        // to be a marker.
        assert_eq!(trailer_len(0), None);
        assert_eq!(trailer_len(3), None);
        assert_eq!(trailer_len(255), None);
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

    /// MAC2 covers the envelope up to but NOT including MAC1, with MAC1 fed in
    /// separately. Hashing the buffer whole folds MAC1 in twice and never
    /// verifies — and because a failing MAC2 is indistinguishable from a client
    /// that has no cookie, the symptom is not an error but a handshake that
    /// takes an extra round trip forever. Both sides have to draw the boundary
    /// in the same place, so it is pinned here.
    #[test]
    fn mac2_covers_the_envelope_up_to_mac1() {
        let cookie = [0x7Au8; 16];
        let shared = [0xABu8; 32];
        let datagram = b"a QUIC Initial, more or less";
        let ed = [0u8; ED25519_SIZE];
        let ts = now_timestamp();
        let nonce = generate_nonce();
        let mac1 = compute_mac1(ENVELOPE_V1, &shared, datagram, &ed, ts, &nonce);

        let mut buf = Vec::new();
        buf.extend_from_slice(datagram);
        buf.extend_from_slice(&[0x11u8; CLIENT_KEY_SIZE]);
        buf.extend_from_slice(&ed);
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&nonce);
        let before_mac1 = buf.len();
        buf.extend_from_slice(&mac1);

        let right = compute_mac2(&cookie, &buf[..before_mac1], &mac1);
        assert!(verify_mac2(&cookie, &buf[..before_mac1], &mac1, &right));

        // The mistake: covering MAC1 as well, then passing it again.
        let wrong = compute_mac2(&cookie, &buf, &mac1);
        assert!(
            !verify_mac2(&cookie, &buf[..before_mac1], &mac1, &wrong),
            "MAC2 over the whole buffer must not verify against the specified range"
        );
    }

    /// An IPv4 address and its IPv4-mapped IPv6 form are the same client, and
    /// must mint the same cookie — otherwise a client reaching a dual-stack
    /// socket is challenged with one cookie and verified against another.
    #[test]
    fn cookie_is_the_same_for_v4_and_its_mapped_form() {
        let secret = [0x33u8; 32];
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(cookie_value(&secret, v4), cookie_value(&secret, mapped));

        // A different address is a different cookie.
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        assert_ne!(cookie_value(&secret, v4), cookie_value(&secret, other));
    }

    /// The client derives the reply key from the server's public key alone —
    /// no Diffie-Hellman, which is the whole point of the cookie. If the two
    /// ends ever disagreed on this derivation the client could not open a
    /// challenge and would be stuck at one round trip per Initial, forever.
    #[test]
    fn cookie_reply_opens_under_the_derived_key() {
        let server_pub = [0x5Cu8; 32];
        let key = cookie_key(&server_pub);
        let cookie = [0x42u8; 16];

        let sealed = encrypt_cookie(&key, &cookie).expect("seal");
        assert_eq!(sealed.len(), COOKIE_NONCE_SIZE + 16 + 16);
        assert_eq!(decrypt_cookie(&key, &sealed).as_deref(), Some(&cookie[..]));

        // Derived from a different server key, it does not open.
        let wrong = cookie_key(&[0x5Du8; 32]);
        assert!(decrypt_cookie(&wrong, &sealed).is_none());
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
