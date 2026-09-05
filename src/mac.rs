use chacha20poly1305::{aead::Aead, aead::KeyInit as AeadKeyInit, XChaCha20Poly1305};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Size of the MAC1 tag in bytes.
pub const MAC_SIZE: usize = 16;

/// Size of the gate tag in bytes (SIP-37 successor).
pub const GATE_SIZE: usize = 16;

/// Size of an X25519 public key.
pub const CLIENT_KEY_SIZE: usize = 32;

/// Size of the carried Ed25519 identity key (SIP-3), when one is present.
pub const ED25519_SIZE: usize = 32;

/// Size of the replay-protection timestamp (uint32 epoch seconds).
pub const TIMESTAMP_SIZE: usize = 4;

/// Size of the trailing header byte: version in the high nibble, flags in the
/// low one.
pub const HDR_SIZE: usize = 1;

/// Envelope version 4.
///
/// One gate tag replaces the separate MAC0 and MAC2 of version 3. They were
/// never both load-bearing: a cookie is delivered encrypted under a key derived
/// from the server's public key, so producing a valid MAC2 already demonstrated
/// the key knowledge MAC0 existed to prove. Version 3 paid 32 bytes for two
/// states of one proof.
///
/// The identity field is now carried only when there is one, and the version-1
/// nonce is gone — SIP-6 said it was never tracked, and the QUIC datagram
/// underneath already differs per attempt.
pub const ENVELOPE_V4: u8 = 4;

/// Flag bit: a 32-byte Ed25519 identity follows the X25519 key (SIP-3).
pub const FLAG_IDENTITY: u8 = 0x01;

/// The header's remaining flag bits, which no version defines a meaning for.
///
/// Refused rather than ignored, and the reason is that ignoring them is a
/// one-way door. Both tags cover the header byte as it arrived, so a client
/// that sets a reserved bit *and computes its tags over it* would otherwise be
/// admitted — the tags verify, and nothing else looks at the bit. Deployed
/// servers would then be accepting these bits with no meaning attached, and a
/// later version could not give them one: it would have no way to tell a peer
/// asserting the new flag from an older peer that set the bit for no reason.
///
/// Tampering in transit was never the risk here — a flipped bit changes the
/// tag input and fails. The risk is to the protocol's own future, and closing
/// it costs nothing only while none of the bits are wanted.
pub const FLAG_RESERVED: u8 = 0x0E;

/// Every envelope version this build knows.
///
/// The one list to extend when a version is added — `trailer_len` and the
/// per-version accept counters are both keyed off it.
pub const ENVELOPE_VERSIONS: [u8; 1] = [ENVELOPE_V4];

/// The position of `version` in [`ENVELOPE_VERSIONS`], for indexing per-version
/// state. `None` for a version this build does not know.
pub fn version_index(version: u8) -> Option<usize> {
    ENVELOPE_VERSIONS.iter().position(|&v| v == version)
}

/// Build the trailing header byte.
pub fn hdr(version: u8, identity: bool) -> u8 {
    (version << 4) | if identity { FLAG_IDENTITY } else { 0 }
}

/// The version half of a header byte.
pub fn hdr_version(hdr: u8) -> u8 {
    hdr >> 4
}

/// Whether a header byte says an Ed25519 identity is carried.
pub fn hdr_has_identity(hdr: u8) -> bool {
    hdr & FLAG_IDENTITY != 0
}

/// Trailer width for an anonymous caller: X25519, timestamp, gate, MAC1, header.
pub const TRAILER_ANON: usize =
    CLIENT_KEY_SIZE + TIMESTAMP_SIZE + GATE_SIZE + MAC_SIZE + HDR_SIZE;

/// Trailer width when an identity is carried.
pub const TRAILER_WITH_IDENTITY: usize = TRAILER_ANON + ED25519_SIZE;

// The Initial send path bypasses quinn-udp because a 1200-byte QUIC datagram
// plus this trailer exceeds the 1200-byte GSO segment size. These assertions
// fail if the arithmetic behind that decision moves.
const _: () = assert!(TRAILER_ANON == 69, "TRAILER_ANON changed — check the Initial send path in conn.rs");
const _: () = assert!(TRAILER_WITH_IDENTITY == 101, "TRAILER_WITH_IDENTITY changed — check the Initial send path in conn.rs");

/// The trailer width a header byte implies, or `None` if the version is unknown.
///
/// Unlike version 3 this is not a constant per version: the identity field is
/// present only when flagged, so the width has to be read off the header byte
/// that a receiver finds at the end of the datagram.
pub fn trailer_len(hdr: u8) -> Option<usize> {
    if hdr_version(hdr) != ENVELOPE_V4 {
        return None;
    }
    if hdr & FLAG_RESERVED != 0 {
        return None;
    }
    Some(if hdr_has_identity(hdr) {
        TRAILER_WITH_IDENTITY
    } else {
        TRAILER_ANON
    })
}

/// Domain separator for the gate key.
const GATE_KEY_LABEL: &[u8] = b"squic-gate-v1";

/// Derive the no-cookie gate key from the server's X25519 public key.
///
/// Keyed on a *public* value, deliberately. Every legitimate caller already
/// holds the server's public key — that is the premise of a silent server — so
/// both ends compute this with one hash and no key agreement. It is therefore
/// not authentication: anyone holding the key can forge this tag, and MAC1
/// remains the proof of possession. What it buys is that a caller who does
/// *not* hold the key is turned away for the price of one HMAC, before the
/// Diffie-Hellman.
pub fn gate_key(server_x25519_pub: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(GATE_KEY_LABEL);
    hasher.update(server_x25519_pub);
    hasher.finalize().into()
}

/// Compute the gate tag over the envelope up to but not including the tag.
///
/// `covered` is `datagram || x25519 || [ed25519] || ts` — one contiguous slice,
/// which is why this takes bytes rather than fields. The header byte is
/// prefixed for the reason SIP-29 gives: it authenticates the byte a receiver
/// has to read before it can verify anything, and because it comes first, tags
/// computed under different versions or different flags are unrelated even when
/// the rest of the input coincides.
///
/// The key is what makes this one field do two jobs:
///
/// * [`gate_key`] — the caller holds no cookie, and the tag proves only that it
///   knows the server's public key.
/// * the cookie itself — the caller answered a challenge, and the tag proves
///   that *and* that its source address receives packets, which no single
///   datagram can demonstrate on its own.
pub fn compute_gate(hdr: u8, key: &[u8], covered: &[u8]) -> [u8; GATE_SIZE] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&[hdr]);
    mac.update(covered);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; GATE_SIZE];
    tag.copy_from_slice(&result[..GATE_SIZE]);
    tag
}

/// Verify a gate tag with constant-time comparison.
pub fn verify_gate(hdr: u8, key: &[u8], covered: &[u8], gate: &[u8]) -> bool {
    constant_time_eq(&compute_gate(hdr, key, covered), gate)
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

/// Compute MAC1 over the same range the gate tag covers, keyed on the
/// Diffie-Hellman shared secret.
///
/// One covered range for both tags — `hdr || datagram || x25519 || [ed25519] ||
/// ts` — so there is a single rule to hold rather than two constructions with
/// different opinions about what they authenticate.
///
/// This is the proof of possession, and the reason it cannot merge with the
/// gate: verifying it requires the curve operation the gate exists to avoid.
///
/// SIP-3: the carried Ed25519 identity is inside the covered range. That is
/// load-bearing — it does not feed the shared secret, so if it were left
/// unauthenticated an on-path attacker could substitute the sign-conjugate key,
/// which passes the server's derivation check, and flip the reported identity.
pub fn compute_mac1(hdr: u8, shared_secret: &[u8], covered: &[u8]) -> [u8; MAC_SIZE] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(shared_secret).expect("HMAC accepts any key size");
    mac.update(&[hdr]);
    mac.update(covered);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_SIZE];
    tag.copy_from_slice(&result[..MAC_SIZE]);
    tag
}

/// Verify MAC1 with constant-time comparison.
pub fn verify_mac1(hdr: u8, shared_secret: &[u8], covered: &[u8], mac1: &[u8]) -> bool {
    constant_time_eq(&compute_mac1(hdr, shared_secret, covered), mac1)
}

/// Constant-time equality over two byte slices (public helper for the SIP-3
/// identity-derivation check in conn.rs).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
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

/// Compute a deterministic cookie for a (secret, IP) pair.
/// `cookie = HMAC-SHA256(secret, ip)[:16]`
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

/// Check if a packet is a QUIC 0-RTT packet: long header, packet type 0x01.
/// First byte & 0xF0 == 0xD0.
///
/// sQUIC does not carry 0-RTT. The envelope proves possession of the server's
/// key and of a Diffie-Hellman shared secret, and it is attached to the
/// Initial; a standalone 0-RTT datagram arrives with none of that, so a stack
/// that accepts one is taking application data from a caller this transport
/// has not authenticated — past the gate, past MAC1, and past the whitelist
/// SIP-8 enforces on the X25519 field the datagram does not carry.
pub fn is_quic_zero_rtt(data: &[u8]) -> bool {
    data.len() >= 5 && data[0] & 0xF0 == 0xD0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED: &[u8] = b"shared secret for tests..........";

    fn covered() -> Vec<u8> {
        b"a QUIC datagram, a client key, a timestamp".to_vec()
    }

    #[test]
    fn mac1_round_trips_and_rejects_a_tampered_range() {
        let h = hdr(ENVELOPE_V4, false);
        let c = covered();
        let tag = compute_mac1(h, SHARED, &c);
        assert!(verify_mac1(h, SHARED, &c, &tag));

        let mut altered = c.clone();
        altered[0] ^= 1;
        assert!(!verify_mac1(h, SHARED, &altered, &tag));
    }

    /// SIP-29's reason for prefixing the header: a tag computed under one
    /// header must be unrelated to the same input under another, so a flipped
    /// flag or version can only cost a drop and never an accept.
    #[test]
    fn both_tags_are_bound_to_the_header_byte() {
        let c = covered();
        let anon = hdr(ENVELOPE_V4, false);
        let ident = hdr(ENVELOPE_V4, true);

        let m = compute_mac1(anon, SHARED, &c);
        assert!(!verify_mac1(ident, SHARED, &c, &m), "MAC1 ignored the flag");

        let key = gate_key(&[7u8; 32]);
        let g = compute_gate(anon, &key, &c);
        assert!(!verify_gate(ident, &key, &c, &g), "gate ignored the flag");
    }

    /// The property the gate exists for: a caller who does not hold the
    /// server's public key cannot produce one.
    #[test]
    fn the_gate_separates_a_caller_who_knows_the_key_from_one_who_does_not() {
        let h = hdr(ENVELOPE_V4, false);
        let c = covered();
        let server_pub = [3u8; 32];
        let tag = compute_gate(h, &gate_key(&server_pub), &c);

        assert!(verify_gate(h, &gate_key(&server_pub), &c, &tag));
        assert!(
            !verify_gate(h, &gate_key(&[4u8; 32]), &c, &tag),
            "a stranger's tag verified"
        );
    }

    /// The same field, keyed on a cookie, is what proves the source address —
    /// and the two modes must not verify each other, or the load rule could be
    /// side-stepped by sending the cheaper form.
    #[test]
    fn the_two_gate_modes_do_not_verify_each_other() {
        let h = hdr(ENVELOPE_V4, false);
        let c = covered();
        let cookie = [9u8; 16];
        let by_key = compute_gate(h, &gate_key(&[3u8; 32]), &c);
        let by_cookie = compute_gate(h, &cookie, &c);

        assert_ne!(by_key, by_cookie);
        assert!(!verify_gate(h, &cookie, &c, &by_key));
        assert!(!verify_gate(h, &gate_key(&[3u8; 32]), &c, &by_cookie));
    }

    /// Both keys are derived from the same public value and separated only by
    /// their labels. Reusing one label would key two unrelated constructions
    /// identically.
    #[test]
    fn gate_and_cookie_keys_are_separated_by_their_labels() {
        let server_pub = [5u8; 32];
        assert_ne!(gate_key(&server_pub), cookie_key(&server_pub));
    }

    #[test]
    fn the_header_byte_carries_version_and_flags() {
        let anon = hdr(ENVELOPE_V4, false);
        let ident = hdr(ENVELOPE_V4, true);
        assert_eq!(hdr_version(anon), ENVELOPE_V4);
        assert_eq!(hdr_version(ident), ENVELOPE_V4);
        assert!(!hdr_has_identity(anon));
        assert!(hdr_has_identity(ident));
    }

    /// The trailer is no longer a constant: it depends on whether an identity
    /// is carried, and the width has to be readable from the header alone.
    #[test]
    fn trailer_width_follows_the_identity_flag() {
        assert_eq!(trailer_len(hdr(ENVELOPE_V4, false)), Some(TRAILER_ANON));
        assert_eq!(trailer_len(hdr(ENVELOPE_V4, true)), Some(TRAILER_WITH_IDENTITY));
        assert_eq!(TRAILER_ANON, 69);
        assert_eq!(TRAILER_WITH_IDENTITY, 101);
        assert_eq!(TRAILER_WITH_IDENTITY - TRAILER_ANON, ED25519_SIZE);
    }

    #[test]
    fn trailer_len_refuses_versions_this_build_does_not_implement() {
        for v in [0u8, 1, 2, 3, 5, 15] {
            assert_eq!(trailer_len(hdr(v, false)), None, "version {v} was accepted");
        }
    }

    #[test]
    fn every_known_version_has_a_trailer() {
        for v in ENVELOPE_VERSIONS {
            assert!(trailer_len(hdr(v, false)).is_some(), "version {v} has no width");
            assert!(version_index(v).is_some(), "version {v} has no counter slot");
        }
    }

    #[test]
    fn test_timestamp_replay_window() {
        let now = 1_000_000u32;
        assert!(timestamp_in_window(now, now));
        assert!(timestamp_in_window(now - REPLAY_WINDOW as u32, now));
        assert!(timestamp_in_window(now + REPLAY_WINDOW as u32, now));
        assert!(!timestamp_in_window(now - REPLAY_WINDOW as u32 - 1, now));
        assert!(!timestamp_in_window(now + REPLAY_WINDOW as u32 + 1, now));
    }

    #[test]
    fn cookie_is_the_same_for_v4_and_its_mapped_form() {
        let secret = [1u8; 32];
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(cookie_value(&secret, v4), cookie_value(&secret, mapped));
    }

    #[test]
    fn cookie_reply_opens_under_the_derived_key() {
        let server_pub = [2u8; 32];
        let key = cookie_key(&server_pub);
        let cookie = [0xABu8; 16];
        let sealed = encrypt_cookie(&key, &cookie).expect("seal");
        assert_eq!(decrypt_cookie(&key, &sealed).as_deref(), Some(&cookie[..]));
        assert!(decrypt_cookie(&cookie_key(&[9u8; 32]), &sealed).is_none());
    }

    #[test]
    fn test_is_quic_initial() {
        assert!(is_quic_initial(&[0xC0, 0, 0, 0, 1]));
        assert!(is_quic_initial(&[0xCF, 0, 0, 0, 1]));
        assert!(!is_quic_initial(&[0xD0, 0, 0, 0, 1]), "0-RTT is not an Initial");
        assert!(!is_quic_initial(&[0x40, 0, 0, 0, 1]), "short header");
        assert!(!is_quic_initial(&[0xC0]));
    }

    #[test]
    fn test_is_quic_zero_rtt() {
        assert!(is_quic_zero_rtt(&[0xD0, 0, 0, 0, 1]));
        assert!(is_quic_zero_rtt(&[0xDF, 0, 0, 0, 1]));
        assert!(!is_quic_zero_rtt(&[0xC0, 0, 0, 0, 1]), "an Initial is not 0-RTT");
        assert!(!is_quic_zero_rtt(&[0xE0, 0, 0, 0, 1]), "a Handshake is not 0-RTT");
        assert!(!is_quic_zero_rtt(&[0x50, 0, 0, 0, 1]), "short header");
        assert!(!is_quic_zero_rtt(&[0xD0]));
    }
}
