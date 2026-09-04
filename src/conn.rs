use crate::mac::{
    compute_mac0, compute_mac1, compute_mac2, cookie_value, ct_eq, decrypt_cookie, encrypt_cookie,
    generate_nonce, has_mac0, is_quic_initial, now_timestamp, timestamp_in_window, trailer_len,
    verify_mac0, verify_mac1, verify_mac2,
    CLIENT_KEY_SIZE, COOKIE_REPLY_TYPE, COOKIE_SECRET_LIFETIME_SECS, ED25519_SIZE, ENVELOPE_V1,
    ENVELOPE_VERSIONS, MAC0_SIZE, MAC2_SIZE,
    MAC_SIZE, NONCE_SIZE, TIMESTAMP_SIZE,
};
use crate::crypto::ed25519_identity_to_x25519;
use crate::whitelist::Whitelist;
use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::AsyncUdpSocket;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// How long a validated peer key is retained before the connection is accepted.
/// An Initial that passes MAC1 but whose handshake never completes would
/// otherwise leave its key in the table for the life of the process; a peer
/// that can pass MAC1 could fill it. The window only has to span the gap
/// between the first Initial and `accept`, which is sub-second in practice.
const PEER_KEY_TTL: Duration = Duration::from_secs(30);

/// The most insertion records the table will hold, and so the most live
/// entries — every live entry owns exactly one record.
///
/// The table is filled by anything that passes MAC1, which without a whitelist
/// is anyone holding the server's public key: a value that is *published*,
/// being the tail of the connection string. The previous arrangement pruned
/// only *expired* entries and then inserted regardless, so it freed nothing
/// whenever arrivals outran the TTL — which is exactly what an attacker
/// arranges — and the table grew without limit while every insert paid for a
/// full scan that reclaimed nothing.
///
/// At roughly 250 bytes an entry this bounds the table to about 4 MB. The
/// healthy steady state is near-empty: an entry lives from the first Initial
/// to `accept`, which is sub-second.
const PEER_TABLE_MAX: usize = 16_384;

struct PeerEntry {
    key: [u8; 32],
    /// The MAC1-bound Ed25519 identity (SIP-3), if the Initial carried one and it
    /// forward-derived to `key`. `None` for an anonymous (zero-field) connection.
    identity: Option<[u8; 32]>,
    inserted: Instant,
    /// Two Initials shared this DCID with different keys or identities. The
    /// connection can no longer be attributed to one identity, so the entry
    /// answers for neither.
    poisoned: bool,
}

/// Maps a QUIC Destination Connection ID to the peer X25519 key that MAC1
/// verified on the Initial carrying it, so the accepting application can learn
/// who it is talking to. See SIP-2.
#[derive(Default)]
struct PeerTable {
    inner: Mutex<Inner>,
}

/// The map and the insertion order that bounds it.
#[derive(Default)]
struct Inner {
    map: HashMap<Vec<u8>, PeerEntry>,
    /// One record per entry, in insertion order, so expiry and eviction are
    /// both amortised O(1) and neither scans the map.
    ///
    /// A record is appended once, when the entry is first recorded, and its
    /// timestamp never changes — which is what makes the front always the
    /// oldest. A record whose timestamp no longer matches the map (the entry
    /// was drained, or evicted and re-recorded since) is stale, and is
    /// discarded without touching whatever is there now.
    order: VecDeque<(Instant, Vec<u8>)>,
}

impl Inner {
    /// Drop the oldest record, and the entry it names if that entry is still
    /// the one the record refers to. Returns whether a live entry went with it.
    fn drop_front(&mut self) -> bool {
        let Some((recorded, dcid)) = self.order.pop_front() else {
            return false;
        };
        match self.map.get(&dcid) {
            Some(e) if e.inserted == recorded => {
                self.map.remove(&dcid);
                true
            }
            _ => false, // stale record; the entry it named is already gone
        }
    }

    /// Drop everything past its TTL. Timestamps never change and records are
    /// appended in order, so the front is always the oldest and this stops at
    /// the first live one — no scan, and no dependence on how full the table is.
    fn expire(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) >= PEER_KEY_TTL)
        {
            self.drop_front();
        }
    }
}

impl PeerTable {
    /// Record `dcid -> key` for an Initial that just passed MAC1.
    ///
    /// A repeat of the same DCID with the same key is an ordinary
    /// retransmission and refreshes the entry. A repeat with a *different* key
    /// is a collision that cannot be resolved safely — an on-path attacker
    /// could otherwise overwrite a victim's entry — so the entry is poisoned
    /// and will answer for neither key.
    fn record(&self, dcid: &[u8], key: [u8; 32], identity: Option<[u8; 32]>, now: Instant) {
        let mut inner = self.inner.lock().unwrap();

        // An entry that is already here is settled in place, ahead of any
        // expiry or eviction, so a live connection is never turned away by
        // pressure a flood created a moment ago.
        //
        // A retransmission no longer extends the entry: it lives its TTL from
        // when it was first seen. That is what lets the order queue be exact —
        // a timestamp that never moves means the front is always the oldest —
        // and it stops a peer holding an entry open indefinitely by
        // retransmitting. The TTL is 30s against a 10s handshake timeout, so
        // the first sighting already covers the whole handshake.
        match inner.map.get_mut(dcid) {
            Some(e) if e.poisoned => return,
            Some(e) if e.key == key && e.identity == identity => return,
            Some(e) => {
                e.poisoned = true;
                return;
            }
            None => {}
        }

        inner.expire(now);

        // Every live entry owns exactly one record, so bounding the queue
        // bounds the map. Dropping from the front evicts the oldest, which is
        // the right end: a legitimate caller's entry is read within
        // milliseconds of being written, so it is the newest thing here and
        // the last to go.
        //
        // Under a flood heavy enough to fill this, some legitimate peer keys
        // will be evicted before their connection is accepted, and those
        // connections are then anonymous. That is a refusal at every consumer
        // that fails closed, which is the correct way to lose: the alternative
        // this replaces was unbounded growth and a quadratic prune under the
        // lock on the receive path, which loses everything.
        while inner.order.len() >= PEER_TABLE_MAX {
            inner.drop_front();
        }

        inner
            .map
            .insert(dcid.to_vec(), PeerEntry { key, identity, inserted: now, poisoned: false });
        inner.order.push_back((now, dcid.to_vec()));
    }

    /// Return the (key, identity) recorded for `dcid`, if one is present, not
    /// poisoned, and not expired. This is a peek, not a drain: an application may
    /// read the peer key and the peer identity separately for one connection
    /// (SIP-2 + SIP-3), so both accessors must resolve. The table is bounded by
    /// the TTL and by [`PEER_TABLE_MAX`] instead.
    fn get(&self, dcid: &[u8], now: Instant) -> Option<([u8; 32], Option<[u8; 32]>)> {
        let inner = self.inner.lock().unwrap();
        let entry = inner.map.get(dcid)?;
        if entry.poisoned || now.duration_since(entry.inserted) >= PEER_KEY_TTL {
            return None;
        }
        Some((entry.key, entry.identity))
    }

    /// Live entries, for the tests that pin the bound.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().map.len()
    }
}

/// The Destination Connection ID of a QUIC long-header (Initial) packet.
///
/// Layout: byte 0 flags, bytes 1..5 version, byte 5 DCID length (0..=20),
/// bytes 6..6+len DCID. `is_quic_initial` has already checked the flags.
fn initial_dcid(pkt: &[u8]) -> Option<&[u8]> {
    let len = *pkt.get(5)? as usize;
    if len > 20 {
        return None;
    }
    pkt.get(6..6 + len)
}

/// A QUIC short header: header-form bit clear, fixed bit set. Everything after
/// the handshake looks like this, and nothing before it does.
fn is_short_header(data: &[u8]) -> bool {
    !data.is_empty() && data[0] & 0xC0 == 0x40
}

/// Whether two socket addresses name the same peer.
///
/// An IPv4 address and its IPv4-mapped IPv6 form are the same host, and a
/// dual-stack socket may report either — so comparing `SocketAddr` directly
/// would reject the server's own cookie reply and stall the handshake rather
/// than fail loudly. `cookie_value` normalises the same way for the same
/// reason.
fn same_peer(a: SocketAddr, b: SocketAddr) -> bool {
    fn unmap(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        }
    }
    a.port() == b.port() && unmap(a.ip()) == unmap(b.ip())
}

/// A QUIC long header: the header-form bit is set. Initial, 0-RTT, Handshake
/// and Retry all look like this.
fn is_long_header(data: &[u8]) -> bool {
    !data.is_empty() && data[0] & 0x80 != 0
}

/// The QUIC version of a long-header packet — bytes 1..5, big-endian.
fn long_header_version(data: &[u8]) -> Option<u32> {
    let v = data.get(1..5)?;
    Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

/// Whether the QUIC stack behind us would parse this version.
///
/// The envelope gates Initials, but *every* long header reaches the QUIC
/// stack, and a stack that does not recognise the version answers with a
/// Version Negotiation packet — quinn decides this inside `PartialDecode::new`,
/// before the Initial-header check and before it looks up the connection at
/// all. That reply costs the caller no key and no captured traffic, so without
/// this gate one datagram proves the server exists and SIP-6's silence is over.
///
/// The set is quinn's own constant rather than a copy, so the gate cannot drift
/// away from the stack it is protecting.
fn version_is_supported(version: u32) -> bool {
    quinn_proto::DEFAULT_SUPPORTED_VERSIONS.contains(&version)
}

/// What one envelope-version attempt concluded (SIP-29).
///
/// `Challenge` is reported rather than acted on, so that trying two layouts for
/// one datagram cannot send the caller two cookie replies.
enum Outcome {
    Accepted(usize),
    Challenge,
    Drop,
}

/// Server-side UDP socket wrapper.
/// Validates MAC1 on incoming Initial packets, silently drops invalid ones.
pub struct ServerSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
    server_x25519_priv: X25519Secret,
    whitelist: Arc<Whitelist>,
    /// Keys MAC0 (envelope v3), derived from our own public key.
    mac0_key: [u8; 32],
    // MAC2 + cookie DDoS protection
    cookie_key: [u8; 32],
    cookie_secret: RwLock<[u8; 32]>,
    prev_cookie_secret: RwLock<[u8; 32]>,
    under_load: AtomicBool,
    dh_count: AtomicU64,
    cookie_replies: AtomicU64,
    mac2_verified: AtomicU64,
    /// Initials accepted, per envelope version, indexed as [`ENVELOPE_VERSIONS`].
    ///
    /// The number a deployment needs before retiring a version: without it the
    /// choice is made on nerve, and getting it wrong locks out every client
    /// that had not moved — silently, because a refused envelope is dropped
    /// without a word.
    accepted: [AtomicU64; ENVELOPE_VERSIONS.len()],
    load_threshold: u64,
    /// Envelope versions this server parses (SIP-29).
    accepted_versions: Vec<u8>,
    /// DCID -> MAC1-verified peer key, drained by the application at accept.
    peer_table: PeerTable,
}

/// Build the UDP socket state, with GRO turned back **off** on Linux.
///
/// `quinn_udp::UdpSocketState::new` opportunistically enables `UDP_GRO`, so the
/// kernel may return one `RecvMeta` covering several coalesced datagrams: `len`
/// is the total, `stride` the size of each. quinn handles that correctly — it
/// splits by `stride` before parsing.
///
/// squic never gets that far. It validates and strips the envelope *before*
/// quinn sees the buffer, reading only `len`, so a coalesced run is MAC1'd as
/// one giant datagram and fails. Handling `stride` here is not a fix either:
/// stripping removes a trailer only from Initials, and a different width per
/// envelope version, so the survivors have non-uniform lengths that a single
/// strided `RecvMeta` cannot express — and expanding one meta into several
/// slots can overflow fixed-size arrays, since a coalesced meta carries up to
/// 64 segments. So squic declines the optimisation instead of half-applying it.
///
/// This was measured, not reasoned about. On Linux 6.12, four identical and
/// individually valid Initials sent in one GSO write arrived as a single
/// 5300-byte `RecvMeta` with `stride` 1325 and **all four were dropped**; the
/// same four sent separately were **all accepted**. That is a client retrying a
/// handshake being refused in silence, which is the failure this whole codebase
/// is meant not to have.
///
/// squic-go enables no GRO at all, so this also stops the two receive paths
/// disagreeing about a security-relevant default — the standing complaint.
fn socket_state(socket: &tokio::net::UdpSocket) -> UdpSocketState {
    let state = UdpSocketState::new(socket.into()).expect("UdpSocketState::new");
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // Kernel ABI constant; `libc::UDP_GRO` is not exposed on every target.
        const UDP_GRO: libc::c_int = 104;
        let off: libc::c_int = 0;
        // Best effort by design: a kernel without UDP_GRO refuses this, and a
        // kernel without UDP_GRO cannot coalesce, so it is already safe.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_UDP,
                UDP_GRO,
                std::ptr::addr_of!(off).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    state
}

impl ServerSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        server_x25519_priv: X25519Secret,
        whitelist: Arc<Whitelist>,
        load_threshold: u64,
        accepted_versions: Vec<u8>,
    ) -> Self {
        let inner = socket_state(&socket);
        let server_pub = X25519Public::from(&server_x25519_priv);
        let cookie_key = crate::mac::cookie_key(server_pub.as_bytes());
        let mac0_key = crate::mac::mac0_key(server_pub.as_bytes());
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("getrandom failed");
        Self {
            io: socket,
            inner,
            server_x25519_priv,
            whitelist,
            mac0_key,
            cookie_key,
            // The previous secret starts out equal to the current one rather
            // than random: until the first rotation there is no earlier secret,
            // and seeding it randomly would make the grace branch check a
            // secret that was never in use.
            cookie_secret: RwLock::new(secret),
            prev_cookie_secret: RwLock::new(secret),
            under_load: AtomicBool::new(false),
            dh_count: AtomicU64::new(0),
            cookie_replies: AtomicU64::new(0),
            mac2_verified: AtomicU64::new(0),
            accepted: [const { AtomicU64::new(0) }; ENVELOPE_VERSIONS.len()],
            // Zero means the caller turned the cookie defence off; it is not a
            // stand-in for the default, which lib.rs has already applied.
            load_threshold,
            accepted_versions,
            peer_table: PeerTable::default(),
        }
    }

    /// Dispatch an Initial on its envelope version (SIP-29) and validate it.
    ///
    /// The version marker is the **last byte of the datagram**, which is the
    /// only place a receiver can read without already knowing the trailer's
    /// width — and knowing the width is what the marker is for. Version 1
    /// predates the marker and carries none, so it is the fallback: its last
    /// byte is the last byte of MAC2, uniformly random, and names version 2
    /// about once in 256 packets. That costs one wasted parse before the
    /// fallback succeeds, and nothing at all for the other 255.
    fn validate_and_strip(&self, buf: &mut [u8], len: usize, addr: Option<SocketAddr>) -> Option<usize> {
        // SIP-6 asks for silence toward anyone who cannot authenticate, and
        // the envelope alone does not deliver it: a long header carrying a
        // version the QUIC stack does not know draws a Version Negotiation
        // reply out of it before any of the envelope's steps run. Drop those
        // here, where the stack cannot see them.
        //
        // Only the unknown-version case. A long header the stack *does*
        // recognise has to pass: the client's Handshake packets are
        // long-headed too, and dropping every non-Initial long header would
        // break every connection at the second flight. Those are silent
        // already — quinn ignores a non-Initial long header for a connection
        // it does not know.
        if is_long_header(&buf[..len]) && !long_header_version(&buf[..len]).is_some_and(version_is_supported)
        {
            return None;
        }

        if !is_quic_initial(&buf[..len]) {
            return Some(len); // non-Initial passes through
        }

        let marked = buf[len - 1];
        let mut challenge = false;

        // A marked version, if we accept it and it is not the unmarked one.
        if marked != ENVELOPE_V1 && self.accepts(marked) {
            match self.try_version(marked, buf, len, addr) {
                Outcome::Accepted(quic_len) => return Some(quic_len),
                Outcome::Challenge => challenge = true,
                Outcome::Drop => {}
            }
        }

        // Then the unmarked form, which is the only version that needs guessing.
        if self.accepts(ENVELOPE_V1) {
            match self.try_version(ENVELOPE_V1, buf, len, addr) {
                Outcome::Accepted(quic_len) => return Some(quic_len),
                Outcome::Challenge => challenge = true,
                Outcome::Drop => {}
            }
        }

        // At most one challenge per datagram, however many layouts were tried.
        if challenge && let Some(a) = addr {
            self.send_cookie_reply(a);
        }
        None
    }

    /// Whether this server parses `version`.
    fn accepts(&self, version: u8) -> bool {
        self.accepted_versions.contains(&version)
    }

    /// Validate one Initial under one envelope version.
    ///
    /// Returns `Challenge` rather than sending the cookie reply itself, so that
    /// trying two layouts cannot challenge the same caller twice.
    fn try_version(
        &self,
        version: u8,
        buf: &[u8],
        len: usize,
        addr: Option<SocketAddr>,
    ) -> Outcome {
        let Some(trailer) = trailer_len(version) else {
            return Outcome::Drop;
        };
        if len <= trailer {
            return Outcome::Drop; // too short
        }

        let quic_len = len - trailer;
        let mut off = quic_len;
        let client_pub = &buf[off..off + CLIENT_KEY_SIZE];
        off += CLIENT_KEY_SIZE;
        let ed25519 = &buf[off..off + ED25519_SIZE];
        off += ED25519_SIZE;
        let ts_bytes = &buf[off..off + TIMESTAMP_SIZE];
        off += TIMESTAMP_SIZE;
        let nonce = &buf[off..off + NONCE_SIZE];
        off += NONCE_SIZE;
        // MAC0 covers everything up to here, contiguously.
        let mac0_end = off;
        let mac0 = if has_mac0(version) {
            let m = &buf[off..off + MAC0_SIZE];
            off += MAC0_SIZE;
            Some(m)
        } else {
            None
        };
        let mac1_start = off;
        let mac1 = &buf[off..off + MAC_SIZE];
        off += MAC_SIZE;
        let mac2 = &buf[off..off + MAC2_SIZE];

        let timestamp = u32::from_be_bytes([ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3]]);

        // Step 1: Replay protection (cheap)
        if !timestamp_in_window(timestamp, now_timestamp()) {
            return Outcome::Drop;
        }

        // Step 2: MAC0 — the cheap gate (envelope v3).
        //
        // This is the step that makes the cookie defence below silent. MAC1 is
        // a Diffie-Hellman, so without something cheap in front of it a server
        // cannot tell a caller who knows its public key from a stranger, and
        // must therefore challenge both — which is how a server under load ends
        // up answering everybody. MAC0 costs one HMAC and settles that question
        // before the challenge is issued, and before the curve operation, so
        // rubbish never reaches either.
        //
        // Versions 1 and 2 carry no MAC0 and skip this. A caller on those
        // versions is still challenged without proving anything, so this closes
        // the hole only for v3 traffic — and closes it outright once a
        // deployment retires the older versions.
        if let Some(mac0) = mac0
            && !verify_mac0(version, &self.mac0_key, &buf[..mac0_end], mac0)
        {
            return Outcome::Drop;
        }

        // Step 3: MAC2 check — if under load, require valid MAC2
        if self.under_load.load(Ordering::Relaxed) {
            let is_zero = mac2.iter().all(|&b| b == 0);
            let mut mac2_valid = false;

            if !is_zero
                && let Some(a) = addr
            {
                let ip = a.ip();
                let data_before_mac2 = &buf[..mac1_start];
                let secret = *self.cookie_secret.read().unwrap();
                let cookie = cookie_value(&secret, ip);
                if verify_mac2(&cookie, data_before_mac2, mac1, mac2) {
                    mac2_valid = true;
                } else {
                    let prev = *self.prev_cookie_secret.read().unwrap();
                    let cookie = cookie_value(&prev, ip);
                    if verify_mac2(&cookie, data_before_mac2, mac1, mac2) {
                        mac2_valid = true;
                    }
                }
            }

            if mac2_valid {
                self.mac2_verified.fetch_add(1, Ordering::Relaxed);
            } else {
                return Outcome::Challenge;
            }
        }

        // Step 4: Whitelist check (fast, before expensive DH)
        let mut key = [0u8; 32];
        key.copy_from_slice(client_pub);
        if !self.whitelist.is_allowed(&key) {
            return Outcome::Drop;
        }

        // Step 5: DH + MAC1 verification (expensive)
        self.dh_count.fetch_add(1, Ordering::Relaxed);
        let client_x25519 = X25519Public::from(key);
        let shared = self.server_x25519_priv.diffie_hellman(&client_x25519);

        // A small-order client key makes the exchange non-contributory: the
        // shared secret comes out all zeros whatever our private key is, so a
        // caller who has never seen our public key can compute it in advance
        // and forge a MAC1 that verifies. That defeats the silent server
        // outright for any deployment without a whitelist, and it is the
        // whitelist — not this check — that has been carrying us.
        if !shared.was_contributory() {
            return Outcome::Drop;
        }

        if !verify_mac1(
            version,
            shared.as_bytes(),
            &buf[..quic_len],
            ed25519,
            timestamp,
            nonce,
            mac1,
        ) {
            return Outcome::Drop;
        }

        // MAC1 holds: this caller possesses the private key for `key` (X25519),
        // and the Ed25519 field is authenticated (it is in the MAC1 input). So
        // is the version marker, which SIP-29 prefixes to that input — a peer
        // that tampered with it produces a tag over a different layout, which
        // is why a flipped marker can only cost a drop and never an accept.
        //
        // SIP-3: if the caller asserted an Ed25519 identity (nonzero field), it
        // must forward-derive to the X25519 key MAC1 just proved. The map runs
        // this way — Ed25519 -> X25519 is a function — even though it does not
        // run backwards; the caller states which key is really its own and the
        // server checks the statement with work it is already doing. A mismatch,
        // a non-point key, or a small-order point fails the handshake rather
        // than downgrading to anonymous (the peer must not get to choose that
        // downgrade).
        //
        // All zeros means "no identity asserted". It is a *valid* point — the
        // order-4 point, deriving to u = 1 — not an invalid encoding, so it is
        // matched explicitly rather than left to fail the derivation.
        let identity = if ed25519.iter().all(|&b| b == 0) {
            None
        } else {
            let ed_arr: [u8; 32] = ed25519.try_into().expect("ED25519_SIZE == 32");
            match ed25519_identity_to_x25519(&ed_arr) {
                Ok(derived) if ct_eq(derived.as_bytes(), &key) => Some(ed_arr),
                _ => return Outcome::Drop,
            }
        };

        // Record (X25519 key, Ed25519 identity) against the Initial's DCID so the
        // application can recover the peer at accept (SIP-2 key, SIP-3 identity).
        if let Some(dcid) = initial_dcid(&buf[..quic_len]) {
            self.peer_table.record(dcid, key, identity, Instant::now());
        }

        if let Some(i) = crate::mac::version_index(version) {
            self.accepted[i].fetch_add(1, Ordering::Relaxed);
        }
        Outcome::Accepted(quic_len)
    }

    /// The MAC1-verified peer X25519 key recorded for `dcid`, if any (SIP-2).
    /// Called by the listener when the application accepts a connection.
    pub(crate) fn peer_key(&self, dcid: &[u8]) -> Option<[u8; 32]> {
        self.peer_table.get(dcid, Instant::now()).map(|(k, _)| k)
    }

    /// The MAC1-bound Ed25519 identity recorded for `dcid`, if the Initial
    /// carried one that forward-derived to the peer key (SIP-3).
    pub(crate) fn peer_identity(&self, dcid: &[u8]) -> Option<[u8; 32]> {
        self.peer_table.get(dcid, Instant::now()).and_then(|(_, id)| id)
    }

    fn send_cookie_reply(&self, addr: SocketAddr) {
        let secret = *self.cookie_secret.read().unwrap();
        let cookie = cookie_value(&secret, addr.ip());
        // Encrypted under the key derived from our public key, which the
        // client can also derive — not under `secret`, which is ours alone and
        // which the client could never decrypt with.
        if let Some(encrypted) = encrypt_cookie(&self.cookie_key, &cookie) {
            let mut reply = Vec::with_capacity(1 + encrypted.len());
            reply.push(COOKIE_REPLY_TYPE);
            reply.extend_from_slice(&encrypted);
            self.cookie_replies.fetch_add(1, Ordering::Relaxed);
            let _ = self.io.try_send_to(&reply, addr);
        }
    }

    /// Start the background work the cookie defence depends on: one task
    /// tracking DH load, one rotating the cookie secret.
    ///
    /// Without these `under_load` never becomes true and the whole MAC2 branch
    /// is unreachable, and `prev_cookie_secret` never holds a secret that was
    /// actually in use. Both hold a `Weak` reference and stop as soon as the
    /// endpoint is dropped, so a short-lived server does not leak a pair of
    /// tasks that keep its socket alive.
    pub fn spawn_maintenance(socket: &Arc<Self>) {
        if socket.load_threshold == 0 {
            // Cookie defence disabled: no load to track, and no cookies to
            // rotate secrets for.
            return;
        }

        let weak: Weak<Self> = Arc::downgrade(socket);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            // The first tick completes immediately, over a window that has not
            // elapsed yet. Discard it rather than judging load on no data.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(s) = weak.upgrade() else { return };
                let count = s.dh_count.swap(0, Ordering::Relaxed);
                s.under_load.store(count > s.load_threshold, Ordering::Relaxed);
            }
        });

        let weak: Weak<Self> = Arc::downgrade(socket);
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(COOKIE_SECRET_LIFETIME_SECS));
            ticker.tick().await; // the first tick completes immediately
            loop {
                ticker.tick().await;
                let Some(s) = weak.upgrade() else { return };
                let mut fresh = [0u8; 32];
                getrandom::fill(&mut fresh).expect("getrandom failed");
                let current = *s.cookie_secret.read().unwrap();
                *s.prev_cookie_secret.write().unwrap() = current;
                *s.cookie_secret.write().unwrap() = fresh;
            }
        });
    }

    /// A snapshot of the cookie defence's state.
    pub fn load_stats(&self) -> crate::LoadStats {
        crate::LoadStats {
            under_load: self.under_load.load(Ordering::Relaxed),
            cookie_replies_sent: self.cookie_replies.load(Ordering::Relaxed),
            mac2_verified: self.mac2_verified.load(Ordering::Relaxed),
            accepted_by_version: std::array::from_fn(|i| {
                (ENVELOPE_VERSIONS[i], self.accepted[i].load(Ordering::Relaxed))
            }),
        }
    }

    /// Force the under-load state, so a test does not have to win a race with
    /// the one-second load monitor to exercise the cookie path.
    #[doc(hidden)]
    pub fn set_under_load(&self, value: bool) {
        self.under_load.store(value, Ordering::Relaxed);
    }

    /// Rotate the cookie secret now, so a test does not have to wait out the
    /// 120-second timer to reach the grace branch.
    #[doc(hidden)]
    pub fn rotate_cookie_secret(&self) {
        let mut fresh = [0u8; 32];
        getrandom::fill(&mut fresh).expect("getrandom failed");
        let current = *self.cookie_secret.read().unwrap();
        *self.prev_cookie_secret.write().unwrap() = current;
        *self.cookie_secret.write().unwrap() = fresh;
    }
}

impl std::fmt::Debug for ServerSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSocket").finish()
    }
}

impl AsyncUdpSocket for ServerSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        let io = self.io.clone();
        Arc::new(UdpPollHelper { io }).create_io_poller_inner()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&*self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(count) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&*self.io).into(), bufs, metas)
            }) {
                // Validate each packet in place, stripping the envelope from
                // Initials, and compact the survivors to the front — quinn
                // expects the entries it is handed to be contiguous.
                //
                // One pass, and one definition of "kept". This used to count
                // survivors in a first pass and compact on `meta.len > 0` in a
                // second, which are not the same predicate: a zero-length
                // datagram is *accepted* by `validate_and_strip` (it is not an
                // Initial, so it passes through) and so was counted, but the
                // compaction skipped it. A batch holding one of those and one
                // dropped packet returned a count of 1 with nothing written,
                // handing quinn a stale `RecvMeta`. Harmless in practice —
                // quinn discards it — but two predicates for one property is
                // the kind of thing that stops being harmless when either side
                // is edited.
                let mut valid = 0;
                for read in 0..count {
                    let len = metas[read].len;
                    let addr = Some(metas[read].addr);
                    let Some(new_len) = self.validate_and_strip(&mut bufs[read][..len], len, addr)
                    else {
                        continue; // dropped
                    };
                    if new_len == 0 {
                        continue; // an empty datagram; there is nothing to parse
                    }
                    if valid != read {
                        metas[valid] = metas[read];
                        let (left, right) = bufs.split_at_mut(read);
                        left[valid][..new_len].copy_from_slice(&right[0][..new_len]);
                    }
                    metas[valid].len = new_len;
                    valid += 1;
                }
                if valid == 0 {
                    continue; // all dropped; poll again
                }
                return Poll::Ready(Ok(valid));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        // One. `socket_state` turned GRO off, so nothing coalesces; reporting
        // `gro_segments()` here would size buffers for segments that never
        // arrive. The setsockopt is the load-bearing half — this only tells
        // quinn what to expect, it does not stop the kernel.
        1
    }
}

/// Client-side UDP socket wrapper.
/// Appends MAC1 + client pubkey + timestamp to outgoing Initial packets.
pub struct ClientSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
    shared_secret: [u8; 32],
    client_pub_key: [u8; 32],
    /// SIP-3: the Ed25519 identity advertised in the Initial envelope, or all
    /// zeros to assert none. It forward-derives to `client_pub_key`.
    advertise_ed25519: [u8; 32],
    /// The address this client dialled. A cookie reply from anywhere else is
    /// not ours to act on.
    server_addr: SocketAddr,
    /// SIP-29: the envelope version this client emits. One version per
    /// connection attempt, never a fallback — the server is silent, so a
    /// timeout would say nothing about which version it wanted.
    envelope_version: u8,
    /// Keys MAC0 (envelope v3), derived from the server's public key.
    mac0_key: [u8; 32],
    cookie_key: [u8; 32], // decrypts cookie replies; derived from the server's public key
    handshake_done: AtomicBool, // true after first non-cookie packet received; skips the cookie scan
    cookie: RwLock<Option<[u8; 16]>>, // decrypted cookie from the server, keys MAC2
    // The most recent Initial datagram and where it went, so a cookie
    // challenge can be answered immediately rather than at the next PTO.
    last_initial: RwLock<Option<(Vec<u8>, SocketAddr)>>,
    /// Whether the current Initial has already had a challenge answered for
    /// it. One answer per Initial sent, which is what bounds the work an
    /// injected cookie reply can buy.
    answered: AtomicBool,
}

/// The key material a client derives before its socket exists.
///
/// Grouped because it is derived together, from the same two keys, and passing
/// five `[u8; 32]`s positionally is how they get transposed.
pub struct ClientKeys {
    /// X25519(client_priv, server_pub) — keys MAC1.
    pub shared_secret: [u8; 32],
    /// The client's X25519 public key, as it appears in the envelope.
    pub client_pub_key: [u8; 32],
    /// SIP-3: the Ed25519 identity to advertise, or all zeros for none.
    pub advertise_ed25519: [u8; 32],
    /// Keys MAC0 (envelope v3); derived from the server's public key.
    pub mac0_key: [u8; 32],
    /// Decrypts cookie replies; derived from the server's public key.
    pub cookie_key: [u8; 32],
}

impl ClientSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        keys: ClientKeys,
        server_addr: SocketAddr,
        envelope_version: u8,
    ) -> Self {
        let ClientKeys {
            shared_secret,
            client_pub_key,
            advertise_ed25519,
            mac0_key,
            cookie_key,
        } = keys;
        let inner = socket_state(&socket);
        Self {
            io: socket,
            inner,
            shared_secret,
            client_pub_key,
            advertise_ed25519,
            server_addr,
            envelope_version,
            mac0_key,
            cookie_key,
            handshake_done: AtomicBool::new(false),
            cookie: RwLock::new(None),
            last_initial: RwLock::new(None),
            answered: AtomicBool::new(false),
        }
    }
}

impl std::fmt::Debug for ClientSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSocket").finish()
    }
}

impl ClientSocket {
    /// Append the MAC1 envelope to one Initial datagram and send it raw.
    ///
    /// Every Initial must carry this envelope, not just the first: the server
    /// silently drops any Initial that fails MAC1, so an unauthenticated
    /// retransmission is indistinguishable from an attack and gets dropped.
    /// A client that stopped stamping after the first packet could never
    /// recover from losing it — the handshake would stall until it timed out.
    fn send_initial(&self, datagram: &[u8], destination: SocketAddr) -> io::Result<()> {
        let cookie = *self.cookie.read().unwrap();
        let buf = self.build_initial(datagram, cookie.as_ref());
        *self.last_initial.write().unwrap() = Some((datagram.to_vec(), destination));
        // A fresh Initial earns one answered challenge.
        self.answered.store(false, Ordering::Relaxed);

        // PERF NOTE: We bypass quinn-udp's UdpSocketState::send() here and
        // send the Initial packet as a raw datagram via try_send_to().
        //
        // Why: The Initial packet is 1308 bytes (1200 QUIC + 108 MAC overhead),
        // which exceeds Quinn's normal 1200-byte segment size. On Linux with
        // GSO (Generic Segmentation Offload) enabled, quinn-udp's send() with
        // segment_size: None is ambiguous — it may attempt to segment the packet
        // at 1200 bytes, silently dropping it. This caused the Rust client to
        // hang indefinitely during handshake on Linux VPS.
        //
        // Trade-off: Initial packets miss GSO, ECN marking, and sendmmsg
        // batching from quinn-udp. This is acceptable because:
        // 1. Initial packets are only sent while the handshake is in flight
        // 2. All subsequent 1-RTT data packets go through quinn-udp normally
        // 3. The Go client uses the same raw-send approach (WriteMsgUDP)
        //
        // If MAC_OVERHEAD changes, the static assertion in mac.rs will fail at
        // compile time. If the overhead is ever reduced to fit within 1200 bytes,
        // this bypass can be removed and the packet sent through quinn-udp.
        self.io.try_io(Interest::WRITABLE, || {
            self.io.try_send_to(&buf, destination).map(|_| ())
        })
    }

    /// Open a cookie reply and keep the cookie for the next Initial.
    ///
    /// The reply arrives encrypted; MAC2 is keyed on the plaintext, so it has
    /// to be opened here. A reply we cannot open did not come from a server
    /// holding the key we expect, so it is dropped and any cookie we already
    /// had is kept. Returns whether a cookie was stored.
    fn store_cookie(&self, payload: &[u8]) -> bool {
        let Some(plain) = decrypt_cookie(&self.cookie_key, payload) else {
            return false;
        };
        let Ok(c) = <[u8; 16]>::try_from(plain.as_slice()) else {
            return false;
        };

        // A reply carrying a cookie we already hold tells us nothing new, so
        // it earns no retransmission. Without this, one captured cookie reply
        // replayed at us is an unbounded supply of Initials aimed at the
        // server — the reply is 57 bytes and the Initial it provokes is
        // 1308.
        let is_new = {
            let mut slot = self.cookie.write().unwrap();
            let new = *slot != Some(c);
            *slot = Some(c);
            new
        };
        if is_new {
            self.answer_challenge(&c);
        }
        true
    }

    /// Re-send the last Initial straight away, now carrying MAC2.
    ///
    /// Quinn never sees a cookie reply — poll_recv strips them out — so left to
    /// itself it would not retransmit until its next PTO, roughly a second. The
    /// challenge is answerable immediately and waiting costs the caller a full
    /// second per challenge, so answer it here. WireGuard does the same.
    ///
    /// Replaying the datagram is sound. The server dropped the original at the
    /// MAC2 gate before quinn ever saw it, so this is the first time that packet
    /// number reaches the peer; in the case where it did get through (under-load
    /// cleared in between) quinn discards the duplicate. Only the sQUIC envelope
    /// is rebuilt — fresh timestamp, nonce and MAC1 — never the QUIC packet.
    fn answer_challenge(&self, cookie: &[u8; 16]) {
        // One answer per Initial sent. A challenge is a response to something
        // we sent, so answering more than once for the same Initial is work an
        // attacker chose for us rather than work the handshake needs. `swap`
        // is the whole check: whoever gets `false` answers, everyone else
        // returns.
        if self.answered.swap(true, Ordering::Relaxed) {
            return;
        }
        let Some((datagram, destination)) = self.last_initial.read().unwrap().clone() else {
            return; // nothing sent yet; the next Initial will carry the cookie
        };
        let buf = self.build_initial(&datagram, Some(cookie));
        let _ = self.io.try_io(Interest::WRITABLE, || {
            self.io.try_send_to(&buf, destination).map(|_| ())
        });
    }

    /// Build one Initial datagram plus its MAC envelope.
    ///
    /// Kept separate from the send so a test can check the bytes against what
    /// `ServerSocket::validate_and_strip` expects — the two sides disagreeing
    /// about what MAC2 covers is exactly the defect this guards.
    fn build_initial(&self, datagram: &[u8], cookie: Option<&[u8; 16]>) -> Vec<u8> {
        let ts = now_timestamp();
        let nonce = generate_nonce();
        let mac1 = compute_mac1(
            self.envelope_version,
            &self.shared_secret,
            datagram,
            &self.advertise_ed25519,
            ts,
            &nonce,
        );
        let mut buf = Vec::with_capacity(datagram.len() + crate::mac::MAC_OVERHEAD_V3);
        buf.extend_from_slice(datagram);
        buf.extend_from_slice(&self.client_pub_key);
        buf.extend_from_slice(&self.advertise_ed25519);
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&nonce);

        // MAC0 (v3): computed over exactly the bytes written so far, which is
        // the contiguous range the server hashes.
        if has_mac0(self.envelope_version) {
            let mac0 = compute_mac0(self.envelope_version, &self.mac0_key, &buf);
            buf.extend_from_slice(&mac0);
        }

        buf.extend_from_slice(&mac1);

        // MAC2: zeros if no cookie, computed if the server has sent us one.
        //
        // The server verifies over everything up to but NOT including mac1,
        // passing mac1 separately, so the slice here has to stop short of the
        // mac1 we just appended. Hashing buf whole folds mac1 in twice and
        // never verifies.
        match cookie {
            Some(c) => {
                let mac2 = compute_mac2(c, &buf[..buf.len() - MAC_SIZE], &mac1);
                buf.extend_from_slice(&mac2);
            }
            None => buf.extend_from_slice(&[0u8; MAC2_SIZE]),
        }

        // SIP-29: the marker goes last, after MAC2, because that is the only
        // offset a receiver can find without already knowing the trailer's
        // width. Version 1 predates it and emits nothing, which is what keeps
        // this client able to talk to a server that has not moved yet.
        if self.envelope_version != ENVELOPE_V1 {
            buf.push(self.envelope_version);
        }
        buf
    }
}

impl AsyncUdpSocket for ClientSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        let io = self.io.clone();
        Arc::new(UdpPollHelper { io }).create_io_poller_inner()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Hot path: short-header packets, which is everything after the
        // handshake. One byte test, no atomics.
        if !is_quic_initial(transmit.contents) {
            // A short header means 1-RTT keys, which means the handshake
            // finished — and only then can there be no further cookie
            // challenge, because only an Initial is ever challenged. This is
            // where the receive side's fast path is armed. Arming it on the
            // receive side instead, at the first batch containing no cookie,
            // was wrong: the very first packet back from the server clears it,
            // and a server that then enters under-load mode mid-handshake
            // challenges an Initial whose reply the client has stopped
            // reading, so the connection stalls until it times out.
            if is_short_header(transmit.contents) {
                self.handshake_done.store(true, Ordering::Relaxed);
            }
            return self.io.try_io(Interest::WRITABLE, || {
                self.inner.send((&*self.io).into(), transmit)
            });
        }

        // A GSO batch is several datagrams in one buffer; each needs its own
        // envelope, so send them individually.
        match transmit.segment_size {
            Some(seg) if seg < transmit.contents.len() => {
                for datagram in transmit.contents.chunks(seg) {
                    self.send_initial(datagram, transmit.destination)?;
                }
                Ok(())
            }
            _ => self.send_initial(transmit.contents, transmit.destination),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(count) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&*self.io).into(), bufs, metas)
            }) {
                // Fast path: after handshake, no cookie replies possible
                if self.handshake_done.load(Ordering::Relaxed) {
                    return Poll::Ready(Ok(count));
                }

                // Take out the cookie replies and compact what is left, in one
                // pass. Testing the type byte again during compaction is
                // cheaper than the flags array this used to carry, which was
                // fixed at 64 entries against a batch size that is quinn-udp's
                // to choose — safe at its current 32, and a panic if it ever
                // grew.
                let mut valid = 0;
                for i in 0..count {
                    let len = metas[i].len;
                    // A cookie reply is only ours if it came from the server we
                    // dialled. The reply is encrypted under a key derived from
                    // the server's *public* key, so anyone at all can mint one
                    // that opens — the source is the only thing that
                    // distinguishes the server from a stranger who wants us to
                    // shout at it.
                    if len > 0
                        && bufs[i][0] == COOKIE_REPLY_TYPE
                        && same_peer(metas[i].addr, self.server_addr)
                    {
                        self.store_cookie(&bufs[i][1..len]);
                        continue;
                    }
                    if valid != i {
                        metas[valid] = metas[i];
                        let src_len = metas[i].len;
                        let (left, right) = bufs.split_at_mut(i);
                        left[valid][..src_len].copy_from_slice(&right[0][..src_len]);
                    }
                    valid += 1;
                }
                if valid == 0 {
                    continue; // all were cookie replies, poll again
                }
                return Poll::Ready(Ok(valid));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        // One. `socket_state` turned GRO off, so nothing coalesces; reporting
        // `gro_segments()` here would size buffers for segments that never
        // arrive. The setsockopt is the load-bearing half — this only tells
        // quinn what to expect, it does not stop the kernel.
        1
    }
}

/// Helper to create a UdpPoller from a tokio UdpSocket.
struct UdpPollHelper {
    io: Arc<tokio::net::UdpSocket>,
}

impl UdpPollHelper {
    fn create_io_poller_inner(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        let io = self.io.clone();
        Box::pin(UdpPollWritable { io })
    }
}

#[derive(Debug)]
struct UdpPollWritable {
    io: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for UdpPollWritable {
    fn poll_writable(self: std::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}

use std::task::ready;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ed25519_private_to_x25519, x25519};
    use crate::mac::{cookie_key, ENVELOPE_V2, ENVELOPE_V3};
    use std::task::Waker;

    async fn socket() -> Arc<tokio::net::UdpSocket> {
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    /// Build a matched client and server over loopback sockets, with the
    /// client emitting version 1 and the server accepting both (SIP-29).
    async fn pair() -> (ServerSocket, ClientSocket) {
        pair_with(ENVELOPE_V1, vec![ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3]).await
    }

    /// As `pair`, choosing which envelope version the client emits and which
    /// the server will parse.
    async fn pair_with(
        client_version: u8,
        server_versions: Vec<u8>,
    ) -> (ServerSocket, ClientSocket) {
        let (signing_key, _) = crate::crypto::generate_keypair();
        let server_priv = ed25519_private_to_x25519(&signing_key);
        let server_pub = X25519Public::from(&server_priv);

        let client_priv = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let client_pub = X25519Public::from(&client_priv);
        let shared = x25519(&client_priv, &server_pub).unwrap();

        let server_sock = socket().await;
        let server_addr = server_sock.local_addr().unwrap();
        let server = ServerSocket::new(
            server_sock,
            server_priv,
            Arc::new(Whitelist::new(None)),
            1000,
            server_versions,
        );
        let client = ClientSocket::new(
            socket().await,
            ClientKeys {
                shared_secret: shared,
                client_pub_key: client_pub.to_bytes(),
                // advertise no Ed25519 identity (random X25519 test key)
                advertise_ed25519: [0u8; 32],
                mac0_key: crate::mac::mac0_key(server_pub.as_bytes()),
                cookie_key: cookie_key(server_pub.as_bytes()),
            },
            server_addr,
            client_version,
        );
        (server, client)
    }

    /// The four-way defect this pins down: the client has to be able to open
    /// the cookie at all, and then MAC2 has to cover exactly the bytes the
    /// server checks. Any of those disagreeing and the cookie defence rejects
    /// every legitimate client instead of only attackers.
    #[tokio::test]
    async fn client_mac2_is_what_the_server_verifies() {
        let (server, client) = pair().await;
        let peer = client.io.local_addr().unwrap();

        // Let the server issue a real challenge over a real socket, and let
        // the client open it with the code path poll_recv uses. Anything
        // reimplemented here would test the reimplementation instead.
        // send_cookie_reply is deliberately best-effort — it uses try_send_to
        // and drops the reply rather than blocking the recv path, so retry
        // until one lands.
        let mut reply = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                server.send_cookie_reply(peer);
                if let Ok(Ok((n, _))) = tokio::time::timeout(
                    Duration::from_millis(50),
                    client.io.recv_from(&mut reply),
                )
                .await
                {
                    return n;
                }
            }
        })
        .await
        .expect("no cookie reply arrived");
        assert_eq!(reply[0], COOKIE_REPLY_TYPE);
        assert!(
            client.store_cookie(&reply[1..n]),
            "client cannot open the cookie the server sent"
        );
        let cookie = client.cookie.read().unwrap().expect("cookie stored");

        // An Initial carrying that cookie must satisfy a server demanding one.
        server.set_under_load(true);
        let datagram = quic_initial(1200);
        let mut envelope = client.build_initial(&datagram, Some(&cookie));
        let len = envelope.len();

        assert_eq!(
            server.validate_and_strip(&mut envelope, len, Some(peer)),
            Some(1200),
            "server rejected an Initial carrying a cookie it issued itself"
        );
        assert_eq!(server.load_stats().mac2_verified, 1);
    }

    /// The other half: no cookie means challenged, not admitted.
    #[tokio::test]
    async fn under_load_an_initial_without_a_cookie_is_challenged() {
        let (server, client) = pair().await;
        let peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        server.set_under_load(true);

        let datagram = quic_initial(1200);
        let mut envelope = client.build_initial(&datagram, None);
        let len = envelope.len();

        assert_eq!(server.validate_and_strip(&mut envelope, len, Some(peer)), None);
        let stats = server.load_stats();
        assert_eq!(stats.mac2_verified, 0);
        assert_eq!(stats.cookie_replies_sent, 1);
    }

    /// A cookie minted for one address must not travel to another.
    #[tokio::test]
    async fn a_cookie_is_bound_to_the_address_it_was_issued_for() {
        let (server, client) = pair().await;
        let issued_to: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let used_by: SocketAddr = "127.0.0.2:40002".parse().unwrap();
        server.set_under_load(true);

        let secret = *server.cookie_secret.read().unwrap();
        let cookie = cookie_value(&secret, issued_to.ip());

        let datagram = quic_initial(1200);
        let mut envelope = client.build_initial(&datagram, Some(&cookie));
        let len = envelope.len();

        assert_eq!(server.validate_and_strip(&mut envelope, len, Some(used_by)), None);
        assert_eq!(server.load_stats().mac2_verified, 0);
    }

    /// A caller who has never seen the server's public key must not be able to
    /// pass MAC1. A small-order client key makes the exchange non-contributory
    /// — the shared secret is all zeros whatever the server's key is, and the
    /// attacker knows that in advance — so without the guard this succeeds and
    /// the silent server answers a stranger.
    #[tokio::test]
    async fn a_small_order_client_key_is_refused() {
        let (server, _client) = pair().await;
        let peer: SocketAddr = "127.0.0.1:40404".parse().unwrap();

        let datagram = quic_initial(1200);
        let zero_key = [0u8; 32];
        // The attacker assumes the exchange yields zeros, and is right.
        let assumed_shared = [0u8; 32];

        let ed = [0u8; 32];
        let ts = now_timestamp();
        let nonce = generate_nonce();
        let mac1 = compute_mac1(ENVELOPE_V1, &assumed_shared, &datagram, &ed, ts, &nonce);

        let mut buf = Vec::new();
        buf.extend_from_slice(&datagram);
        buf.extend_from_slice(&zero_key);
        buf.extend_from_slice(&ed);
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&mac1);
        buf.extend_from_slice(&[0u8; MAC2_SIZE]);
        let len = buf.len();

        assert_eq!(
            server.validate_and_strip(&mut buf, len, Some(peer)),
            None,
            "a stranger forged a valid MAC1 with a small-order key"
        );
    }

    /// The same degenerate exchange reached from the other side: a client given
    /// a server key of small order must refuse rather than proceed with a
    /// secret anyone can predict.
    #[tokio::test]
    async fn a_small_order_server_key_is_refused() {
        let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let zero_pub = X25519Public::from([0u8; 32]);
        assert!(
            crate::crypto::x25519(&priv_key, &zero_pub).is_err(),
            "client accepted a non-contributory exchange"
        );
    }

    /// Not under load, MAC2 is not consulted, so the zeros a fresh client sends
    /// are fine. This is the path every normal connection takes.
    #[tokio::test]
    async fn without_load_no_cookie_is_required() {
        let (server, client) = pair().await;
        let peer: SocketAddr = "127.0.0.1:40003".parse().unwrap();

        let datagram = quic_initial(1200);
        let mut envelope = client.build_initial(&datagram, None);
        let len = envelope.len();

        assert_eq!(server.validate_and_strip(&mut envelope, len, Some(peer)), Some(1200));
    }


    const DATAGRAM: usize = 1200;

    /// A datagram shaped like a real QUIC v1 Initial: long header, version 1,
    /// an 8-byte DCID.
    ///
    /// The version field is load-bearing in a fixture now. The server drops a
    /// long header whose version its QUIC stack would not parse, so a buffer
    /// filled with 0xC0 — whose version field reads 0xC0C0C0C0 — never reaches
    /// the envelope at all, and a test built on one that asserts a *drop*
    /// passes without exercising the thing it names.
    fn quic_initial(len: usize) -> Vec<u8> {
        let mut pkt = vec![0xC0u8; len];
        pkt[1..5].copy_from_slice(&1u32.to_be_bytes()); // QUIC v1
        pkt[5] = 8; // DCID length
        pkt[6..14].copy_from_slice(&[0xA1u8; 8]); // DCID
        pkt
    }

    fn initial() -> Vec<u8> {
        quic_initial(DATAGRAM)
    }

    /// A version 2 client and a server that accepts version 2 agree on the
    /// whole envelope: the marker's position, the trailer's width, and the
    /// version prefix in MAC1.
    #[tokio::test]
    async fn version_2_round_trips() {
        let (server, client) = pair_with(ENVELOPE_V2, vec![ENVELOPE_V1, ENVELOPE_V2]).await;
        let mut envelope = client.build_initial(&initial(), None);
        assert_eq!(envelope.len(), DATAGRAM + crate::mac::MAC_OVERHEAD_V2);
        assert_eq!(*envelope.last().unwrap(), ENVELOPE_V2, "marker is not last");

        let len = envelope.len();
        assert_eq!(
            server.validate_and_strip(&mut envelope, len, None),
            Some(DATAGRAM)
        );
    }

    /// The transition case, and the reason this SIP is worth having: one server
    /// serving both versions at once.
    #[tokio::test]
    async fn a_server_serves_both_versions_at_once() {
        for version in [ENVELOPE_V1, ENVELOPE_V2] {
            let (server, client) = pair_with(version, vec![ENVELOPE_V1, ENVELOPE_V2]).await;
            let mut envelope = client.build_initial(&initial(), None);
            let len = envelope.len();
            assert_eq!(
                server.validate_and_strip(&mut envelope, len, None),
                Some(DATAGRAM),
                "server accepting both refused version {version}"
            );
        }
    }

    /// A version 1 packet's last byte is the last byte of MAC2. With no cookie
    /// that is deterministically zero — the reserved version, never a marker —
    /// so the collision only arises for a packet carrying a real MAC2, which
    /// means one issued under load. Forced here, because one in 256 is not a
    /// thing to leave to chance in a test.
    #[tokio::test]
    async fn a_version_1_packet_naming_version_2_still_gets_through() {
        let (server, client) = pair_with(ENVELOPE_V1, vec![ENVELOPE_V1, ENVELOPE_V2]).await;
        let mut envelope = client.build_initial(&initial(), None);
        assert_eq!(*envelope.last().unwrap(), 0, "no cookie should mean a zero tail");

        // Now make it look like a version 2 marker. Not under load, so MAC2's
        // contents are never examined and only the dispatch changes.
        *envelope.last_mut().unwrap() = ENVELOPE_V2;
        let len = envelope.len();
        assert_eq!(
            server.validate_and_strip(&mut envelope, len, None),
            Some(DATAGRAM),
            "the version 1 fallback did not rescue a packet that named version 2"
        );
    }

    /// The S8 finding, and the reason envelope v3 exists.
    ///
    /// Under load the server challenges before it knows who is calling, because
    /// MAC1 is a Diffie-Hellman and there is nothing cheaper in front of it. So
    /// a stranger — no key, no captured traffic — sends something Initial-shaped
    /// with a plausible timestamp and gets a cookie reply, which is a server
    /// that is supposed to be silent telling them it exists.
    ///
    /// With v3 the same stranger is dropped at MAC0, before the challenge.
    #[tokio::test]
    async fn under_load_a_stranger_is_not_challenged_on_version_3() {
        let (server, _client) = pair_with(ENVELOPE_V3, vec![ENVELOPE_V3]).await;
        let peer: SocketAddr = "127.0.0.1:40501".parse().unwrap();
        server.set_under_load(true);

        // Everything an attacker can produce without the server's public key:
        // a real QUIC v1 header, a timestamp inside the window, and noise for
        // the rest of the envelope.
        let mut buf = quic_initial(1200);
        buf.extend_from_slice(&[0x42u8; CLIENT_KEY_SIZE]);
        buf.extend_from_slice(&[0u8; ED25519_SIZE]);
        buf.extend_from_slice(&now_timestamp().to_be_bytes());
        buf.extend_from_slice(&generate_nonce());
        buf.extend_from_slice(&[0x11u8; MAC0_SIZE]); // guessed
        buf.extend_from_slice(&[0x22u8; MAC_SIZE]);
        buf.extend_from_slice(&[0x33u8; MAC2_SIZE]);
        buf.push(ENVELOPE_V3);
        let len = buf.len();

        assert_eq!(server.validate_and_strip(&mut buf, len, Some(peer)), None);
        let stats = server.load_stats();
        assert_eq!(
            stats.cookie_replies_sent, 0,
            "a stranger drew a cookie out of a server that is supposed to be silent"
        );
        assert_eq!(stats.mac2_verified, 0);
    }

    /// And the other half: a caller that *does* hold the server's public key is
    /// still challenged, so the cookie defence keeps working for the people it
    /// is meant to serve.
    #[tokio::test]
    async fn under_load_a_caller_who_knows_the_key_is_still_challenged() {
        let (server, client) = pair_with(ENVELOPE_V3, vec![ENVELOPE_V3]).await;
        let peer: SocketAddr = "127.0.0.1:40502".parse().unwrap();
        server.set_under_load(true);

        let mut envelope = client.build_initial(&initial(), None);
        let len = envelope.len();
        assert_eq!(server.validate_and_strip(&mut envelope, len, Some(peer)), None);
        assert_eq!(
            server.load_stats().cookie_replies_sent, 1,
            "a legitimate caller was not challenged, so it can never learn the cookie"
        );
    }

    /// A v3 envelope whose MAC0 does not verify is dropped even when the server
    /// is not under load — the gate is unconditional, so rubbish costs one HMAC
    /// rather than a curve operation.
    #[tokio::test]
    async fn a_bad_mac0_is_dropped_without_a_diffie_hellman() {
        let (server, client) = pair_with(ENVELOPE_V3, vec![ENVELOPE_V3]).await;
        let mut envelope = client.build_initial(&initial(), None);
        // Corrupt MAC0, which sits just before MAC1 and MAC2 and the marker.
        let mac0_at = envelope.len() - (MAC_SIZE + MAC2_SIZE + 1 + MAC0_SIZE);
        envelope[mac0_at] ^= 0xFF;
        let len = envelope.len();
        assert_eq!(server.validate_and_strip(&mut envelope, len, None), None);
    }

    /// Version 3 round-trips: both ends agree on the trailer width, where MAC0
    /// sits, and what it covers.
    #[tokio::test]
    async fn version_3_round_trips() {
        let (server, client) = pair_with(ENVELOPE_V3, vec![ENVELOPE_V3]).await;
        let mut envelope = client.build_initial(&initial(), None);
        assert_eq!(envelope.len(), DATAGRAM + crate::mac::MAC_OVERHEAD_V3);
        assert_eq!(*envelope.last().unwrap(), ENVELOPE_V3);
        let len = envelope.len();
        assert_eq!(
            server.validate_and_strip(&mut envelope, len, None),
            Some(DATAGRAM)
        );
    }

    /// One server serving all three at once, which is what makes the rollout
    /// possible at all.
    #[tokio::test]
    async fn a_server_serves_all_three_versions() {
        for version in [ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3] {
            let (server, client) =
                pair_with(version, vec![ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3]).await;
            let mut envelope = client.build_initial(&initial(), None);
            let len = envelope.len();
            assert_eq!(
                server.validate_and_strip(&mut envelope, len, None),
                Some(DATAGRAM),
                "server accepting all three refused version {version}"
            );
        }
    }

    /// The honest limit of this fix, pinned so nobody mistakes it for done: a
    /// server that still accepts v1 or v2 keeps answering strangers on those
    /// versions, because those envelopes have no MAC0 to check. S8 is closed
    /// only when a deployment retires them.
    #[tokio::test]
    async fn a_v1_stranger_is_still_challenged_while_v1_is_accepted() {
        let (server, _client) = pair_with(ENVELOPE_V1, vec![ENVELOPE_V1, ENVELOPE_V3]).await;
        let peer: SocketAddr = "127.0.0.1:40503".parse().unwrap();
        server.set_under_load(true);

        let mut buf = quic_initial(1200);
        buf.extend_from_slice(&[0x42u8; CLIENT_KEY_SIZE]);
        buf.extend_from_slice(&[0u8; ED25519_SIZE]);
        buf.extend_from_slice(&now_timestamp().to_be_bytes());
        buf.extend_from_slice(&generate_nonce());
        buf.extend_from_slice(&[0x22u8; MAC_SIZE]);
        buf.extend_from_slice(&[0x33u8; MAC2_SIZE]);
        let len = buf.len();

        assert_eq!(server.validate_and_strip(&mut buf, len, Some(peer)), None);
        assert_eq!(
            server.load_stats().cookie_replies_sent, 1,
            "expected v1 to still leak a challenge — if this changed, update SIP-7 and the rollout note"
        );
    }

    /// Drive one pass of the client's receive path, so the cookie-reply
    /// handling in `poll_recv` is what the tests below exercise rather than a
    /// reimplementation of it.
    fn pump(client: &ClientSocket) {
        let mut cx = Context::from_waker(Waker::noop());
        let mut b = [0u8; 2048];
        let mut bufs = [std::io::IoSliceMut::new(&mut b)];
        let mut metas = [quinn::udp::RecvMeta::default()];
        let _ = client.poll_recv(&mut cx, &mut bufs, &mut metas);
    }

    /// Anyone can mint a cookie reply the client will open — it is sealed under
    /// a key derived from the server's *public* key, which is published. So the
    /// source address is the only thing separating the server from a stranger
    /// who would like the client to send a 1308-byte Initial for every 57 bytes
    /// they spend.
    #[tokio::test]
    async fn a_cookie_reply_from_a_stranger_is_ignored() {
        let (server, client) = pair().await;
        let server_addr = server.io.local_addr().unwrap();
        let client_addr = client.io.local_addr().unwrap();
        let mut junk = vec![0u8; 4096];

        // An Initial in flight, so a challenge would be answerable.
        client.io.writable().await.unwrap();
        client.send_initial(&initial(), server_addr).unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            server.io.recv_from(&mut junk),
        )
        .await;

        let stranger = socket().await;
        let sealed = encrypt_cookie(&client.cookie_key, &[0x9Au8; 16]).unwrap();
        let mut reply = vec![COOKIE_REPLY_TYPE];
        reply.extend_from_slice(&sealed);
        stranger.send_to(&reply, client_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.io.writable().await.unwrap();
        pump(&client);

        assert!(
            client.cookie.read().unwrap().is_none(),
            "a stranger set our cookie"
        );
        let echoed = tokio::time::timeout(
            Duration::from_millis(300),
            server.io.recv_from(&mut junk),
        )
        .await;
        assert!(
            echoed.is_err(),
            "an injected cookie reply made the client shout at the server"
        );
    }

    /// The amplifier this closes: one Initial earns one answered challenge,
    /// however many replies arrive. Each reply here carries a *different*
    /// cookie, so it is the per-Initial allowance being measured and not the
    /// duplicate check.
    #[tokio::test]
    async fn one_initial_earns_one_answered_challenge() {
        let (server, client) = pair().await;
        let server_addr = server.io.local_addr().unwrap();
        let client_addr = client.io.local_addr().unwrap();
        let mut junk = vec![0u8; 4096];

        client.io.writable().await.unwrap();
        client.send_initial(&initial(), server_addr).unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            server.io.recv_from(&mut junk),
        )
        .await;

        for i in 0..10u8 {
            let sealed = encrypt_cookie(&client.cookie_key, &[i; 16]).unwrap();
            let mut reply = vec![COOKIE_REPLY_TYPE];
            reply.extend_from_slice(&sealed);
            server.io.send_to(&reply, client_addr).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        client.io.writable().await.unwrap();
        for _ in 0..10 {
            pump(&client);
        }

        let mut answers = 0;
        while tokio::time::timeout(
            Duration::from_millis(250),
            server.io.recv_from(&mut junk),
        )
        .await
        .is_ok()
        {
            answers += 1;
        }
        assert_eq!(
            answers, 1,
            "ten injected replies bought {answers} Initials; the allowance is one per Initial sent"
        );
    }

    /// And a cookie we already hold earns nothing, even after a fresh Initial
    /// has re-armed the allowance. A captured reply replayed at the client is
    /// then worth nothing at all.
    #[tokio::test]
    async fn a_repeated_cookie_earns_no_further_answer() {
        let (server, client) = pair().await;
        let server_addr = server.io.local_addr().unwrap();
        let client_addr = client.io.local_addr().unwrap();
        let mut junk = vec![0u8; 4096];

        let sealed = encrypt_cookie(&client.cookie_key, &[0x77u8; 16]).unwrap();
        let mut reply = vec![COOKIE_REPLY_TYPE];
        reply.extend_from_slice(&sealed);

        // First Initial, first reply: answered.
        client.io.writable().await.unwrap();
        client.send_initial(&initial(), server_addr).unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(300), server.io.recv_from(&mut junk)).await;
        server.io.send_to(&reply, client_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.io.writable().await.unwrap();
        pump(&client);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), server.io.recv_from(&mut junk))
                .await
                .is_ok(),
            "the first challenge was not answered at all"
        );

        // A second Initial re-arms the allowance, so only the duplicate check
        // stands between a replayed reply and another Initial.
        client.io.writable().await.unwrap();
        client.send_initial(&initial(), server_addr).unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(300), server.io.recv_from(&mut junk)).await;
        server.io.send_to(&reply, client_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.io.writable().await.unwrap();
        pump(&client);

        assert!(
            tokio::time::timeout(Duration::from_millis(300), server.io.recv_from(&mut junk))
                .await
                .is_err(),
            "a cookie we already held bought another Initial"
        );
    }

    /// The receive path counted survivors with one predicate and compacted
    /// with another. A zero-length datagram sits exactly in the gap: it is not
    /// an Initial, so `validate_and_strip` passes it through and it was
    /// counted — but it has no length, so the compaction skipped it, and quinn
    /// could be handed a count covering an entry nothing had written.
    ///
    /// There is nothing in an empty datagram for quinn to parse, so it is
    /// dropped and reported as what it is: nothing.
    #[tokio::test]
    async fn a_zero_length_datagram_is_not_reported_as_a_packet() {
        let (server, _client) = pair().await;
        let server_addr = server.io.local_addr().unwrap();

        let sender = socket().await;
        sender.send_to(&[], server_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut cx = Context::from_waker(Waker::noop());
        let mut b = [0u8; 2048];
        let mut bufs = [std::io::IoSliceMut::new(&mut b)];
        let mut metas = [quinn::udp::RecvMeta::default()];
        match server.poll_recv(&mut cx, &mut bufs, &mut metas) {
            Poll::Pending => {}
            Poll::Ready(Ok(n)) => panic!(
                "reported {n} packet(s) for a zero-length datagram, with meta.len = {}",
                metas[0].len
            ),
            Poll::Ready(Err(e)) => panic!("poll_recv errored: {e}"),
        }
    }

    /// A dual-stack socket may report an IPv4 peer either way round, and the
    /// server's own reply must not be turned away for it.
    #[test]
    fn same_peer_sees_through_the_ipv4_mapped_form() {
        let v4: SocketAddr = "192.0.2.7:443".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:443".parse().unwrap();
        assert!(same_peer(v4, mapped));
        assert!(same_peer(mapped, v4));
        // A different port or host is a different peer.
        assert!(!same_peer(v4, "192.0.2.7:444".parse().unwrap()));
        assert!(!same_peer(v4, "192.0.2.8:443".parse().unwrap()));
    }

    /// The counter that turns retiring a version from nerve into arithmetic.
    ///
    /// A server that drops an envelope does so in silence, so retiring one that
    /// clients are still sending locks them out with nothing in any log on
    /// either side. Before this there was no way to ask "is anything still
    /// arriving on version 2" — the question the decision rests on.
    #[tokio::test]
    async fn accepted_initials_are_counted_per_envelope_version() {
        let (server, _c) = pair_with(ENVELOPE_V1, vec![ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3]).await;

        let count = |s: &ServerSocket, v: u8| {
            s.load_stats()
                .accepted_by_version
                .iter()
                .find(|(ver, _)| *ver == v)
                .map(|(_, n)| *n)
                .expect("every known version is reported")
        };

        for (version, times) in [(ENVELOPE_V1, 1), (ENVELOPE_V2, 3), (ENVELOPE_V3, 2)] {
            let (_s, client) =
                pair_with(version, vec![ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3]).await;
            for _ in 0..times {
                let mut envelope = client.build_initial(&initial(), None);
                let len = envelope.len();
                // The client here was built against a different server, so its
                // MAC1 will not verify — drive the counter through the server
                // under test with its own client instead.
                let _ = server.validate_and_strip(&mut envelope, len, None);
            }
        }

        // Only the matched client's envelopes are accepted, so every count is
        // zero — which is the point: a rejected Initial must not be counted as
        // an arrival on its claimed version.
        for v in [ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3] {
            assert_eq!(count(&server, v), 0, "a rejected envelope was counted");
        }

        // Now the real thing: one client that matches this server.
        let (server, client) =
            pair_with(ENVELOPE_V2, vec![ENVELOPE_V1, ENVELOPE_V2, ENVELOPE_V3]).await;
        for _ in 0..3 {
            let mut envelope = client.build_initial(&initial(), None);
            let len = envelope.len();
            assert_eq!(server.validate_and_strip(&mut envelope, len, None), Some(DATAGRAM));
        }
        assert_eq!(count(&server, ENVELOPE_V2), 3);
        assert_eq!(count(&server, ENVELOPE_V1), 0);
        assert_eq!(count(&server, ENVELOPE_V3), 0);
    }

    /// A deployment must be able to retire a version, or the oldest envelope
    /// ever defined is a permanent floor.
    #[tokio::test]
    async fn a_server_can_retire_version_1() {
        let (server, client) = pair_with(ENVELOPE_V1, vec![ENVELOPE_V2]).await;
        let mut envelope = client.build_initial(&initial(), None);
        let len = envelope.len();
        assert_eq!(
            server.validate_and_strip(&mut envelope, len, None),
            None,
            "a server that retired version 1 still accepted it"
        );
    }

    /// And a server that has not learned version 2 refuses it, which is the
    /// direction that does not interoperate and the reason for servers-first.
    #[tokio::test]
    async fn a_version_1_server_refuses_version_2() {
        let (server, client) = pair_with(ENVELOPE_V2, vec![ENVELOPE_V1]).await;
        let mut envelope = client.build_initial(&initial(), None);
        let len = envelope.len();
        assert_eq!(server.validate_and_strip(&mut envelope, len, None), None);
    }

    /// The marker is read before it is authenticated. Tampering with it must
    /// cost a drop and never an accept: MAC1 covers it as a prefix, so a
    /// flipped marker is a tag over a layout the sender never used.
    #[tokio::test]
    async fn a_flipped_marker_is_dropped() {
        let (server, client) = pair_with(ENVELOPE_V2, vec![ENVELOPE_V1, ENVELOPE_V2]).await;
        let mut envelope = client.build_initial(&initial(), None);
        *envelope.last_mut().unwrap() = 7; // a version nobody defines
        let len = envelope.len();
        assert_eq!(
            server.validate_and_strip(&mut envelope, len, None),
            None,
            "an unknown marker was accepted"
        );
    }
}

#[cfg(test)]
mod peer_table_tests {
    use super::*;

    #[test]
    fn same_dcid_same_key_is_idempotent() {
        let t = PeerTable::default();
        let now = Instant::now();
        t.record(b"cid1", [1u8; 32], Some([9u8; 32]), now);
        t.record(b"cid1", [1u8; 32], Some([9u8; 32]), now); // retransmission
        assert_eq!(t.get(b"cid1", now), Some(([1u8; 32], Some([9u8; 32]))));
    }

    #[test]
    fn contested_dcid_is_poisoned_and_answers_for_neither() {
        let t = PeerTable::default();
        let now = Instant::now();
        t.record(b"cid1", [1u8; 32], None, now);
        t.record(b"cid1", [2u8; 32], None, now); // different key, same DCID
        assert_eq!(t.get(b"cid1", now), None, "poisoned entry must not resolve");
    }

    #[test]
    fn contested_identity_is_also_poisoned() {
        let t = PeerTable::default();
        let now = Instant::now();
        t.record(b"cid1", [1u8; 32], Some([9u8; 32]), now);
        t.record(b"cid1", [1u8; 32], Some([8u8; 32]), now); // same key, different identity
        assert_eq!(t.get(b"cid1", now), None);
    }

    #[test]
    fn get_is_a_peek_not_a_drain() {
        // SIP-2 peer_key and SIP-3 peer_identity are read separately for one
        // connection, so a read must not remove the entry.
        let t = PeerTable::default();
        let now = Instant::now();
        t.record(b"cid1", [1u8; 32], None, now);
        assert_eq!(t.get(b"cid1", now), Some(([1u8; 32], None)));
        assert_eq!(t.get(b"cid1", now), Some(([1u8; 32], None)));
    }

    #[test]
    fn expired_entry_does_not_resolve() {
        let t = PeerTable::default();
        let start = Instant::now();
        t.record(b"cid1", [1u8; 32], None, start);
        let later = start + PEER_KEY_TTL + Duration::from_secs(1);
        assert_eq!(t.get(b"cid1", later), None);
    }

    /// The finding this replaces: the old prune dropped only *expired* entries
    /// and then inserted regardless, so when arrivals outran the TTL it freed
    /// nothing and the table grew without limit — while every insert past the
    /// threshold paid for a full scan that reclaimed nothing, under the lock,
    /// on the receive path. A peer that can pass MAC1 could drive both.
    #[test]
    fn table_is_bounded_by_a_flood_of_fresh_entries() {
        let t = PeerTable::default();
        let now = Instant::now();
        for i in 0..(PEER_TABLE_MAX * 3) {
            // Every one distinct, every one fresh: nothing is ever expired, so
            // the old prune would have reclaimed nothing on any of these.
            t.record(&(i as u64).to_be_bytes(), [1u8; 32], None, now);
        }
        assert!(
            t.len() <= PEER_TABLE_MAX,
            "table grew to {} entries, past the {PEER_TABLE_MAX} bound",
            t.len()
        );
    }

    /// Eviction takes from the oldest end, so the caller that just arrived —
    /// whose key is read within milliseconds — is the last thing to go.
    #[test]
    fn the_newest_entry_survives_a_flood() {
        let t = PeerTable::default();
        let now = Instant::now();
        for i in 0..(PEER_TABLE_MAX * 2) {
            t.record(&(i as u64).to_be_bytes(), [1u8; 32], None, now);
        }
        t.record(b"mine", [7u8; 32], Some([8u8; 32]), now);
        assert_eq!(t.get(b"mine", now), Some(([7u8; 32], Some([8u8; 32]))));
    }

    /// Expiry runs off the queue front rather than a scan, so it must still be
    /// exact: everything past the TTL goes, everything inside it stays.
    #[test]
    fn expiry_takes_the_old_and_leaves_the_new() {
        let t = PeerTable::default();
        let start = Instant::now();
        t.record(b"old", [1u8; 32], None, start);
        let later = start + PEER_KEY_TTL + Duration::from_secs(1);
        t.record(b"new", [2u8; 32], None, later);

        assert_eq!(t.get(b"old", later), None, "past its TTL");
        assert_eq!(t.get(b"new", later), Some(([2u8; 32], None)));
        assert_eq!(t.len(), 1, "the expired entry was not reclaimed");
    }

    /// A retransmission no longer extends the entry — it lives its TTL from
    /// first sight. That is what keeps the order queue exact, and it stops a
    /// peer holding an entry open forever by retransmitting. 30s of TTL
    /// against a 10s handshake timeout leaves the handshake covered either way.
    #[test]
    fn a_retransmission_does_not_extend_the_entry() {
        let t = PeerTable::default();
        let start = Instant::now();
        t.record(b"cid1", [1u8; 32], None, start);
        // Retransmitted most of a TTL later, and still resolving at that point.
        let midway = start + Duration::from_secs(25);
        t.record(b"cid1", [1u8; 32], None, midway);
        assert_eq!(t.get(b"cid1", midway), Some(([1u8; 32], None)));

        // Expiry is measured from the first sighting, not the last.
        let past = start + PEER_KEY_TTL + Duration::from_secs(1);
        assert_eq!(t.get(b"cid1", past), None);
    }

    #[test]
    fn dcid_parsed_from_initial_header() {
        // flags, 4-byte version, len=4, then 4-byte DCID, then payload.
        let pkt = [0xC0, 0, 0, 0, 1, 4, 0xAA, 0xBB, 0xCC, 0xDD, 0x99];
        assert_eq!(initial_dcid(&pkt), Some(&[0xAA, 0xBB, 0xCC, 0xDD][..]));
        // Over-long length is rejected rather than trusted.
        let bad = [0xC0, 0, 0, 0, 1, 21];
        assert_eq!(initial_dcid(&bad), None);
    }
}

#[cfg(test)]
mod short_header_tests {
    use super::*;

    /// The client stops watching for cookie replies when it sends its first
    /// 1-RTT packet, so this test decides when that happens. Getting it wrong
    /// in one direction leaves the fast path permanently disarmed; in the other
    /// it disarms the cookie path during the handshake, which is the stall this
    /// classification was introduced to fix.
    #[test]
    fn classifies_quic_headers() {
        // Short header: header-form clear, fixed bit set. 1-RTT, and only 1-RTT.
        assert!(is_short_header(&[0x40]));
        assert!(is_short_header(&[0x7F]));

        // Long headers, whatever their packet type — Initial, 0-RTT, Handshake,
        // Retry — all have the header-form bit set.
        for first in [0xC0u8, 0xD0, 0xE0, 0xF0] {
            assert!(!is_short_header(&[first]), "long header {first:#04x}");
        }

        // A cookie reply is neither, which is what lets it share the socket.
        assert!(!is_short_header(&[COOKIE_REPLY_TYPE]));
        assert!(!is_quic_initial(&[COOKIE_REPLY_TYPE, 0, 0, 0, 0]));

        // Fixed bit clear is not a QUIC packet at all.
        assert!(!is_short_header(&[0x00]));
        assert!(!is_short_header(&[]));
    }
}
