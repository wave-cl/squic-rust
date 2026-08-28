use crate::mac::{
    compute_mac1, compute_mac2, cookie_value, ct_eq, decrypt_cookie, encrypt_cookie, generate_nonce,
    is_quic_initial, now_timestamp, timestamp_in_window, trailer_len, verify_mac1, verify_mac2,
    CLIENT_KEY_SIZE, COOKIE_REPLY_TYPE, COOKIE_SECRET_LIFETIME_SECS, ED25519_SIZE, ENVELOPE_V1,
    MAC2_SIZE,
    MAC_OVERHEAD, MAC_SIZE, NONCE_SIZE, TIMESTAMP_SIZE,
};
use crate::crypto::ed25519_identity_to_x25519;
use crate::whitelist::Whitelist;
use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::AsyncUdpSocket;
use std::io;
use std::net::SocketAddr;
use std::collections::HashMap;
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

/// Above this many live entries, an insert first drops the expired ones. Keeps
/// the table bounded without a background task; the bound is generous because
/// each entry is tiny and the healthy steady state is near-empty.
const PEER_TABLE_PRUNE_AT: usize = 512;

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
    map: Mutex<HashMap<Vec<u8>, PeerEntry>>,
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
        let mut map = self.map.lock().unwrap();
        if map.len() >= PEER_TABLE_PRUNE_AT {
            map.retain(|_, e| now.duration_since(e.inserted) < PEER_KEY_TTL);
        }
        match map.get_mut(dcid) {
            Some(e) if e.poisoned => {}
            Some(e) if e.key == key && e.identity == identity => e.inserted = now,
            Some(e) => e.poisoned = true,
            None => {
                map.insert(
                    dcid.to_vec(),
                    PeerEntry { key, identity, inserted: now, poisoned: false },
                );
            }
        }
    }

    /// Return the (key, identity) recorded for `dcid`, if one is present, not
    /// poisoned, and not expired. This is a peek, not a drain: an application may
    /// read the peer key and the peer identity separately for one connection
    /// (SIP-2 + SIP-3), so both accessors must resolve. The table is bounded by
    /// the TTL and the prune-on-insert instead.
    fn get(&self, dcid: &[u8], now: Instant) -> Option<([u8; 32], Option<[u8; 32]>)> {
        let map = self.map.lock().unwrap();
        let entry = map.get(dcid)?;
        if entry.poisoned || now.duration_since(entry.inserted) >= PEER_KEY_TTL {
            return None;
        }
        Some((entry.key, entry.identity))
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
    // MAC2 + cookie DDoS protection
    cookie_key: [u8; 32],
    cookie_secret: RwLock<[u8; 32]>,
    prev_cookie_secret: RwLock<[u8; 32]>,
    under_load: AtomicBool,
    dh_count: AtomicU64,
    cookie_replies: AtomicU64,
    mac2_verified: AtomicU64,
    load_threshold: u64,
    /// Envelope versions this server parses (SIP-29).
    accepted_versions: Vec<u8>,
    /// DCID -> MAC1-verified peer key, drained by the application at accept.
    peer_table: PeerTable,
}

impl ServerSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        server_x25519_priv: X25519Secret,
        whitelist: Arc<Whitelist>,
        load_threshold: u64,
        accepted_versions: Vec<u8>,
    ) -> Self {
        let inner = UdpSocketState::new((&*socket).into()).expect("UdpSocketState::new");
        let cookie_key = crate::mac::cookie_key(
            X25519Public::from(&server_x25519_priv).as_bytes(),
        );
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("getrandom failed");
        Self {
            io: socket,
            inner,
            server_x25519_priv,
            whitelist,
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
        let mac1_start = off;
        let mac1 = &buf[off..off + MAC_SIZE];
        off += MAC_SIZE;
        let mac2 = &buf[off..off + MAC2_SIZE];

        let timestamp = u32::from_be_bytes([ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3]]);

        // Step 1: Replay protection (cheap)
        if !timestamp_in_window(timestamp, now_timestamp()) {
            return Outcome::Drop;
        }

        // Step 2: MAC2 check — if under load, require valid MAC2
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

        // Step 3: Whitelist check (fast, before expensive DH)
        let mut key = [0u8; 32];
        key.copy_from_slice(client_pub);
        if !self.whitelist.is_allowed(&key) {
            return Outcome::Drop;
        }

        // Step 4: DH + MAC1 verification (expensive)
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
                // Validate each received packet in place.
                // Strip MAC overhead from Initial packets by adjusting meta.len.
                // Invalid packets get meta.len = 0 and are counted as dropped.
                let mut valid = 0;
                for i in 0..count {
                    let len = metas[i].len;
                    let buf = &mut bufs[i][..len];
                    let addr = Some(metas[i].addr);
                    match self.validate_and_strip(buf, len, addr) {
                        Some(new_len) => {
                            metas[i].len = new_len;
                            valid += 1;
                        }
                        None => {
                            metas[i].len = 0; // mark as dropped
                        }
                    }
                }
                // Remove dropped packets by compacting metas
                // (Quinn expects contiguous valid entries)
                if valid < count {
                    let mut write = 0;
                    for read in 0..count {
                        if metas[read].len > 0 {
                            if write != read {
                                metas[write] = metas[read];
                                // Copy packet data to compacted position
                                let len = metas[write].len;
                                let (left, right) = bufs.split_at_mut(read);
                                left[write][..len].copy_from_slice(&right[0][..len]);
                            }
                            write += 1;
                        }
                    }
                }
                if valid == 0 {
                    // All dropped, need to poll again
                    continue;
                } else {
                    return Poll::Ready(Ok(valid));
                }
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
        self.inner.gro_segments()
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
    /// SIP-29: the envelope version this client emits. One version per
    /// connection attempt, never a fallback — the server is silent, so a
    /// timeout would say nothing about which version it wanted.
    envelope_version: u8,
    cookie_key: [u8; 32], // decrypts cookie replies; derived from the server's public key
    handshake_done: AtomicBool, // true after first non-cookie packet received; skips the cookie scan
    cookie: RwLock<Option<[u8; 16]>>, // decrypted cookie from the server, keys MAC2
    // The most recent Initial datagram and where it went, so a cookie
    // challenge can be answered immediately rather than at the next PTO.
    last_initial: RwLock<Option<(Vec<u8>, SocketAddr)>>,
}

impl ClientSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        shared_secret: [u8; 32],
        client_pub_key: [u8; 32],
        advertise_ed25519: [u8; 32],
        cookie_key: [u8; 32],
        envelope_version: u8,
    ) -> Self {
        let inner = UdpSocketState::new((&*socket).into()).expect("UdpSocketState::new");
        Self {
            io: socket,
            inner,
            shared_secret,
            client_pub_key,
            advertise_ed25519,
            envelope_version,
            cookie_key,
            handshake_done: AtomicBool::new(false),
            cookie: RwLock::new(None),
            last_initial: RwLock::new(None),
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
        match <[u8; 16]>::try_from(plain.as_slice()) {
            Ok(c) => {
                *self.cookie.write().unwrap() = Some(c);
                self.answer_challenge(&c);
                true
            }
            Err(_) => false,
        }
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
        let mut buf = Vec::with_capacity(datagram.len() + MAC_OVERHEAD + 1);
        buf.extend_from_slice(datagram);
        buf.extend_from_slice(&self.client_pub_key);
        buf.extend_from_slice(&self.advertise_ed25519);
        buf.extend_from_slice(&ts.to_be_bytes());
        buf.extend_from_slice(&nonce);
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
                    if len > 0 && bufs[i][0] == COOKIE_REPLY_TYPE {
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
        self.inner.gro_segments()
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
    use crate::mac::{cookie_key, ENVELOPE_V2};

    async fn socket() -> Arc<tokio::net::UdpSocket> {
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    /// Build a matched client and server over loopback sockets, with the
    /// client emitting version 1 and the server accepting both (SIP-29).
    async fn pair() -> (ServerSocket, ClientSocket) {
        pair_with(ENVELOPE_V1, vec![ENVELOPE_V1, ENVELOPE_V2]).await
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

        let server = ServerSocket::new(
            socket().await,
            server_priv,
            Arc::new(Whitelist::new(None)),
            1000,
            server_versions,
        );
        let client = ClientSocket::new(
            socket().await,
            shared,
            client_pub.to_bytes(),
            [0u8; 32], // advertise no Ed25519 identity (random X25519 test key)
            cookie_key(server_pub.as_bytes()),
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
        let datagram = vec![0xC0u8; 1200];
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

        let datagram = vec![0xC0u8; 1200];
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

        let datagram = vec![0xC0u8; 1200];
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

        let datagram = vec![0xC0u8; 1200];
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

        let datagram = vec![0xC0u8; 1200];
        let mut envelope = client.build_initial(&datagram, None);
        let len = envelope.len();

        assert_eq!(server.validate_and_strip(&mut envelope, len, Some(peer)), Some(1200));
    }


    const DATAGRAM: usize = 1200;

    fn initial() -> Vec<u8> {
        vec![0xC0u8; DATAGRAM]
    }

    /// A version 2 client and a server that accepts version 2 agree on the
    /// whole envelope: the marker's position, the trailer's width, and the
    /// version prefix in MAC1.
    #[tokio::test]
    async fn version_2_round_trips() {
        let (server, client) = pair_with(ENVELOPE_V2, vec![ENVELOPE_V1, ENVELOPE_V2]).await;
        let mut envelope = client.build_initial(&initial(), None);
        assert_eq!(envelope.len(), DATAGRAM + MAC_OVERHEAD + 1);
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
