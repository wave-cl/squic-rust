use crate::mac::{
    compute_mac1, compute_mac2, cookie_value, encrypt_cookie, generate_nonce, is_quic_initial,
    now_timestamp, timestamp_in_window, verify_mac1, verify_mac2, CLIENT_KEY_SIZE,
    COOKIE_REPLY_TYPE, MAC_OVERHEAD, MAC_SIZE, NONCE_SIZE, TIMESTAMP_SIZE,
};
use crate::whitelist::Whitelist;
use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::AsyncUdpSocket;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::io::Interest;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Server-side UDP socket wrapper.
/// Validates MAC1 on incoming Initial packets, silently drops invalid ones.
pub struct ServerSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: UdpSocketState,
    server_x25519_priv: X25519Secret,
    whitelist: Arc<Whitelist>,
    // MAC2 + cookie DDoS protection
    cookie_secret: RwLock<[u8; 32]>,
    prev_cookie_secret: RwLock<[u8; 32]>,
    under_load: AtomicBool,
    dh_count: AtomicU64,
    load_threshold: u64,
}

impl ServerSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        server_x25519_priv: X25519Secret,
        whitelist: Arc<Whitelist>,
        load_threshold: u64,
    ) -> Self {
        let inner = UdpSocketState::new((&*socket).into()).expect("UdpSocketState::new");
        let mut secret1 = [0u8; 32];
        let mut secret2 = [0u8; 32];
        getrandom::fill(&mut secret1).expect("getrandom failed");
        getrandom::fill(&mut secret2).expect("getrandom failed");
        Self {
            io: socket,
            inner,
            server_x25519_priv,
            whitelist,
            cookie_secret: RwLock::new(secret1),
            prev_cookie_secret: RwLock::new(secret2),
            under_load: AtomicBool::new(false),
            dh_count: AtomicU64::new(0),
            load_threshold: if load_threshold == 0 { 1000 } else { load_threshold },
        }
    }

    fn validate_and_strip(&self, buf: &mut [u8], len: usize, addr: Option<SocketAddr>) -> Option<usize> {
        if !is_quic_initial(&buf[..len]) {
            return Some(len); // non-Initial passes through
        }

        if len <= MAC_OVERHEAD {
            return None; // too short
        }

        let quic_len = len - MAC_OVERHEAD;
        let mut off = quic_len;
        let client_pub = &buf[off..off + CLIENT_KEY_SIZE];
        off += CLIENT_KEY_SIZE;
        let ts_bytes = &buf[off..off + TIMESTAMP_SIZE];
        off += TIMESTAMP_SIZE;
        let nonce = &buf[off..off + NONCE_SIZE];
        off += NONCE_SIZE;
        let mac1_start = off;
        let mac1 = &buf[off..off + MAC_SIZE];
        off += MAC_SIZE;
        let mac2 = &buf[off..len];

        let timestamp = u32::from_be_bytes([ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3]]);

        // Step 1: Replay protection (cheap)
        if !timestamp_in_window(timestamp, now_timestamp()) {
            return None;
        }

        // Step 2: MAC2 check — if under load, require valid MAC2
        if self.under_load.load(Ordering::Relaxed) {
            let is_zero = mac2.iter().all(|&b| b == 0);
            let mut mac2_valid = false;

            if !is_zero {
                if let Some(a) = addr {
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
            }

            if !mac2_valid {
                // Send cookie reply and drop
                if let Some(a) = addr {
                    self.send_cookie_reply(a);
                }
                return None;
            }
        }

        // Step 3: Whitelist check (fast, before expensive DH)
        let mut key = [0u8; 32];
        key.copy_from_slice(client_pub);
        if !self.whitelist.is_allowed(&key) {
            return None;
        }

        // Step 4: DH + MAC1 verification (expensive)
        self.dh_count.fetch_add(1, Ordering::Relaxed);
        let client_x25519 = X25519Public::from(key);
        let shared = self.server_x25519_priv.diffie_hellman(&client_x25519);

        if !verify_mac1(shared.as_bytes(), &buf[..quic_len], timestamp, nonce, mac1) {
            return None;
        }

        Some(quic_len)
    }

    fn send_cookie_reply(&self, addr: SocketAddr) {
        let secret = *self.cookie_secret.read().unwrap();
        let cookie = cookie_value(&secret, addr.ip());
        if let Some(encrypted) = encrypt_cookie(&secret, &cookie) {
            let mut reply = Vec::with_capacity(1 + encrypted.len());
            reply.push(COOKIE_REPLY_TYPE);
            reply.extend_from_slice(&encrypted);
            let _ = self.io.try_send_to(&reply, addr);
        }
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
    initial_sent: AtomicBool,
    handshake_done: AtomicBool, // true after first non-cookie packet received; skips all checks
    cookie: RwLock<Option<Vec<u8>>>, // stored cookie from server for MAC2
}

impl ClientSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        shared_secret: [u8; 32],
        client_pub_key: [u8; 32],
    ) -> Self {
        let inner = UdpSocketState::new((&*socket).into()).expect("UdpSocketState::new");
        Self {
            io: socket,
            inner,
            shared_secret,
            client_pub_key,
            initial_sent: AtomicBool::new(false),
            handshake_done: AtomicBool::new(false),
            cookie: RwLock::new(None),
        }
    }
}

impl std::fmt::Debug for ClientSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSocket").finish()
    }
}

impl AsyncUdpSocket for ClientSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        let io = self.io.clone();
        Arc::new(UdpPollHelper { io }).create_io_poller_inner()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Fast path: after handshake, all packets go directly to quinn-udp
        if self.handshake_done.load(Ordering::Relaxed) {
            return self.io.try_io(Interest::WRITABLE, || {
                self.inner.send((&*self.io).into(), transmit)
            });
        }

        if !self.initial_sent.load(Ordering::Relaxed) && is_quic_initial(transmit.contents) {
            self.initial_sent.store(true, Ordering::Relaxed);
            let ts = now_timestamp();
            let nonce = generate_nonce();
            let mac1 = compute_mac1(&self.shared_secret, transmit.contents, ts, &nonce);
            let mut buf = Vec::with_capacity(transmit.contents.len() + MAC_OVERHEAD);
            buf.extend_from_slice(transmit.contents);
            buf.extend_from_slice(&self.client_pub_key);
            buf.extend_from_slice(&ts.to_be_bytes());
            buf.extend_from_slice(&nonce);
            buf.extend_from_slice(&mac1);

            // MAC2: zeros if no cookie, computed if cookie available
            let cookie = self.cookie.read().unwrap();
            if let Some(ref c) = *cookie {
                let mac2 = compute_mac2(c, &buf[..buf.len()], &mac1);
                buf.extend_from_slice(&mac2);
            } else {
                buf.extend_from_slice(&[0u8; 16]); // MAC2 = zeros
            }

            // PERF NOTE: We bypass quinn-udp's UdpSocketState::send() here and
            // send the Initial packet as a raw datagram via try_send_to().
            //
            // Why: The Initial packet is 1276 bytes (1200 QUIC + 76 MAC overhead),
            // which exceeds Quinn's normal 1200-byte segment size. On Linux with
            // GSO (Generic Segmentation Offload) enabled, quinn-udp's send() with
            // segment_size: None is ambiguous — it may attempt to segment the packet
            // at 1200 bytes, silently dropping it. This caused the Rust client to
            // hang indefinitely during handshake on Linux VPS.
            //
            // Trade-off: This single Initial packet misses GSO, ECN marking, and
            // sendmmsg batching from quinn-udp. This is acceptable because:
            // 1. Initial packets are sent once per connection (not on the hot path)
            // 2. All subsequent 1-RTT data packets go through quinn-udp normally
            // 3. The Go client uses the same raw-send approach (WriteMsgUDP)
            //
            // If MAC_OVERHEAD changes, the static assertion in mac.rs will fail at
            // compile time. If the overhead is ever reduced to fit within 1200 bytes,
            // this bypass can be removed and the packet sent through quinn-udp.
            self.io.try_io(Interest::WRITABLE, || {
                (&*self.io).try_send_to(&buf, transmit.destination)
                    .map(|_| ())
            })
        } else {
            self.io.try_io(Interest::WRITABLE, || {
                self.inner.send((&*self.io).into(), transmit)
            })
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

                // Check for cookie replies — store them, mark for removal
                let mut is_cookie = [false; 64]; // stack array, max GRO batch size
                let mut any_cookie = false;
                for i in 0..count {
                    let len = metas[i].len;
                    if len > 0 && bufs[i][0] == COOKIE_REPLY_TYPE {
                        let cookie_data = bufs[i][1..len].to_vec();
                        *self.cookie.write().unwrap() = Some(cookie_data);
                        is_cookie[i] = true;
                        any_cookie = true;
                    }
                }

                // If no cookies in this batch, handshake is done — set fast path
                if !any_cookie {
                    self.handshake_done.store(true, Ordering::Relaxed);
                    return Poll::Ready(Ok(count));
                }

                // Compact non-cookie packets
                let mut valid = 0;
                for i in 0..count {
                    if is_cookie[i] {
                        continue;
                    }
                    if valid != i {
                        metas[valid] = metas[i];
                        let src_len = metas[valid].len;
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
