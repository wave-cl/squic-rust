use crate::mac::{
    compute_mac1, is_quic_initial, now_timestamp, timestamp_in_window, verify_mac1, MAC_OVERHEAD,
    CLIENT_KEY_SIZE, TIMESTAMP_SIZE,
};
use crate::whitelist::Whitelist;
use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::AsyncUdpSocket;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
}

impl ServerSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        server_x25519_priv: X25519Secret,
        whitelist: Arc<Whitelist>,
    ) -> Self {
        let inner = UdpSocketState::new((&*socket).into()).expect("UdpSocketState::new");
        Self {
            io: socket,
            inner,
            server_x25519_priv,
            whitelist,
        }
    }

    fn validate_and_strip(&self, buf: &mut [u8], len: usize) -> Option<usize> {
        if !is_quic_initial(&buf[..len]) {
            return Some(len); // non-Initial passes through
        }

        if len <= MAC_OVERHEAD {
            return None; // too short
        }

        let quic_len = len - MAC_OVERHEAD;
        let client_pub = &buf[quic_len..quic_len + CLIENT_KEY_SIZE];
        let ts_bytes = &buf[quic_len + CLIENT_KEY_SIZE..quic_len + CLIENT_KEY_SIZE + TIMESTAMP_SIZE];
        let mac1 = &buf[quic_len + CLIENT_KEY_SIZE + TIMESTAMP_SIZE..len];

        let timestamp = u32::from_be_bytes([ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3]]);

        // Step 1: Replay protection
        if !timestamp_in_window(timestamp, now_timestamp()) {
            return None;
        }

        // Step 2: Whitelist check (fast, before expensive DH)
        let mut key = [0u8; 32];
        key.copy_from_slice(client_pub);
        if !self.whitelist.is_allowed(&key) {
            return None;
        }

        // Step 3: DH + MAC1 verification
        let client_x25519 = X25519Public::from(key);
        let shared = self.server_x25519_priv.diffie_hellman(&client_x25519);

        if !verify_mac1(shared.as_bytes(), &buf[..quic_len], timestamp, mac1) {
            return None;
        }

        Some(quic_len)
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
                    match self.validate_and_strip(buf, len) {
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
        if !self.initial_sent.load(Ordering::Relaxed) && is_quic_initial(transmit.contents) {
            self.initial_sent.store(true, Ordering::Relaxed);
            let ts = now_timestamp();
            let mac = compute_mac1(&self.shared_secret, transmit.contents, ts);
            let mut buf = Vec::with_capacity(transmit.contents.len() + MAC_OVERHEAD);
            buf.extend_from_slice(transmit.contents);
            buf.extend_from_slice(&self.client_pub_key);
            buf.extend_from_slice(&ts.to_be_bytes());
            buf.extend_from_slice(&mac);
            let new_transmit = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &buf,
                segment_size: None, // Initial is a single packet; disable GSO to avoid size mismatch from MAC1 overhead
                src_ip: transmit.src_ip,
            };
            self.io.try_io(Interest::WRITABLE, || {
                self.inner.send((&*self.io).into(), &new_transmit)
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
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&*self.io).into(), bufs, metas)
            }) {
                return Poll::Ready(Ok(res));
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
