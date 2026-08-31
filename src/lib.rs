pub mod conn;
pub mod crypto;
pub mod mac;
pub mod tls;
pub mod whitelist;

use conn::{ClientSocket, ServerSocket};
use crypto::{ed25519_private_to_x25519, ed25519_public_to_x25519, x25519};
use ed25519_dalek::SigningKey;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use whitelist::Whitelist;
use x25519_dalek::PublicKey as X25519Public;

/// Create a UDP socket with 2MB send/recv buffers for high-throughput QUIC.
/// Linux defaults to ~160KB which causes ACK loss at high data rates.
fn create_udp_socket(addr: SocketAddr) -> std::result::Result<std::net::UdpSocket, Error> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .map_err(Error::Io)?;
    // 2MB buffers — critical on Linux where defaults are ~160KB
    let _ = sock.set_recv_buffer_size(2 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(2 * 1024 * 1024);
    sock.set_nonblocking(true).map_err(Error::Io)?;
    sock.bind(&addr.into()).map_err(Error::Io)?;
    Ok(sock.into())
}

/// Connection IDs that are unguessable and that this endpoint recognises for
/// nothing after the fact.
///
/// quinn sends a **stateless reset** when a short-header packet arrives for a
/// connection it does not know, provided the destination CID passes the
/// generator's `validate` — a reply to a caller that has proved nothing, which
/// is exactly what a silent server must not send. squic-go closes this by
/// leaving `StatelessResetKey` nil; quinn 0.11 has no equivalent, because
/// `EndpointConfig::new` requires a reset key and `Default` fills a random one,
/// so the reply is on by default and there is no switch to turn it off.
///
/// `validate` is consulted in exactly one place in quinn — the gate in front of
/// that reset (`endpoint.rs`, the `!is_initial() && validate(..).is_err()`
/// branch). Live traffic never reaches it: a packet for a connection the
/// endpoint knows is routed by the connection index several branches earlier.
/// So refusing every CID here makes the reset unreachable and costs a
/// legitimate peer nothing.
///
/// The CIDs are random for a second reason. quinn's default
/// `HashedConnectionIdGenerator` signs an 8-byte CID with five bytes of
/// `rustc_hash::FxHasher` keyed on a `u64` — a non-cryptographic, algebraically
/// invertible hash, over CIDs that travel in cleartext in the server's own
/// long-header packets. Recovering that key from a handful of observed CIDs is
/// arithmetic, after which an attacker mints CIDs that validate. Random CIDs
/// carry nothing to recover.
///
/// The cost is the one squic-go already accepts: a peer whose server has
/// forgotten it waits out `max_idle_timeout` instead of being told at once.
#[derive(Debug, Clone, Copy, Default)]
struct SilentCidGenerator;

/// Eight bytes, matching quinn's own default.
const CID_LEN: usize = 8;

impl quinn::ConnectionIdGenerator for SilentCidGenerator {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut bytes = [0u8; CID_LEN];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        quinn::ConnectionId::new(&bytes)
    }

    /// Recognise nothing. The trait permits false positives here and this is
    /// the opposite — a false negative for every CID, including our own — whose
    /// only effect at quinn's single call site is to drop a packet that would
    /// otherwise have been answered with a stateless reset.
    fn validate(&self, _cid: &quinn::ConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        Err(quinn_proto::InvalidCid)
    }

    fn cid_len(&self) -> usize {
        CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// The endpoint configuration both ends use.
///
/// `EndpointConfig::default()` is not usable as-is: it enables stateless resets
/// and it picks a CID generator whose signature can be forged. See
/// [`SilentCidGenerator`].
fn endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.cid_generator(|| Box::<SilentCidGenerator>::default());
    // Belt and braces. With `validate` refusing everything the reset is already
    // unreachable, but this is the only other lever quinn offers and the
    // property should not rest on one of them alone.
    config.min_reset_interval(Duration::from_secs(86_400));
    config
}

/// Errors returned by sQUIC operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("quinn connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("quinn connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("tls: {0}")]
    Tls(String),
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
}

/// Congestion control algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionController {
    /// CUBIC (default). Good general-purpose algorithm.
    Cubic,
    /// BBR. Better for bufferbloat and high-latency links.
    Bbr,
}

/// Configuration for sQUIC connections.
pub struct Config {
    /// Maximum idle timeout. Default: 30 seconds.
    pub max_idle_timeout: Duration,
    /// Maximum concurrent incoming streams. Default: 100.
    pub max_incoming_streams: u64,
    /// TLS ALPN protocols. Default: ["squic"].
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Optional client key whitelist (X25519 public keys).
    pub allowed_keys: Option<Vec<[u8; 32]>>,

    /// Send periodic keep-alive packets. Default: None (disabled).
    pub keep_alive: Option<Duration>,
    /// Maximum time for handshake to complete. Default: None (Quinn default: 10s).
    pub handshake_timeout: Option<Duration>,
    /// Per-stream receive window. Default: None (1 MB).
    pub stream_receive_window: Option<u64>,
    /// Connection-level receive window. Default: None (10 MB).
    pub receive_window: Option<u64>,
    /// Maximum unacknowledged data. Default: None (10 MB).
    pub send_window: Option<u64>,

    /// Initial UDP payload size. Range: 1200-65000. Default: None (1200).
    pub initial_mtu: Option<u16>,
    /// Disable path MTU discovery. Default: false.
    pub disable_mtu_discovery: bool,
    /// Enable QUIC datagram support (RFC 9221). Default: false.
    pub enable_datagrams: bool,
    /// Initial RTT estimate. Default: None (333ms).
    pub initial_rtt: Option<Duration>,
    /// Disable active connection migration (RFC 9000 §9). Default: false.
    pub disable_active_migration: bool,
    /// Congestion control algorithm. Default: Cubic.
    pub congestion_controller: CongestionController,
    /// Optional hex-encoded Ed25519 private key seed (64 hex chars).
    /// When set, dial() uses this persistent identity instead of generating an ephemeral one.
    /// The client's X25519 public key is derived from this for MAC1 and whitelist matching.
    pub client_key: Option<String>,
    /// SIP-3: advertise this client's Ed25519 identity in the Initial envelope,
    /// so the server can report it at accept via `peer_identity()` without
    /// having pre-registered the caller. Requires `client_key` (the identity to
    /// advertise is derived from it); ignored otherwise. Default: `false` —
    /// callers stay anonymous on the wire (the field is zeros) unless they opt
    /// in, since the identity is server-visible plaintext.
    pub advertise_identity: bool,
    /// DH operations per second before the server enters under-load mode and
    /// starts requiring a cookie (MAC2) from callers it has not challenged yet.
    /// Default: 1000. `Some(0)` disables the cookie defence entirely.
    pub load_threshold: Option<u64>,
    /// SIP-29: the envelope version this client emits.
    ///
    /// Default: `ENVELOPE_V3` as of v0.20.0. It was `ENVELOPE_V2` in v0.19.0,
    /// which introduced version 3 — the discipline SIP-29 requires is that a
    /// release introducing a version ships clients still sending the previous
    /// one, so upgrading a client before a server cannot break anything, and a
    /// later release moves the default once servers have deployed. This is
    /// that later release.
    ///
    /// Version 3 is what carries MAC0 (SIP-37), so this is also the release
    /// that lets a deployment retire versions 1 and 2 and get a server that
    /// stays silent under load.
    ///
    /// Set it back to `ENVELOPE_V2` if you still talk to a server older than
    /// squic v0.19.0, or to `ENVELOPE_V1` for one older than v0.17.0. Either
    /// will drop a version 3 Initial in silence, so the symptom of aiming too
    /// high is a handshake timeout with no diagnostic.
    pub envelope_version: u8,
    /// SIP-29: the envelope versions this server parses.
    ///
    /// Default: all of them, so a server can be upgraded without waiting for
    /// its clients. Drop older versions to retire them — which a deployment
    /// MUST be able to do, or the oldest envelope ever defined becomes a
    /// permanent floor.
    ///
    /// Retiring v1 and v2 is what finishes the job v3 starts. Only v3 carries
    /// MAC0, so only a v3 caller can be turned away before the cookie stage; a
    /// server still accepting v1 or v2 will keep answering callers on those
    /// versions with a cookie while it is under load, whatever they know. Set
    /// this to `vec![ENVELOPE_V3]` once the clients have moved.
    pub accepted_envelope_versions: Vec<u8>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(30),
            max_incoming_streams: 100,
            alpn_protocols: vec![b"squic".to_vec()],
            allowed_keys: None,
            keep_alive: None,
            handshake_timeout: None,
            stream_receive_window: None,
            receive_window: None,
            send_window: None,
            initial_mtu: None,
            disable_mtu_discovery: false,
            enable_datagrams: false,
            initial_rtt: None,
            disable_active_migration: false,
            congestion_controller: CongestionController::Cubic,
            client_key: None,
            advertise_identity: false,
            load_threshold: None,
            envelope_version: crate::mac::ENVELOPE_V3,
            accepted_envelope_versions: vec![
                crate::mac::ENVELOPE_V1,
                crate::mac::ENVELOPE_V2,
                crate::mac::ENVELOPE_V3,
            ],
        }
    }
}

/// A snapshot of the server's cookie-based DDoS defence.
///
/// Worth watching: `under_load` means the server has stopped doing
/// Diffie-Hellman for callers that have not echoed back a cookie, which costs
/// every new client an extra round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    /// Whether the server is currently demanding a valid MAC2.
    pub under_load: bool,
    /// Cookie challenges issued since start.
    pub cookie_replies_sent: u64,
    /// Initial packets accepted on a valid MAC2 since start.
    pub mac2_verified: u64,
}

/// Server listener with silent-server support.
pub struct ServerListener {
    endpoint: quinn::Endpoint,
    whitelist: Arc<Whitelist>,
    socket: Arc<ServerSocket>,
    public_key: [u8; 32],
}

impl ServerListener {
    /// Accept the next incoming connection.
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }

    /// This server's Ed25519 public key — the one clients pin when they dial.
    ///
    /// This is the identity half of the signing key passed to [`listen`], and
    /// it is what a client supplies as `server_pub_key` to [`dial`]. Callers
    /// otherwise have to keep a copy of it alongside the listener, which is
    /// how it has been done so far.
    ///
    /// Note this is the *server's own* key, not the caller's: sQUIC verifies
    /// the peer's X25519 key while validating the Initial packet, but does not
    /// currently surface it, and it could not be reported as Ed25519 in any
    /// case — the map from Ed25519 to X25519 does not run backwards.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The peer's X25519 public key for a connection being accepted, as
    /// verified by MAC1 on its Initial packet — or `None` if none was
    /// recorded.
    ///
    /// Pass the `Incoming` yielded by [`accept`](Self::accept); the key is
    /// looked up by the connection's original destination CID. `None` covers a
    /// peer that never passed MAC1 (there is none), a DCID contested by two
    /// different keys, and an entry that expired before accept. The lookup is a
    /// peek, so [`peer_key`](Self::peer_key) and
    /// [`peer_identity`](Self::peer_identity) may both be read for one
    /// connection (SIP-2 + SIP-3).
    ///
    /// This is the *transport* key. On its own it is not the caller's Ed25519
    /// identity and cannot be reversed to one; a closed-set consumer forward-
    /// matches known keys (SIP-2). For the Ed25519 name an unregistered caller
    /// asserts, use [`peer_identity`](Self::peer_identity) (SIP-3).
    pub fn peer_key(&self, incoming: &quinn::Incoming) -> Option<[u8; 32]> {
        self.socket.peer_key(incoming.orig_dst_cid().as_ref())
    }

    /// The peer's MAC1-bound Ed25519 identity for a connection being accepted
    /// (SIP-3), or `None` if the caller advertised none (the common, anonymous
    /// case), the DCID was contested, or the entry expired.
    ///
    /// When present, the transport proved possession of the matching scalar and
    /// the server checked that this Ed25519 key forward-derives to the verified
    /// X25519 key — so an open-set service (e.g. a public exchange) may name and
    /// authorise the caller by this key without having pre-registered it.
    pub fn peer_identity(&self, incoming: &quinn::Incoming) -> Option<[u8; 32]> {
        self.socket.peer_identity(incoming.orig_dst_cid().as_ref())
    }

    /// Add a client key to the whitelist.
    pub fn allow_key(&self, key: &[u8; 32]) {
        self.whitelist.allow_key(*key);
    }

    /// Remove a client key from the whitelist.
    pub fn remove_key(&self, key: &[u8; 32]) {
        self.whitelist.remove_key(key);
    }

    /// Check if a key is in the whitelist.
    pub fn has_key(&self, key: &[u8; 32]) -> bool {
        self.whitelist.has_key(key)
    }

    /// Get a copy of all whitelisted keys.
    pub fn allowed_keys(&self) -> Vec<[u8; 32]> {
        self.whitelist.allowed_keys()
    }

    /// Enable whitelisting with the given keys.
    pub fn enable_whitelist(&self, keys: &[[u8; 32]]) {
        self.whitelist.enable(keys);
    }

    /// Disable whitelisting.
    pub fn disable_whitelist(&self) {
        self.whitelist.disable();
    }

    /// Get the local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// A snapshot of the cookie defence's state.
    pub fn load_stats(&self) -> LoadStats {
        self.socket.load_stats()
    }

    /// Force the under-load state. Exposed for tests, which would otherwise
    /// have to win a race with the one-second load monitor.
    #[doc(hidden)]
    pub fn set_under_load(&self, value: bool) {
        self.socket.set_under_load(value);
    }

    /// Rotate the cookie secret now. Exposed for tests, which would otherwise
    /// have to wait out the 120-second rotation timer.
    #[doc(hidden)]
    pub fn rotate_cookie_secret(&self) {
        self.socket.rotate_cookie_secret();
    }

    /// Close the listener.
    pub fn close(&self, code: quinn::VarInt, reason: &[u8]) {
        self.endpoint.close(code, reason);
    }
}

fn build_transport_config(config: &Config) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(config.max_idle_timeout.try_into().unwrap()));

    let stream_window = config.stream_receive_window.unwrap_or(1_048_576);
    let conn_window = config.receive_window.unwrap_or(10_485_760);
    let send_window = config.send_window.unwrap_or(10_485_760);
    transport.stream_receive_window((stream_window as u32).into());
    transport.receive_window((conn_window as u32).into());
    transport.send_window(send_window);

    if let Some(ka) = config.keep_alive {
        transport.keep_alive_interval(Some(ka));
    }
    if let Some(mtu) = config.initial_mtu {
        transport.initial_mtu(mtu);
    }
    if config.disable_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    if config.enable_datagrams {
        transport.datagram_receive_buffer_size(Some(1_048_576));
    }
    if let Some(rtt) = config.initial_rtt {
        transport.initial_rtt(rtt);
    }
    match config.congestion_controller {
        CongestionController::Bbr => {
            transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        CongestionController::Cubic => {} // Quinn default
    }
    transport
}

/// Start a sQUIC server.
pub async fn listen(
    addr: SocketAddr,
    signing_key: &SigningKey,
    config: Config,
) -> Result<ServerListener, Error> {
    let server_x25519_priv = ed25519_private_to_x25519(signing_key);
    let whitelist = Arc::new(Whitelist::new(
        config.allowed_keys.as_deref(),
    ));

    let std_socket = create_udp_socket(addr)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket).map_err(Error::Io)?);

    let load_threshold = config.load_threshold.unwrap_or(1000);
    let server_socket = Arc::new(ServerSocket::new(
        socket,
        server_x25519_priv,
        whitelist.clone(),
        load_threshold,
        config.accepted_envelope_versions.clone(),
    ));
    ServerSocket::spawn_maintenance(&server_socket);

    let tls_config = tls::server_tls_config(signing_key, &config.alpn_protocols)?;
    let quic_server_config: quinn_proto::crypto::rustls::QuicServerConfig = tls_config
        .try_into()
        .map_err(|e: quinn_proto::crypto::rustls::NoInitialCipherSuite| {
            crate::Error::Tls(format!("quic server config: {e}"))
        })?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    if config.disable_active_migration {
        server_config.migration(false);
    }

    let mut transport = build_transport_config(&config);
    transport.max_concurrent_bidi_streams(config.max_incoming_streams.try_into().unwrap());
    transport.max_concurrent_uni_streams(config.max_incoming_streams.try_into().unwrap());
    server_config.transport_config(Arc::new(transport));

    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Io(std::io::Error::other("no async runtime")))?;

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config(),
        Some(server_config),
        server_socket.clone(),
        runtime,
    )?;

    Ok(ServerListener {
        endpoint,
        whitelist,
        socket: server_socket,
        public_key: signing_key.verifying_key().to_bytes(),
    })
}

/// Connect to a sQUIC server.
pub async fn dial(
    addr: SocketAddr,
    server_pub_key: &[u8; 32],
    config: Config,
) -> Result<quinn::Connection, Error> {
    // Derive or generate X25519 key pair, and the Ed25519 identity (if any) it
    // came from — the latter can be advertised in the envelope (SIP-3).
    let (client_x25519_priv, client_x25519_pub, client_ed25519_pub) =
        if let Some(ref key_hex) = config.client_key {
            // Persistent client identity: derive X25519 from Ed25519 seed
            let seed = hex::decode(key_hex).map_err(|e| Error::Tls(format!("invalid client_key hex: {e}")))?;
            if seed.len() != 32 {
                return Err(Error::Tls(format!("client_key must be 32 bytes (got {})", seed.len())));
            }
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
            let x25519_priv = ed25519_private_to_x25519(&signing_key);
            let x25519_pub = X25519Public::from(&x25519_priv);
            (x25519_priv, x25519_pub, Some(signing_key.verifying_key().to_bytes()))
        } else {
            // Ephemeral: random X25519 key pair, no Ed25519 identity to assert.
            let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
            let pub_key = X25519Public::from(&priv_key);
            (priv_key, pub_key, None)
        };

    // SIP-3: the Ed25519 field to place in the envelope — the derived identity
    // when opted in, otherwise all zeros ("no identity").
    let advertise_ed25519 = match (config.advertise_identity, client_ed25519_pub) {
        (true, Some(ed)) => ed,
        _ => [0u8; 32],
    };

    // DH shared secret
    let server_x25519_pub = ed25519_public_to_x25519(server_pub_key)?;
    let shared = x25519(&client_x25519_priv, &server_x25519_pub)?;

    // Bind in the same family as the peer. Quinn refuses a remote whose
    // address family does not match its endpoint, so a socket bound to
    // 0.0.0.0 cannot dial an IPv6 server at all — it fails with "invalid
    // remote address" before a packet is sent.
    let bind_addr = if addr.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let std_socket = create_udp_socket(bind_addr)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket).map_err(Error::Io)?);

    let cookie_key = crate::mac::cookie_key(server_x25519_pub.as_bytes());
    let mac0_key = crate::mac::mac0_key(server_x25519_pub.as_bytes());
    let client_socket = ClientSocket::new(
        socket,
        conn::ClientKeys {
            shared_secret: shared,
            client_pub_key: client_x25519_pub.to_bytes(),
            advertise_ed25519,
            mac0_key,
            cookie_key,
        },
        addr,
        config.envelope_version,
    );

    let tls_config = tls::client_tls_config(server_pub_key, &config.alpn_protocols)?;
    let quic_client_config: quinn_proto::crypto::rustls::QuicClientConfig = tls_config
        .try_into()
        .map_err(|e: quinn_proto::crypto::rustls::NoInitialCipherSuite| {
            crate::Error::Tls(format!("quic client config: {e}"))
        })?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let transport = build_transport_config(&config);
    client_config.transport_config(Arc::new(transport));

    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Io(std::io::Error::other("no async runtime")))?;

    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        endpoint_config(),
        None,
        Arc::new(client_socket),
        runtime,
    )?;
    endpoint.set_default_client_config(client_config);

    let handshake_timeout = config.handshake_timeout.unwrap_or(Duration::from_secs(10));
    let connecting = endpoint.connect(addr, "squic")?;
    let conn = tokio::time::timeout(handshake_timeout, connecting)
        .await
        .map_err(|_| Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("handshake timed out after {:?}", handshake_timeout),
        )))??;
    Ok(conn)
}

/// Generate a new Ed25519 keypair for sQUIC.
pub fn generate_keypair() -> (SigningKey, [u8; 32]) {
    crypto::generate_keypair()
}

/// Load a keypair from a hex-encoded Ed25519 private seed.
pub fn load_keypair(hex_seed: &str) -> Result<(SigningKey, [u8; 32]), Error> {
    crypto::load_keypair(hex_seed)
}

#[cfg(test)]
mod endpoint_config_tests {
    use super::*;
    use quinn::ConnectionIdGenerator;
    use quinn_proto::HashedConnectionIdGenerator;

    /// The property that closes the hole: our generator recognises nothing,
    /// including its own output, so quinn's stateless-reset gate never opens.
    #[test]
    fn our_generator_recognises_nothing_not_even_its_own_cids() {
        let mut cids = SilentCidGenerator;
        let cid = cids.generate_cid();
        assert_eq!(cid.len(), CID_LEN);
        assert!(
            cids.validate(&cid).is_err(),
            "a CID we minted ourselves still validates, so the reset gate is open"
        );
    }

    /// And the contrast that makes it worth doing. quinn's default validates
    /// its own CIDs, which is what let a retired one draw a stateless reset —
    /// and it signs them with five bytes of a non-cryptographic, algebraically
    /// invertible hash over CIDs that travel in cleartext, so the signature is
    /// recoverable rather than merely guessable.
    #[test]
    fn quinns_default_generator_validates_its_own_cids() {
        let mut cids = HashedConnectionIdGenerator::default();
        let cid = cids.generate_cid();
        assert!(
            cids.validate(&cid).is_ok(),
            "quinn changed its default; re-check whether the reset gate still needs closing here"
        );
    }

    /// CIDs must not repeat, or connections collide.
    #[test]
    fn generated_cids_are_distinct() {
        let mut cids = SilentCidGenerator;
        let a = cids.generate_cid();
        let b = cids.generate_cid();
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
