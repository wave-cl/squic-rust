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
/// Open the NAT mapping for each peer, so its packets are not dropped on the way
/// in.
///
/// One byte, `0x00`: a short-header packet for a connection nobody has, which
/// every squic endpoint discards in silence — and never answers, because a
/// stateless reset would be a reply to a caller that has proved nothing.
///
/// Errors are ignored on purpose. A punch that does not leave is a punch that
/// did not work, and there is nothing to report to a caller who will find that
/// out when the connection does not form.
fn punch(sock: &std::net::UdpSocket, targets: &[SocketAddr]) {
    for target in targets.iter().take(MAX_PUNCH_TARGETS) {
        for _ in 0..PUNCH_DATAGRAMS {
            let _ = sock.send_to(&[0u8], target);
        }
    }
}

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
///
/// # Parity with squic-go
///
/// The two implementations share a wire format, not a config surface, and the
/// gaps below are not oversights — they are places where quinn and quic-go
/// disagree about what is tunable. Recorded here because a caller who reads one
/// API and assumes the other is wrong without being told.
///
/// **No Go equivalent, and none can be added.** quic-go's `Config` has no field
/// for any of these, so a mirrored field could only be accepted and discarded —
/// which is worse than its absence, because a setting that is read and never
/// applied looks like it works:
///
/// | Rust | why Go has none |
/// |---|---|
/// | `send_window` | quic-go exposes no send window |
/// | `initial_rtt` | quic-go exposes no initial RTT |
/// | `congestion_controller` | quic-go does not let you choose one |
/// | `disable_active_migration` | quic-go exposes no migration control |
///
/// **No Rust equivalent.** Go has `QuicConfig`, a `*quic.Config` that replaces
/// everything else wholesale. quinn's `TransportConfig` is built here rather
/// than accepted from the caller, so there is no equivalent hatch; the fields
/// on this struct are the whole surface.
///
/// **Same concept, same meaning, different defaults.** `stream_receive_window`
/// and `receive_window` pair with Go's `StreamReceiveWindow` and
/// `ReceiveWindow`. They did not always: Go's were `MaxStreamReceiveWindow` and
/// `MaxConnectionReceiveWindow`, and set only quic-go's auto-tuning ceiling, so
/// one name meant a fixed window here and a cap there. Setting either now pins
/// the window in both. What still differs is the value you get by leaving them
/// unset — quinn does not auto-tune, so this side is fixed at 1 MB and 10 MB,
/// while quic-go starts there and tunes up to 6 MB and 15 MB. To cap
/// auto-tuning rather than pin the window, which only quic-go can do, a Go
/// caller uses `QuicConfig`.
///
/// **Same in both, with the types each language prefers.** `local_bind` and
/// `punch` pair with Go's `LocalBind` and `Punch`. They are `SocketAddr` here
/// and `string` there, because that is what each side's own `dial` and `listen`
/// already take — a caller in either language passes what it would have passed
/// anyway, and neither has to learn the other's address type.
///
/// `Clone` because Go's `Config` is a plain struct a caller can copy, and one
/// config is often wanted for both a `listen` and a `dial` — `listen` takes it
/// by value, so without this the caller has to build it twice.
#[derive(Debug, Clone)]
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
    /// starts requiring a cookie-keyed gate tag from callers it has not
    /// challenged yet.
    /// Default: 1000. `Some(0)` disables the cookie defence entirely.
    pub load_threshold: Option<u64>,
    /// SIP-29: the envelope version this client emits.
    ///
    /// Default and only implemented version: `ENVELOPE_V4`. Versions 1 to 3
    /// were removed rather than deprecated — a version that has to be narrowed
    /// *to* in order to be safe will be left wide somewhere, and versions 1 and
    /// 2 carried no cheap gate at all, so a default that included them handed
    /// every stranger a curve operation.
    ///
    /// Kept as a setting because the next transition will need it, not because
    /// there is anything to choose today.
    pub envelope_version: u8,
    /// SIP-29: the envelope versions this server parses.
    ///
    /// Default: `[ENVELOPE_V4]`, the only version implemented. The mechanism
    /// survives for the next transition; what does not survive is a default
    /// that admits a weaker version than the one the client sends.
    pub accepted_envelope_versions: Vec<u8>,

    /// SIP-25: the local address [`dial`] binds, instead of an ephemeral port.
    ///
    /// **This exists for hole punching and for nothing else.** A NAT maps an
    /// internal `ip:port` to an external one, and a peer can only be reached
    /// through the mapping the exchange observed — which means dialling *from*
    /// the port that made it. `dial` otherwise binds `:0` and gets a fresh
    /// port, and therefore a fresh mapping the peer has never seen.
    ///
    /// `None` — the default, and what every ordinary caller wants — binds an
    /// ephemeral port. Pinning one costs you the ability to have two dials in
    /// flight at once, and gains nothing unless something else is holding the
    /// mapping open.
    ///
    /// Ignored by [`listen`], which already takes the address it binds.
    pub local_bind: Option<SocketAddr>,

    /// SIP-25: addresses to send a punch datagram to, right after binding.
    ///
    /// A NAT will not deliver an inbound packet until something has gone out to
    /// that peer, so both sides send first and each one's outbound opens its own
    /// mapping. The datagram is one byte and is meant to be **dropped**: a
    /// short-header packet for a connection nobody has, which every squic
    /// endpoint discards in silence and never answers — a stateless reset here
    /// would be a reply to a caller that has proved nothing.
    ///
    /// **This is a send primitive with a caller-supplied destination**, which is
    /// the shape a reflection abuse takes, so it is bounded: at most
    /// [`MAX_PUNCH_TARGETS`] addresses, [`PUNCH_DATAGRAMS`] one-byte datagrams
    /// each. It amplifies nothing — one byte out per byte asked for — and the
    /// caller is the local application, which could send these itself.
    ///
    /// SIP-25 requires that an address reach a peer only after *both* sides
    /// asked an exchange to be introduced. Nothing here can enforce that; the
    /// transport takes an address and sends to it.
    pub punch: Vec<SocketAddr>,

    /// Server: cap on the number of concurrently *established* connections.
    ///
    /// Each accepted connection can hold up to its receive window (see
    /// [`Config::receive_window`], ~10 MB by default) of unread data, and the
    /// transport has no other ceiling on how many may be open at once — so a
    /// caller that completes handshakes and holds connections open can drive
    /// server memory to N × the window. This bounds N. When the count of
    /// established connections is at or above the cap, further Initials are
    /// dropped in silence (the caller proved its key at the envelope, but the
    /// server is full), exactly like any other refusal.
    ///
    /// Default: `None` — unlimited, the historical behaviour. A public,
    /// whitelist-off deployment should set a finite value sized to its memory
    /// budget (`cap × receive_window`). Ignored on the client.
    pub max_connections: Option<u64>,
}

/// Addresses one [`Config::punch`] may name.
pub const MAX_PUNCH_TARGETS: usize = 4;
/// Datagrams sent to each punch target.
///
/// More than one because the first may cross the peer's on the way and find its
/// NAT still shut; few, because this is unsolicited traffic to an address a
/// caller named.
pub const PUNCH_DATAGRAMS: usize = 3;

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
            envelope_version: crate::mac::ENVELOPE_V4,
            accepted_envelope_versions: vec![crate::mac::ENVELOPE_V4],
            local_bind: None,
            punch: Vec::new(),
            max_connections: None,
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
    /// Whether the server is currently demanding a cookie-keyed gate tag.
    pub under_load: bool,
    /// Cookie challenges issued since start.
    pub cookie_replies_sent: u64,
    /// Initial packets accepted on a cookie-keyed gate tag since start.
    pub mac2_verified: u64,
    /// Initials accepted, per envelope version, as `(version, count)`.
    ///
    /// The number to look at before retiring a version (SIP-29). A server that
    /// drops an envelope does so in silence, so retiring one that clients are
    /// still sending locks them out with no diagnostic on either side — this is
    /// the evidence that turns that decision from nerve into arithmetic.
    ///
    /// Counts accepted Initials, not connections: a handshake retransmits, so
    /// treat these as "is anything still arriving on this version", not as a
    /// connection count.
    pub accepted_by_version: [(u8, u64); crate::mac::ENVELOPE_VERSIONS.len()],
}

/// Server listener with silent-server support.
pub struct ServerListener {
    endpoint: quinn::Endpoint,
    whitelist: Arc<Whitelist>,
    socket: Arc<ServerSocket>,
    public_key: [u8; 32],
    max_connections: Option<u64>,
}

impl ServerListener {
    /// Accept the next incoming connection.
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        loop {
            let incoming = self.endpoint.accept().await?;
            // Cap concurrently-established connections. quinn tracks the live
            // count and decrements it on close, so no bookkeeping of our own is
            // needed; over the cap we drop the Initial in silence rather than
            // refuse it, keeping the server's no-reply posture.
            let at_capacity = self
                .max_connections
                .is_some_and(|cap| self.endpoint.open_connections() as u64 >= cap);
            if at_capacity {
                incoming.ignore();
                continue;
            }
            return Some(incoming);
        }
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

/// A `u64` config value as a QUIC varint, or an error naming the field.
///
/// These fields are `u64` and QUIC varints top out at 2^62 - 1. They used to be
/// cast `as u32`, which silently wrapped anything from 4 GiB up — a caller
/// asking for a larger window got a *smaller* one than the default, with
/// nothing said.
///
/// Refusing rather than clamping, and that was measured, not assumed. Clamping
/// to `VarInt::MAX` was the first fix and it is worse than the bug: every field
/// binds happily at that value, and the process then grows without bound the
/// moment a stream carries data, because quinn sizes buffers from the window.
/// A config value that cannot be honoured should stop the caller, not be
/// rewritten into one that looks fine until traffic arrives.
///
/// A value that *fits* is passed through as given, however large. That is
/// quinn's business, and quietly rewriting a caller's number is the habit this
/// function exists to break.
fn varint(field: &str, value: u64) -> Result<quinn::VarInt, Error> {
    quinn::VarInt::from_u64(value).map_err(|_| {
        Error::Tls(format!(
            "{field} is {value}, which no QUIC varint can carry (the ceiling is \
             {}); it would have been silently truncated",
            quinn::VarInt::MAX
        ))
    })
}

fn build_transport_config(config: &Config) -> Result<quinn::TransportConfig, Error> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(config.max_idle_timeout.try_into().unwrap()));

    let stream_window = config.stream_receive_window.unwrap_or(1_048_576);
    let conn_window = config.receive_window.unwrap_or(10_485_760);
    let send_window = config.send_window.unwrap_or(10_485_760);
    transport.stream_receive_window(varint("stream_receive_window", stream_window)?);
    transport.receive_window(varint("receive_window", conn_window)?);
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
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        CongestionController::Cubic => {} // Quinn default
    }
    Ok(transport)
}

/// Start a sQUIC server.
pub async fn listen(
    addr: SocketAddr,
    signing_key: &SigningKey,
    config: Config,
) -> Result<ServerListener, Error> {
    // The mirror of the guard in `dial`, and the one that costs more to be
    // without. A server told to accept a version this build cannot parse does
    // not fail: it binds, it logs that it is listening, systemd calls it
    // healthy — and it drops every Initial that arrives, in silence, because
    // SIP-6 requires exactly that of anything it cannot validate. The operator
    // sees a live process and a dead port with no line anywhere saying why.
    //
    // This is not hypothetical. `ex` ran `accepted_envelope_versions = [3]`
    // right up to the v4 cut, and installing the binary without editing that
    // line in the same breath would have taken the exchange down without a
    // single error. Refuse at listen instead, where the operator is looking.
    //
    // Every named version must be implemented, not merely one of them. A set
    // like [3, 4] on a v4-only build is the quieter half of the same fault:
    // v4 callers connect, v3 callers are dropped without a word, and the
    // operator believes both are served. Listing a version this build cannot
    // parse is a statement the server has no way to honour, so it is refused
    // whatever else is in the list. That does mean a config naming a version
    // ahead of the binary is rejected — which is correct: the accept set is
    // read at start, and a version arrives with the code that parses it.
    if config.accepted_envelope_versions.is_empty() {
        return Err(Error::Tls(
            "accepted_envelope_versions is empty; a server that accepts no envelope \
             version binds successfully and then drops every Initial in silence"
                .into(),
        ));
    }
    let unparsable: Vec<u8> = config
        .accepted_envelope_versions
        .iter()
        .copied()
        .filter(|v| crate::mac::trailer_len(crate::mac::hdr(*v, false)).is_none())
        .collect();
    if !unparsable.is_empty() {
        return Err(Error::Tls(format!(
            "accepted_envelope_versions names {unparsable:?}, which this build \
             cannot parse (it implements {:?}); a server accepting only versions \
             it cannot parse binds successfully and then drops every Initial \
             in silence",
            crate::mac::ENVELOPE_VERSIONS
        )));
    }

    let server_x25519_priv = ed25519_private_to_x25519(signing_key);
    let whitelist = Arc::new(Whitelist::new(config.allowed_keys.as_deref()));

    let std_socket = create_udp_socket(addr)?;
    // SIP-25: a listening peer punches too. Whichever side dials, both NATs
    // have to be opened, and only an outbound packet opens one.
    punch(&std_socket, &config.punch);
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
    let quic_server_config: quinn_proto::crypto::rustls::QuicServerConfig =
        tls_config
            .try_into()
            .map_err(|e: quinn_proto::crypto::rustls::NoInitialCipherSuite| {
                crate::Error::Tls(format!("quic server config: {e}"))
            })?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
    if config.disable_active_migration {
        server_config.migration(false);
    }

    let mut transport = build_transport_config(&config)?;
    // Checked for the same reason as the windows, and here it also removes a
    // panic: `try_into().unwrap()` aborted the process on any value a varint
    // cannot hold, which is a library killing its caller over a tuning knob.
    let streams = varint("max_incoming_streams", config.max_incoming_streams)?;
    transport.max_concurrent_bidi_streams(streams);
    transport.max_concurrent_uni_streams(streams);
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
        max_connections: config.max_connections,
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
            let seed = hex::decode(key_hex)
                .map_err(|e| Error::Tls(format!("invalid client_key hex: {e}")))?;
            if seed.len() != 32 {
                return Err(Error::Tls(format!(
                    "client_key must be 32 bytes (got {})",
                    seed.len()
                )));
            }
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
            let x25519_priv = ed25519_private_to_x25519(&signing_key);
            let x25519_pub = X25519Public::from(&x25519_priv);
            (
                x25519_priv,
                x25519_pub,
                Some(signing_key.verifying_key().to_bytes()),
            )
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
    // Refuse a version this build cannot emit, here, where the caller can see
    // it. A client that sends an envelope no server parses gets a handshake
    // timeout and nothing else — the server drops it in silence, by design —
    // so a misconfiguration and an unreachable host look identical. squic-go
    // has refused this at Dial since S11; this is the Rust half, which never
    // panicked the way Go's did and so never grew the guard.
    if crate::mac::trailer_len(crate::mac::hdr(config.envelope_version, false)).is_none() {
        return Err(Error::Tls(format!(
            "unknown envelope_version {} (this build emits {})",
            config.envelope_version,
            crate::mac::ENVELOPE_V4
        )));
    }

    // Bind in the same family as the peer. Quinn refuses a remote whose
    // address family does not match its endpoint, so a socket bound to
    // 0.0.0.0 cannot dial an IPv6 server at all.
    //
    // A caller pinning a local address (SIP-25) is taken at its word, and gets
    // the family it asked for — mismatching the peer is then its own error and
    // is reported as quinn's, which names it.
    let bind_addr = match config.local_bind {
        Some(bound) => bound,
        None if addr.is_ipv6() => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        None => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    };
    let std_socket = create_udp_socket(bind_addr)?;
    // Before quinn owns the socket: the mapping has to exist before the
    // handshake starts, and this is the only moment the raw socket is in hand.
    punch(&std_socket, &config.punch);
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket).map_err(Error::Io)?);

    let cookie_key = crate::mac::cookie_key(server_x25519_pub.as_bytes());
    let gate_key = crate::mac::gate_key(server_x25519_pub.as_bytes());
    let client_socket = ClientSocket::new(
        socket,
        conn::ClientKeys {
            shared_secret: shared,
            client_pub_key: client_x25519_pub.to_bytes(),
            advertise_ed25519,
            gate_key,
            cookie_key,
        },
        addr,
        config.envelope_version,
    );

    let tls_config = tls::client_tls_config(server_pub_key, &config.alpn_protocols)?;
    let quic_client_config: quinn_proto::crypto::rustls::QuicClientConfig =
        tls_config
            .try_into()
            .map_err(|e: quinn_proto::crypto::rustls::NoInitialCipherSuite| {
                crate::Error::Tls(format!("quic client config: {e}"))
            })?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let transport = build_transport_config(&config)?;
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
        .map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("handshake timed out after {:?}", handshake_timeout),
            ))
        })??;
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
