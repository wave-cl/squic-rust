pub mod conn;
pub mod crypto;
pub mod mac;
pub mod tls;
pub mod whitelist;

use conn::{ClientSocket, ServerSocket};
use crypto::{ed25519_private_to_x25519, ed25519_public_to_x25519, x25519};
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
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
        .map_err(|e| Error::Io(e))?;
    // 2MB buffers — critical on Linux where defaults are ~160KB
    let _ = sock.set_recv_buffer_size(2 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(2 * 1024 * 1024);
    sock.set_nonblocking(true).map_err(|e| Error::Io(e))?;
    sock.bind(&addr.into()).map_err(|e| Error::Io(e))?;
    Ok(sock.into())
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
    /// Optional hex-encoded Ed25519 private key seed (64 hex chars).
    /// When set, dial() uses this persistent identity instead of generating an ephemeral one.
    /// The client's X25519 public key is derived from this for MAC1 and whitelist matching.
    pub client_key: Option<String>,
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
            client_key: None,
        }
    }
}

/// Server listener with silent-server support.
pub struct ServerListener {
    endpoint: quinn::Endpoint,
    whitelist: Arc<Whitelist>,
}

impl ServerListener {
    /// Accept the next incoming connection.
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
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

    let server_socket = ServerSocket::new(socket, server_x25519_priv, whitelist.clone());

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
        quinn::EndpointConfig::default(),
        Some(server_config),
        Arc::new(server_socket),
        runtime,
    )?;

    Ok(ServerListener {
        endpoint,
        whitelist,
    })
}

/// Connect to a sQUIC server.
pub async fn dial(
    addr: SocketAddr,
    server_pub_key: &[u8; 32],
    config: Config,
) -> Result<quinn::Connection, Error> {
    // Derive or generate X25519 key pair
    let (client_x25519_priv, client_x25519_pub) = if let Some(ref key_hex) = config.client_key {
        // Persistent client identity: derive X25519 from Ed25519 seed
        let seed = hex::decode(key_hex).map_err(|e| Error::Tls(format!("invalid client_key hex: {e}")))?;
        if seed.len() != 32 {
            return Err(Error::Tls(format!("client_key must be 32 bytes (got {})", seed.len())));
        }
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed.try_into().unwrap());
        let x25519_priv = ed25519_private_to_x25519(&signing_key);
        let x25519_pub = X25519Public::from(&x25519_priv);
        (x25519_priv, x25519_pub)
    } else {
        // Ephemeral: random X25519 key pair
        let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let pub_key = X25519Public::from(&priv_key);
        (priv_key, pub_key)
    };

    // DH shared secret
    let server_x25519_pub = ed25519_public_to_x25519(server_pub_key)?;
    let shared = x25519(&client_x25519_priv, &server_x25519_pub);

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let std_socket = create_udp_socket(bind_addr)?;
    let socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket).map_err(Error::Io)?);

    let client_socket = ClientSocket::new(socket, shared, client_x25519_pub.to_bytes());

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
        quinn::EndpointConfig::default(),
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
