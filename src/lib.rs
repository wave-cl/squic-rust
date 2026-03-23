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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(30),
            max_incoming_streams: 100,
            alpn_protocols: vec![b"squic".to_vec()],
            allowed_keys: None,
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

    let socket = tokio::net::UdpSocket::bind(addr).await?;
    let socket = Arc::new(socket);

    let server_socket = ServerSocket::new(socket, server_x25519_priv, whitelist.clone());

    let tls_config = tls::server_tls_config(signing_key, &config.alpn_protocols)?;
    let quic_server_config: quinn_proto::crypto::rustls::QuicServerConfig = tls_config
        .try_into()
        .map_err(|e: quinn_proto::crypto::rustls::NoInitialCipherSuite| {
            crate::Error::Tls(format!("quic server config: {e}"))
        })?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        config.max_idle_timeout.try_into().unwrap(),
    ));
    transport.max_concurrent_bidi_streams(config.max_incoming_streams.try_into().unwrap());
    transport.max_concurrent_uni_streams(config.max_incoming_streams.try_into().unwrap());
    transport.stream_receive_window(1_048_576u32.into()); // 1MB per stream
    transport.receive_window(10_485_760u32.into()); // 10MB per connection
    transport.send_window(10_485_760u64); // 10MB send window
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
    // Generate ephemeral client X25519 key pair
    let client_x25519_priv = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let client_x25519_pub = X25519Public::from(&client_x25519_priv);

    // DH shared secret
    let server_x25519_pub = ed25519_public_to_x25519(server_pub_key)?;
    let shared = x25519(&client_x25519_priv, &server_x25519_pub);

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Arc::new(socket);

    let client_socket = ClientSocket::new(socket, shared, client_x25519_pub.to_bytes());

    let tls_config = tls::client_tls_config(server_pub_key, &config.alpn_protocols)?;
    let quic_client_config: quinn_proto::crypto::rustls::QuicClientConfig = tls_config
        .try_into()
        .map_err(|e: quinn_proto::crypto::rustls::NoInitialCipherSuite| {
            crate::Error::Tls(format!("quic client config: {e}"))
        })?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        config.max_idle_timeout.try_into().unwrap(),
    ));
    transport.stream_receive_window(1_048_576u32.into()); // 1MB per stream
    transport.receive_window(10_485_760u32.into()); // 10MB per connection
    transport.send_window(10_485_760u64); // 10MB send window
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

    let conn = endpoint.connect(addr, "squic")?.await?;
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
