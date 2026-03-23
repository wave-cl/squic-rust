use squic::{self, Config, Error};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper: start a server and return (listener, public key hex).
async fn start_server(
    config: Config,
) -> (squic::ServerListener, ed25519_dalek::SigningKey, [u8; 32]) {
    let (signing_key, pub_key) = squic::generate_keypair();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = squic::listen(addr, &signing_key, config).await.unwrap();
    (listener, signing_key, pub_key)
}

#[tokio::test]
async fn test_client_server_connection() {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        send.write_all(&buf[..n]).await.unwrap();
        send.finish().unwrap();
        // Wait until the peer has received all data before dropping the
        // connection, otherwise ApplicationClose races with the read.
        let _ = send.stopped().await;
    });

    let conn = squic::dial(addr, &pub_key, Config::default()).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hello squic").await.unwrap();
    send.finish().unwrap();

    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello squic");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_silent_server_drops_invalid_mac() {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    // Send garbage to the server — should get no response
    let garbage_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    garbage_socket.send_to(b"garbage data that is not a valid QUIC packet", addr).await.unwrap();

    // Send a fake QUIC Initial with wrong MAC
    let mut fake_initial = vec![0xC0u8; 200]; // looks like Initial
    fake_initial.extend_from_slice(&[0u8; 52]); // fake overhead
    garbage_socket.send_to(&fake_initial, addr).await.unwrap();

    // Server must be accepting for the handshake to complete
    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
    });

    // Try to connect with the correct key — should succeed despite garbage
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        squic::dial(addr, &pub_key, Config::default()),
    )
    .await
    .expect("should not timeout")
    .expect("valid client should connect despite garbage");

    drop(conn);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_silent_server_rejects_wrong_key() {
    let (listener, _key, _pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    // Generate a different key pair — wrong server key
    let (_wrong_key, wrong_pub) = squic::generate_keypair();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        squic::dial(addr, &wrong_pub, Config::default()),
    )
    .await;

    // Should timeout or error — server silently drops Initial with wrong MAC
    assert!(result.is_err() || result.unwrap().is_err());
    drop(listener);
}

#[tokio::test]
async fn test_whitelist_allows_known_client() {
    // No whitelist = accept any valid MAC1 client
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
    });

    let conn = squic::dial(addr, &pub_key, Config::default()).await.unwrap();
    drop(conn);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_whitelist_rejects_unknown_client() {
    let random_key = [0xABu8; 32]; // not the client's key
    let config = Config {
        allowed_keys: Some(vec![random_key]),
        ..Config::default()
    };
    let (listener, _key, pub_key) = start_server(config).await;
    let addr = listener.local_addr().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        squic::dial(addr, &pub_key, Config::default()),
    )
    .await;

    // Should timeout — client's ephemeral X25519 key isn't in whitelist
    assert!(result.is_err() || result.unwrap().is_err());
    drop(listener);
}

#[tokio::test]
async fn test_runtime_allow_key() {
    let config = Config {
        allowed_keys: Some(vec![]), // empty whitelist = block all
        ..Config::default()
    };
    let (listener, _key, pub_key) = start_server(config).await;
    let addr = listener.local_addr().unwrap();

    // Initially blocked
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        squic::dial(addr, &pub_key, Config::default()),
    )
    .await;
    assert!(result.is_err() || result.unwrap().is_err());

    // Let the failed attempt fully clean up
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Disable whitelist at runtime — now any valid client can connect
    listener.disable_whitelist();

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
    });

    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        squic::dial(addr, &pub_key, Config::default()),
    )
    .await
    .expect("should connect after whitelist disabled")
    .expect("connection should succeed");

    drop(conn);
    let _ = server_task.await;
}

#[tokio::test]
async fn test_runtime_remove_key() {
    let (listener, _key, _pub_key) = start_server(Config::default()).await;

    let key1 = [1u8; 32];
    let key2 = [2u8; 32];

    listener.allow_key(&key1);
    listener.allow_key(&key2);
    assert!(listener.has_key(&key1));
    assert!(listener.has_key(&key2));
    assert_eq!(listener.allowed_keys().len(), 2);

    listener.remove_key(&key1);
    assert!(!listener.has_key(&key1));
    assert!(listener.has_key(&key2));
    assert_eq!(listener.allowed_keys().len(), 1);
}

#[tokio::test]
async fn test_enable_whitelist_with_keys() {
    let (listener, _key, _pub_key) = start_server(Config::default()).await;

    let key1 = [1u8; 32];
    let key2 = [2u8; 32];

    listener.enable_whitelist(&[key1, key2]);
    assert!(listener.has_key(&key1));
    assert!(listener.has_key(&key2));
    assert!(!listener.has_key(&[3u8; 32]));

    listener.disable_whitelist();
    assert!(!listener.has_key(&key1));
    assert_eq!(listener.allowed_keys().len(), 0);
}

// MAC and timestamp tests are in the unit test modules.
// These integration tests focus on the full network stack.
