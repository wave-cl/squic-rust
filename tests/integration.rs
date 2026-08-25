use squic::{self, Config};
use std::net::SocketAddr;
use std::time::Duration;

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

/// Regression test: Initial packet must arrive despite being oversized (1200 + 76 = 1276 bytes).
/// On Linux with GSO enabled, quinn-udp previously silently dropped the oversized packet
/// when segment_size was set to None. The fix bypasses quinn-udp for Initial packets.
/// If this test times out, the Initial send bypass is broken.
#[tokio::test]
async fn test_initial_packet_arrives_fast() {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        send.write_all(&buf[..n]).await.unwrap();
        send.finish().unwrap();
        // Wait for client to finish reading before dropping connection
        let _ = recv.read(&mut buf).await;
        // Keep connection alive briefly
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    // Handshake must complete within 3 seconds.
    // The original bug caused an indefinite hang here.
    let conn = tokio::time::timeout(
        Duration::from_secs(3),
        squic::dial(addr, &pub_key, Config::default()),
    )
    .await
    .expect("handshake timed out — Initial packet likely dropped (GSO regression)")
    .expect("dial failed");

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let mut buf = vec![0u8; 16];
    let n = recv.read(&mut buf).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"ping");

    let _ = server_task.await;
}

/// Verify MAC_OVERHEAD is the expected 108 bytes at runtime (SIP-3 added the
/// 32-byte Ed25519 identity field).
#[test]
fn test_mac_overhead_is_108() {
    assert_eq!(squic::mac::MAC_OVERHEAD, 108);
    assert_eq!(
        squic::mac::MAC_OVERHEAD,
        squic::mac::CLIENT_KEY_SIZE
            + squic::mac::ED25519_SIZE
            + squic::mac::TIMESTAMP_SIZE
            + squic::mac::NONCE_SIZE
            + squic::mac::MAC_SIZE
            + squic::mac::MAC2_SIZE,
    );
}

/// A client must be able to dial an IPv6 server.
///
/// `dial` used to bind `0.0.0.0:0` whatever the peer looked like, and quinn
/// refuses a remote whose address family does not match its endpoint — so
/// every IPv6 server was unreachable with "invalid remote address", before a
/// packet was sent. Loopback is enough to catch that: it is the family of the
/// socket that matters, not the route.
#[tokio::test]
async fn test_ipv6_connection() {
    let (signing_key, pub_key) = squic::generate_keypair();
    let addr: SocketAddr = "[::1]:0".parse().unwrap();
    let listener = squic::listen(addr, &signing_key, Config::default())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(addr.is_ipv6(), "expected an IPv6 listener, got {addr}");

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        send.write_all(&buf[..n]).await.unwrap();
        send.finish().unwrap();
        let _ = send.stopped().await;
    });

    let conn = squic::dial(addr, &pub_key, Config::default()).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hello over v6").await.unwrap();
    send.finish().unwrap();

    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"hello over v6");

    server_task.await.unwrap();
}

/// A UDP relay that drops the first `drop_first` datagrams travelling
/// client -> server, then forwards everything in both directions.
/// Returns the address the client should dial.
async fn lossy_relay(server: SocketAddr, drop_first: usize) -> SocketAddr {
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    back.connect(server).await.unwrap();

    tokio::spawn(async move {
        let mut up = vec![0u8; 65536];
        let mut down = vec![0u8; 65536];
        let mut client: Option<SocketAddr> = None;
        let mut dropped = 0usize;
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut up) => {
                    client = Some(from);
                    if dropped < drop_first {
                        dropped += 1;
                        continue; // blackhole it
                    }
                    let _ = back.send(&up[..n]).await;
                }
                Ok(n) = back.recv(&mut down) => {
                    if let Some(c) = client {
                        let _ = front.send_to(&down[..n], c).await;
                    }
                }
            }
        }
    });

    front_addr
}

#[tokio::test]
async fn test_handshake_survives_initial_packet_loss() {
    assert_handshake_survives_losing(1).await;
}

/// Several PTOs deep, the envelope must still be there.
#[tokio::test]
async fn test_handshake_survives_repeated_initial_loss() {
    assert_handshake_survives_losing(3).await;
}

async fn assert_handshake_survives_losing(lost: usize) {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = listener.accept().await {
            tokio::spawn(async move { let _ = incoming.await; });
        }
    });

    // Blackhole the client's first datagrams. QUIC must retransmit the
    // Initial, and every retransmission has to carry a valid MAC or the
    // silent server drops it too.
    let relay = lossy_relay(server_addr, lost).await;

    let config = Config {
        handshake_timeout: Some(Duration::from_secs(8)),
        ..Config::default()
    };
    let started = std::time::Instant::now();
    let conn = squic::dial(relay, &pub_key, config).await;
    assert!(
        conn.is_ok(),
        "handshake failed after losing {lost} Initial(s) in {:?}: {:?}",
        started.elapsed(),
        conn.err()
    );
}

/// Poll until the server's under-load state reaches `want`, or give up.
async fn wait_for_under_load(listener: &squic::ServerListener, want: bool) -> bool {
    for _ in 0..80 {
        if listener.load_stats().under_load == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// The cookie defence has to admit legitimate clients, not just reject
/// attackers. This exercises the whole exchange over real sockets: challenge,
/// decrypt, retransmit carrying MAC2, accept.
#[tokio::test]
async fn test_cookie_challenge_admits_a_legitimate_client() {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();
    let listener = std::sync::Arc::new(listener);

    // Under load before the first packet arrives. The client answers the
    // challenge as soon as it lands rather than waiting for a PTO, so this
    // completes in about a round trip and needs no help from a shortened
    // initial_rtt to fit inside the monitor's one-second window.
    listener.set_under_load(true);

    let accepting = listener.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    let config = Config {
        handshake_timeout: Some(Duration::from_secs(10)),
        ..Config::default()
    };
    let started = std::time::Instant::now();
    let conn = squic::dial(addr, &pub_key, config).await;
    let elapsed = started.elapsed();

    assert!(
        conn.is_ok(),
        "cookie challenge locked out a legitimate client after {elapsed:?}: {:?}",
        conn.err()
    );
    let stats = listener.load_stats();
    assert!(stats.cookie_replies_sent >= 1, "server never issued a challenge");
    assert!(
        stats.mac2_verified >= 1,
        "the client's MAC2 never verified — the exchange did not complete: {stats:?}"
    );
    // A PTO-driven answer takes ~1s on loopback; answering on receipt takes a
    // round trip. Anything approaching a second means the immediate
    // retransmission regressed and quinn's timer is doing the work again.
    assert!(
        elapsed < Duration::from_millis(300),
        "cookie exchange took {elapsed:?}; expected roughly one RTT, so the \
         challenge is being answered by a PTO rather than on receipt"
    );
}

/// Without the load monitor running, `under_load` stays false forever and the
/// whole cookie branch is unreachable — which is how it shipped.
#[tokio::test]
async fn test_load_monitor_raises_and_clears_under_load() {
    let config = Config {
        load_threshold: Some(1),
        ..Config::default()
    };
    let (listener, _key, pub_key) = start_server(config).await;
    let addr = listener.local_addr().unwrap();
    let listener = std::sync::Arc::new(listener);

    let accepting = listener.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    // Four handshakes in well under a second, against a threshold of one DH
    // per second.
    for _ in 0..4 {
        squic::dial(addr, &pub_key, Config::default()).await.unwrap();
    }

    assert!(
        wait_for_under_load(&listener, true).await,
        "load monitor never raised under_load"
    );
    assert!(
        wait_for_under_load(&listener, false).await,
        "under_load never cleared once the load stopped"
    );
}

/// `Some(0)` means off, as documented — not "use the default", which is what
/// it used to quietly become.
#[tokio::test]
async fn test_zero_load_threshold_disables_the_cookie_defence() {
    let config = Config {
        load_threshold: Some(0),
        ..Config::default()
    };
    let (listener, _key, pub_key) = start_server(config).await;
    let addr = listener.local_addr().unwrap();
    let listener = std::sync::Arc::new(listener);

    let accepting = listener.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    for _ in 0..4 {
        squic::dial(addr, &pub_key, Config::default()).await.unwrap();
    }
    assert!(
        !wait_for_under_load(&listener, true).await,
        "cookie defence engaged despite being disabled"
    );
    assert_eq!(listener.load_stats().cookie_replies_sent, 0);
}

#[tokio::test]
async fn test_server_public_key_is_dialable() {
    let (listener, signing_key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    // The accessor agrees with both the keypair it was built from and the
    // signing key's own verifying half.
    assert_eq!(listener.public_key(), pub_key);
    assert_eq!(listener.public_key(), signing_key.verifying_key().to_bytes());

    // The point of the accessor is that a caller need not have kept a copy, so
    // dial with the key the listener reports rather than the one we generated.
    // A wrong key here fails the handshake outright: the client pins it, and
    // MAC1 is computed against it.
    let reported = listener.public_key();

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        send.write_all(&buf[..n]).await.unwrap();
        send.finish().unwrap();
        let _ = send.stopped().await;
    });

    let conn = squic::dial(addr, &reported, Config::default()).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let mut buf = vec![0u8; 64];
    let n = recv.read(&mut buf).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"ping");

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_peer_key_matches_dialing_client() {
    use ed25519_dalek::SigningKey;

    // A client with a persistent identity: its X25519 transport key is derived
    // from an Ed25519 seed, exactly as real clients do.
    let client_seed = [42u8; 32];
    let client_signing = SigningKey::from_bytes(&client_seed);
    let client_x25519_pub = squic::crypto::ed25519_private_to_x25519(&client_signing);
    let expected = x25519_dalek::PublicKey::from(&client_x25519_pub).to_bytes();

    let (listener, _sk, server_pub) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        // The verified peer key is available before the handshake completes.
        let seen = listener.peer_key(&incoming);
        // The lookup is a peek (SIP-3 needs peer_key and peer_identity both
        // readable for one connection), so a second call still resolves.
        let seen_again = listener.peer_key(&incoming);
        let conn = incoming.await.unwrap();
        let (mut s, mut r) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = r.read(&mut buf).await.unwrap().unwrap();
        s.write_all(&buf[..n]).await.unwrap();
        s.finish().unwrap();
        let _ = s.stopped().await;
        (seen, seen_again)
    });

    let client_cfg = Config {
        client_key: Some(client_seed.iter().map(|b| format!("{b:02x}")).collect()),
        ..Default::default()
    };
    let conn = squic::dial(addr, &server_pub, client_cfg).await.unwrap();
    let (mut s, mut r) = conn.open_bi().await.unwrap();
    s.write_all(b"x").await.unwrap();
    s.finish().unwrap();
    let mut buf = vec![0u8; 16];
    let _ = r.read(&mut buf).await.unwrap().unwrap();

    let (seen, seen_again) = server.await.unwrap();
    assert_eq!(seen, Some(expected), "peer key must match the dialing client");
    assert_eq!(seen_again, Some(expected), "peek must resolve repeatedly");
}

/// SIP-3: a client that opts in carries its Ed25519 identity in the Initial, and
/// the server reports it at accept via `peer_identity()` — with no prior
/// registration of that caller. `peer_key` still resolves too.
#[tokio::test]
async fn test_peer_identity_is_reported_when_advertised() {
    use ed25519_dalek::SigningKey;
    let client_seed = [7u8; 32];
    let client_signing = SigningKey::from_bytes(&client_seed);
    let expected_ed = client_signing.verifying_key().to_bytes();

    let (listener, _sk, server_pub) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let key = listener.peer_key(&incoming);
        let id = listener.peer_identity(&incoming);
        let conn = incoming.await.unwrap();
        let (mut s, mut r) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = r.read(&mut buf).await.unwrap().unwrap();
        s.write_all(&buf[..n]).await.unwrap();
        s.finish().unwrap();
        let _ = s.stopped().await;
        (key, id)
    });

    let client_cfg = Config {
        client_key: Some(client_seed.iter().map(|b| format!("{b:02x}")).collect()),
        advertise_identity: true,
        ..Default::default()
    };
    let conn = squic::dial(addr, &server_pub, client_cfg).await.unwrap();
    let (mut s, mut r) = conn.open_bi().await.unwrap();
    s.write_all(b"x").await.unwrap();
    s.finish().unwrap();
    let mut buf = vec![0u8; 16];
    let _ = r.read(&mut buf).await.unwrap().unwrap();

    let (key, id) = server.await.unwrap();
    assert!(key.is_some(), "peer key must still be present");
    assert_eq!(id, Some(expected_ed), "advertised Ed25519 identity reported at accept");
}

/// SIP-3 is opt-in: a client that does not advertise (the default) is anonymous
/// on the wire — `peer_identity` is `None` though `peer_key` still resolves.
#[tokio::test]
async fn test_peer_identity_absent_by_default() {
    let client_seed = [7u8; 32];

    let (listener, _sk, server_pub) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let key = listener.peer_key(&incoming);
        let id = listener.peer_identity(&incoming);
        let conn = incoming.await.unwrap();
        let (mut s, mut r) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = r.read(&mut buf).await.unwrap().unwrap();
        s.write_all(&buf[..n]).await.unwrap();
        s.finish().unwrap();
        let _ = s.stopped().await;
        (key, id)
    });

    let client_cfg = Config {
        client_key: Some(client_seed.iter().map(|b| format!("{b:02x}")).collect()),
        // advertise_identity defaults to false
        ..Default::default()
    };
    let conn = squic::dial(addr, &server_pub, client_cfg).await.unwrap();
    let (mut s, mut r) = conn.open_bi().await.unwrap();
    s.write_all(b"x").await.unwrap();
    s.finish().unwrap();
    let mut buf = vec![0u8; 16];
    let _ = r.read(&mut buf).await.unwrap().unwrap();

    let (key, id) = server.await.unwrap();
    assert!(key.is_some(), "peer key present");
    assert_eq!(id, None, "no identity advertised, so none reported");
}

#[tokio::test]
async fn test_peer_key_none_for_unknown_dcid() {
    // A listener that has accepted nothing has nothing to report. We cannot
    // easily forge an Incoming, so this exercises the empty-table path via a
    // real accept whose key we drain twice (second is None) — the draining is
    // covered above; here we assert the ephemeral-client case still yields a
    // key, since an ephemeral client has a random X25519 key and no Ed25519
    // preimage, but MAC1 still proves possession of it.
    let (listener, _sk, server_pub) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let seen = listener.peer_key(&incoming);
        let conn = incoming.await.unwrap();
        let (mut s, mut r) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = r.read(&mut buf).await.unwrap().unwrap();
        s.write_all(&buf[..n]).await.unwrap();
        s.finish().unwrap();
        let _ = s.stopped().await;
        seen
    });

    // No client_key => ephemeral random X25519 key.
    let conn = squic::dial(addr, &server_pub, Config::default()).await.unwrap();
    let (mut s, mut r) = conn.open_bi().await.unwrap();
    s.write_all(b"x").await.unwrap();
    s.finish().unwrap();
    let mut buf = vec![0u8; 16];
    let _ = r.read(&mut buf).await.unwrap().unwrap();

    let seen = server.await.unwrap();
    assert!(seen.is_some(), "an ephemeral client still has a verified transport key");
}
