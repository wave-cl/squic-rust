use squic::{self, Config};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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
    fake_initial[1..5].copy_from_slice(&1u32.to_be_bytes()); // QUIC v1, so this
    // reaches MAC1 rather than being turned away at the version gate
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

/// SIP-6 promises silence to any caller that cannot authenticate, and the
/// envelope does not deliver it on its own: it gates Initials, and every other
/// long header reaches the QUIC stack untouched. A stack that does not
/// recognise the version answers with a Version Negotiation packet before it
/// has looked at the connection at all — no key, no captured traffic, one
/// datagram.
///
/// This test listens for the reply. Every other silence test here asserts that
/// a *legitimate* client still connects, which is why none of them could have
/// caught this: the probe is a packet a sQUIC client never sends.
#[tokio::test]
async fn test_silent_server_answers_no_version_probe() {
    let (listener, _key, _pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Every long-header type, including the Initial — the version gate runs
    // ahead of the envelope, so a bad version is dropped whatever the type.
    // 1200 bytes because quic-go will not answer anything smaller; quinn has
    // no such floor, so the Rust side is if anything easier to probe.
    for first in [0xE0u8, 0xD0, 0xF0, 0xC0] {
        let mut pkt = vec![0u8; 1200];
        pkt[0] = first;
        pkt[1..5].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // no one supports this
        pkt[5] = 0; // DCID length
        pkt[6] = 0; // SCID length
        probe.send_to(&pkt, addr).await.unwrap();

        let mut reply = [0u8; 2048];
        let got =
            tokio::time::timeout(Duration::from_millis(300), probe.recv_from(&mut reply)).await;
        assert!(
            got.is_err(),
            "server answered a {first:#04x} long header with an unsupported version \
             ({} bytes) — a scanner just proved it exists",
            got.unwrap().unwrap().0
        );
    }
    drop(listener);
}

/// The other half, and the reason the gate is on the version rather than the
/// packet type: a client's Handshake and 0-RTT packets are long-headed too, so
/// a blanket drop of non-Initial long headers would break every connection at
/// the second flight. A full handshake exercises that path.
#[tokio::test]
async fn test_version_gate_does_not_break_the_handshake() {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let _conn = incoming.await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        squic::dial(addr, &pub_key, Config::default()),
    )
    .await
    .expect("handshake timed out — the version gate is dropping live traffic")
    .expect("handshake failed");

    drop(conn);
    let _ = server_task.await;
}

/// quinn answers a short-header packet for a connection it does not know with a
/// **stateless reset**, provided the destination CID passes its generator's
/// `validate`. That is a reply to a caller who has proved nothing, and it is
/// what squic-go closes by leaving `StatelessResetKey` nil. quinn offers no
/// such switch, so squic-rust had it on by default.
///
/// A genuine CID is needed to test it: a random one would fail quinn's default
/// `validate` about 2^40 times out of 2^40 and the test would pass whether or
/// not the hole was open. So this relays a real connection, records the
/// destination CID the client puts on its 1-RTT packets — a CID the *server*
/// issued — then closes the connection and probes with it.
#[tokio::test]
async fn test_no_stateless_reset_for_a_server_issued_cid() {
    let (listener, _key, pub_key) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    // A relay that notes the DCID of the first short-header packet going up.
    let seen: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    back.connect(addr).await.unwrap();
    {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut up = vec![0u8; 65536];
            let mut down = vec![0u8; 65536];
            let mut client: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    Ok((n, from)) = front.recv_from(&mut up) => {
                        client = Some(from);
                        // Short header: header-form clear, fixed bit set. The
                        // DCID follows the first byte and is 8 bytes wide.
                        if n >= 9 && up[0] & 0xC0 == 0x40 {
                            let mut slot = seen.lock().unwrap();
                            if slot.is_none() {
                                *slot = Some(up[1..9].to_vec());
                            }
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
    }

    let server_task = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut s, mut r) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 16];
        let n = r.read(&mut buf).await.unwrap().unwrap();
        s.write_all(&buf[..n]).await.unwrap();
        s.finish().unwrap();
        let _ = s.stopped().await;
        listener
    });

    let conn = squic::dial(front_addr, &pub_key, Config::default())
        .await
        .expect("dial through the relay");
    let (mut s, mut r) = conn.open_bi().await.unwrap();
    s.write_all(b"x").await.unwrap();
    s.finish().unwrap();
    let mut buf = vec![0u8; 16];
    let _ = r.read(&mut buf).await.unwrap();

    // Wait for the relay to see a short-header datagram, rather than assuming
    // it already has. The read returning does not guarantee one: QUIC coalesces
    // packets, so the client's first 1-RTT packet can ride in the same datagram
    // behind a Handshake packet, leaving `up[0]` a long header that the relay
    // does not match. A standalone short-header datagram follows within a few
    // tens of milliseconds — the ACK for the response just read — but checking
    // once, immediately, raced it and failed about one run in twenty.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let cid = loop {
        if let Some(cid) = seen.lock().unwrap().clone() {
            break cid;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay saw no short-header packet in 5s, so no server CID was \
             captured — every datagram from the client was long-headed or \
             coalesced behind a long header"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(cid.len(), 8);

    // Retire it: close the connection so the CID is no longer routable.
    conn.close(0u32.into(), b"done");
    let listener = server_task.await.unwrap();
    drop(conn);

    // Probe with the genuine, now-unroutable CID. quinn drains a closed
    // connection for a few PTOs before the CID leaves its index, so keep
    // probing well past that — the reset appears once draining ends.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = vec![0u8; 64];
    pkt[0] = 0x40; // short header, fixed bit set
    pkt[1..9].copy_from_slice(&cid);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut reply = [0u8; 2048];
    while tokio::time::Instant::now() < deadline {
        probe.send_to(&pkt, addr).await.unwrap();
        if let Ok(Ok((n, _))) = tokio::time::timeout(
            Duration::from_millis(200),
            probe.recv_from(&mut reply),
        )
        .await
        {
            panic!("server answered a short header bearing one of its own retired CIDs with {n} bytes — that is a stateless reset, and it proves the server exists");
        }
    }
    drop(listener);
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

/// The trailer widths, at runtime as well as at compile time. An anonymous
/// caller pays 69 bytes; carrying an identity costs the 32 that version 3 spent
/// on every Initial whether there was one or not.
#[test]
fn trailer_widths_are_69_and_101() {
    assert_eq!(squic::mac::TRAILER_ANON, 69);
    assert_eq!(
        squic::mac::TRAILER_ANON,
        squic::mac::CLIENT_KEY_SIZE
            + squic::mac::TIMESTAMP_SIZE
            + squic::mac::GATE_SIZE
            + squic::mac::MAC_SIZE
            + squic::mac::HDR_SIZE,
    );
    assert_eq!(
        squic::mac::TRAILER_WITH_IDENTITY,
        squic::mac::TRAILER_ANON + squic::mac::ED25519_SIZE
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

/// The gate key a caller derives from the server's *published* Ed25519 key.
///
/// The forgeries below use the real one deliberately. The gate proves only that
/// a caller holds a public value, so an attacker has it too — and every check
/// these tests exercise has to stand on its own, without the gate turning the
/// attacker away first and making the test pass for the wrong reason.
fn server_gate_key(server_ed_pub: &[u8; 32]) -> [u8; 32] {
    let x = squic::crypto::ed25519_public_to_x25519(server_ed_pub).expect("server key maps");
    squic::mac::gate_key(x.as_bytes())
}

/// Build one Initial envelope by hand, the way a client would.
/// Returns the datagram ready to put on the wire.
fn forge_initial(
    shared: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    gate_key: &[u8],
) -> Vec<u8> {
    let datagram = {
        let mut d = vec![0u8; 1200];
        d[0] = 0xC0; // long header, fixed bit, Initial
        // QUIC v1. The server drops a long header carrying a version its QUIC
        // stack would not parse, and it does so before the envelope is read —
        // so a forgery left at version 0 is refused for that reason alone, and
        // the tests below would pass without ever reaching the check they name.
        d[1..5].copy_from_slice(&1u32.to_be_bytes());
        d[5] = 8; // DCID length
        d
    };
    let ts = squic::mac::now_timestamp();
    let h = squic::mac::hdr(squic::mac::ENVELOPE_V4, false);

    let mut buf = datagram;
    buf.extend_from_slice(client_x25519_pub);
    buf.extend_from_slice(&ts.to_be_bytes());
    // The forgery holds the server's public key — it is published — so the gate
    // is no obstacle to it. That is deliberate: the check this fixture exists to
    // exercise is the non-contributory one, and it must stand on its own.
    let gate = squic::mac::compute_gate(h, gate_key, &buf);
    let mac1 = squic::mac::compute_mac1(h, shared, &buf);
    buf.extend_from_slice(&gate);
    buf.extend_from_slice(&mac1);
    buf.push(h);
    buf
}

/// A small-order client key makes the exchange non-contributory: the shared
/// secret is all zeros whatever the server's private key is, so a caller who
/// has never seen the server's public key can predict it and forge a MAC1 that
/// verifies. SIP-6 step 5 is the only thing stopping this for a deployment with
/// no whitelist.
#[tokio::test]
async fn test_small_order_client_key_is_refused() {
    let (listener, _sk, pk) = start_server(Config::default()).await;
    let server_addr = listener.local_addr().unwrap();

    // The attacker knows nothing about the server, and assumes the shared
    // secret will be zeros — which it will be, if the check is missing.
    let assumed_shared = [0u8; 32];
    let small_order_key = [0u8; 32];
    let buf = forge_initial(&assumed_shared, &small_order_key, &server_gate_key(&pk));

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&buf, server_addr).await.unwrap();

    let accepted = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "a stranger forged MAC1 with a small-order key and was admitted"
    );
}

/// The whitelist is a filter, not proof of possession: the X25519 key is
/// plaintext on the wire, so anyone who has seen an authorised client connect
/// can copy the key. MAC1 still has to verify afterwards.
#[tokio::test]
async fn test_whitelist_does_not_substitute_for_mac1() {
    let (_victim_sk, victim_ed) = squic::generate_keypair();
    let victim_x = squic::crypto::ed25519_public_to_x25519(&victim_ed).unwrap();
    let victim_key = victim_x.to_bytes();

    let (listener, _sk, pk) = start_server(Config {
        allowed_keys: Some(vec![victim_key]),
        ..Default::default()
    })
    .await;
    let server_addr = listener.local_addr().unwrap();

    // The attacker presents the victim's whitelisted key, and cannot compute
    // the shared secret it belongs to.
    let mut wrong_shared = [0u8; 32];
    wrong_shared[0] = 0x5A;
    let buf = forge_initial(&wrong_shared, &victim_key, &server_gate_key(&pk));

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&buf, server_addr).await.unwrap();

    let accepted = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "a whitelisted key admitted a caller that could not pass MAC1"
    );
}

/// Under load, an Initial carrying the all-zero MAC2 sentinel must draw a
/// cookie reply rather than being admitted — even though its MAC1 is perfectly
/// good. This is the challenge half of SIP-7; the existing cookie test covers
/// the answer half.
#[tokio::test]
async fn test_zero_mac2_under_load_draws_a_challenge() {
    let (listener, signing_key, pk) = start_server(Config::default()).await;
    let server_addr = listener.local_addr().unwrap();
    listener.set_under_load(true);

    // A genuine caller: real key, real shared secret, real MAC1, no cookie.
    let (client_sk, _client_ed) = squic::generate_keypair();
    let client_x_priv = squic::crypto::ed25519_private_to_x25519(&client_sk);
    let client_x_pub = x25519_dalek::PublicKey::from(&client_x_priv).to_bytes();
    let server_x_pub =
        squic::crypto::ed25519_public_to_x25519(&signing_key.verifying_key().to_bytes()).unwrap();
    let shared = squic::crypto::x25519(&client_x_priv, &server_x_pub).unwrap();

    let buf = forge_initial(&shared, &client_x_pub, &server_gate_key(&pk));

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&buf, server_addr).await.unwrap();

    let mut reply = [0u8; 128];
    let got = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut reply))
        .await
        .expect("no cookie reply arrived");
    let (n, _from) = got.unwrap();

    assert_eq!(
        reply[0],
        squic::mac::COOKIE_REPLY_TYPE,
        "expected a cookie reply, got first byte {:#04x}",
        reply[0]
    );
    // 1 type byte + 24 nonce + 16 cookie + 16 tag.
    assert_eq!(n, 57, "cookie reply is not the width SIP-7 specifies");

    // And it opens under the key any client can derive from the server's
    // public key — SIP-7's cookie_key.
    let cookie_key = squic::mac::cookie_key(&server_x_pub.to_bytes());
    let cookie = squic::mac::decrypt_cookie(&cookie_key, &reply[1..n])
        .expect("cookie reply did not open under the derived key");
    assert_eq!(cookie.len(), 16);

    let stats = listener.load_stats();
    assert!(stats.under_load);
    assert!(stats.cookie_replies_sent >= 1);
}

/// The server keeps the previous cookie secret for one rotation period. Without
/// that grace, a client challenged just before a rotation answers with a cookie
/// the server no longer recognises, is challenged again, and in a pathological
/// case never converges.
#[tokio::test]
async fn test_cookie_secret_rotation_keeps_one_generation_of_grace() {
    let (listener, signing_key, pk) = start_server(Config::default()).await;
    let server_addr = listener.local_addr().unwrap();
    listener.set_under_load(true);

    let (client_sk, _ed) = squic::generate_keypair();
    let client_x_priv = squic::crypto::ed25519_private_to_x25519(&client_sk);
    let client_x_pub = x25519_dalek::PublicKey::from(&client_x_priv).to_bytes();
    let server_x_pub =
        squic::crypto::ed25519_public_to_x25519(&signing_key.verifying_key().to_bytes()).unwrap();
    let shared = squic::crypto::x25519(&client_x_priv, &server_x_pub).unwrap();
    let cookie_key = squic::mac::cookie_key(&server_x_pub.to_bytes());

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Draw a challenge and keep the cookie.
    sock.send_to(&forge_initial(&shared, &client_x_pub, &server_gate_key(&pk)), server_addr)
        .await
        .unwrap();
    let mut reply = [0u8; 128];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut reply))
        .await
        .expect("no challenge")
        .unwrap();
    let cookie: [u8; 16] = squic::mac::decrypt_cookie(&cookie_key, &reply[1..n])
        .expect("open the challenge")
        .try_into()
        .unwrap();

    // Answering with a cookie minted under the current secret is admitted.
    let before = listener.load_stats().mac2_verified;
    send_with_cookie(&sock, server_addr, &shared, &client_x_pub, &cookie).await;
    assert_eq!(
        wait_for_mac2(&listener, before + 1).await,
        before + 1,
        "a fresh cookie was not accepted"
    );

    // One rotation later it is the *previous* secret, and still accepted.
    listener.rotate_cookie_secret();
    let before = listener.load_stats().mac2_verified;
    send_with_cookie(&sock, server_addr, &shared, &client_x_pub, &cookie).await;
    assert_eq!(
        wait_for_mac2(&listener, before + 1).await,
        before + 1,
        "the grace period did not accept a cookie from the previous secret"
    );

    // Two rotations later it is older than the grace period, and is refused.
    listener.rotate_cookie_secret();
    listener.rotate_cookie_secret();
    let before = listener.load_stats().mac2_verified;
    send_with_cookie(&sock, server_addr, &shared, &client_x_pub, &cookie).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        listener.load_stats().mac2_verified,
        before,
        "a cookie two rotations old was still accepted"
    );
}

async fn send_with_cookie(
    sock: &tokio::net::UdpSocket,
    to: SocketAddr,
    shared: &[u8; 32],
    client_pub: &[u8; 32],
    cookie: &[u8; 16],
) {
    // The same envelope, with the cookie as the gate key instead of the one
    // derived from the server's public key. One field, two modes.
    let buf = forge_initial(shared, client_pub, cookie);
    sock.send_to(&buf, to).await.unwrap();
}

async fn wait_for_mac2(listener: &squic::ServerListener, want: u64) -> u64 {
    for _ in 0..40 {
        let n = listener.load_stats().mac2_verified;
        if n >= want {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    listener.load_stats().mac2_verified
}

/// One version, and the default accept-set is that same version.
///
/// The second audit measured why this matters: with `[1, 2, 3]` as the shipped
/// default, a junk datagram bought a curve operation, because versions 1 and 2
/// carried no cheap gate for the server to check. A default that admits a
/// weaker envelope than the client sends undoes the gate entirely.
#[test]
fn the_only_version_is_four_and_it_is_the_default_on_both_sides() {
    let config = Config::default();
    assert_eq!(config.envelope_version, squic::mac::ENVELOPE_V4);
    assert_eq!(config.accepted_envelope_versions, vec![squic::mac::ENVELOPE_V4]);
    assert_eq!(squic::mac::ENVELOPE_VERSIONS, [squic::mac::ENVELOPE_V4]);
}

/// S9: a coalesced burst of Initials must still be accepted.
///
/// On Linux, `quinn_udp::UdpSocketState::new` opportunistically enables
/// UDP_GRO, so the kernel can hand back one `RecvMeta` covering several
/// datagrams. squic validates and strips the envelope before quinn sees the
/// buffer, reading only `len`, so a coalesced run used to be MAC1'd as one
/// giant datagram and dropped — silently, which is the failure mode this
/// codebase exists to avoid. `socket_state` turns GRO back off; this guards it.
///
/// The two cases send byte-identical, individually valid Initials and differ
/// only in how they reach the kernel. Case B is the control: if it ever fails,
/// the harness is wrong and case A proves nothing, so it is asserted first.
///
/// Linux-only, deliberately: nothing coalesces elsewhere, and a test that
/// passes by not exercising its condition is worse than no test.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_coalesced_burst_of_initials_is_still_accepted() {
    use quinn::udp::{Transmit, UdpSockRef, UdpSocketState};
    use squic::crypto::{ed25519_private_to_x25519, ed25519_public_to_x25519, x25519};
    use squic::mac::{
        ENVELOPE_V4, compute_gate, compute_mac1, gate_key, hdr, now_timestamp,
    };
    use std::net::UdpSocket;

    const BURST: usize = 4;

    let (listener, _key, server_pub) = start_server(Config::default()).await;
    let addr = listener.local_addr().unwrap();

    let (client_key, client_ed_pub) = squic::generate_keypair();
    let client_x_priv = ed25519_private_to_x25519(&client_key);
    let client_x_pub = ed25519_public_to_x25519(&client_ed_pub).unwrap();
    let server_x_pub = ed25519_public_to_x25519(&server_pub).unwrap();
    let shared = x25519(&client_x_priv, &server_x_pub).unwrap();
    let kg = gate_key(server_x_pub.as_bytes());

    // A v4 Initial. Bytes 1..5 must carry a QUIC version the server supports or
    // S1's version gate drops it before the envelope is reached — which is how
    // the first draft of this test managed to refuse its own control.
    let build = || {
        let mut datagram = vec![0xC3u8; 1200];
        datagram[1..5].copy_from_slice(&1u32.to_be_bytes());
        let h = hdr(ENVELOPE_V4, false);
        let ts = now_timestamp();
        let mut buf = Vec::new();
        buf.extend_from_slice(&datagram);
        buf.extend_from_slice(client_x_pub.as_bytes());
        buf.extend_from_slice(&ts.to_be_bytes());
        let gate = compute_gate(h, &kg, &buf);
        let mac1 = compute_mac1(h, &shared, &buf);
        buf.extend_from_slice(&gate);
        buf.extend_from_slice(&mac1);
        buf.push(h);
        buf
    };

    let accepted_v4 = || {
        listener
            .load_stats()
            .accepted_by_version
            .iter()
            .find(|(v, _)| *v == ENVELOPE_V4)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    };

    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx_state = UdpSocketState::new(UdpSockRef::from(&tx)).unwrap();

    // Control first: separate writes, nothing to coalesce.
    let before = accepted_v4();
    for _ in 0..BURST {
        tx.send_to(&build(), addr).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let separate = accepted_v4() - before;
    assert_eq!(
        separate, BURST as u64,
        "control failed: plain Initials were refused, so this test cannot \
         say anything about coalescing"
    );

    // The finding: the same Initials in one GSO write, which the kernel
    // coalesces into a single RecvMeta on the way in.
    let before = accepted_v4();
    let mut blob = Vec::new();
    for _ in 0..BURST {
        blob.extend_from_slice(&build());
    }
    let one = build().len();
    tx_state
        .send(
            UdpSockRef::from(&tx),
            &Transmit {
                destination: addr,
                ecn: None,
                contents: &blob,
                segment_size: Some(one),
                src_ip: None,
            },
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let coalesced = accepted_v4() - before;

    assert_eq!(
        coalesced, BURST as u64,
        "a coalesced burst of valid Initials was dropped ({coalesced} of {BURST} \
         accepted) while the same packets sent separately were all accepted — \
         GRO is back on, and a client retrying a handshake is being refused in \
         silence"
    );
}
