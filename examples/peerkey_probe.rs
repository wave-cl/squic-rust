//! Cross-implementation probe for the SIP-2 peer-key and SIP-3 peer-identity
//! accessors.
//!
//! server: load a fixed keypair, accept one connection, print the peer key the
//!         transport verified as `PEERKEY=<hex>` and the Ed25519 identity it
//!         bound as `PEERID=<hex>` (or `PEERID=none`), then complete the
//!         handshake.
//! client: dial with a fixed client key and print the X25519 key it will send
//!         as `CLIENTX=<hex>`, plus the Ed25519 identity it advertises as
//!         `CLIENTED=<hex>` — or `CLIENTED=none` without `--advertise`.
//!
//! With --under-load the server demands a cookie (SIP-7) from every caller
//! before doing any key agreement, and reports the defence's counters as
//! `COOKIES=<replies sent>,<MAC2 verified>` — so a harness can tell a
//! connection that went through the cookie exchange from one that merely
//! succeeded.
//!
//! A harness runs this against the Go probe in every client/server combination
//! and asserts every PEERKEY equals every CLIENTX, and every PEERID equals
//! every CLIENTED (which covers both the advertised and the anonymous case).
//!
//! Both modes must end the exchange rather than leave it to time out, and the
//! harnesses (`cross_peerkey_test.sh` and `cross_cookie_test.sh` in squic-go)
//! run the client in the foreground, so a probe that lingers is charged to
//! every row. The client bounds its read of the reply and closes the
//! connection; the server flushes its reply before returning. Drop either and
//! the peer waits out `max_idle_timeout` — 30 seconds a row, which took the
//! peer-key matrix from 2 seconds to 2m03s. The symptom misleads, too: the
//! delay lands on whichever side is waiting, not the side that left without
//! saying goodbye.
use clap::Parser;
use squic::{self, Config};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    server: bool,
    #[arg(long)]
    client: bool,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "5060")]
    port: u16,
    /// Server Ed25519 seed (hex) — server mode.
    #[arg(long)]
    server_key: Option<String>,
    /// Server Ed25519 public key (hex) — client mode.
    #[arg(long)]
    server_pub: Option<String>,
    /// Client Ed25519 seed (hex) — client mode.
    #[arg(long)]
    client_key: Option<String>,
    /// Advertise the client's Ed25519 identity in the envelope (SIP-3).
    #[arg(long)]
    advertise: bool,
    /// Start the server in under-load mode, so every caller is challenged for
    /// a cookie before the Diffie-Hellman (SIP-7) — server mode.
    #[arg(long)]
    under_load: bool,
    /// Envelope version to emit (SIP-29) — client mode.
    #[arg(long, default_value = "4")]
    envelope_version: u8,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.server {
        run_server(args).await
    } else if args.client {
        run_client(args).await
    } else {
        Err("specify --server or --client".into())
    }
}

async fn run_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let seed = args.server_key.ok_or("--server-key required")?;
    let (signing_key, pubk) = squic::load_keypair(&seed)?;
    println!("SERVERPUB={}", hex::encode(pubk));
    std::io::stdout().flush()?;
    let addr: SocketAddr = format!("127.0.0.1:{}", args.port).parse()?;
    let listener = squic::listen(addr, &signing_key, Config::default()).await?;
    if args.under_load {
        listener.set_under_load(true);
    }

    let incoming = listener.accept().await.ok_or("no connection")?;
    match listener.peer_key(&incoming) {
        Some(k) => println!("PEERKEY={}", hex::encode(k)),
        None => println!("PEERKEY=none"),
    }
    match listener.peer_identity(&incoming) {
        Some(id) => println!("PEERID={}", hex::encode(id)),
        None => println!("PEERID=none"),
    }
    let stats = listener.load_stats();
    println!(
        "COOKIES={},{}",
        stats.cookie_replies_sent, stats.mac2_verified
    );
    std::io::stdout().flush()?;
    // Complete the handshake so the client does not error out.
    let conn = incoming.await?;
    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let mut buf = [0u8; 8];
        let _ = recv.read(&mut buf).await;
        let _ = send.write_all(b"ok").await;
        let _ = send.finish();
        let _ = send.stopped().await;
    }
    Ok(())
}

async fn run_client(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let seed = args.client_key.ok_or("--client-key required")?;
    let server_pub_hex = args.server_pub.ok_or("--server-pub required")?;
    let server_pub: [u8; 32] = hex::decode(&server_pub_hex)?
        .try_into()
        .map_err(|_| "server-pub must be 32 bytes")?;

    // Print the X25519 key this client will stamp into its Initial, and the
    // Ed25519 identity it will advertise (or `none`).
    let (sk, ed_pub) = squic::load_keypair(&seed)?;
    let x = squic::crypto::ed25519_private_to_x25519(&sk);
    let xpub = x25519_dalek::PublicKey::from(&x);
    println!("CLIENTX={}", hex::encode(xpub.to_bytes()));
    println!("CLIENTVER={}", args.envelope_version);
    if args.advertise {
        println!("CLIENTED={}", hex::encode(ed_pub));
    } else {
        println!("CLIENTED=none");
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    let conn = squic::dial(
        addr,
        &server_pub,
        Config {
            client_key: Some(seed),
            advertise_identity: args.advertise,
            envelope_version: args.envelope_version,
            ..Default::default()
        },
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hi").await?;
    send.finish()?;
    // The reply is an acknowledgement, not a result: everything the harness
    // reads from this process is already on stdout, and everything it reads
    // from the server was printed during the handshake. So bound the wait. An
    // unbounded read costs `max_idle_timeout` — 30 seconds — against any peer
    // that exits without flushing its reply, which is a probe that has already
    // succeeded sitting silent for half a minute.
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), recv.read(&mut buf)).await;
    // Say we are done rather than letting the connection idle out, so the peer
    // learns of the close now instead of on its own timeout.
    conn.close(0u32.into(), b"done");
    Ok(())
}
