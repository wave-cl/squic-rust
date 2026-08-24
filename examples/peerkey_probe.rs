//! Cross-implementation probe for the SIP-2 peer-key accessor.
//!
//! server: load a fixed keypair, accept one connection, print the peer key the
//!         transport verified as `PEERKEY=<hex>`, then complete the handshake.
//! client: dial with a fixed client key and print the X25519 key it will send
//!         as `CLIENTX=<hex>`.
//!
//! A harness runs this against the Go probe in every client/server combination
//! and asserts every PEERKEY equals every CLIENTX.
use clap::Parser;
use squic::{self, Config};
use std::net::SocketAddr;

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

    let incoming = listener.accept().await.ok_or("no connection")?;
    match listener.peer_key(&incoming) {
        Some(k) => println!("PEERKEY={}", hex::encode(k)),
        None => println!("PEERKEY=none"),
    }
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

    // Print the X25519 key this client will stamp into its Initial.
    let (sk, _) = squic::load_keypair(&seed)?;
    let x = squic::crypto::ed25519_private_to_x25519(&sk);
    let xpub = x25519_dalek::PublicKey::from(&x);
    println!("CLIENTX={}", hex::encode(xpub.to_bytes()));

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    let conn = squic::dial(
        addr,
        &server_pub,
        Config { client_key: Some(seed), ..Default::default() },
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hi").await?;
    send.finish()?;
    let mut buf = [0u8; 8];
    let _ = recv.read(&mut buf).await;
    Ok(())
}
