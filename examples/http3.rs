//! HTTP/3 server and client over sQUIC.
//!
//! Server: invisible to port scanners, responds only to clients with the server's public key.
//! Client: pins the server's Ed25519 public key — no certificate authorities.
//!
//! Usage:
//!   cargo run --example http3 -- -s [-p port]
//!   cargo run --example http3 -- -c <host> -p <port> --key <hex> [path]

use clap::Parser;
use squic::{self, Config};
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "http3", about = "HTTP/3 over sQUIC")]
struct Args {
    /// Run as server
    #[arg(short = 's', long)]
    server: bool,

    /// Connect to server (host)
    #[arg(short = 'c', long)]
    client: Option<String>,

    /// Port
    #[arg(short = 'p', long, default_value = "443")]
    port: u16,

    /// Server public key (hex)
    #[arg(long)]
    key: Option<String>,

    /// Request path (client only)
    path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.server {
        run_server(args.port).await
    } else if let Some(host) = args.client {
        let key = args.key.ok_or("--key is required")?;
        let path = args.path.unwrap_or_else(|| "/".to_string());
        run_client(&host, args.port, &key, &path).await
    } else {
        println!("Usage:");
        println!("  cargo run --example http3 -- -s [-p port]");
        println!("  cargo run --example http3 -- -c <host> -p <port> --key <hex> [path]");
        Ok(())
    }
}

async fn run_server(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let (signing_key, pub_key) = squic::generate_keypair();
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    println!("Server public key: {}", hex::encode(pub_key));
    println!("Listening on {} (HTTP/3)", addr);

    let listener = squic::listen(addr, &signing_key, Config {
        alpn_protocols: vec![b"h3".to_vec()],
        ..Config::default()
    }).await?;

    loop {
        let incoming = match listener.accept().await {
            Some(i) => i,
            None => break,
        };

        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_h3_connection(conn).await {
                        eprintln!("H3 error: {e}");
                    }
                }
                Err(e) => eprintln!("Accept error: {e}"),
            }
        });
    }

    Ok(())
}

async fn handle_h3_connection(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                tokio::spawn(async move {
                    let (req, mut stream) = match resolver.resolve_request().await {
                        Ok(v) => v,
                        Err(e) => { eprintln!("resolve error: {e}"); return; }
                    };

                    let path = req.uri().path().to_string();
                    let (status, content_type, body) = match path.as_str() {
                        "/health" => (
                            200,
                            "application/json",
                            r#"{"status":"ok","protocol":"h3","server":"squic"}"#.to_string(),
                        ),
                        _ => (
                            200,
                            "text/plain",
                            "Hello from sQUIC HTTP/3!\n".to_string(),
                        ),
                    };

                    let resp = http::Response::builder()
                        .status(status)
                        .header("content-type", content_type)
                        .header("content-length", body.len())
                        .body(())
                        .unwrap();

                    if let Err(e) = stream.send_response(resp).await {
                        eprintln!("send response error: {e}");
                        return;
                    }
                    if let Err(e) = stream.send_data(bytes::Bytes::from(body)).await {
                        eprintln!("send data error: {e}");
                        return;
                    }
                    let _ = stream.finish().await;
                });
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("accept error: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn run_client(
    host: &str,
    port: u16,
    key_hex: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pub_key_bytes = hex::decode(key_hex)?;
    let mut pub_key = [0u8; 32];
    pub_key.copy_from_slice(&pub_key_bytes);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    let conn = squic::dial(addr, &pub_key, Config {
        alpn_protocols: vec![b"h3".to_vec()],
        ..Config::default()
    }).await?;

    let quinn_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await?;

    // Drive the connection in the background
    let drive = tokio::spawn(async move {
        driver.wait_idle().await;
    });

    let req = http::Request::builder()
        .uri(format!("https://{}:{}{}", host, port, path))
        .header("user-agent", "squic-rust/0.1")
        .body(())
        .unwrap();

    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;

    let resp = stream.recv_response().await?;
    println!("HTTP/3 {}", resp.status());
    for (name, value) in resp.headers() {
        println!("  {}: {}", name, value.to_str().unwrap_or("?"));
    }
    println!();

    // Read body
    use bytes::Buf;
    while let Some(chunk) = stream.recv_data().await? {
        let bytes = chunk.chunk();
        print!("{}", String::from_utf8_lossy(bytes));
    }

    drop(send_request);
    let _ = drive.await;

    Ok(())
}
