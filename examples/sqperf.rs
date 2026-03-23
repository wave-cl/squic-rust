use clap::Parser;
use squic::{self, Config};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "sqperf", about = "sQUIC throughput benchmark")]
struct Args {
    /// Run as server
    #[arg(short = 's', long)]
    server: bool,

    /// Connect to server
    #[arg(short = 'c', long)]
    client: Option<String>,

    /// Port
    #[arg(short = 'p', long, default_value = "5000")]
    port: u16,

    /// Test duration in seconds
    #[arg(short = 't', long, default_value = "10")]
    time: u64,

    /// Server public key (hex)
    #[arg(long)]
    key: Option<String>,

    /// Reverse mode (server sends)
    #[arg(short = 'R', long)]
    reverse: bool,

    /// Bidirectional mode
    #[arg(short = 'd', long)]
    bidir: bool,

    /// Generate a new keypair
    #[arg(long)]
    genkey: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.genkey {
        let (key, pub_bytes) = squic::generate_keypair();
        println!("private: {}", hex::encode(key.to_bytes()));
        println!("public:  {}", hex::encode(pub_bytes));
        return Ok(());
    }

    if args.server {
        run_server(args).await
    } else if args.client.is_some() {
        run_client(args).await
    } else {
        println!("Usage:");
        println!("  sqperf --genkey");
        println!("  sqperf -s [-p port]");
        println!("  sqperf -c <addr> --key <hex> [-p port] [-t secs] [-R] [-d]");
        Ok(())
    }
}

async fn run_server(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let (signing_key, pub_key) = squic::generate_keypair();
    let addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;

    println!("Server listening on {}", addr);
    println!("Public key: {}", hex::encode(pub_key));

    let listener = squic::listen(addr, &signing_key, Config::default()).await?;

    loop {
        let incoming = match listener.accept().await {
            Some(i) => i,
            None => break,
        };

        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_connection(conn).await {
                        eprintln!("Connection error: {e}");
                    }
                }
                Err(e) => eprintln!("Accept error: {e}"),
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };

        tokio::spawn(async move {
            let mut mode = [0u8; 1];
            if recv.read_exact(&mut mode).await.is_err() {
                return;
            }

            match mode[0] {
                b'U' => {
                    // Upload: receive data, report total
                    let mut total = 0u64;
                    let mut buf = vec![0u8; 32768];
                    let start = Instant::now();
                    let mut last_report = start;

                    loop {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                total += n as u64;
                                let now = Instant::now();
                                if now.duration_since(last_report) >= Duration::from_secs(1) {
                                    let elapsed = now.duration_since(start).as_secs_f64();
                                    let mbps = (total as f64 * 8.0) / elapsed / 1_000_000.0;
                                    eprintln!("  Server: {:.0} MB in {:.0}s ({:.1} Mbps)",
                                        total as f64 / 1_048_576.0, elapsed, mbps);
                                    last_report = now;
                                }
                            }
                            _ => break,
                        }
                    }

                    // Send total back to client as text (matches Go sqperf format)
                    let _ = send.write_all(total.to_string().as_bytes()).await;
                    let _ = send.finish();
                }
                b'D' => {
                    // Download: send data as fast as possible
                    let buf = vec![0xABu8; 32768];
                    loop {
                        if send.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                }
                _ => {}
            }
        });
    }

    Ok(())
}

async fn run_client(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let host = args.client.unwrap();
    let key_hex = args.key.ok_or("--key is required")?;
    let pub_key_bytes = hex::decode(&key_hex)?;
    let mut pub_key = [0u8; 32];
    pub_key.copy_from_slice(&pub_key_bytes);

    let addr: SocketAddr = format!("{}:{}", host, args.port).parse()?;
    let duration = Duration::from_secs(args.time);

    println!("Connecting to {}...", addr);
    let conn = squic::dial(addr, &pub_key, Config::default()).await?;
    println!("Connected!");

    if args.bidir {
        // Bidirectional — run both on the current task
        let conn2 = conn.clone();
        let upload = async move { run_upload(&conn2, duration).await };
        let download = async move { run_download(&conn, duration).await };
        let (up, down) = tokio::join!(upload, download);
        let (up_bytes, up_secs) = up?;
        let (down_bytes, down_secs) = down?;
        println!("[UP]   {} MB  {:.1} Mbits/sec  sender",
            up_bytes / 1_048_576,
            up_bytes as f64 * 8.0 / up_secs / 1_000_000.0);
        println!("[DOWN] {} MB  {:.1} Mbits/sec  receiver",
            down_bytes / 1_048_576,
            down_bytes as f64 * 8.0 / down_secs / 1_000_000.0);
    } else if args.reverse {
        let (bytes, secs) = run_download(&conn, duration).await?;
        println!("[SUM]  {:.2}-{:.2} sec  {} MB  {:.1} Mbits/sec  receiver",
            0.0, secs, bytes / 1_048_576,
            bytes as f64 * 8.0 / secs / 1_000_000.0);
    } else {
        let (bytes, secs) = run_upload(&conn, duration).await?;
        println!("[SUM]  {:.2}-{:.2} sec  {} MB  {:.1} Mbits/sec  sender",
            0.0, secs, bytes / 1_048_576,
            bytes as f64 * 8.0 / secs / 1_000_000.0);
    }

    Ok(())
}

async fn run_upload(
    conn: &quinn::Connection,
    duration: Duration,
) -> Result<(u64, f64), Box<dyn std::error::Error>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"U").await?;

    let buf = vec![0xCDu8; 32768];
    let start = Instant::now();
    let mut total = 0u64;

    while start.elapsed() < duration {
        send.write_all(&buf).await?;
        total += buf.len() as u64;
    }
    send.finish()?;

    // Read server-confirmed bytes (text format, matches Go sqperf)
    let mut server_buf = vec![0u8; 64];
    let n = recv.read(&mut server_buf).await?.unwrap_or(0);
    let confirmed: u64 = String::from_utf8_lossy(&server_buf[..n])
        .trim()
        .parse()
        .unwrap_or(0);

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!("  server confirmed: {} bytes", confirmed);
    Ok((total, elapsed))
}

async fn run_download(
    conn: &quinn::Connection,
    duration: Duration,
) -> Result<(u64, f64), Box<dyn std::error::Error>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"D").await?;
    send.finish()?;

    let mut buf = vec![0u8; 32768];
    let start = Instant::now();
    let mut total = 0u64;

    while start.elapsed() < duration {
        match recv.read(&mut buf).await? {
            Some(n) => total += n as u64,
            None => break,
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    Ok((total, elapsed))
}
