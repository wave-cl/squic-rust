use quinn::{Endpoint, ServerConfig, ClientConfig, TransportConfig, VarInt};
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage:");
        println!("  quinn_perf -s [-p port]");
        println!("  quinn_perf -c <addr> [-p port] [-t secs] [-R] [-d]");
        return Ok(());
    }

    let is_server = args.contains(&"-s".to_string());
    let port = get_arg(&args, "-p").unwrap_or(5100);
    let time: u64 = get_arg(&args, "-t").unwrap_or(10);
    let reverse = args.contains(&"-R".to_string());
    let bidir = args.contains(&"-d".to_string());

    if is_server {
        run_server(port).await
    } else {
        let addr_str = get_arg_str(&args, "-c").ok_or("-c <addr> required")?;
        let addr: SocketAddr = format!("{}:{}", addr_str, port).parse()?;
        run_client(addr, Duration::from_secs(time), reverse, bidir).await
    }
}

fn get_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Option<T> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)?.parse().ok())
}

fn get_arg_str(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).map(|i| args[i + 1].clone())
}

fn generate_self_signed() -> (Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![cert_der], key_der)
}

fn transport_config() -> TransportConfig {
    let mut tc = TransportConfig::default();
    tc.max_idle_timeout(Some(VarInt::from_u32(30_000).into()));
    tc.max_concurrent_bidi_streams(VarInt::from_u32(100));
    tc.stream_receive_window(VarInt::from_u32(1_048_576));
    tc.receive_window(VarInt::from_u32(10_485_760));
    tc.send_window(10_485_760);
    tc
}

async fn run_server(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let (certs, key) = generate_self_signed();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())?;
    server_crypto.alpn_protocols = vec![b"quinn-perf".to_vec()];

    let quic_server_config: quinn_proto::crypto::rustls::QuicServerConfig = server_crypto
        .try_into()
        .expect("failed to create quic server config");
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(transport_config()));

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let endpoint = Endpoint::server(server_config, addr)?;
    println!("Quinn server listening on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
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
                    let mut total = 0u64;
                    let mut buf = vec![0u8; 32768];
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => total += n as u64,
                            _ => break,
                        }
                    }
                    let _ = send.write_all(total.to_string().as_bytes()).await;
                    let _ = send.finish();
                }
                b'D' => {
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

async fn run_client(
    addr: SocketAddr,
    duration: Duration,
    reverse: bool,
    bidir: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"quinn-perf".to_vec()];

    let quic_client_config: quinn_proto::crypto::rustls::QuicClientConfig = client_crypto
        .try_into()
        .expect("failed to create quic client config");
    let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
    client_config.transport_config(Arc::new(transport_config()));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    println!("Connecting to {}...", addr);
    let conn = endpoint.connect(addr, "localhost")?.await?;
    println!("Connected!");

    if bidir {
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
    } else if reverse {
        let (bytes, secs) = run_download(&conn, duration).await?;
        println!("[SUM]  0.00-{:.2} sec  {} MB  {:.1} Mbits/sec  receiver",
            secs, bytes / 1_048_576,
            bytes as f64 * 8.0 / secs / 1_000_000.0);
    } else {
        let (bytes, secs) = run_upload(&conn, duration).await?;
        println!("[SUM]  0.00-{:.2} sec  {} MB  {:.1} Mbits/sec  sender",
            secs, bytes / 1_048_576,
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
    let total = Arc::new(AtomicU64::new(0));

    let total_ref = total.clone();
    let progress = tokio::spawn(async move {
        let mut last_total = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;
        loop {
            interval.tick().await;
            let t = total_ref.load(Ordering::Relaxed);
            let delta = t - last_total;
            last_total = t;
            let elapsed = start.elapsed().as_secs_f64();
            let mbps = delta as f64 * 8.0 / 1_000_000.0;
            eprintln!("[  0]  {:.0}-{:.0}s  {} MB  {:.1} Mbits/sec  send",
                elapsed - 1.0, elapsed, delta / 1_048_576, mbps);
        }
    });

    while start.elapsed() < duration {
        send.write_all(&buf).await?;
        total.fetch_add(buf.len() as u64, Ordering::Relaxed);
    }
    send.finish()?;
    progress.abort();

    let mut server_buf = vec![0u8; 64];
    let n = recv.read(&mut server_buf).await?.unwrap_or(0);
    let confirmed: u64 = String::from_utf8_lossy(&server_buf[..n])
        .trim()
        .parse()
        .unwrap_or(0);

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!("  server confirmed: {} bytes", confirmed);
    Ok((total.load(Ordering::Relaxed), elapsed))
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
    let total = Arc::new(AtomicU64::new(0));

    let total_ref = total.clone();
    let progress = tokio::spawn(async move {
        let mut last_total = 0u64;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;
        loop {
            interval.tick().await;
            let t = total_ref.load(Ordering::Relaxed);
            let delta = t - last_total;
            last_total = t;
            let elapsed = start.elapsed().as_secs_f64();
            let mbps = delta as f64 * 8.0 / 1_000_000.0;
            eprintln!("[  0]  {:.0}-{:.0}s  {} MB  {:.1} Mbits/sec  recv",
                elapsed - 1.0, elapsed, delta / 1_048_576, mbps);
        }
    });

    while start.elapsed() < duration {
        match recv.read(&mut buf).await? {
            Some(n) => { total.fetch_add(n as u64, Ordering::Relaxed); }
            None => break,
        }
    }
    progress.abort();

    let elapsed = start.elapsed().as_secs_f64();
    Ok((total.load(Ordering::Relaxed), elapsed))
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
