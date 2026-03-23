# sQUIC — Sovereign QUIC (Rust)

Rust implementation of sQUIC, wrapping [Quinn](https://github.com/quinn-rs/quinn). Wire-compatible with [squic-go](https://github.com/wave-cl/squic-go).

## Features

1. **Silent server** — invisible to port scanners. Only clients with the server's public key can elicit a response.
2. **No CA/PKI** — identity is a pinned Ed25519 public key (32 bytes). No certificate authorities.
3. **Client whitelisting** — runtime-manageable set of allowed client keys. Non-whitelisted clients are silently dropped at the MAC layer.
4. **Replay protection** — 120-second timestamp window in the MAC computation.
5. **Interoperable** — same wire format as squic-go. Go server + Rust client (and vice versa) work together.

## Install

```toml
[dependencies]
squic = { git = "https://github.com/wave-cl/squic-rust" }
```

## Performance

| Mode | macOS M4 Pro | Cheapest Linux VPS |
|------|-------------|-------------------|
| Upload | 2,023 Mbps | 2,510 Mbps |
| Download | 1,918 Mbps | 2,287 Mbps |
| Bidirectional | 2,571 Mbps total | 4,797 Mbps total |

Cross-implementation (Rust↔Go, same wire format):

| Mode | macOS M4 Pro | Cheapest Linux VPS |
|------|-------------|-------------------|
| Go client → Rust server | 1,679 Mbps | 1,849 Mbps |
| Rust server → Go client | 1,662 Mbps | 1,791 Mbps |

Measured with the included sqperf tool over loopback, 30-second runs.

## Examples

### sqperf

Throughput benchmark:

```bash
# Server
cargo run --release --example sqperf -- -s -p 5000

# Upload
cargo run --release --example sqperf -- -c 127.0.0.1 -p 5000 --key <hex> -t 30

# Download
cargo run --release --example sqperf -- -c 127.0.0.1 -p 5000 --key <hex> -t 30 -R

# Bidirectional
cargo run --release --example sqperf -- -c 127.0.0.1 -p 5000 --key <hex> -t 30 -d
```

### http3

HTTP/3 server and client:

```bash
# Server
cargo run --release --example http3 -- -s -p 443

# Client
cargo run --release --example http3 -- -c 127.0.0.1 -p 443 --key <hex>
cargo run --release --example http3 -- -c 127.0.0.1 -p 443 --key <hex> /health
```

## License

MIT
