# sQUIC — Shielded QUIC (Rust)

Rust implementation of sQUIC, wrapping [Quinn](https://github.com/quinn-rs/quinn). Wire-compatible with [squic-go](https://github.com/wave-cl/squic-go).

## Features

1. **Pre-handshake authentication** — clients must prove knowledge of the server's public key before the QUIC handshake begins. Invalid packets are silently discarded.
2. **No CA/PKI** — identity is a pinned Ed25519 public key (32 bytes). No certificate authorities.
3. **Client whitelisting** — runtime-manageable set of allowed client keys. Non-whitelisted clients are silently dropped at the MAC layer.
4. **Persistent client identity** — optional `client_key` config for stable client identity across reconnects, enabling server-side whitelisting.
5. **Replay protection** — 120-second timestamp window in the MAC computation.
6. **Interoperable** — same wire format as squic-go. Go server + Rust client (and vice versa) work together.

### Connection Modes

| Mode | Server config | Client config | Behaviour |
|------|--------------|---------------|-----------|
| **Open** | No `allowed_keys` | No `client_key` | Any client with the server's public key can connect. Default. |
| **Whitelisted** | `allowed_keys` set | `client_key` set | Only clients whose keys are in the whitelist can connect. Silently dropped before any QUIC processing. |

In all three modes, the server is silent to anyone who does not possess the server's public key.

### Connection String

A server's address and public key can be shared as a single string, for example:

```
sqc://example.com:443/EFj2YJzH6MwVfPnbLdR4SjrUkA9QpXhgK7CcTx31Wm5
```

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
