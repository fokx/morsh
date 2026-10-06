# morsh

[![Crates.io](https://img.shields.io/crates/v/morsh.svg)](https://crates.io/crates/morsh)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**morsh** is a next-generation remote terminal and shell over QUIC and TLS 1.3, combining the responsiveness and roaming resilience of [Mosh](https://mosh.org/) with the versatility, tunneling, and authentication flexibility of [OpenSSH](https://www.openssh.com/).

---

## Features

- **QUIC & TLS 1.3 Transport**: Multiplexed bidirectional streams over UDP with TLS 1.3 encryption, eliminating head-of-line blocking and providing single-RTT connection establishment.
- **Connection Migration & IP Roaming**: Seamlessly roam between Wi-Fi, Ethernet, and cellular networks without dropping active sessions.
- **Predictive Local Echo**: Speculative keystroke rendering with ANSI styling (dim/underline) and 1-RTT server divergence rollback, eliminating perceived latency on high-RTT links.
- **Session Persistence & Screen Recovery**: Server-side virtual terminal emulator (`vt100`) tracks screen state and cursor coordinates. Detach voluntarily (`Ctrl-^ d`) or recover from connection drops instantly via 128-bit cryptographic session tokens.
- **TCP Fallback & Happy Eyeballs**: RFC 8305 connection racing automatically selects QUIC/UDP or seamlessly falls back to multiplexed TLS 1.3 over TCP in UDP-restricted network environments.
- **Port Forwarding & Tunnels**:
  - Local TCP forwarding (`-L [bind:]port:host:hostport`)
  - Remote TCP forwarding (`-R [bind:]port:host:hostport`)
  - Dynamic SOCKS5 proxy (`-D [bind:]port`)
  - Native UDP datagram forwarding (`-U [bind:]port:host:hostport`)
  - Tunnel-only mode (`-N` / `--no-shell`)
- **Stealth Security & Handshake Authentication**:
  - Stealth Knock protection (SSH3-style URL path validation to reject unauthorized port scanners)
  - OpenSSH `authorized_keys` parsing with Ed25519, ECDSA, and RSA signature verification
  - UNIX domain socket `ssh-agent` integration
  - Linux PAM password verification
- **OpenSSH CLI & Configuration Parity**:
  - OpenSSH flag compatibility (`-p`, `-i`, `-F`, `-o`, `-C`, `-4`, `-6`, `-v`)
  - Client configuration in `~/.morsh/config.toml` with DP wildcard pattern matching, negations (`!pattern`), and host aliases
  - Server configuration in `/etc/morsh/morshd.toml` with dynamic SIGHUP configuration reload

---

## Installation

### From crates.io

Install the client CLI:
```bash
cargo install morsh
```

Install the server daemon:
```bash
cargo install morshd
```

---

## Quick Start

### 1. Start Server Daemon (`morshd`)

Run with ephemeral self-signed certificates:
```bash
morshd --listen 0.0.0.0:2222
```

Or run with stealth knock path protection and explicit certificates:
```bash
morshd --listen 0.0.0.0:2222 \
       --cert /etc/ssl/certs/morshd.crt \
       --key /etc/ssl/private/morshd.key \
       --stealth-knock "/api/v1/telemetry-stream"
```

### 2. Connect with Client (`morsh`)

Connect to a remote server:
```bash
morsh user@example.com:2222
```

Using OpenSSH key and stealth knock path:
```bash
morsh -i ~/.ssh/id_ed25519 \
      --stealth-knock "/api/v1/telemetry-stream" \
      user@example.com:2222
```

Detaching and resuming sessions:
- Press `Ctrl-^ d` inside the shell to detach without killing remote processes.
- Re-run `morsh user@example.com:2222` to resume the persistent session with instant screen state recovery.

Port forwarding and SOCKS5 proxy:
```bash
# Dynamic SOCKS5 proxy on local port 1080
morsh -D 1080 -N user@example.com:2222

# Forward local port 8080 to remote Postgres 5432
morsh -L 8080:localhost:5432 user@example.com:2222
```

---

## Workspace Architecture

| Crate | Purpose |
|---|---|
| [`morsh`](https://crates.io/crates/morsh) | Interactive client CLI binary with terminal raw mode and config resolution |
| [`morshd`](https://crates.io/crates/morshd) | Server daemon binary multiplexing PTY, auth, tunnels, and sessions |
| [`morsh-core`](https://crates.io/crates/morsh-core) | Binary wire protocol framing, Postcard serialization codecs, and constants |
| [`morsh-transport`](https://crates.io/crates/morsh-transport) | Multiplexed QUIC (Quinn) and TCP transport with Happy Eyeballs auto-detection |
| [`morsh-auth`](https://crates.io/crates/morsh-auth) | SSH key parsing (Ed25519/ECDSA/RSA), `ssh-agent`, PAM, and stealth knock verification |
| [`morsh-term`](https://crates.io/crates/morsh-term) | PTY supervisor (`portable-pty`), TIOCSWINSZ resizing, and `vt100` state buffer |
| [`morsh-predict`](https://crates.io/crates/morsh-predict) | Speculative local echo engine, visual ANSI styling, and 1-RTT divergence rollback |
| [`morsh-tunnel`](https://crates.io/crates/morsh-tunnel) | Local/remote TCP forwarding, SOCKS5 proxy engine, and UDP datagram bridging |

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or <http://www.apache.org/licenses/LICENSE-2.0>).
