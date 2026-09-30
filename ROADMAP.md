# morsh: Architectural Blueprint & Phased Roadmap

> **IMPORTANT ARCHITECTURAL INVARIANT**:
> **`ROADMAP.md` IS IMMUTABLE**. This document defines the permanent, authoritative architectural design, protocol specifications, crate structure, and phase objectives for `morsh`.
> **DO NOT** edit this file to track execution progress, toggle checkmarks, or record implementation logs.
> **ALL execution updates, task completions, and handoff instructions MUST be recorded in [`PROGRESS.md`](PROGRESS.md)**.

---

## 1. Executive Summary & Design Vision

`morsh` is a next-generation terminal and multiplexing protocol written in pure Rust. It combines the strongest architectural innovations of **Mosh** and **SSH3**:

```
+-----------------------------------------------------------------------------------+
|                                  morsh (Client CLI)                               |
|  +---------------------+  +-----------------------+  +-------------------------+  |
|  |  Predictive Engine  |  |  Screen State Buffer  |  |  Terminal I/O (Raw Mode)|  |
|  |  (speculative echo) |  |     (vt100 / diff)    |  |       (crossterm)       |  |
|  +----------+----------+  +-----------+-----------+  +------------+------------+  |
+-------------|-------------------------|---------------------------|---------------+
              |                         |                           |
              | QUIC Multiplexed Channels:                          |
              | - Stream 0: Control, Auth & Stealth Knocking        |
              | - Stream 1..N: Interactive PTY & Command Channels   |
              | - Stream / Datagram: State Sync & Realtime Diffs    |
              | - Stream / Datagram: TCP / UDP Port Forwardings     |
              v                         v                           v
+-----------------------------------------------------------------------------------+
|                   Transport Layer (QUIC / TLS 1.3 + TCP Fallback)                 |
|  - Connection Migration: Seamless IP/Interface roaming via Connection IDs (CID)   |
|  - Stealth Masking: Secret Knock / Subpath (Silent Drops / Fake HTTP 404)         |
|  - Unreliable Datagrams (RFC 9221) for realtime screen updates                    |
+-----------------------------------------------------------------------------------+
              ^                         ^                           ^
              |                         |                           |
+-------------|-------------------------|---------------------------|---------------+
|  +----------+----------+  +-----------+-----------+  +------------+------------+  |
|  | Auth & Secret Knock |  |  Session Supervisor   |  | PTY Process Supervisor  |  |
|  | (SSH Keys, PAM, OIDC|  |  (Detached PTY State) |  |   (portable-pty / nix)  |  |
|  +---------------------+  +-----------------------+  +-------------------------+  |
|                                 morshd (Server Daemon)                            |
+-----------------------------------------------------------------------------------+
```

### Core Value Propositions
1. **Survives Network Drops and Sleep (Mosh)**: Laptops can sleep for hours or drop connection; the server retains the shell session and virtual terminal state.
2. **Seamless IP Roaming (Mosh / QUIC Native)**: Dynamic handover between Wi-Fi, cellular, and wired interfaces using QUIC Connection IDs (CID) without session resets.
3. **Sub-millisecond Typing Latency (Mosh)**: Speculative local echo engine predicts printable characters, cursor movements, and backspaces with automatic 1-RTT rollback on misprediction.
4. **Stealth & Anti-Port-Scanning (SSH3)**: Secret pre-auth knocking paths make the server invisible to port scanners (e.g. Nmap, Shodan) by responding with HTTP 404 or dropping packets.
5. **Modern Security & Faster Handshake (SSH3)**: Pure TLS 1.3 encryption with 0-RTT/1-RTT connection setup over QUIC/UDP.
6. **UDP + TCP Port Forwarding (SSH3)**: First-class UDP port forwarding alongside classic TCP forwarding and SOCKS5 dynamic proxying.
7. **Resilient TCP Fallback**: Automatic fallback to TLS 1.3 over TCP in restrictive corporate firewalls that block UDP.

---

## 2. Workspace Crate Architecture

The codebase is structured as a Cargo workspace with strict module boundaries:

```
morsh/
├── Cargo.toml                  # Workspace root configuration
├── ROADMAP.md                  # Master architecture blueprint (IMMUTABLE)
├── PROGRESS.md                 # Living progress log & handoffs (APPEND-HEAVY)
└── crates/
    ├── morsh-core/             # Wire protocol frames, codecs, error types, constants
    ├── morsh-transport/        # QUIC (Quinn + Rustls), TLS 1.3, TCP fallback, migration
    ├── morsh-auth/             # SSH keys, ssh-agent, PAM, stealth token authentication
    ├── morsh-term/             # PTY supervisor (portable-pty/nix), vt100 state buffer
    ├── morsh-predict/          # Speculative local echo engine, divergence rollback
    ├── morsh-tunnel/           # TCP/UDP port forwarding, SOCKS5 proxy engine
    ├── morshd/                 # Server daemon executable (`morshd`)
    └── morsh/                  # Client CLI executable (`morsh`)
```

---

## 3. Wire Protocol & Channel Layout

### Framing Specification
- Control messages are transmitted as length-prefixed binary frames:
  - Header: `[u32 length in big-endian]` (4 bytes)
  - Payload: Postcard-serialized binary struct (max `16 MiB`)
- Application-Layer Protocol Negotiation (ALPN): `b"morsh-v1"`
- Protocol Magic Header: `b"MRSH"`

### Stream Channel Map
| Stream ID / Type | Direction | Purpose |
|---|---|---|
| **Stream 0 (Bi)** | Client <-> Server | Control, authentication, window resizing, heartbeats |
| **Stream 1 (Bi)** | Client <-> Server | Primary interactive PTY byte stream |
| **Stream 2..N (Bi)** | Client <-> Server | TCP forwarded port channels or auxiliary execution streams |
| **Datagrams (RFC 9221)** | Client <-> Server | Realtime UDP forwarding packets & delta screen sync frames |

---

## 4. Detailed Phased Roadmap

### Phase 1: Workspace Foundation & Core QUIC Transport
* **Goal**: Establish the workspace skeleton and verified secure QUIC transport.
- Multi-crate Cargo workspace initialization with strict dependency boundary.
- Wire protocol definition in `morsh-core`: length-prefixed postcard codec, control frame types (`ClientHello`, `ServerHello`, `Ping`, `Pong`, `Disconnect`).
- QUIC transport abstraction in `morsh-transport` via `quinn` + `rustls` (TLS 1.3).
- Ephemeral self-signed X.509 certificate generator (`rcgen`) and SHA-256 host key fingerprinting.
- Executable binaries: `morshd` server daemon and `morsh` client CLI with initial handshake verification.
- Comprehensive unit and integration test suite covering frame bounds, serialization, QUIC streams, and datagrams.

### Phase 2: Stealth Security & Authentication Layer (SSH3 Style)
* **Goal**: Defend against port scanning and implement standard & modern authentication mechanisms.
- **Stealth Knocking**: Enforce secret path/token verification during handshake. Non-matching probes receive silent connection drops or HTTP 404 responses.
- **SSH Public Key Authentication**: Support Ed25519, RSA, and ECDSA keys matching standard `~/.ssh/authorized_keys`.
- **SSH Agent Integration**: Connect to local `ssh-agent` UNIX domain socket to sign authentication challenges without prompting for passphrases.
- **System Authentication**: Linux PAM integration for user login credentials and session permission drop (`setuid`/`setgid`).

### Phase 3: Interactive PTY & QUIC Connection Migration (Roaming)
* **Goal**: Deliver a responsive, raw terminal interactive shell with network roaming resilience.
- **PTY Supervisor**: Server-side pseudo-terminal allocation (`portable-pty`/Unix PTY) running user login shell (`/bin/bash`, `/bin/zsh`).
- **Client Raw Mode**: Terminal raw mode management (`crossterm`), raw input forwarding, and clean terminal state restoration on exit.
- **Window Resizing**: Out-of-band propagation of window resize events (`SIGWINCH` / cols & rows).
- **QUIC Connection Migration**: Server-side verification of Connection ID (CID) validation to ensure active interactive sessions persist through IP/interface switching (Wi-Fi <-> Cellular).

### Phase 4: Port Forwarding & Tunnels
* **Goal**: Provide modern tunneling capabilities for TCP, UDP, and dynamic proxying.
- **Local TCP Forwarding (`-L`)**: Forward local ports through QUIC streams to remote hosts.
- **Remote TCP Forwarding (`-R`)**: Forward remote ports through QUIC streams to client networks.
- **Native UDP Forwarding**: Forward UDP packets bidirectionally using QUIC Datagrams or fast streams.
- **Dynamic SOCKS5 Proxy (`-D`)**: Integrated local SOCKS5 proxy server multiplexed through the morsh session.

### Phase 5: Session Persistence & Screen State Recovery (Mosh Style)
* **Goal**: Decouple shell lifetime from network connection lifetime and support detached reattachment.
- **Detached PTY Supervisor**: The shell session continues running when a client disconnects or sleeps.
- **Session Tokens**: Cryptographic 128-bit session tokens for resuming detached sessions.
- **Screen State Tracking**: Server-side virtual terminal emulator (`vt100`) maintaining screen buffers and cursor state.
- **Fast Resumption**: Reconnecting clients receive an immediate screen snapshot rather than replaying unbuffered byte history.

### Phase 6: Predictive Local Echo & Speculative UI (Mosh Style)
* **Goal**: Eliminate perceived latency on high-RTT networks.
- **Predictive Engine**: Optimistically echoes printable characters, cursor navigation (arrow keys), and backspace locally.
- **Visual Feedback**: Speculative characters are styled (e.g. underlined or dimmed) until acknowledged by server sequence frames.
- **Confidence Tracking**: Heuristics to suppress speculative echo during no-echo modes (e.g. password entry) or complex fullscreen apps.
- **1-RTT Rollback**: Automatic correction when server output diverges from local predictions.

### Phase 7: TCP Fallback & Network Resilience
* **Goal**: Ensure connectivity in environments blocking UDP/QUIC.
- **Happy Eyeballs Auto-Detection**: Fast race between QUIC/UDP and TCP fallback.
- **TLS 1.3 over TCP**: Framing layer running TLS 1.3 over TCP stream sockets.
- **Dual-Stack Listener**: `morshd` listening concurrently on QUIC/UDP and TCP fallback ports.

### Phase 8: Production Polish, Configuration & Distribution
* **Goal**: Deliver a production-grade CLI and system daemon.
- **OpenSSH Compatibility**: Command-line flag compatibility with OpenSSH conventions (`-p`, `-i`, `-L`, `-R`, `-D`, `-N`, `-v`).
- **Configuration Files**: TOML configuration support (`~/.morsh/config.toml` and `/etc/morsh/morshd.toml`).
- **Packaging & Daemonization**: Systemd service definition (`morshd.service`), signals (`SIGHUP`, `SIGTERM`), and Debian/tarball packaging.
