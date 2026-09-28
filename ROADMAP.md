# morsh: Project Architecture & Phased Roadmap

`morsh` is a next-generation SSH replacement written in Rust, combining the best properties of:
1. **Mosh**: Resilient sessions across sleeping/waking devices, network drops, IP roaming, terminal state synchronization, and a predictive local echo engine for ultra-low typing latency.
2. **SSH3**: QUIC + TLS 1.3 transport, secret-path / port-knocking defense against port scanners, HTTP-style authentication semantics, UDP port forwarding, and automatic TCP fallback.

---

Here is the comprehensive architectural blueprint and phased implementation plan for morsh (client) and morshd (server daemon).

1. Architectural Vision
   morsh synthesizes the strengths of Mosh (session durability, connection roaming, predictive local echo) and SSH3 (QUIC + TLS 1.3, stealth/port-scan defense, HTTP authorization semantics, UDP forwarding, TCP fallback) into a single, memory-safe Rust codebase.



+-----------------------------------------------------------------------------------+
|                                     morsh (Client)                                |
|  +--------------------+  +-----------------------+  +--------------------------+  |
|  | Predictive Engine  |  |  Screen State Buffer  |  |   Terminal Input/Output  |  |
|  |  (speculative echo)|  |     (vt100 / diff)    |  |       (crossterm)        |  |
|  +---------+----------+  +-----------+-----------+  +------------+-------------+  |
+------------|-------------------------|---------------------------|----------------+
|                         |                           |
| QUIC Multiplexed Channels:                          |
| - Control / Auth / Knocking (Stream 0)              |
| - Terminal State Sync / Stream (Stream 1 / Datagram)|
| - Port Forwarding (TCP/UDP streams & datagrams)     |
v                         v                           v
+-----------------------------------------------------------------------------------+
|                      Transport Layer (QUIC / TLS 1.3 + TCP Fallback)              |
|  - Connection Migration (Seamless IP roaming via Connection IDs)                  |
|  - Stealth Masking (Secret URL path / Port Knocking)                              |
+-----------------------------------------------------------------------------------+
^                         ^                           ^
|                         |                           |
+------------|-------------------------|---------------------------|----------------+
|  +---------+----------+  +-----------+-----------+  +------------+-------------+  |
|  | Auth & Secret Knock|  | Session Persistence   |  |   PTY Process Supervisor |  |
|  | (SSH Keys/PAM/OIDC)|  | (Detached Shell State)|  |   (portable-pty / nix)   |  |
|  +--------------------+  +-----------------------+  +--------------------------+  |
|                                    morshd (Server)                                |
+-----------------------------------------------------------------------------------+
2. Key Pillars & Technical Strategy
   Pillar A: QUIC Transport, Roaming & TCP Fallback (SSH3 & Mosh)
   QUIC over UDP (quinn + rustls):
   Full TLS 1.3 encryption with 0-RTT session resumption.
   Connection Migration: QUIC’s Connection IDs (CIDs) allow clients to switch from Wi-Fi to cellular or Ethernet without dropping the transport connection.
   Independent multiplexed streams avoid Head-of-Line (HoL) blocking between terminal output, keystrokes, and port forwarding.
   Stealth Mode (Anti-Port-Scanning):
   Like SSH3, the server can operate behind an HTTP/3 ALPN or custom QUIC ALPN.
   Unauthenticated or non-matching probe packets (scanning tools like Nmap or Shodan) receive generic HTTP 404 responses or silent packet drops.
   Access requires a secret pre-auth knocking path or signed token.
   TCP Fallback:
   If UDP is blocked by a corporate firewall, client runs a fast fallback (Happy Eyeballs style) to TLS 1.3 over TCP.
   Pillar B: Session Persistence & Resumption (Mosh)
   Detached Session Server:
   Traditional SSH ties the shell lifecycle directly to the TCP socket. When TCP drops, SIGHUP terminates the shell.
   morshd separates the Session Controller from the Network Connection:
   The shell PTY remains running in the background even if the network is disconnected for hours or the laptop sleeps.
   Sessions have cryptographic session tokens. Reconnecting clients present their session token and reattach seamlessly.
   Screen State Sync vs. Raw Byte Streams:
   For interactive sessions, morshd maintains a virtual terminal emulator state (via vt100).
   When reattaching, the server sends the current screen state snapshot rather than replaying megabytes of raw terminal history.
   Pillar C: Predictive Local Echo Engine (Mosh)
   Speculative Keystroke Prediction:
   On high-latency links (cellular, satellite), waiting for server round-trips makes typing painful.
   Client speculatively displays printable characters, cursor movements (left/right arrows), and backspaces immediately.
   Speculative output is visually distinguished (e.g., subtle underline).
   Confidence Heuristics & 1-RTT Divergence Rollback:
   Tracks server sequence numbers. When the server confirms the frame, underlines disappear.
   If the server output diverges (e.g., password input with echo off, tab completion, syntax highlighting, or vim screen refresh), the client rolls back speculative changes within 1 RTT.
   Pillar D: Forwarding & Multiplexing
   TCP Port Forwarding (-L, -R) & SOCKS5 Dynamic Proxy (-D): Each forwarded connection maps to a lightweight QUIC stream.
   UDP Port Forwarding: Supported natively over QUIC Datagrams (RFC 9221) or multiplexed streams.
3. Workspace Crate Architecture
   To ensure separation of concerns and maintainability, the project will be structured as a Cargo workspace:



morsh/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── morsh-core/             # Protocol frames, wire formats, config, shared errors
│   ├── morsh-transport/        # QUIC (Quinn), TLS 1.3, TCP fallback, connection migration
│   ├── morsh-auth/             # SSH key auth, SSH-agent, PAM, secret knock verification
│   ├── morsh-term/             # PTY supervisor (portable-pty/nix), vt100 state buffer
│   ├── morsh-predict/          # Predictive local echo model, divergence tracking
│   ├── morsh-tunnel/           # TCP/UDP port forwarding, SOCKS5 proxy engine
│   ├── morshd/                 # Server daemon binary
│   └── morsh-cli/              # Client CLI binary (installed as `morsh`)
4. Phased Implementation Roadmap
   Phase 1: Workspace Foundation & Core QUIC Transport
   Goal: Establish the workspace structure and basic secure QUIC connection between client and server.
   Set up Cargo workspace and crate hierarchy.
   Implement morsh-core binary protocol framing (framed messages / serialization with CBOR or postcard).
   Implement morsh-transport: QUIC client and server using quinn with TLS 1.3 self-signed certificates or system PKI.
   Basic hello-world stream exchange between morsh and morshd.
   Phase 2: Stealth Handshake & Authentication (SSH3 Style)
   Goal: Prevent port scanning identification and support SSH key authentication.
   Implement stealth endpoint routing: client must provide a secret path / knock token during the ALPN/connection handshake; unauthorized probes are dropped or served a dummy 404.
   Implement public-key authentication: Ed25519 and standard SSH public keys (~/.ssh/authorized_keys).
   Integration with local ssh-agent.
   Password / system user authentication support (Linux PAM).
   Phase 3: Interactive PTY & Connection Migration (Roaming)
   Goal: Full interactive shell with seamless IP roaming.
   Server-side PTY allocation using portable-pty / Unix PTY, launching user login shell (/bin/bash, /bin/zsh).
   Client raw terminal handling (crossterm): raw mode, resize events (SIGWINCH), clean terminal restoration on exit.
   QUIC Connection Migration: simulate IP address change (e.g., switching network interfaces) to verify the shell session continues uninterrupted without reconnecting.
   Phase 4: Port Forwarding & Tunnels
   Goal: Support standard and modern forwarding modes.
   Local TCP forwarding (-L local_port:remote_host:remote_port).
   Remote TCP forwarding (-R remote_port:local_host:local_port).
   Native UDP forwarding (using QUIC Datagrams or fast streams).
   Dynamic proxy: integrated SOCKS5 proxy server on the client (-D port).
   Phase 5: Session Persistence & Reconnection (Mosh Style)
   Goal: Keep shell sessions alive through laptop sleep or hours of network disconnect.
   Server session daemonization: decouple shell PTY processes from network connection lifetimes.
   Session IDs and cryptographic reconnect tokens.
   Virtual terminal emulation (vt100) running on morshd to maintain the canonical screen state.
   Client reconnect handshake: seamlessly reattach to an existing session and synchronize the screen buffer.
   Phase 6: Predictive Local Echo & Speculative UI (Mosh Style)
   Goal: Mask high network latency with instant typing feedback.
   Client-side prediction engine:
   Printable characters, cursor navigation (arrow keys, Home/End), backspace.
   Confidence scoring: disable prediction when terminal is in no-echo mode (e.g., password entry).
   Visual feedback: underline unacknowledged speculative characters.
   Server frame synchronization: acknowledge input sequence numbers.
   Rollback engine: detect mispredictions and restore true server screen state within 1 RTT.
   Phase 7: TCP Fallback & Network Resilience
   Goal: Guarantee connectivity in restrictive networks.
   Client auto-detection of UDP blocking (Happy Eyeballs timeout).
   TCP fallback transport: TLS 1.3 over TCP framing.
   Server dual-stack listener: UDP/QUIC primary + TCP fallback on the same or configurable port.
   Phase 8: CLI Polish, Configuration & Distribution
   Goal: Production-ready tooling.
   Full CLI flags compatible with SSH habits (-p, -i, -L, -R, -D, -N, -v).
   Configuration files (~/.morsh/config or /etc/morsh/morshd.toml).
   Systemd service definition and packaging (morshd.service).


### Core Crates

- **`morsh-core`**: Protocol definitions, frame codecs, wire messages, error types, shared models.
- **`morsh-transport`**: QUIC transport abstraction (`quinn` + `rustls`), connection migration, stealth knocking handshake, TCP fallback.
- **`morsh-auth`**: Authentication mechanisms (SSH keys / `authorized_keys`, agent forwarding, password/PAM, secret knock tokens).
- **`morsh-term`**: PTY management (`portable-pty`/nix), virtual terminal emulation (`vt100`), screen buffer diffing and detached session supervisor.
- **`morsh-predict`**: Speculative local echo model, cursor prediction, divergence detection, and rollback engine.
- **`morsh-tunnel`**: Port forwarding engine (TCP `-L`/`-R`, UDP forwarding, SOCKS5 proxy `-D`).
- **`morshd`**: Server daemon executable.
- **`morsh`**: Client CLI executable.

---

## 2. Phased Roadmap

### Phase 1: Workspace Foundation & Core QUIC Transport [IN PROGRESS]
- [x] Multi-crate Cargo workspace setup.
- [x] Wire protocol definitions in `morsh-core` (magic bytes, versioning, framed messages).
- [x] QUIC transport foundation in `morsh-transport` using `quinn` + `rustls` (TLS 1.3).
- [x] Self-signed / dynamic TLS certificate generation and verification helper.
- [x] Minimal client (`morsh`) and daemon (`morshd`) with bidirectional handshake verification.

### Phase 2: Stealth Security & Authentication Layer (SSH3 Style)
- [ ] Stealth handshake: secret URL path / knock token during handshake to avoid identification by port scanners (unrecognized probes receive dummy responses or silent drops).
- [ ] SSH public-key authentication (Ed25519, ECDSA, RSA) via `~/.ssh/authorized_keys`.
- [ ] Integration with SSH Agent (`ssh-agent` / unix domain socket).
- [ ] System authentication (Linux PAM / password) and token/bearer pre-auth credentials.

### Phase 3: Interactive PTY & QUIC Connection Migration (Roaming)
- [ ] Server-side PTY allocation (spawning `/bin/bash` or user shell).
- [ ] Client-side raw terminal mode with `crossterm` and window resize event propagation (`SIGWINCH`).
- [ ] Multiplexed QUIC streams for standard input/output/error and out-of-band window changes.
- [ ] Connection migration validation: seamless IP address switching without dropping active interactive sessions.

### Phase 4: Port Forwarding & Tunnels
- [ ] Local TCP forwarding (`-L local_port:remote_host:remote_port`).
- [ ] Remote TCP forwarding (`-R remote_port:local_host:local_port`).
- [ ] Native UDP port forwarding via QUIC datagrams / streams.
- [ ] Dynamic proxy: client-side SOCKS5 proxy server (`-D port`).

### Phase 5: Session Persistence & Reconnection (Mosh Style)
- [ ] Decouple PTY shell lifetimes from individual client connection lifecycles.
- [ ] Cryptographic session resumption tokens.
- [ ] Server-side virtual terminal emulator (`vt100`) maintaining active screen buffers.
- [ ] Seamless reattachment: reconnecting clients receive current screen state snapshot rather than raw unbuffered streams.

### Phase 6: Predictive Local Echo & Speculative UI (Mosh Style)
- [ ] Client-side predictive keystroke model (printable chars, backspace, arrow keys).
- [ ] Visual indicator for speculative output (underlining or dimming).
- [ ] Server frame sequence acknowledgement and 1-RTT automatic rollback on divergence (e.g. vim modes, password fields, completion).

### Phase 7: TCP Fallback & Network Resilience
- [ ] Happy Eyeballs auto-detection for UDP-restricted networks.
- [ ] Fallback transport using TLS 1.3 over TCP.
- [ ] Dual-listening daemon supporting simultaneous QUIC and TCP fallback.

### Phase 8: CLI Ergonomics, Configuration, & Production Packaging
- [ ] Full OpenSSH-compatible CLI options (`-p`, `-i`, `-L`, `-R`, `-D`, `-N`, `-v`).
- [ ] Client and daemon configuration files (`morsh.toml`, `morshd.toml`).
- [ ] Systemd service unit (`morshd.service`) and distribution packaging.
