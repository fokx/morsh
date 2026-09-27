# morsh: Project Architecture & Phased Roadmap

`morsh` is a next-generation SSH replacement written in Rust, combining the best properties of:
1. **Mosh**: Resilient sessions across sleeping/waking devices, network drops, IP roaming, terminal state synchronization, and a predictive local echo engine for ultra-low typing latency.
2. **SSH3**: QUIC + TLS 1.3 transport, secret-path / port-knocking defense against port scanners, HTTP-style authentication semantics, UDP port forwarding, and automatic TCP fallback.

---

## 1. System Architecture

```
                          morsh (Client CLI)
+-------------------------------------------------------------------------+
|  Terminal I/O (crossterm)  <-->  Predictive Echo Engine (morsh-predict)  |
|                                         |                               |
|                                Screen State (vt100)                     |
|                                         |                               |
|       Client Transport Manager (QUIC / TLS 1.3 + TCP Fallback)          |
+-------------------------------------------------------------------------+
                                    |
          QUIC Multiplexed Channels / Unreliable Datagrams / Fallback TCP
                                    |
+-------------------------------------------------------------------------+
|       Server Transport Manager (Stealth Handshake & Verification)       |
|                                         |                               |
|          Auth & Permission Engine (SSH keys, PAM, OIDC, Secret)         |
|                                         |                               |
|       Persistent Session Supervisor & Detached PTY (morsh-term)         |
+-------------------------------------------------------------------------+
                         morshd (Server Daemon)
```

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
