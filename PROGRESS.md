# morsh Implementation Progress

| Phase | Description | Status | Completion Date |
|---|---|---|---|
| **Phase 1** | Workspace Foundation & Core QUIC Transport | ✅ Completed | 2026-10-05 |
| **Phase 2** | Stealth Security & Authentication Layer | ⏳ Ready for next session | - |
| **Phase 3** | Interactive PTY & QUIC Connection Migration | ⏳ Pending | - |
| **Phase 4** | Port Forwarding & Tunnels (TCP, UDP, SOCKS5) | ⏳ Pending | - |
| **Phase 5** | Session Persistence & Reconnection (Mosh Style) | ⏳ Pending | - |
| **Phase 6** | Predictive Local Echo & Speculative UI | ⏳ Pending | - |
| **Phase 7** | TCP Fallback & Network Resilience | ⏳ Pending | - |
| **Phase 8** | CLI Polish, Configuration & Packaging | ⏳ Pending | - |

---

## Phase 1 Summary (Completed)

1. **Workspace Architecture**:
   - Initialized a Cargo workspace with member crates:
     - `crates/morsh-core`: Framed message wire format with Postcard serialization (`encode_frame`, `decode_payload`, `read_frame`, `write_frame`), error types, and protocol constants (`ALPN: morsh-v1`).
     - `crates/morsh-transport`: QUIC client & server abstractions via `quinn` + `rustls` (TLS 1.3), `rcgen` self-signed cert generation, SHA-256 fingerprinting, connection migration hooks, and stream management.
     - `crates/morsh-auth`: Stub crate prepared for Phase 2 authentication engines.
     - `crates/morsh-term`: Stub crate prepared for Phase 3 PTY and Phase 5 virtual terminal screen buffers.
     - `crates/morsh-predict`: Stub crate prepared for Phase 6 predictive local echo engine.
     - `crates/morsh-tunnel`: Stub crate prepared for Phase 4 TCP/UDP forwarding and SOCKS5 proxy.
     - `crates/morshd`: Server daemon binary with CLI flags (`--listen`, `--cert`, `--key`, `--stealth-knock`, `--verbose`).
     - `crates/morsh`: Client CLI binary with CLI flags (`destination`, `-p`, `-k`, `-s`, `--stealth-knock`, `--ping`).

2. **Integration Verification**:
   - Automated unit tests passing for serialization framing and transport handshake.
   - Live end-to-end testing verified:
     - QUIC handshake under 4 ms.
     - `ClientHello` and `ServerHello` exchange.
     - Cryptographic 128-bit session ID generation.
     - Liveness Ping/Pong latency measurement.
     - Stealth knock verification: unauthorized scanner probes receive silent drop / 404, while matching knock tokens connect cleanly.

---

## Next Up: Phase 2 (Stealth Security & Authentication Layer)

When picking up development in a new conversation:
1. **Public Key Authentication**:
   - Implement Ed25519, RSA, and ECDSA client key signing (`ssh-key` / `ring`).
   - Server-side validation against `~/.ssh/authorized_keys`.
2. **SSH Agent Integration**:
   - Query local `ssh-agent` UNIX socket for keys without requiring manual passwords or passphrase unlocking.
3. **Password & PAM Support**:
   - Linux PAM integration for system username/password verification.
4. **Stealth Mode Hardening (SSH3 style)**:
   - Secret URL path / token integration into initial QUIC connection handshake before exposing any server identifying characteristics.
