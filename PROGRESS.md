# morsh Implementation Progress Ledger

> **USAGE DIRECTIVE FOR ASSISTANTS & CONTRIBUTORS**:
> - **[`ROADMAP.md`](ROADMAP.md) IS IMMUTABLE**: Do not modify or check off items in `ROADMAP.md`.
> - **`PROGRESS.md` IS APPEND-HEAVY**: Update this file with phase completion logs, benchmarks, and handoff instructions for the next phase.

---

## 1. Executive Status Dashboard

| Phase | Description | Status | Completion Date | Commit Hash | Key Deliverables |
|---|---|---|---|---|---|
| **Phase 1** | Workspace Foundation & Core QUIC Transport | ✅ **Completed** | 2026-10-05 | `dcf1e0d` (updated) | Workspace, `morsh-core`, `morsh-transport`, `morshd`, `morsh` CLI, 17 unit/integration tests |
| **Phase 2** | Stealth Security & Authentication Layer | 🎯 **Active / Next** | Pending | - | SSH keys, `authorized_keys`, `ssh-agent`, PAM, stealth knocking |
| **Phase 3** | Interactive PTY & QUIC Connection Migration | ⏳ Pending | - | - | PTY allocation, `crossterm` raw mode, `SIGWINCH`, IP roaming |
| **Phase 4** | Port Forwarding & Tunnels (TCP, UDP, SOCKS5) | ⏳ Pending | - | - | `-L`, `-R`, native UDP forwarding, `-D` SOCKS5 proxy |
| **Phase 5** | Session Persistence & Screen State Recovery | ⏳ Pending | - | - | Detached PTY supervisor, 128-bit session tokens, `vt100` state sync |
| **Phase 6** | Predictive Local Echo & Speculative UI | ⏳ Pending | - | - | Speculative keystroke echo, underline styling, 1-RTT rollback |
| **Phase 7** | TCP Fallback & Network Resilience | ⏳ Pending | - | - | Happy Eyeballs auto-detection, TLS 1.3 over TCP fallback |
| **Phase 8** | CLI Polish, Configuration & Packaging | ⏳ Pending | - | - | OpenSSH CLI parity, config files, `morshd.service` systemd unit |

---

## 2. Phase 1 Completion Record

### Delivered Components
1. **Workspace Architecture**:
   - Initialized Cargo workspace with members:
     - `crates/morsh-core`: Framed message wire format with Postcard serialization (`encode_frame`, `decode_payload`, `read_frame`, `write_frame`), error types, and protocol constants (`ALPN: morsh-v1`).
     - `crates/morsh-transport`: QUIC transport layer using `quinn` 0.11 and `rustls` 0.23 (TLS 1.3), `rcgen` self-signed certificate generation, SHA-256 fingerprinting, connection migration hooks, and stream/datagram management.
     - `crates/morsh-auth`: Stub crate prepared for Phase 2 authentication engines.
     - `crates/morsh-term`: Stub crate prepared for Phase 3 PTY and Phase 5 virtual terminal screen buffers.
     - `crates/morsh-predict`: Stub crate prepared for Phase 6 predictive local echo engine.
     - `crates/morsh-tunnel`: Stub crate prepared for Phase 4 TCP/UDP forwarding and SOCKS5 proxy.
     - `crates/morshd`: Server daemon binary with CLI flags (`--listen`, `--cert`, `--key`, `--stealth-knock`, `--verbose`).
     - `crates/morsh`: Client CLI binary with CLI flags (`destination`, `-p`, `-k`, `-s`, `--stealth-knock`, `--ping`).

2. **Automated Test Suite (17 Tests Passing)**:
   - **`morsh-core` Unit Tests**:
     - `frame::tests::test_frame_roundtrip`: Verifies `ClientHello` roundtrip serialization.
     - `frame::tests::test_server_hello_roundtrip`: Verifies `ServerHello` roundtrip serialization.
     - `frame::tests::test_ping_pong_disconnect_roundtrip`: Verifies `Ping`, `Pong`, `Disconnect` messages.
     - `frame::tests::test_frame_too_large_rejected`: Verifies frame rejection when size exceeds `MAX_FRAME_SIZE`.
     - `frame::tests::test_unexpected_eof_on_empty_or_truncated_stream`: Verifies consistent `UnexpectedEof` error on truncated headers or payloads.
     - `frame::tests::test_corrupted_payload_returns_deserialization_error`: Verifies graceful deserialization error handling on corrupted bytes.
   - **`morsh-transport` Unit Tests**:
     - `connection::tests::test_generate_session_id_uniqueness`: Cryptographic 128-bit ID generation randomness.
     - `tls::tests::test_generate_self_signed_cert_and_fingerprint`: Self-signed cert generation and SHA-256 colon-delimited format.
     - `tls::tests::test_configs_construct_with_alpn`: Quinn Client/Server configurations with ALPN `morsh-v1`.
     - `tests::test_quic_handshake_and_control_message_exchange`: Client-server bidirectional handshake.
   - **`morsh-transport` Integration Tests (`tests/quic_integration.rs`)**:
     - `test_full_handshake_flow_and_pings`: Complete live exchange of `ClientHello` -> `ServerHello` -> `Ping` -> `Pong` -> `Disconnect` with clean shutdown.
     - `test_unreliable_datagram_exchange`: Bidirectional RFC 9221 datagram transmission over QUIC.
     - `test_multiplexed_bidirectional_streams`: 5 concurrent streams on a single QUIC connection without blocking.
     - `test_stealth_knock_authorization_flow`: Verifies unauthorized knock is rejected with 404, while matching knock succeeds.
     - `test_version_mismatch_rejection`: Server rejects incompatible protocol versions with descriptive Disconnect frame.
   - **`morsh` Client CLI Tests**:
     - `tests::test_parse_destination_various_formats`: Standard hostname, host:port, user@host, user@host:port, IPv6 bracket syntax (`[::1]:8080`), and port overrides.
     - `tests::test_parse_destination_invalid`: Graceful rejection of malformed addresses.

3. **Live End-to-End Verification**:
   - Live daemon `morshd` run on UDP/QUIC port `4242`.
   - Live client `morsh` handshake completed in ~3 ms, measured sub-millisecond round-trip pings, and cleanly disconnected.
   - Stealth knock mode verified: unauthorized probes rejected with 404; authorized probes authenticated immediately.

---

## 3. Phase 2 Action Plan (Handoff Instructions)

When beginning a new conversation to implement **Phase 2: Stealth Security & Authentication Layer**:

### Primary Objective
Implement cryptographic public-key authentication (`~/.ssh/authorized_keys`), integration with local `ssh-agent`, Linux PAM system authentication, and hardened stealth knock routing.

### Step-by-Step Task Breakdown
1. **Extend Protocol Messages in `crates/morsh-core/src/protocol.rs`**:
   - Add authentication request and response variants to `ControlMessage`:
     - `AuthRequest::PublicKey { username: String, algorithm: String, public_key: Vec<u8>, signature: Vec<u8> }`
     - `AuthRequest::Password { username: String, password: Vec<u8> }`
     - `AuthChallenge { challenge: [u8; 32] }`
     - `AuthResult { success: bool, message: String }`
2. **Implement `crates/morsh-auth`**:
   - Add dependencies: `ssh-key = { version = "0.6", features = ["ed25519", "rsa", "ecdsa"] }`, `ring = "0.17"`.
   - Implement `AuthorizedKeys` loader that parses `~/.ssh/authorized_keys` and verifies public key signatures against a random challenge.
   - Implement `AgentClient` connecting to `$SSH_AUTH_SOCK` (UNIX domain socket) to sign challenges using the local SSH agent.
   - Implement optional PAM / password verification module for Linux.
3. **Integrate into `morshd`**:
   - When a client connects, `morshd` requires an authentication step before granting session access.
   - Verify signatures against authorized keys for the requested Unix user.
4. **Integrate into `morsh`**:
   - Automatically locate user SSH private keys (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`) or query `SSH_AUTH_SOCK`.
   - Sign authentication challenges and send to `morshd`.
5. **Testing Requirements for Phase 2**:
   - Unit tests for authorized_keys parser and key verification.
   - Integration tests: successful login with Ed25519 key, rejected login with unauthorized key, password auth test.

---

## 4. Work Log (Append History)

### 2026-10-05 — Phase 1 Completed
- Initialized multi-crate workspace (`morsh-core`, `morsh-transport`, `morsh-auth`, `morsh-term`, `morsh-predict`, `morsh-tunnel`, `morshd`, `morsh`).
- Implemented Postcard-framed binary codec in `morsh-core`.
- Implemented QUIC transport with TLS 1.3 in `morsh-transport`.
- Implemented `morshd` daemon and `morsh` client CLI with live handshake and latency pinging.
- Added 17 unit and integration tests across all workspace crates (`cargo test --workspace` passing).
- Structured `ROADMAP.md` as immutable blueprint and `PROGRESS.md` as append-heavy ledger.
- Committed state to Git (`dcf1e0d` and follow-up test commit).
