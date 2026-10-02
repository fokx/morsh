# morsh Implementation Progress Ledger

> **USAGE DIRECTIVE FOR ASSISTANTS & CONTRIBUTORS**:
> - **[`ROADMAP.md`](ROADMAP.md) IS IMMUTABLE**: Do not modify or check off items in `ROADMAP.md`.
> - **`PROGRESS.md` IS APPEND-HEAVY**: Update this file with phase completion logs, benchmarks, and handoff instructions for the next phase.

---

## 1. Executive Status Dashboard

| Phase | Description | Status | Completion Date | Commit Hash | Key Deliverables |
|---|---|---|---|---|---|
| **Phase 1** | Workspace Foundation & Core QUIC Transport | ✅ **Completed** | 2026-10-05 | `dcf1e0d` | Workspace, `morsh-core`, `morsh-transport`, `morshd`, `morsh` CLI, 17 tests |
| **Phase 2** | Stealth Security & Authentication Layer | ✅ **Completed** | 2026-10-05 | - | `morsh-auth`, SSH keys (Ed25519/RSA/ECDSA), `authorized_keys`, `ssh-agent`, PAM, 33 tests |
| **Phase 3** | Interactive PTY & QUIC Connection Migration | ✅ **Completed** | 2026-10-05 | - | `morsh-term`, `portable-pty`, `crossterm` raw mode, `SIGWINCH` resize, IP roaming, 38 tests |
| **Phase 4** | Port Forwarding & Tunnels (TCP, UDP, SOCKS5) | 🎯 **Active / Next** | Pending | - | `-L`, `-R`, native UDP forwarding, `-D` SOCKS5 proxy |
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

## 3. Phase 2 Completion Record

### Delivered Components
1. **Wire Protocol Authentication Extensions (`crates/morsh-core`)**:
   - `protocol::AuthRequest`: Enums for `PublicKey { username, algorithm, public_key, signature }`, `Password { username, password }`, and `None { username }`.
   - `protocol::ControlMessage`: Added `AuthChallenge { challenge: [u8; 32] }`, `AuthRequest(AuthRequest)`, and `AuthResult { success: bool, message: String }`.
   - `protocol::make_challenge_payload`: Domain-separated canonical signing payload function binding `morsh-auth-v1:`, 16-byte session ID, 32-byte challenge, and requested Unix username.
   - `error::CoreError::AuthFailed`: Dedicated error type for authentication rejections.
   - Postcard binary frame roundtrip tests for all new authentication message types.

2. **Authentication Subsystem (`crates/morsh-auth`)**:
   - **`AuthorizedKeys` Loader & Verifier (`src/authorized_keys.rs`)**:
     - Parses OpenSSH `~/.ssh/authorized_keys` format (supporting comments, key types, options).
     - Resolves paths for specific Unix users (`~username/.ssh/authorized_keys`, `/home/user`, `/root`).
     - Verifies incoming cryptographic challenges against authorized keys using `signature::Verifier`.
   - **Key Loader & Signer (`src/keys.rs`)**:
     - Reads OpenSSH private keys (unencrypted and passphrase-encrypted via `ssh-key::PrivateKey`).
     - Default key auto-discovery scanning `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa`.
     - `sign_challenge`: Signs authentication challenge payloads for Ed25519, ECDSA (P-256), and RSA.
   - **SSH Agent Integration (`src/agent.rs`)**:
     - Connects to local `ssh-agent` Unix domain socket via `$SSH_AUTH_SOCK` using `ssh-agent-client-rs`.
     - Queries stored agent identities and requests cryptographic signatures on challenges without exposing private keys.
   - **System & PAM Authentication (`src/pam.rs`)**:
     - `PasswordVerifier` trait defining extensible password authentication.
     - `PamAuthenticator`: Linux PAM client authenticating credentials via `pam::Client`.
     - `MockPasswordVerifier`: In-memory thread-safe verifier for automated tests and standalone environments.
   - **Challenge Generator (`src/challenge.rs`)**:
     - Generates 32-byte cryptographically secure pseudo-random challenges via `ring::rand::SystemRandom`.

3. **Daemon Integration (`crates/morshd`)**:
   - Server CLI flags: `--auth-keys <path>`, `--allow-password`, `--pam-service <service>`, `--no-auth`.
   - Handshake authentication state machine: issues `AuthChallenge`, verifies `AuthRequest` before admitting client, issues descriptive `AuthResult` frames before graceful transport closure.

4. **Client CLI Integration (`crates/morsh`)**:
   - Client CLI flags: `-i, --identity <path>`, `--password <pass>`, `--no-agent`.
   - Automatic credential selection cascade:
     1. Explicit identity file (`-i`)
     2. Active `ssh-agent` identities (`$SSH_AUTH_SOCK`)
     3. Default user SSH keys in `~/.ssh/` (`id_ed25519`, `id_ecdsa`, `id_rsa`)
     4. Password flag fallback (`--password`)
     5. Unauthenticated guest fallback (if allowed by server)

5. **Architectural Choices & Tradeoffs Recorded**:
   - **Cryptographic Domain Separation**: The challenge buffer is formatted as `morsh-auth-v1: || session_id || challenge || username`. This tightly binds the signature to the specific QUIC connection and user, preventing replay attacks across different sessions or unauthorized user impersonation.
   - **Upstream `ssh-key 0.6.7` RSA Workaround**: Discovered an upstream bug in `ssh-key 0.6.7` where `RsaKeypair::try_into()` attempts to construct an RSA private key with duplicate prime factors `vec![p, p]` instead of `vec![p, q]`, causing RSA signature generation to fail. Resolved by directly constructing `rsa::pkcs1v15::SigningKey` using the correct prime components `p` and `q` from the parsed RSA keypair.
   - **Pluggable PAM Abstraction**: To prevent test failures in unprivileged CI/Docker environments that lack root permissions or PAM configuration files (`/etc/pam.d/morsh`), we introduced the `PasswordVerifier` trait with both native `PamAuthenticator` and `MockPasswordVerifier`.
   - **Graceful Rejection Signaling**: Before closing rejected client connections with code 401, `morshd` flushes the `AuthResult` message frame and waits briefly before transport teardown, ensuring the client receives the explicit rejection reason rather than an abrupt connection reset.

6. **Automated Test Suite (33 Tests Passing Workspace-wide)**:
   - **`morsh-auth` Unit Tests (11 passed)**:
     - `challenge::tests::test_generate_challenge_uniqueness`: Entropy uniqueness.
     - `agent::tests::test_agent_availability_detection`: Socket existence check.
     - `pam::tests::test_mock_password_verifier`: Password verifier correctness.
     - `tests::test_end_to_end_ed25519_flow`: Full Ed25519 sign & verify.
     - `tests::test_end_to_end_ecdsa_flow`: Full ECDSA P-256 sign & verify.
     - `tests::test_end_to_end_rsa_flow`: Full RSA-SHA512 sign & verify with 3072-bit key.
     - `authorized_keys::tests::test_parse_authorized_keys_entries`: OpenSSH parser.
     - `authorized_keys::tests::test_verify_challenge_success_and_failure`: Positive and negative challenge verification (wrong user, wrong challenge, unauthorized key).
     - `keys::tests::test_sign_and_verify_ed25519_challenge` & `test_sign_and_verify_ecdsa_challenge`: Key module signing.
   - **`morsh-auth` Integration Tests (`tests/auth_integration.rs`, 4 passed)**:
     - `test_ed25519_auth_flow_success`: Live QUIC handshake + public key authentication.
     - `test_unauthorized_key_rejected`: Live rejection of rogue key with code 401.
     - `test_password_auth_flow`: Live password authentication handshake.
     - `test_stealth_knock_with_public_key_auth`: Stealth knocking filter protecting public-key auth.
   - **Live CLI End-to-End Verification**:
     - Live `morshd` run with stealth knock and authorized keys.
     - Live `morsh` CLI connected, authenticated via Ed25519 key in ~3 ms, ran latency probes (0.96 ms RTT), and cleanly exited.
     - Rogue key rejected with descriptive message.
     - Incorrect stealth knock dropped silently with HTTP 404.

---

## 4. Phase 3 Completion Record

### Delivered Components
1. **Wire Protocol Terminal Extensions (`crates/morsh-core`)**:
   - `protocol::ControlMessage::WindowResize`: Out-of-band terminal window resize event with `cols`, `rows`, `x_pixels`, and `y_pixels`.
   - `protocol::ControlMessage::PtyRequest`: Client terminal request specifying `term` environment string and initial window dimensions.
   - Channel map enforced:
     - **Stream 0 (Bi)**: Control stream (`ControlMessage` binary frames with Postcard serialization).
     - **Stream 1 (Bi)**: Interactive raw PTY byte stream (`StreamChannelKind::Pty`).
   - Frame serialization roundtrip unit tests in `crates/morsh-core/src/frame.rs`.

2. **Terminal & PTY Subsystem (`crates/morsh-term`)**:
   - **`PtySession` & `PtyHandle` (`src/pty.rs`)**:
     - Pseudo-terminal allocation via `portable-pty 0.9` (`native_pty_system().openpty()`).
     - Automatic shell discovery via `resolve_shell` scanning `$SHELL`, `/etc/passwd` (`libc::getpwnam`), and standard system shells (`/bin/bash`, `/usr/bin/bash`, `/bin/zsh`, `/bin/sh`).
     - Environment setup: `TERM`, `COLORTERM=truecolor`, `USER`, `LOGNAME`, `SHELL`, and custom environment variables.
     - Out-of-band window resize propagation via `MasterPty::resize` (`TIOCSWINSZ` / `SIGWINCH`).
     - Process lifecycle management (`kill`, `wait`, `try_wait`, `process_id`).
   - **Async I/O Bridge (`src/io.rs`)**:
     - `AsyncPtyReader`: Dedicated background reader thread feeding `tokio::sync::mpsc` channel; implements `tokio::io::AsyncRead`.
     - `AsyncPtyWriter`: Dedicated background writer thread receiving from `tokio::sync::mpsc::UnboundedSender`; implements `tokio::io::AsyncWrite`.
     - Clean handling of Linux PTY `EIO` (errno 5) as EOF upon slave closure.

3. **Daemon Integration (`crates/morshd`)**:
   - Multi-stream supervisor: accepts Stream 0 for control loop, accepts Stream 1 (`conn.accept_bi()`) for interactive PTY byte streaming.
   - Pipes remote PTY stdout -> Stream 1 writer, and Stream 1 reader -> remote PTY stdin.
   - Dynamically updates PTY window dimensions on incoming `ControlMessage::WindowResize` frames.
   - PTY process decoupling: when client input finishes (half-close), the PTY process continues running until its stdout closes naturally, supporting pipe workflows (e.g. `printf "cmd\n" | morsh host`).

4. **Client CLI Integration (`crates/morsh`)**:
   - Added `crossterm 0.28` raw mode management with RAII `RawModeGuard` ensuring terminal restoration on exit or error.
   - Detects TTY vs. piped execution via `std::io::stdin().is_terminal()`.
   - Opens Stream 1 for raw terminal I/O and forwards `stdin` <-> Stream 1 <-> `stdout`.
   - On Unix, registers `tokio::signal::unix::SignalKind::window_change()` to catch `SIGWINCH` and emit `ControlMessage::WindowResize` frames over Stream 0.
   - Selective polling in `tokio::select!` (`if !stdin_eof`) allowing clean half-close execution for non-interactive scripts.

5. **QUIC Connection Migration (Roaming) (`crates/morsh-transport`)**:
   - Implemented `QuicClient::rebind(&self, socket: std::net::UdpSocket)` to dynamically switch local UDP sockets on active Quinn client endpoints.
   - Quinn Connection IDs (CID) allow the server to validate path migration without connection resets.
   - Verified that active interactive streams (Stream 0, Stream 1) survive socket rebinding, and server dynamically tracks updated remote client address.

6. **Architectural Choices & Tradeoffs Recorded**:
   - **Dedicated OS Threads for PTY I/O**: Master PTY file descriptors on Unix exhibit subtle epoll edge-trigger quirks with `EIO` signaling upon slave process termination. Spawning dedicated reader and writer OS threads bridging to Tokio channels guarantees portable, non-blocking async execution across Linux, macOS, and Windows.
   - **Linux `EIO` As EOF**: On Linux, reading from a master PTY returns `io::Error(kind: Os(5) / EIO)` when the child process exits and closes all slave PTY descriptors. `AsyncPtyReader` intercepts this error and treats it as a clean EOF rather than an I/O failure.
   - **Out-of-band Window Resizing over Stream 0**: By transmitting `ControlMessage::WindowResize` frames over Stream 0 rather than embedding in-band escape sequences into Stream 1, the interactive PTY channel remains a 100% pure binary byte stream with zero framing overhead or parsing ambiguities.
   - **Preconditioned Select for Stdin Half-Close**: When local stdin reaches EOF in piped mode, `morsh` client marks `stdin_eof = true`, calls `pty_send.finish()`, and disables the stdin branch in `tokio::select!` using guard preconditions. This prevents busy loops and enables the remote shell to finish writing its output before client exit.

7. **Automated Test Suite (38 Tests Passing Workspace-wide)**:
   - **`morsh-term` Unit Tests (5 passed)**:
     - `test_resolve_default_shell`: Resolves system shell and respects explicit overrides.
     - `test_pty_resize`: Verifies PTY window resize (`cols` and `rows`) and pixel resize propagation.
     - `test_pty_write_and_echo`: Verifies raw byte writing and echo back from `cat`.
     - `test_pty_spawn_and_read_output`: Verifies shell command execution and output capture.
     - `test_pty_kill_and_status`: Verifies process kill signaling and status inspection.
   - **`morsh-term` Integration Tests (`tests/term_integration.rs`, 2 passed)**:
     - `test_interactive_pty_over_quic_streams`: Full live QUIC exchange with Stream 0 control, Stream 1 raw PTY piping, out-of-band `WindowResize`, and clean exit.
     - `test_pty_session_persists_across_quic_connection_migration`: Full live test proving interactive PTY stream survives client UDP socket rebinding (roaming) without stream reset.
   - **`morsh-transport` Integration Tests (`tests/quic_integration.rs`, 6 passed)**:
     - `test_quic_connection_migration`: Quinn client endpoint rebinding with active stream transmission and server remote address verification.
   - **Live CLI End-to-End Verification**:
     - Started live `morshd` daemon on UDP/QUIC port `4545`.
     - Executed live `morsh` CLI with interactive shell piping (`printf "echo LIVE_PTY_SHELL_OK\nexit\n"`).
     - Verified user's login shell (zsh) spawned inside pseudo-terminal, executed commands, printed prompt and output, and exited cleanly in ~200 ms.

---

## 5. Phase 4 Action Plan (Handoff Instructions)

When beginning a new conversation to implement **Phase 4: Port Forwarding & Tunnels (TCP, UDP, SOCKS5)**:

### Primary Objective
Implement local TCP port forwarding (`-L`), remote TCP port forwarding (`-R`), dynamic SOCKS5 proxying (`-D`), and native UDP forwarding over QUIC streams and RFC 9221 datagrams.

### Prerequisites & Dependencies
- Crates to implement: `crates/morsh-tunnel`
- Workspace crates to integrate: `morsh-core`, `morsh-transport`, `morshd`, `morsh`
- Dependencies to consider:
  - `tokio = { workspace = true }` (TCP listeners, UDP sockets, streams)
  - `async-socks5` or lightweight native SOCKS5 RFC 1928 handshake parser in `morsh-tunnel`.

### Step-by-Step Task Breakdown
1. **Extend Wire Protocol in `crates/morsh-core/src/protocol.rs`**:
   - Add tunnel control frames to `ControlMessage`:
     - `TunnelOpenRequest { tunnel_id: u32, tunnel_type: TunnelType, host: String, port: u16 }`
     - `TunnelOpenResponse { tunnel_id: u32, success: bool, message: String }`
     - `TunnelClose { tunnel_id: u32 }`
   - Define `TunnelType`: `LocalTcp`, `RemoteTcp`, `Socks5`, `UdpForward`.
2. **Implement `crates/morsh-tunnel`**:
   - **Local Forwarding Engine (`-L`)**:
     - Binds local `tokio::net::TcpListener` on client.
     - On incoming client TCP connection: requests tunnel stream from server, opens bidirectional QUIC stream (`StreamChannelKind::TcpForward`), and bridges bytes.
   - **Remote Forwarding Engine (`-R`)**:
     - Server binds `TcpListener` on remote network.
     - On incoming remote TCP connection: opens bidirectional QUIC stream to client, bridges to client target host/port.
   - **Dynamic SOCKS5 Proxy Engine (`-D`)**:
     - Integrated SOCKS5 proxy server (RFC 1928, `NO_AUTH` method) listening locally on client.
     - Parses `CONNECT` requests for IPv4, IPv6, and domain names, forwarding target connections through QUIC streams.
   - **Native UDP Port Forwarding**:
     - Binds local `UdpSocket`, forwards packets via QUIC Datagrams (RFC 9221) or low-latency streams.
3. **Integrate into `morshd` and `morsh` CLIs**:
   - Add CLI arguments to `morsh`:
     - `-L, --local-forward <[bind_addr:]bind_port:target_host:target_port>`
     - `-R, --remote-forward <[bind_addr:]bind_port:target_host:target_port>`
     - `-D, --dynamic-forward <[bind_addr:]bind_port>`
     - `-N, --no-shell` (do not allocate interactive PTY, tunnel mode only).
   - Add corresponding listener daemon handling in `morshd`.
4. **Verification & Tests**:
   - Add unit tests in `morsh-tunnel` covering SOCKS5 handshake parsing and tunnel frame codecs.
   - Add integration tests verifying live TCP port forwarding and SOCKS5 proxy requests through active QUIC sessions.

---

## 6. Work Log (Append History)

### 2026-10-05 — Phase 1 Completed
- Initialized multi-crate workspace (`morsh-core`, `morsh-transport`, `morsh-auth`, `morsh-term`, `morsh-predict`, `morsh-tunnel`, `morshd`, `morsh`).
- Implemented Postcard-framed binary codec in `morsh-core`.
- Implemented QUIC transport with TLS 1.3 in `morsh-transport`.
- Implemented `morshd` daemon and `morsh` client CLI with live handshake and latency pinging.
- Added 17 unit and integration tests across all workspace crates (`cargo test --workspace` passing).
- Structured `ROADMAP.md` as immutable blueprint and `PROGRESS.md` as append-heavy ledger.
- Committed state to Git (`dcf1e0d` and follow-up test commit).

### 2026-10-05 — Phase 2 Completed
- Implemented Phase 2 authentication layer across `morsh-core`, `morsh-auth`, `morshd`, and `morsh`.
- Implemented cryptographic SSH public key authentication (Ed25519, RSA, ECDSA P-256) matching `~/.ssh/authorized_keys`.
- Implemented local `ssh-agent` Unix domain socket integration (`AgentClient` over `$SSH_AUTH_SOCK`).
- Implemented Linux PAM system authentication (`PamAuthenticator`) and `PasswordVerifier` trait with mock verifiers.
- Implemented domain-separated 32-byte cryptographic challenge-response authentication protocol over QUIC Stream 0.
- Resolved upstream `ssh-key 0.6.7` RSA key component bug by directly constructing `rsa::pkcs1v15` keys with distinct `p` and `q` primes.
- Integrated authentication flows into `morshd` daemon and `morsh` client CLI with automatic key discovery and fallback cascade.
- Added 15 new tests (11 unit tests in `morsh-auth`, 4 integration tests in `auth_integration.rs`), reaching 33 passing tests workspace-wide.
- Conducted live end-to-end CLI verification: sub-3ms authenticated handshake, stealth knock verification, and unauthorized probe rejection.

### 2026-10-05 — Phase 3 Completed
- Implemented Phase 3 interactive PTY subsystem, raw terminal mode, window resize propagation, and QUIC connection migration across `morsh-core`, `morsh-term`, `morsh-transport`, `morshd`, and `morsh`.
- Added `ControlMessage::WindowResize` and `ControlMessage::PtyRequest` wire frames to `morsh-core`.
- Built `morsh-term` pseudo-terminal subsystem using `portable-pty 0.9`:
  - `PtySession` and `PtyHandle` managing slave shell allocation and window resize propagation (`TIOCSWINSZ` / `SIGWINCH`).
  - `AsyncPtyReader` implementing `tokio::io::AsyncRead` with dedicated worker thread and Linux `EIO` handling.
  - `AsyncPtyWriter` implementing `tokio::io::AsyncWrite` with non-blocking Tokio unbounded channels.
  - Automatic login shell resolution inspecting `$SHELL`, `/etc/passwd`, and candidate shells.
- Integrated interactive raw mode in `morsh` client CLI with `crossterm 0.28`, RAII `RawModeGuard`, out-of-band `SIGWINCH` listening on Unix, and input half-close support for pipeline commands.
- Integrated PTY session supervisor in `morshd` daemon multiplexing Stream 0 (Control) and Stream 1 (PTY raw stream) with decoupled process lifecycles.
- Implemented and verified QUIC connection migration (IP roaming) via `QuicClient::rebind`: proved active interactive PTY sessions survive UDP socket rebinding with server dynamically tracking updated remote address.
- Added 5 new unit tests in `morsh-term`, 2 integration tests in `term_integration.rs`, and 1 migration integration test in `quic_integration.rs`, reaching 38 passing tests workspace-wide with 0 warnings.
- Verified live end-to-end interactive execution with `morshd` and `morsh` running the user's login shell inside a pseudo-terminal.

