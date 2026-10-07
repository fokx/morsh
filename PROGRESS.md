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
| **Phase 4** | Port Forwarding & Tunnels (TCP, UDP, SOCKS5) | ✅ **Completed** | 2026-10-06 | - | `morsh-tunnel`, `-L`, `-R`, `-D`, `-U`, `-N`, 57 tests |
| **Phase 5** | Session Persistence & Screen State Recovery | ✅ **Completed** | 2026-10-06 | - | Detached PTY supervisor, 128-bit session tokens, `vt100` state sync, 65 tests |
| **Phase 6** | Predictive Local Echo & Speculative UI | ✅ **Completed** | 2026-10-06 | - | Predictive echo engine, underline/dim styling, confidence heuristics, 1-RTT rollback, 92 tests |
| **Phase 7** | TCP Fallback & Network Resilience | ✅ **Completed** | 2026-10-06 | - | Happy Eyeballs auto-detection, TLS 1.3 over TCP fallback, dual-stack `morshd`, 103 tests |
| **Phase 8** | Production Polish, Configuration & Distribution | ✅ **Completed** | 2026-10-06 | - | OpenSSH CLI parity, TOML configs, SIGHUP reload, systemd unit, man/completions, 126 tests |


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

## 5. Phase 4 Completion Record

### Delivered Components
1. **Wire Protocol Tunnel Extensions (`crates/morsh-core`)**:
   - `protocol::TunnelType`: Enums for `LocalTcp`, `RemoteTcp`, `Socks5`, and `UdpForward`.
   - `protocol::ControlMessage`: Added tunnel control frames:
     - `TunnelOpenRequest { tunnel_id, tunnel_type, host, port }`
     - `TunnelOpenResponse { tunnel_id, success, message }`
     - `TunnelClose { tunnel_id }`
     - `RemoteForwardRequest { bind_addr, bind_port, target_host, target_port }`
     - `RemoteForwardResponse { bind_port, success, message }`
     - `NoShell` (signals tunnel-only execution without interactive PTY).
   - `protocol::TunnelStreamPreamble`: Zero-allocation 8-byte binary preamble (`MTUN` magic + `tunnel_id: u32`) written at the start of forwarded QUIC streams.
   - `error::CoreError::Tunnel`: Dedicated tunnel error variant.
   - Unit tests covering all new frames and preamble binary encoding roundtrip.

2. **Port Forwarding & Tunnels Subsystem (`crates/morsh-tunnel`)**:
   - **Configuration Parser (`src/config.rs`)**:
     - `ForwardRule`: parses OpenSSH `[bind_addr:]bind_port:target_host:target_port` specifications, including bracketed IPv6 `[::1]:port`.
     - `DynamicRule`: parses OpenSSH `[bind_addr:]bind_port` dynamic proxy specifications.
     - `UdpRule`: parses OpenSSH-style UDP forwarding specifications.
   - **Bidirectional Stream Bridge (`src/bridge.rs`)**:
     - `bridge_tcp_and_quic`: concurrent non-blocking byte forwarding between `TcpStream` and Quinn `(SendStream, RecvStream)` handling half-close and EOF without framing overhead.
   - **Tunnel State Manager (`src/manager.rs`)**:
     - `TunnelManager`: thread-safe coordinator managing unique `tunnel_id` generation, pending open/bind response channels (`oneshot`), pending server-side TCP sockets, and UDP forwarding routes.
   - **Local TCP Forwarding (`src/local.rs`)**:
     - `run_local_forward`: binds local `TcpListener` on client for `-L`, requests tunnel from server, opens QUIC stream with `TunnelStreamPreamble`, and bridges bytes.
   - **Dynamic SOCKS5 Proxy (`src/socks5.rs`, `src/local.rs`)**:
     - Native RFC 1928 SOCKS5 protocol handshake parser (No Authentication `0x00`).
     - Parses `CONNECT` requests for IPv4 (`0x01`), Domain Name (`0x03`), and IPv6 (`0x04`).
     - Multiplexes requested target connections through QUIC streams.
   - **Remote TCP Forwarding (`src/remote.rs`)**:
     - `request_remote_forward`: requests server to bind remote listening port for `-R`.
     - `bind_remote_forward_server`: server-side listener accepting incoming remote connections, opening QUIC stream to client with `TunnelStreamPreamble`, and bridging to client's local target network.
   - **Native UDP Forwarding (`src/udp.rs`)**:
     - `run_udp_forward` and `setup_server_udp_tunnel`: forwards raw UDP packets bidirectionally using QUIC Datagrams (RFC 9221) with `MUDP` framing and `tunnel_id` routing.

3. **Daemon Integration (`crates/morshd`)**:
   - Stream supervisor demultiplexing Stream 1 (PTY) and Stream 2..N (Tunnels) via `TunnelStreamPreamble`.
   - Control loop handling `TunnelOpenRequest`, `RemoteForwardRequest`, `TunnelClose`, and `NoShell`.
   - Datagram router routing incoming UDP datagrams to/from target UDP sockets.

4. **Client CLI Integration (`crates/morsh`)**:
   - CLI flags: `-L, --local-forward`, `-R, --remote-forward`, `-D, --dynamic-forward`, `-U, --udp-forward`, `-N, --no-shell`.
   - Asynchronous outbound control message pipeline and inbound response dispatcher.
   - Support for pure tunnel mode (`-N`) that maintains tunnels active in the background without entering terminal raw mode.
   - Live stream acceptor for remote forward (`-R`) incoming connections.

5. **Architectural Choices & Tradeoffs Recorded**:
   - **8-Byte Binary Stream Preamble (`MTUN` + `tunnel_id`)**: Rather than framing every payload packet on forwarded streams with Postcard overhead, forwarded QUIC streams transmit an 8-byte binary preamble at the initial connection. After preamble validation, Tokio's `copy` bridges raw bytes at bare-metal line rate.
   - **Pre-Connecting Before Stream Allocation**: Upon receiving `TunnelOpenRequest`, the remote endpoint attempts to connect to the target destination *before* opening a QUIC stream. If the target port is unreachable or connection is refused, an immediate `TunnelOpenResponse { success: false }` is returned, preventing wasted QUIC stream quotas and immediately notifying the client.
   - **Lightweight RFC 1928 Parser**: Implemented a focused, dependency-free SOCKS5 parser supporting IPv4, IPv6, and domain names. This avoided pulling in unmaintained or heavy third-party SOCKS crates while ensuring full async compatibility with Tokio.
   - **Datagrams (RFC 9221) for UDP Forwarding**: Forwarding UDP packets via QUIC Datagrams prevents head-of-line blocking across dropped packets, providing the lowest latency possible for UDP-based traffic (DNS, gaming, audio).
   - **Deterministic Stream Demultiplexing**: Stream index 1 is reserved for interactive PTY unless `-N / NoShell` is explicitly declared. Tunnel streams with indices >= 2 (or index 1 under `-N`) are disambiguated by their 8-byte binary preamble.

6. **Automated Test Suite (57 Tests Passing Workspace-wide)**:
   - **`morsh-tunnel` Unit Tests (13 passed)**:
     - `config::tests::test_parse_forward_rule_three_parts` & `four_parts`: OpenSSH format parsing.
     - `config::tests::test_parse_forward_rule_ipv6`: Bracketed IPv6 notation.
     - `config::tests::test_parse_dynamic_rule`: Dynamic SOCKS5 rule parsing.
     - `config::tests::test_parse_udp_rule`: UDP forwarding rule parsing.
     - `socks5::tests::test_socks5_handshake_ipv4_connect`: IPv4 CONNECT negotiation.
     - `socks5::tests::test_socks5_handshake_domain_connect`: Domain name CONNECT negotiation.
     - `socks5::tests::test_socks5_handshake_ipv6_connect`: IPv6 CONNECT negotiation.
     - `socks5::tests::test_socks5_handshake_unsupported_version`: Version rejection.
     - `socks5::tests::test_socks5_send_reply`: Reply formatting.
     - `udp::tests::test_udp_datagram_encoding_roundtrip`: Datagram encoding/decoding.
   - **`morsh-tunnel` Integration Tests (`tests/tunnel_integration.rs`, 5 passed)**:
     - `test_local_tcp_forwarding`: Full end-to-end `-L` local TCP forwarding through live QUIC transport.
     - `test_remote_tcp_forwarding`: Full end-to-end `-R` remote TCP forwarding through live QUIC transport.
     - `test_dynamic_socks5_proxy`: Full RFC 1928 SOCKS5 proxy handshake and data forwarding.
     - `test_native_udp_forwarding`: Real-time UDP packet forwarding over QUIC Datagrams.
     - `test_no_shell_tunnel_mode`: Tunnel-only execution under `-N` without allocating a PTY.
   - **`morsh-core` Unit Tests**:
     - `test_tunnel_frames_and_preamble_roundtrip`: Postcard serialization for all new tunnel frames and `TunnelStreamPreamble`.

7. **Live CLI End-to-End Verification**:
   - Started live `morshd` daemon on UDP/QUIC port `4646`.
   - Executed live `morsh` CLI with `-L 9112:127.0.0.1:9111`, `-D 9113`, and `-N` (no shell).
   - Verified local TCP port forward `-L` connected and received echoed payload.
   - Verified dynamic SOCKS5 proxy `-D` performed handshake, connected to target, and received echoed payload.

---

## 6. Phase 5 Completion Record

### Delivered Components
1. **Wire Protocol & Codec Extensions (`crates/morsh-core`)**:
   - `protocol::ControlMessage::ServerHello`: added `resumption_token: [u8; 16]` and `session_resumed: bool` for cryptographic resumption validation.
   - `protocol::ControlMessage`: Added session persistence and terminal recovery frames:
     - `SessionDetachRequest`: Voluntary detach request from client leaving server PTY running in background.
     - `SessionResumeRequest { session_id, resumption_token }`: Client request to reconnect to existing session.
     - `SessionResumeResponse { success, session_id, resumption_token, message }`: Server confirmation/rejection.
     - `SessionListRequest`: Query active persistent sessions for authenticated user.
     - `SessionListResponse { sessions: Vec<SessionInfo> }`: Active session metadata list.
     - `ScreenSnapshot { cols, rows, cursor_x, cursor_y, buffer }`: Server-side virtual terminal screen state snapshot.
     - `ScreenDelta { seq, delta }`: Incremental screen updates.
   - `protocol::SessionInfo`: Struct containing `session_id`, `created_at_secs`, `last_attached_secs`, `cols`, `rows`, `attached`.
   - `error::CoreError::Session(String)`: Dedicated session persistence error variant.
   - Frame serialization roundtrip unit tests in `crates/morsh-core/src/frame.rs`.

2. **Virtual Terminal Buffer & Detached PTY Supervisor (`crates/morsh-term`)**:
   - **`TerminalStateBuffer` (`src/buffer.rs`)**:
     - Virtual terminal emulator wrapping `vt100::Parser`.
     - Processes raw ANSI/VT100 escape sequences and PTY output in real-time.
     - Generates consolidated ANSI screen restoration snapshots (`snapshot()`) with screen clearing, cell attribute formatting (colors, bold, underline), and cursor positioning.
     - Supports terminal resize (`resize()`), cursor querying (`cursor_position()`), and raw screen text dump (`text_contents()`).
   - **`PersistentSession` (`src/session.rs`)**:
     - Encapsulates running PTY process (`PtySession`), virtual terminal buffer (`TerminalStateBuffer`), and attached client sender channel.
     - Spawns dedicated background PTY reader thread that feeds `TerminalStateBuffer` even when no client is attached.
     - Non-blocking `write_input()` forwarding client keystrokes directly to slave shell stdin.
     - Safe `attach()` and `detach()` methods managing client stream transitions.
   - **`SessionRegistry` (`src/session.rs`)**:
     - Thread-safe registry (`Arc<RwLock<HashMap<[u8; 16], Arc<PersistentSession>>>>`) managing session lifecycle.
     - `create_session()`, `get_session()`, `resume_session()`, `list_sessions_for_user()`.
     - Cryptographic 128-bit `resumption_token` validation preventing unauthorized session hijacking.
     - `reap_dead_sessions()` periodically cleaning up sessions whose child processes have exited.

3. **Server Daemon (`crates/morshd`)**:
   - Integrated `SessionRegistry` into server daemon state with automatic background dead-session reaping task.
   - Decoupled PTY process lifetime from QUIC connection: client disconnect or `SessionDetachRequest` detaches client streams without killing child shells.
   - Implemented `SessionResumeRequest` handling: validates resumption token, attaches client to existing `PersistentSession`, and immediately transmits a `ScreenSnapshot` frame over Stream 0.
   - Implemented `SessionListRequest` handling returning JSON/structured metadata of running sessions for the authenticated user.

4. **Client CLI (`crates/morsh`)**:
   - Added flags:
     - `--resume <SESSION_ID>`: Reconnect to an existing detached persistent session.
     - `--token <TOKEN>`: Explicit 128-bit cryptographic resumption token.
     - `--list-sessions`: Query and display active sessions on remote server without opening a shell.
   - Automatic session token caching in `~/.morsh/sessions/<session_id>.token`.
   - Raw mode escape sequence state machine: detects `Ctrl-^ d` (0x1e followed by 'd'/'D'/'.') to voluntarily detach without terminating remote shell. Typing `Ctrl-^ Ctrl-^` emits a literal `0x1e`.
   - Instant screen restoration: upon receiving `ScreenSnapshot` on resume, renders ANSI snapshot directly to local stdout.

5. **Architectural Choices & Tradeoffs Recorded**:
   - **Virtual Terminal Grid (`vt100`) vs. Raw Scrollback Replay**: Replaying unbuffered raw byte history on reconnect is bandwidth-intensive, causes terminal flicker, and breaks ncurses apps (e.g. `vim`, `htop`). Maintaining a server-side `vt100::Parser` allows generating a consolidated ANSI snapshot (`snapshot()`) that restores the exact screen layout and cursor position in a single frame.
   - **Decoupled PTY Lifecycles**: In `morshd`, PTY sessions are managed by `PersistentSession`. When a client's QUIC connection closes (graceful disconnect, network drop, or voluntary detach), the daemon only detaches the client stream channel; the master PTY reader continues running in the background, updating the `vt100` buffer. Only explicit child process exit (e.g. typing `exit`) triggers cleanup.
   - **Cryptographic Resumption Bearer Tokens**: Sessions are protected by a random 128-bit `resumption_token` generated during initial connection. Clients resuming a session must present both `session_id` and `resumption_token`, preventing unauthorized session hijacking. Tokens are cached locally in `~/.morsh/sessions/` for seamless user resumption.
   - **Escape Sequence State Machine (`Ctrl-^ d`)**: `0x1E` (`Ctrl-^`, standard Mosh escape) initiates the detach sequence. Pressing `d`, `D`, or `.` sends `SessionDetachRequest` and exits cleanly. Pressing `0x1E` twice emits a literal `0x1E` to the remote shell.

6. **Automated Test Suite (65 Tests Passing Workspace-wide)**:
   - **`morsh-term` Unit Tests (12 passed)**:
     - `buffer::tests::test_buffer_creation_and_size`: Buffer dimensions verification.
     - `buffer::tests::test_buffer_processing_and_text_contents`: Real-time text parsing.
     - `buffer::tests::test_buffer_snapshot_reproduction`: ANSI snapshot generation and screen redraw reproduction.
     - `buffer::tests::test_buffer_resize`: Window resizing on virtual parser.
     - `session::tests::test_session_registry_workflow`: Creation, token validation, resume, rejection, and reaping.
     - `session::tests::test_persistent_session_spawn_and_background_execution`: Shell persistence across attach/detach.
   - **`morsh-term` Integration Tests (`tests/term_integration.rs`, 5 passed)**:
     - `test_session_persistence_detach_and_resume_with_snapshot`: Full live QUIC flow with PTY persistence, client voluntary detach, background execution, reconnection with token, and snapshot verification.
     - `test_session_resume_token_mismatch_rejected`: Verifies unauthorized resumption attempts with rogue tokens are rejected.
     - `test_session_list_query`: Verifies client can query active session list.
   - **`morsh-core` Unit Tests**:
     - `test_session_and_screen_frames_roundtrip`: Postcard serialization for all new session frames.
   - **Live CLI End-to-End Verification**:
     - Verified `morshd` and `morsh` with `--list-sessions`, `--resume`, and interactive `Ctrl-^ d` voluntary detachment.

---

## 7. Phase 6 Completion Record

### Delivered Components
1. **Predictive Local Echo Engine (`crates/morsh-predict`)**:
   - **`style.rs`**:
     - `PredictStyle`: `Underline` (`\x1b[4m ... \x1b[24m`), `Dim` (`\x1b[2m ... \x1b[22m`), and `None` (plain output).
     - `PredictMode`: `Auto`, `Always`, `Never`.
     - `render()` applying non-destructive ANSI SGR styling that leaves shell colors intact.
   - **`keystroke.rs`**:
     - `Keystroke` classification: `Printable(char)`, `Backspace`, `CursorLeft`, `CursorRight`, `Newline`, and `Unpredicted(Vec<u8>)`.
     - `parse_keystrokes()` parses multi-byte UTF-8, backspace (`0x08`, `0x7f`), newlines, and ANSI arrow escape sequences (`\x1b[D`, `\x1b[C`, `\x1bOD`, `\x1bOC`).
   - **`confidence.rs`**:
     - `ConfidenceTracker` adapting prediction confidence (`High`, `Tentative`, `Suppressed`).
     - Heuristic suppression for alternate screen buffers (`\x1b[?1049h`, `\x1b[?47h`) protecting fullscreen apps (Vim, Nano, Htop, Less).
     - Heuristic suppression for password prompts (no-echo mode when prompt contains `password:` or `passphrase:`).
     - Degradation to tentative/suppressed on prediction divergence with automatic cooldown and probation recovery after 3 consecutive confirmations.
   - **`prediction.rs`**:
     - `Prediction` struct recording sequence ID, raw input bytes, predicted echo bytes, speculative render bytes, and cursor column displacement.
   - **`rollback.rs`**:
     - `generate_rollback()` creates ANSI backstep and clear-to-end-of-line escape sequences (`\x08 \x08`, `\x1b[ND\x1b[K`) to seamlessly erase speculative display modifications upon server divergence.
   - **`engine.rs`**:
     - `PredictionEngine`: coordinates speculative rendering on local stdin, stream output matching, divergence detection, 1-RTT rollback, and sequence acknowledgements.
     - `process_input()` returns styled bytes to render immediately to local terminal stdout without waiting for server network RTT.
     - `process_server_output()` matches incoming PTY bytes against prediction queue; outputs authoritative server output or rollback erasure prefix on divergence.
     - `handle_ack()` acknowledges predictions up to given sequence number.
     - `reset()` flushes rollback sequences on exit.

2. **Wire Protocol Sequence Frames (`crates/morsh-core`)**:
   - `protocol::ControlMessage::PredictInputSeq { seq, len }`: Client notifies server of input sequence batch.
   - `protocol::ControlMessage::PredictAck { ack_seq }`: Server acknowledges processed input sequences.
   - Added Postcard binary frame roundtrip test `test_predict_frames_roundtrip` in `crates/morsh-core/src/frame.rs`.

3. **Server Daemon Integration (`crates/morshd`)**:
   - Added `ControlMessage::PredictInputSeq` handling in `morshd` Stream 0 control loop, immediately returning `ControlMessage::PredictAck`.

4. **Client CLI Integration (`crates/morsh`)**:
   - Added CLI flags:
     - `--predict <MODE>`: `auto` (default), `always`, `never`.
     - `--predict-style <STYLE>`: `underline` (default), `dim`, `none`.
   - Connected `PredictionEngine` into the raw mode terminal loop:
     - Typed characters are optimistically styled and rendered to local `stdout` instantly.
     - Remote PTY output from Stream 1 is matched against `PredictionEngine`, executing 1-RTT rollback when server output diverges.
     - Sequence acknowledgements from server (`PredictAck`) advance prediction queue.
     - RAII reset on exit clears any pending speculative characters.

5. **Architectural Choices & Tradeoffs Recorded**:
   - **Attribute-Preserving SGR Reset Codes**: Speculative styling uses specific reset codes (`\x1b[24m` for underline off, `\x1b[22m` for normal intensity) rather than generic `\x1b[0m`. This ensures speculative rendering does not destroy custom foreground/background colors set by user shells (Zsh, Fish, Starship prompt).
   - **Automatic Alternate Screen Buffer Suppression**: Fullscreen applications (Vim, Nano, Htop) exhibit arbitrary cursor jumps and command states where linear character echo is incorrect. Detecting `\x1b[?1049h` and `\x1b[?47h` automatically pauses speculative echo until the application exits (`\x1b[?1049l`).
   - **Password / No-Echo Mode Detection**: Speculative echo is suppressed when password prompts are detected in server output, protecting sensitive credentials from being echoed to the local terminal screen.
   - **1-RTT Zero-Flicker Rollback**: By emitting `\x1b[ND\x1b[K` before writing authoritative server output, the client smoothly replaces speculative predictions with actual server output without terminal jitter or duplicate characters.

6. **Automated Test Suite (92 Tests Passing Workspace-wide)**:
   - **`morsh-predict` Unit Tests (20 passed)**:
     - Keystroke parsing (printable ASCII, UTF-8 Unicode, backspace, arrows, control characters).
     - Visual style rendering (underline, dim, none) and CLI parsing.
     - Confidence state machine (degradation, cooldown recovery, alternate screen suppression, password suppression).
     - Rollback generator (single column, multiple columns, zero).
     - Engine input processing, server output confirmation, backspace erase, and sequence ack handling.
   - **`morsh-predict` Integration Tests (`tests/predict_integration.rs`, 6 passed)**:
     - `test_interactive_typing_simulation_with_server_delay`: Simulated RTT chunking with confirmation.
     - `test_speculative_rollback_on_command_rejection`: 1-RTT divergence detection with rollback sequence verification.
     - `test_dim_style_speculative_rendering`: Visual styling validation.
     - `test_rapid_editing_with_backspace`: Local erasure of speculative characters on backspace.
     - `test_alternate_screen_transition_suppresses_and_restores`: Fullscreen editor detection and restoration.
     - `test_predict_sequence_acknowledgement_over_quic`: Live QUIC client/server sequence notification and acknowledgement exchange.
   - **`morsh-core` Unit Tests**:
     - `test_predict_frames_roundtrip`: Serialization roundtrip for `PredictInputSeq` and `PredictAck`.
   - **Live CLI End-to-End Verification**:
     - Started live `morshd` daemon on UDP/QUIC port `4848`.
     - Executed live `morsh` client with `--predict always --predict-style underline`.
     - Verified interactive pipeline execution (`echo PREDICT_PIPELINE_OK`), command output, and clean session exit.

---

## 8. Phase 7 Completion Record

### Delivered Components
1. **TLS 1.3 over TCP Stream Multiplexer (`crates/morsh-transport`)**:
   - Built `tcp_mux.rs` implementing a zero-overhead binary framing protocol:
     - 9-byte header: `[stream_id: u32 BE, flags: u8, length: u32 BE]`.
     - Frame flags: `FLAG_DATA (0x00)`, `FLAG_FIN (0x01)`, `FLAG_RST (0x02)`, `FLAG_DATAGRAM (0x04)`, `FLAG_PING (0x08)`, `FLAG_PONG (0x10)`.
     - Fair multiplexing chunk size (`DEFAULT_CHUNK_SIZE = 32 KiB`) preventing large transfers from starving interactive control or PTY streams.
   - `TcpSendStream`: implements `tokio::io::AsyncWrite`, non-blocking `finish()` (FIN frame), and logical `id().index()`.
   - `TcpRecvStream`: implements `tokio::io::AsyncRead`, and provides `read(&mut buf) -> IoResult<Option<usize>>` returning `None` on clean peer EOF / FIN.
   - `TcpConnection`: thread-safe coordinator managing write and read event loops, dynamic peer-initiated stream dispatching, datagram queues, RTT tracking, and graceful flush upon connection closure.

2. **Unified Transport Abstraction (`crates/morsh-transport`)**:
   - Built `stream.rs`:
     - `MorshSendStream`: wraps either Quinn `SendStream` or `TcpSendStream`. Implements `AsyncWrite` with inherent `write_all`, `flush`, `finish`, and `id()`.
     - `MorshRecvStream`: wraps either Quinn `RecvStream` or `TcpRecvStream`. Implements `AsyncRead` with inherent `read` and `read_exact`.
     - `MorshStreamId`: logical index (0 for Control, 1 for PTY, 2..N for Tunnels).
   - Refactored `connection.rs`:
     - `MorshConnection`: transparently wraps `Quic(quinn::Connection)` or `Tcp(Arc<TcpConnection>)`.
     - Exposes uniform API: `open_bi`, `accept_bi`, `send_datagram`, `read_datagram`, `send_control_message`, `read_control_message`, `close`, `closed`, `rtt`, `remote_address`, `transport_name`, `is_quic`, `is_tcp`.
   - Built `tcp.rs`:
     - `TcpServer`: native TLS 1.3 listener using `tokio_rustls 0.26` (`TlsAcceptor`) accepting TCP connections and wrapping into `MorshConnection::from_tcp`.
     - `TcpClient`: native TLS 1.3 connector using `tokio_rustls 0.26` (`TlsConnector`) connecting via `TcpStream` and wrapping into `MorshConnection::from_tcp`.
   - Refactored `tls.rs`:
     - Extracted `make_rustls_server_config` and `make_rustls_client_config` sharing identical ALPN (`b"morsh-v1"`), certificate validation (`SkipServerVerification` or system trust), and TLS 1.3 options across both QUIC and TCP.

3. **Happy Eyeballs Auto-Detection Engine (`crates/morsh-transport`)**:
   - Built `happy_eyeballs.rs`:
     - `connect_happy_eyeballs`: implements RFC 8305 racing between QUIC/UDP and TCP fallback.
     - Prefers QUIC (UDP) with fast fallback threshold timer (`DEFAULT_FALLBACK_DELAY = 300 ms`, configurable via CLI).
     - If QUIC connection does not complete within threshold or fails immediately, concurrently initiates TLS 1.3 over TCP connection.
     - First connection to complete TLS handshake wins; loser is cleanly canceled and dropped.
     - Fast path for `--force-tcp` bypassing QUIC entirely.

4. **Dual-Stack Listener in `morshd` (`crates/morshd`)**:
   - Concurrently binds `QuicServer` and `TcpServer` on default port `0.0.0.0:2222` (or explicit `--tcp-listen`).
   - Server event loop multiplexes incoming QUIC and TCP connections into the identical authentication, PTY, tunnel, and session persistence pipeline (`handle_connection`).
   - Added CLI flag `--tcp-listen <addr>` for custom TCP port/address overrides.

5. **Client CLI Integration (`crates/morsh`)**:
   - Added CLI flags:
     - `--force-tcp`: forces TLS 1.3 over TCP fallback immediately without attempting QUIC.
     - `--tcp-fallback-timeout <ms>`: customizable Happy Eyeballs fallback delay (default 300 ms).
   - Client automatically adopts winning transport and displays `Transport: QUIC` or `Transport: TLS/TCP` in the connection banner.
   - PTY interactive loop, tunnels, and detached session recovery run seamlessly over both transports.

6. **Port Forwarding & Tunnels Compatibility (`crates/morsh-tunnel`)**:
   - Updated `bridge_tcp_and_quic` to accept unified `MorshSendStream` and `MorshRecvStream`.
   - Native UDP forwarding (`-U`) operates seamlessly over TCP fallback using encapsulated `FLAG_DATAGRAM` frames.

7. **Architectural Choices & Tradeoffs Recorded**:
   - **9-Byte Multiplexing Header with Flag Bits**: Rather than heavy HTTP/2 or Postcard framing overhead on every packet, TCP fallback uses a compact 9-byte binary header (`[stream_id: u32, flags: u8, len: u32]`). Raw bytes are bridged at line rate with zero serialization overhead.
   - **Parity Stream Allocation (HTTP/2 & QUIC Alignment)**: Client allocates even stream IDs (`0, 2, 4...`), while server allocates odd stream IDs (`1, 3, 5...`). Logical stream index is computed as `stream_id / 2`, ensuring Stream 0 (Control), Stream 1 (PTY), and Stream 2..N (Tunnels) have identical indices across both QUIC and TCP.
   - **Datagram Encapsulation over TCP (`FLAG_DATAGRAM`)**: In UDP-blocked networks, native UDP packets are wrapped in `FLAG_DATAGRAM` frames and demultiplexed into datagram channels, preserving `-U` UDP port forwarding functionality even when operating over TCP fallback.
   - **Drain Queue on Close**: To prevent abrupt connection resets dropping final control messages (such as `Disconnect` or `AuthResult`), the TCP write task drains any queued outbound frames before invoking `writer.shutdown()`.
   - **Unified Enum Stream Wrappers**: Using `MorshSendStream` and `MorshRecvStream` enums rather than generic traits avoids trait bound pollution (`<S: AsyncWrite + Unpin + Send + 'static>`) across `morsh-term`, `morsh-tunnel`, `morshd`, and `morsh`, preserving clean crate boundaries and fast compile times.

8. **Automated Test Suite (103 Tests Passing Workspace-wide)**:
   - **`morsh-transport` Unit Tests (9 passed)**:
     - `test_frame_header_encoding_roundtrip`: 9-byte header serialization and decode.
     - `test_tcp_handshake_and_control_message_exchange`: live TLS/TCP handshake, control message exchange, and bidirectional datagram frame exchange.
     - `test_happy_eyeballs_quic_winner`: verifies QUIC wins race when UDP is healthy.
     - `test_happy_eyeballs_force_tcp`: verifies `--force-tcp` bypasses QUIC and connects via TCP.
     - `test_happy_eyeballs_tcp_fallback_when_quic_unavailable`: verifies automatic TCP fallback when UDP is blocked/unbound.
   - **`morsh-transport` Integration Tests (`tests/tcp_integration.rs`, 6 passed)**:
     - `test_tcp_full_handshake_flow_and_pings`: complete ClientHello -> ServerHello -> Ping -> Pong -> Disconnect over TCP.
     - `test_tcp_multiplexed_bidirectional_streams`: 5 concurrent bidirectional streams transmitting arbitrary data simultaneously over a single TCP connection.
     - `test_tcp_unreliable_datagram_exchange`: encapsulated datagram transmission over TCP.
     - `test_tcp_stealth_knock_authorization_flow`: stealth knock path protection over TCP.
     - `test_tcp_version_mismatch_rejection`: protocol version validation over TCP.
     - `test_happy_eyeballs_seamless_fallback_when_quic_blocked`: live Happy Eyeballs auto-detection falling back seamlessly to TCP when QUIC is unavailable.

9. **Live CLI End-to-End Verification**:
   - Started live dual-stack `morshd` listening on `quic://127.0.0.1:5252` and `tcp://127.0.0.1:5252 (TLS 1.3 fallback)`.
   - Executed live `morsh` client: connected via QUIC (3 ms handshake, sub-2ms RTT).
   - Executed live `morsh` client with `--force-tcp`: connected via TLS 1.3 over TCP (1 ms handshake, sub-2ms RTT).
   - Executed piped interactive shell over forced TCP fallback (`printf "echo TCP_FALLBACK_SHELL_PIPELINE_OK\nexit\n" | morsh -p 5252 -k --force-tcp 127.0.0.1`): spawned login shell in pseudo-terminal over TCP, executed command, rendered output, and cleanly exited.

---

## 9. Phase 8 Completion Record

### Delivered Components
1. **OpenSSH CLI Flag Parity (`crates/morsh`)**:
   - Added full suite of standard OpenSSH flags matching user muscle memory:
     - `-p, --port <port>`: Remote port override.
     - `-i, --identity <path>`: SSH private key path override.
     - `-F, --config <path>`: Alternative client configuration file (default: `~/.morsh/config.toml`).
     - `-o, --option <KEY=VALUE>`: OpenSSH compatibility directives (`Port`, `User`, `IdentityFile`, `StrictHostKeyChecking`, `ForwardAgent`, `Compression`, `LocalForward`, `RemoteForward`, `DynamicForward`, `StealthKnock`, `ForceTcp`, `TcpFallbackTimeout`, `PredictMode`, `PredictStyle`).
     - `-C, --compress`: Request zstd stream compression.
     - `-4, --ipv4`: Restrict address resolution to IPv4 (`addr.is_ipv4()`).
     - `-6, --ipv6`: Restrict address resolution to IPv6 (`addr.is_ipv6()`).
     - `-v, -vv, -vvv`: Verbosity level counting via `ArgAction::Count` mapping to tracing filters.
     - Trailing `[command...]`: Remote command execution via `/bin/sh -c <command>`.
     - `--completions <SHELL>`: Generate shell completions for `bash`, `zsh`, `fish`.
     - `--man`: Generate Section 1 UNIX roff man page to stdout.
   - Implemented 5-tier configuration precedence cascade:
     `Hardcoded Defaults < ~/.morsh/config.toml (global) < [[host]] Rule block < -o Options < CLI Flags`.

2. **Server Configuration & Signals (`crates/morshd`)**:
   - Added CLI flags:
     - `-C, -f, --config <path>`: Server TOML configuration file (default: `/etc/morsh/morshd.toml`).
     - `--completions <SHELL>`: Generate shell completions for `bash`, `zsh`, `fish`.
     - `--man`: Generate Section 8 UNIX roff man page to stdout.
   - Dynamic `SIGHUP` reload:
     - Wrapped server authentication state in `Arc<tokio::sync::RwLock<ServerAuthOptions>>`.
     - On `SIGHUP`, re-reads configuration file from disk and atomically swaps auth keys, stealth knock prefix, and PAM settings without terminating active sessions or listeners.
   - Graceful shutdown:
     - Handled `SIGTERM` and `SIGINT` signals with structured connection close and session detachment before exit.

3. **TOML Configuration System**:
   - Built `crates/morsh/src/config.rs`:
     - `ClientConfig` with global defaults and `[[host]]` blocks (`HostRule`).
     - DP-based `wildcard_match` (`*`, `?`) with space-delimited patterns and OpenSSH `!pattern` negations.
     - `expand_tilde` path expansion for `~/.ssh/` and `~/.morsh/`.
     - `OpenSshOptions::parse_options` directive parser.
   - Built `crates/morshd/src/config.rs`:
     - `ServerConfig` mapping `/etc/morsh/morshd.toml` directives.

4. **Wire Protocol Hardening (`crates/morsh-core`)**:
   - Added `ControlMessage::ExecRequest { command: String }` and `ControlMessage::ExecResponse { success: bool, message: String }`.
   - Serialized `ExecRequest` -> `ExecResponse` exchange before opening Stream 1, eliminating multi-stream concurrency race conditions during PTY creation.
   - Configured non-interactive remote execution: disabled raw terminal mode and speculative local echo when running explicit commands.

5. **Asynchronous Teardown & Channel Safety**:
   - Updated `ctrl_write_task` in `morsh` to immediately break on `ControlMessage::Disconnect` and finish stream without waiting for background forwarder channels.
   - Guarded final `ctrl_write_task` await with `tokio::time::timeout` preventing process hangs on exit.

6. **Distribution & Packaging Artifacts (`dist/`)**:
   - `dist/systemd/morshd.service`: systemd service unit with strict sandboxing (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`).
   - `dist/config/morsh.toml.example`: annotated client configuration template.
   - `dist/config/morshd.toml.example`: annotated daemon configuration template.
   - `dist/debian/control`: Debian packaging control file.
   - `dist/completions/`: shell completion scripts for `morsh` and `morshd` (`bash`, `zsh`, `fish`).
   - `dist/man/`: UNIX roff man pages (`morsh.1`, `morshd.8`).

7. **Automated Test Suite (126 Tests Passing Workspace-Wide)**:
   - **`morsh-core` (8 tests)**: added `test_exec_frames_roundtrip`.
   - **`morsh` (7 unit tests)**:
     - `test_wildcard_matching`: single and multiple `*` and `?` patterns.
     - `test_host_matches_negation_and_wildcard`: OpenSSH `!pattern` negation semantics.
     - `test_parse_openssh_options`: OpenSSH `-o` parsing.
     - `test_client_config_toml_parsing`: TOML configuration parsing.
     - `test_args_parsing_defaults`: default CLI flag verification.
     - `test_args_parsing_custom_flags`: custom CLI flag parsing.
     - `test_args_parsing_openssh_flags`: OpenSSH `-p`, `-i`, `-F`, `-o`, `-C`, `-4`, `-6`, `-v`.
   - **`morshd` (3 unit tests)**:
     - `test_server_config_toml_parsing`: TOML daemon configuration parsing.
     - `test_args_parsing_defaults`: default daemon flag verification.
     - `test_args_parsing_custom_flags`: custom daemon flags.
   - **`morshd` Integration Tests (`crates/morshd/tests/daemon_integration.rs`, 6 tests)**:
     - `test_cli_help_and_version`: `--help`, `--version`, and flag discovery.
     - `test_shell_completions_output`: shell completions generation for bash, zsh, fish.
     - `test_man_pages_output`: roff man page generation for `morsh.1` and `morshd.8`.
     - `test_client_config_file_cascade`: live connection using config file host alias, custom knock, and forced TCP fallback.
     - `test_server_daemon_config_and_sighup_reload`: dynamic `SIGHUP` reload updating stealth knock path in memory on live running daemon.
     - `test_remote_command_execution`: non-interactive command execution over live QUIC connection.

8. **Live CLI End-to-End Verification**:
   - Started live daemon `morshd` listening on port 44445.
   - Ran `target/debug/morsh -p 44445 -k 127.0.0.1 echo MORSH_PHASE_8_VERIFIED < /dev/null`.
   - Verified immediate remote execution (~10 ms), output rendering, clean disconnect with code 0.

---

## 10. Future Maintenance, Operations & Extensions

For future operational maintenance, release engineering, and platform extensions:

1. **Privilege Separation & Process Isolation**:
   - Implement privilege drop in `morshd` after socket binding (`CAP_NET_BIND_SERVICE`) using `nix::unistd::setuid` and `setgid` to switch to target authenticated user prior to PTY execution.
   - Implement Linux seccomp filter profiles for unauthenticated network parsers.

2. **Automated CI/CD Packaging**:
   - Implement `cargo-deb` workflow using `dist/debian/control` to produce `.deb` binaries.
   - Implement `cargo-generate-rpm` for Fedora/RHEL/CentOS systems.
   - Cross-compilation matrix: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.

3. **Performance Benchmarking & Hardening**:
   - Run multi-client stress tests with 10,000+ concurrent multiplexed connections.
   - Profile zero-copy throughput on 10 Gbps networks for `-L` port forwarding and large file transfers.

---

## 11. Work Log (Append History)

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

### 2026-10-06 — Phase 4 Completed
- Implemented Phase 4 Port Forwarding & Tunnels across `morsh-core`, `morsh-tunnel`, `morshd`, and `morsh`.
- Added tunnel control frames to `morsh-core`: `TunnelOpenRequest`, `TunnelOpenResponse`, `TunnelClose`, `RemoteForwardRequest`, `RemoteForwardResponse`, `NoShell`, and zero-allocation 8-byte `TunnelStreamPreamble` (`MTUN` magic).
- Built `morsh-tunnel` crate:
  - Configuration parsing for `-L`, `-R`, `-D`, `-U` rules with OpenSSH CLI format and IPv6 bracket syntax.
  - Non-blocking bidirectional bridge (`bridge_tcp_and_quic`) with half-close handling.
  - Thread-safe `TunnelManager` tracking active tunnels, pending oneshots, pending server streams, and UDP routes.
  - Local TCP port forwarding engine (`-L`).
  - Dynamic SOCKS5 proxy engine (`-D`) implementing native RFC 1928 protocol parser (IPv4, IPv6, Domain names).
  - Remote TCP port forwarding engine (`-R`) with remote listener binding on server and client local bridging.
  - Native UDP forwarding engine (`-U`) over QUIC Datagrams (RFC 9221) with `MUDP` framing.
- Integrated into `morshd` server daemon:
  - Stream supervisor multiplexing Stream 1 (PTY) and Stream 2..N (Tunnels) via `TunnelStreamPreamble`.
  - Background datagram router for UDP tunnels.
  - Control loop handling tunnel open, remote bind, and close frames.
- Integrated into `morsh` client CLI:
  - CLI flags: `-L, --local-forward`, `-R, --remote-forward`, `-D, --dynamic-forward`, `-U, --udp-forward`, `-N, --no-shell`.
  - Tunnel-only mode (`-N`) keeping tunnels alive in background.
  - Server-initiated stream acceptor for `-R`.
  - UDP datagram return router for `-U`.
- Added 19 new tests: 13 unit tests in `morsh-tunnel`, 5 integration tests in `tunnel_integration.rs`, 1 unit test in `morsh-core`, reaching 57 passing tests workspace-wide with 0 warnings.
- Verified live end-to-end execution of `-L` and `-D` SOCKS5 proxy over live QUIC connections with `morshd` and `morsh`.

### 2026-10-06 — Phase 5 Completed
- Implemented Phase 5 Session Persistence & Screen State Recovery (Mosh Style) across `morsh-core`, `morsh-term`, `morshd`, and `morsh`.
- Added session control frames to `morsh-core`: `SessionDetachRequest`, `SessionResumeRequest`, `SessionResumeResponse`, `SessionListRequest`, `SessionListResponse`, `ScreenSnapshot`, `ScreenDelta`, and `SessionInfo` struct.
- Built `TerminalStateBuffer` in `morsh-term` wrapping `vt100::Parser`:
  - Maintained virtual screen cells, dimensions, cursor coordinates, and attributes in real-time.
  - Implemented `snapshot()` producing consolidated ANSI screen clear and redraw sequences.
- Built `PersistentSession` and `SessionRegistry` in `morsh-term`:
  - Decoupled PTY child process lifetime from QUIC connection.
  - Background PTY reader thread keeps `TerminalStateBuffer` synchronized even when detached.
  - Cryptographic 128-bit session resumption token verification preventing unauthorized access.
  - Dead session background cleanup on child process termination.
- Integrated session management into `morshd` daemon:
  - Handled voluntary detachment (`SessionDetachRequest`) and connection drop without killing shell.
  - Implemented resumption handling transmitting immediate `ScreenSnapshot` for instant display recovery.
  - Implemented session listing for authenticated users.
- Integrated session recovery into `morsh` client CLI:
  - CLI flags: `--resume <SESSION_ID>`, `--token <TOKEN>`, `--list-sessions`.
  - Local token caching in `~/.morsh/sessions/`.
  - Raw mode escape sequence state machine: `Ctrl-^ d` (0x1e followed by 'd'/'D'/'.') for clean voluntary detach.
  - Instant screen redraw on receiving `ScreenSnapshot`.
- Added 8 new tests: 7 in `morsh-term` (including 3 integration tests in `term_integration.rs`) and 1 in `morsh-core`, reaching 65 passing tests workspace-wide with 0 warnings.
- Verified live end-to-end execution of `--list-sessions`, `--resume`, and `Ctrl-^ d` voluntary detachment.

### 2026-10-06 — Phase 6 Completed
- Implemented Phase 6 Predictive Local Echo & Speculative UI (Mosh Style) across `morsh-core`, `morsh-predict`, `morshd`, and `morsh`.
- Added predictive sequence control frames to `morsh-core`: `PredictInputSeq { seq, len }` and `PredictAck { ack_seq }`.
- Built full `morsh-predict` crate:
  - `PredictStyle`: underline (`\x1b[4m ... \x1b[24m`), dim (`\x1b[2m ... \x1b[22m`), and none.
  - `PredictMode`: auto (heuristic), always, never.
  - `Keystroke` classifier parsing printable Unicode/ASCII, backspace (`\x08`, `\x7f`), newlines, and ANSI arrow keys (`\x1b[D`, `\x1b[C`).
  - `ConfidenceTracker` adapting confidence level (`High`, `Tentative`, `Suppressed`) with suppression heuristics for alternate screen buffers (`\x1b[?1049h`) and password prompts (`password:`).
  - `Prediction` tracking sequence identifiers, expected echoes, and speculative displays.
  - `generate_rollback` creating ANSI cursor backstep and line erase sequences (`\x08 \x08`, `\x1b[ND\x1b[K`).
  - `PredictionEngine` managing speculative rendering, stream output matching, divergence rollback, and sequence acknowledgements.
- Integrated sequence acknowledgement in `morshd` server daemon over Stream 0.
- Integrated predictive local echo into `morsh` client CLI with `--predict` and `--predict-style` flags, immediate speculative rendering to local stdout, 1-RTT divergence detection and rollback upon server output mismatch, and clean terminal exit restoration.
- Added 27 new tests: 20 unit tests in `morsh-predict`, 6 integration tests in `predict_integration.rs` (including live QUIC exchange), and 1 in `morsh-core`, reaching 92 passing tests workspace-wide with 0 warnings.
- Verified live end-to-end execution with `morshd` and `morsh` running piped shell commands with active speculative prediction.

### 2026-10-06 — Phase 7 Completed
- Implemented Phase 7 TCP Fallback & Network Resilience across `morsh-transport`, `morsh-tunnel`, `morshd`, and `morsh`.
- Built lightweight, high-performance binary TCP stream multiplexer (`tcp_mux.rs`):
  - 9-byte binary frame header (`[stream_id: u32, flags: u8, len: u32]`).
  - Stream flags: `FLAG_DATA`, `FLAG_FIN`, `FLAG_RST`, `FLAG_DATAGRAM`, `FLAG_PING`, `FLAG_PONG`.
  - Non-blocking Tokio `AsyncWrite` and `AsyncRead` implementation with bounded buffers and queue drain upon connection termination.
- Extracted shared TLS 1.3 configuration in `tls.rs`:
  - `make_rustls_server_config` and `make_rustls_client_config` sharing ALPN `b"morsh-v1"` across QUIC and TCP.
  - Implemented `TcpServer` (`TlsAcceptor`) and `TcpClient` (`TlsConnector`).
- Created unified `MorshConnection`, `MorshSendStream`, and `MorshRecvStream` abstractions in `stream.rs` and `connection.rs`:
  - Uniform stream API (`write_all`, `flush`, `finish`, `read`, `read_exact`) across both QUIC and TCP multiplexer.
  - Uniform stream indexing (`stream_id / 2`) aligning client even IDs (`0, 2, 4...`) and server odd IDs (`1, 3, 5...`).
- Built RFC 8305 Happy Eyeballs auto-detection engine (`happy_eyeballs.rs`):
  - Concurrently races QUIC (UDP) and TLS 1.3 over TCP fallback with configurable threshold timer (`DEFAULT_FALLBACK_DELAY = 300 ms`).
  - Supports `--force-tcp` fast path bypassing QUIC entirely.
- Integrated dual-stack listener into `morshd`:
  - Concurrent `QuicServer` and `TcpServer` bindings over `--listen` and `--tcp-listen`.
  - Dispatching both QUIC and TCP connections into unified authentication, PTY shell, tunnel, and session persistence pipeline.
- Integrated TCP fallback and Happy Eyeballs into `morsh` CLI:
  - Added `--force-tcp` and `--tcp-fallback-timeout <ms>` flags.
  - Client automatically adopts winning transport and displays `Transport: QUIC` or `Transport: TLS/TCP` in banner.
  - Transparently bridges PTY shells, persistent session recovery, and `-L`/`-R`/`-D`/`-U` tunnels (with UDP over `FLAG_DATAGRAM`) across both transports.
- Added 11 new tests: 5 unit tests in `morsh-transport` and 6 integration tests in `tcp_integration.rs`, reaching 103 passing tests workspace-wide with 0 warnings.
- Verified live end-to-end execution: QUIC connection, forced TCP connection, and piped interactive shell execution over TLS/TCP fallback.

### 2026-10-06 — Phase 8 Completed
- Implemented Phase 8 Production Polish, Configuration & Distribution across `morsh-core`, `morsh`, `morshd`, and packaging distribution assets.
- Achieved full OpenSSH CLI flag parity in `morsh`: `-p <port>`, `-i <identity>`, `-F <config>`, `-o <Option=Value>`, `-C` (compression), `-4` (IPv4), `-6` (IPv6), `-v`/`-vv`/`-vvv` verbosity levels, and trailing positional remote command `[command...]`.
- Built TOML configuration subsystem:
  - Client configuration in `~/.morsh/config.toml` supporting global defaults and `[[host]]` blocks with DP wildcard matching (`*`, `?`), space-delimited patterns, OpenSSH `!pattern` negation, and `host_name` alias resolution.
  - Server configuration in `/etc/morsh/morshd.toml`.
  - Full configuration precedence cascade: `Defaults < Config File (global) < Host Rule < -o Options < CLI Flags`.
- Implemented systemd daemon signals and sandboxing in `morshd`:
  - Created `dist/systemd/morshd.service` with strict systemd security sandboxing (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`).
  - Unix `SIGHUP` graceful configuration reload updating authentication keys and stealth knock path in memory without restarting daemon or dropping persistent sessions.
  - Unix `SIGTERM` / `SIGINT` graceful shutdown.
- Hardened wire protocol:
  - Added `ControlMessage::ExecRequest` and `ControlMessage::ExecResponse` in `morsh-core`.
  - Serialized command execution before Stream 1 PTY initialization.
  - Automatically disabled raw terminal mode and speculative local echo for non-interactive remote commands.
- Fixed asynchronous channel leaks:
  - Guaranteed `ctrl_write_task` terminates immediately upon `ControlMessage::Disconnect`.
  - Bound client exit with timeout preventing deadlocks.
- Generated distribution and packaging assets:
  - Shell completion scripts for bash, zsh, fish in `dist/completions/`.
  - UNIX roff man pages (`morsh.1`, `morshd.8`) in `dist/man/`.
  - Debian control file in `dist/debian/control`.
  - Example annotated TOML configuration templates in `dist/config/`.
- Added 23 new tests: 1 in `morsh-core`, 7 in `morsh`, 3 in `morshd`, and 6 integration tests in `daemon_integration.rs`, reaching 126 passing tests workspace-wide with 0 warnings.
- Verified live end-to-end execution of non-interactive remote command execution, config file alias resolution, and dynamic `SIGHUP` configuration reload.

### 2026-10-07 — Host Key Verification & TOFU (Trust-On-First-Use) Fix
- Fixed `invalid peer certificate: UnknownIssuer` failure when connecting to `morshd`'s default self-signed host certificate.
- Root Cause:
  - `morshd` defaults to generating an ephemeral self-signed host certificate when launched without `--cert`/`--key`.
  - `morsh` previously only validated certificates using OS root CAs (Web PKI) when `insecure = false`, rejecting self-signed certificates with `UnknownIssuer`.
- Resolution & Architectural Enhancements:
  - Implemented OpenSSH-compatible **Trust-On-First-Use (TOFU)** and `known_hosts` verification in `crates/morsh-transport/src/known_hosts.rs`.
  - Added `KnownHosts` parser and persistence manager maintaining `~/.morsh/known_hosts`.
  - Added `TofuServerCertVerifier` implementing rustls `ServerCertVerifier`:
    - First attempts Web PKI verification (for servers with CA-signed certificates).
    - Falls back to `known_hosts` fingerprint lookup (SHA-256).
    - Rejects changed host keys with OpenSSH-style MITM attack warning banners.
    - Supports `StrictHostKeyChecking` modes (`ask`, `accept-new`, `yes`, `no`), parsing `-o StrictHostKeyChecking=...` and TOML configuration files.
    - Synchronizes interactive prompt decisions between QUIC and TCP fallback handshakes to prevent duplicate prompts.
  - Added unit tests in `known_hosts.rs` and daemon integration test `test_tofu_known_hosts_auto_record_and_reconnect`, reaching 128 passing tests workspace-wide.

### 2026-10-07 — Root Privilege Dropping & Authenticated User Session Isolation Fix
- Fixed security vulnerability where running `morshd` as `root` resulted in normal authenticated users (`morsh liu@localhost:2222`) landing in a `root` shell (`root@I ~ # #`) instead of dropping privileges to the target user.
- Root Cause:
  - `PtySession::spawn` used `portable_pty::CommandBuilder` which only configured environment variables (`USER`, `LOGNAME`).
  - `portable_pty` had no mechanism to drop POSIX privileges (`setuid`, `setgid`, `initgroups`), change UID/GID, or initialize the user's home directory (`HOME`, `PWD`, `working_dir`).
  - As a result, when `morshd` ran as root, child shell sessions retained full UID 0 privileges, `/root` working directory, and root environment.
- Resolution & Architectural Enhancements:
  - Implemented `crates/morsh-term/src/user.rs`:
    - Created thread-safe `UserInfo::lookup` using `getpwnam_r` and `getgrouplist` to resolve user's UID, primary GID, supplementary group lists, home directory (`pw_dir`), and default shell (`pw_shell`).
  - Implemented direct Unix child process spawning with POSIX privilege dropping in `crates/morsh-term/src/pty.rs` (`spawn_unix_as_user`):
    - Sets up user environment: `USER`, `LOGNAME`, `HOME`, `SHELL`, `PWD`, and default clean `PATH`.
    - Automatically sets session working directory to the target user's home directory (`pw_dir`).
    - Strips sensitive daemon and root environment variables (`SUDO_USER`, `SUDO_UID`, `SUDO_GID`, `SUDO_COMMAND`) and sets `XDG_RUNTIME_DIR` to `/run/user/<uid>` if present.
    - Sets login shell `arg0` (`-bash`, `-zsh`, etc.) to trigger login profile initialization (`/etc/profile`, `~/.bashrc`, `~/.zprofile`).
    - Modifies slave PTY device ownership (`chown` to `target_uid:target_gid`, `chmod` to `0620`) when running with root privileges.
    - Drops privileges inside `Command::pre_exec` before executing the shell:
      1. Resets signal masks and dispositions.
      2. Calls `setsid()` to establish a new session.
      3. Calls `ioctl(0, TIOCSCTTY, 0)` to set the slave PTY as the controlling terminal.
      4. Drops supplementary groups via `setgroups(groups)` (falling back to `initgroups`).
      5. Drops primary group via `setgid(target_gid)`.
      6. Drops primary user privileges via `setuid(target_uid)`.
    - Ensures unprivileged daemons cannot arbitrarily impersonate different users without root privileges (`Permission denied`).
  - Added unit and integration tests:
    - `test_pty_spawn_with_current_user_and_env`: verifies environment variable and home directory resolution.
    - `test_pty_spawn_nonexistent_user_error`: verifies safe error handling when target user does not exist.
    - `test_pty_spawn_unprivileged_switch_denied`: verifies unprivileged daemon cannot switch to root.
    - `test_authenticated_user_session_execution`: end-to-end integration test verifying Ed25519 public key authentication and command execution in user session.
  - Test suite status: All 132 tests passing workspace-wide with 0 warnings.

### 2026-10-07 — Persistent Host Certificate & Key Across Restarts
- Fixed issue where `morshd` generated a new ephemeral certificate on every restart, causing clients to trigger `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`.
- Root Cause:
  - Without explicit `--cert`/`--key` flags, `morshd` generated an ephemeral in-memory certificate on the fly using `rcgen`.
  - When `morshd` restarted, its SHA-256 host fingerprint changed, causing `morsh` to fail host key verification against `~/.morsh/known_hosts`.
- Resolution & Architectural Enhancements:
  - Added `generate_self_signed_cert_pem` in `crates/morsh-transport/src/tls.rs` returning PEM-encoded certificate and private key.
  - Implemented persistent host key discovery & auto-generation in `crates/morshd/src/main.rs`:
    - Checks default host key paths: `/etc/morsh/host_cert.pem` & `/etc/morsh/host_key.pem` (when root), or `~/.morsh/host_cert.pem` & `~/.morsh/host_key.pem` (when non-root).
    - If present, loads them on startup, preserving the server's identity across restarts.
    - If not present, generates a new self-signed certificate and key in PEM format and persists them with `0600` permissions.
    - Falls back gracefully to in-memory ephemeral certificates if disk write permissions are not available.
  - Added support for `StrictHostKeyChecking=false`, `no`, `off` and `true`, `on`, `yes` in `crates/morsh/src/config.rs`.


