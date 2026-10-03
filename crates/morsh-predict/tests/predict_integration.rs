//! Integration tests for morsh predictive local echo engine.

use morsh_predict::{
    ConfidenceLevel, PredictMode, PredictStyle, PredictionEngine,
};

#[test]
fn test_interactive_typing_simulation_with_server_delay() {
    let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

    // 1. User types "cargo test"
    let typed_command = b"cargo test";
    let input_result = engine.process_input(typed_command);

    assert_eq!(input_result.predictions.len(), 10);
    assert_eq!(input_result.raw_input, b"cargo test");
    assert_eq!(engine.active_speculative_cols(), 10);
    assert_eq!(engine.pending_count(), 10);

    // Speculative characters should be rendered with underline ANSI escapes
    assert!(input_result.speculative_render.starts_with(b"\x1b[4m"));
    assert!(input_result.speculative_render.ends_with(b"\x1b[24m"));

    // 2. Server echoes the command in two chunks (simulating network chunking/RTT)
    let chunk1 = b"cargo ";
    let srv_res1 = engine.process_server_output(chunk1);
    assert_eq!(srv_res1.had_divergence, false);
    assert_eq!(srv_res1.confirmed_seq, Some(6));
    assert_eq!(engine.active_speculative_cols(), 4);
    assert_eq!(engine.pending_count(), 4);

    let chunk2 = b"test";
    let srv_res2 = engine.process_server_output(chunk2);
    assert_eq!(srv_res2.had_divergence, false);
    assert_eq!(srv_res2.confirmed_seq, Some(10));
    assert_eq!(engine.active_speculative_cols(), 0);
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn test_speculative_rollback_on_command_rejection() {
    let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Dim);

    // User types "rm -rf"
    let input_res = engine.process_input(b"rm -rf");
    assert_eq!(input_res.predictions.len(), 6);
    assert_eq!(engine.active_speculative_cols(), 6);

    // Instead of echo, remote shell sends error message / prompt reset
    let server_error = b"\r\nPermission denied\r\n$ ";
    let srv_res = engine.process_server_output(server_error);

    assert_eq!(srv_res.had_divergence, true);
    assert_eq!(engine.active_speculative_cols(), 0);
    assert_eq!(engine.pending_count(), 0);

    // Local stdout must receive rollback erase sequence (\x1b[6D\x1b[K) followed by the server error
    assert_eq!(
        srv_res.output_to_render,
        [b"\x1b[6D\x1b[K".as_slice(), server_error].concat()
    );

    // Confidence should have degraded from High to Tentative
    assert_eq!(engine.confidence().level(), ConfidenceLevel::Tentative);
}

#[test]
fn test_dim_style_speculative_rendering() {
    let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Dim);

    let input_res = engine.process_input(b"echo 42");
    assert_eq!(
        input_res.speculative_render,
        b"\x1b[2me\x1b[22m\x1b[2mc\x1b[22m\x1b[2mh\x1b[22m\x1b[2mo\x1b[22m\x1b[2m \x1b[22m\x1b[2m4\x1b[22m\x1b[2m2\x1b[22m"
    );
}

#[test]
fn test_rapid_editing_with_backspace() {
    let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

    // User types "abc"
    engine.process_input(b"abc");
    assert_eq!(engine.active_speculative_cols(), 3);

    // User types two backspaces
    let bs_res = engine.process_input(b"\x7f\x7f");
    assert_eq!(bs_res.speculative_render, b"\x08 \x08\x08 \x08");
    assert_eq!(engine.active_speculative_cols(), 1);
    assert_eq!(engine.pending_count(), 1);

    // Server echoes back "abc\x08 \x08\x08 \x08"
    let srv_res = engine.process_server_output(b"a");
    assert_eq!(srv_res.had_divergence, false);
    assert_eq!(engine.active_speculative_cols(), 0);
}

#[test]
fn test_alternate_screen_transition_suppresses_and_restores() {
    let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);

    // Standard shell prompt
    let in1 = engine.process_input(b"vim file.txt\r");
    assert_eq!(in1.predictions.len(), 12);

    // Server launches vim (enters alternate screen)
    let alt_enter = b"\x1b[?1049h\x1b[H\x1b[2J~";
    engine.process_server_output(alt_enter);
    assert!(engine.confidence().is_alt_screen());

    // Inside vim: typing should NOT be predicted locally
    let vim_input = engine.process_input(b"iHello world\x1b");
    assert_eq!(vim_input.predictions.len(), 0);
    assert!(vim_input.speculative_render.is_empty());
    assert_eq!(engine.active_speculative_cols(), 0);

    // Server exits vim (leaves alternate screen)
    let alt_leave = b"\x1b[?1049l$ ";
    engine.process_server_output(alt_leave);
    assert!(!engine.confidence().is_alt_screen());

    // Back in shell: typing predicts again
    let shell_input = engine.process_input(b"ls");
    assert_eq!(shell_input.predictions.len(), 2);
    assert!(!shell_input.speculative_render.is_empty());
}

#[tokio::test]
async fn test_predict_sequence_acknowledgement_over_quic() {
    use morsh_core::protocol::ControlMessage;
    use morsh_transport::{
        generate_self_signed_cert, make_client_config, make_server_config, MorshConnection,
        QuicClient, QuicServer,
    };
    use std::net::SocketAddr;

    // Set up QUIC server
    let (certs, key) = generate_self_signed_cert(vec!["localhost".into()]).unwrap();
    let server_cfg = make_server_config(certs, key).unwrap();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = QuicServer::bind(bind_addr, server_cfg).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Server loop handling ControlMessage
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        // Expect PredictInputSeq
        let msg = MorshConnection::read_control_message(&mut recv).await.unwrap();
        if let ControlMessage::PredictInputSeq { seq, len: _ } = msg {
            // Acknowledge with PredictAck
            let ack = ControlMessage::PredictAck { ack_seq: seq };
            MorshConnection::send_control_message(&mut send, &ack).await.unwrap();
        }

        // Wait for client to read and finish
        let _ = recv.read(&mut [0u8; 1]).await;
    });

    // Client setup
    let client_cfg = make_client_config(true).unwrap();
    let client = QuicClient::new(client_cfg).unwrap();

    let conn = client.connect(server_addr, "localhost").await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    let mut engine = PredictionEngine::new(PredictMode::Auto, PredictStyle::Underline);
    let input_res = engine.process_input(b"echo");
    assert_eq!(input_res.predictions.len(), 4);
    assert_eq!(engine.pending_count(), 4);

    let seq = input_res.highest_seq.unwrap();
    let msg = ControlMessage::PredictInputSeq { seq, len: 4 };
    MorshConnection::send_control_message(&mut send, &msg).await.unwrap();

    let reply = MorshConnection::read_control_message(&mut recv).await.unwrap();
    if let ControlMessage::PredictAck { ack_seq } = reply {
        assert_eq!(ack_seq, seq);
        engine.handle_ack(ack_seq);
    } else {
        panic!("Unexpected reply: {:?}", reply);
    }

    assert_eq!(engine.pending_count(), 0);
    drop(send);
    conn.close(0, "done");
    server_task.await.unwrap();
}
