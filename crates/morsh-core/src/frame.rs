use crate::error::{CoreError, Result};
use crate::protocol::MAX_FRAME_SIZE;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Encodes a serializable value into a length-prefixed postcard frame buffer.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(value)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    if payload.len() > MAX_FRAME_SIZE {
        return Err(CoreError::FrameTooLarge {
            size: payload.len(),
            max: MAX_FRAME_SIZE,
        });
    }

    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes a payload byte slice into a deserializable value.
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    postcard::from_bytes(payload).map_err(|e| CoreError::Deserialization(e.to_string()))
}

/// Asynchronously writes a length-prefixed serialized message to an async writer.
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let frame_bytes = encode_frame(msg)?;
    writer.write_all(&frame_bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Asynchronously reads a length-prefixed frame and deserializes the message.
pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    if let Err(e) = reader.read_exact(&mut len_bytes).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Err(CoreError::UnexpectedEof);
        }
        return Err(CoreError::Io(e));
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(CoreError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0u8; len];
    if let Err(e) = reader.read_exact(&mut payload).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Err(CoreError::UnexpectedEof);
        }
        return Err(CoreError::Io(e));
    }
    decode_payload(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AuthMethod, ControlMessage};
    use std::io::Cursor;

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let original = ControlMessage::ClientHello {
            version: 1,
            client_software: "morsh-test-client".into(),
            knock_path: Some("/secret/path".into()),
            resumption_session_id: None,
        };

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &original).await.unwrap();

        let mut reader = Cursor::new(buffer);
        let decoded: ControlMessage = read_frame(&mut reader).await.unwrap();

        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn test_server_hello_roundtrip() {
        let original = ControlMessage::ServerHello {
            version: 1,
            server_software: "morshd-test".into(),
            session_id: [42u8; 16],
            supported_auth: vec![AuthMethod::None, AuthMethod::Password],
            session_resumed: false,
        };

        let mut buffer = Vec::new();
        write_frame(&mut buffer, &original).await.unwrap();

        let mut reader = Cursor::new(buffer);
        let decoded: ControlMessage = read_frame(&mut reader).await.unwrap();

        assert_eq!(original, decoded);
    }

    #[tokio::test]
    async fn test_ping_pong_disconnect_roundtrip() {
        let ping = ControlMessage::Ping {
            seq: 100,
            timestamp_ms: 1700000000000,
        };
        let pong = ControlMessage::Pong {
            seq: 100,
            echo_timestamp_ms: 1700000000000,
        };
        let disconnect = ControlMessage::Disconnect {
            reason_code: 0,
            message: "user logout".into(),
        };

        for msg in [ping, pong, disconnect] {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &msg).await.unwrap();
            let mut reader = Cursor::new(buffer);
            let decoded: ControlMessage = read_frame(&mut reader).await.unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[tokio::test]
    async fn test_window_resize_and_pty_request_roundtrip() {
        let resize = ControlMessage::WindowResize {
            cols: 120,
            rows: 40,
            x_pixels: 1920,
            y_pixels: 1080,
        };
        let pty_req = ControlMessage::PtyRequest {
            term: "xterm-256color".into(),
            cols: 132,
            rows: 43,
            x_pixels: 0,
            y_pixels: 0,
        };

        for msg in [resize, pty_req] {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &msg).await.unwrap();
            let mut reader = Cursor::new(buffer);
            let decoded: ControlMessage = read_frame(&mut reader).await.unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[tokio::test]
    async fn test_auth_frames_roundtrip() {
        use crate::protocol::AuthRequest;

        let challenge = ControlMessage::AuthChallenge {
            challenge: [0x5au8; 32],
        };

        let pk_req = ControlMessage::AuthRequest(AuthRequest::PublicKey {
            username: "alice".into(),
            algorithm: "ssh-ed25519".into(),
            public_key: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
        });

        let pw_req = ControlMessage::AuthRequest(AuthRequest::Password {
            username: "bob".into(),
            password: b"secret123".to_vec(),
        });

        let none_req = ControlMessage::AuthRequest(AuthRequest::None {
            username: "guest".into(),
        });

        let result_ok = ControlMessage::AuthResult {
            success: true,
            message: "Welcome alice".into(),
        };

        let result_err = ControlMessage::AuthResult {
            success: false,
            message: "Authentication failed: invalid signature".into(),
        };

        for msg in [challenge, pk_req, pw_req, none_req, result_ok, result_err] {
            let mut buffer = Vec::new();
            write_frame(&mut buffer, &msg).await.unwrap();
            let mut reader = Cursor::new(buffer);
            let decoded: ControlMessage = read_frame(&mut reader).await.unwrap();
            assert_eq!(msg, decoded);
        }
    }


    #[tokio::test]
    async fn test_frame_too_large_rejected() {
        // Construct a frame header indicating size > MAX_FRAME_SIZE
        let excessive_len = (MAX_FRAME_SIZE + 1) as u32;
        let mut buffer = excessive_len.to_be_bytes().to_vec();
        buffer.extend_from_slice(&[0u8; 16]);

        let mut reader = Cursor::new(buffer);
        let result: Result<ControlMessage> = read_frame(&mut reader).await;

        assert!(matches!(result, Err(CoreError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn test_unexpected_eof_on_empty_or_truncated_stream() {
        // Completely empty
        let mut empty_reader = Cursor::new(Vec::new());
        let res_empty: Result<ControlMessage> = read_frame(&mut empty_reader).await;
        assert!(matches!(res_empty, Err(CoreError::UnexpectedEof)));

        // Truncated header (only 2 bytes instead of 4)
        let mut truncated_header = Cursor::new(vec![0, 0]);
        let res_hdr: Result<ControlMessage> = read_frame(&mut truncated_header).await;
        assert!(matches!(res_hdr, Err(CoreError::UnexpectedEof)));

        // Header says 10 bytes, but only 3 bytes present
        let mut truncated_payload = Cursor::new(vec![0, 0, 0, 10, 1, 2, 3]);
        let res_payload: Result<ControlMessage> = read_frame(&mut truncated_payload).await;
        assert!(matches!(res_payload, Err(CoreError::UnexpectedEof)));
    }

    #[tokio::test]
    async fn test_corrupted_payload_returns_deserialization_error() {
        let corrupt_data = vec![0, 0, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = Cursor::new(corrupt_data);
        let result: Result<ControlMessage> = read_frame(&mut reader).await;
        assert!(matches!(result, Err(CoreError::Deserialization(_))));
    }
}
