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
    reader.read_exact(&mut payload).await?;
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
}
