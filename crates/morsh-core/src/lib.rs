pub mod error;
pub mod frame;
pub mod protocol;

pub use error::{CoreError, Result};
pub use frame::{decode_payload, encode_frame, read_frame, write_frame};
pub use protocol::{
    AuthMethod, ControlMessage, StreamChannelKind, ALPN_MORSH, MAX_FRAME_SIZE,
    PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
