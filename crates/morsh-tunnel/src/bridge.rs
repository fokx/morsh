use morsh_transport::{MorshRecvStream, MorshSendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

/// Bridges bytes bidirectionally between a local or remote TcpStream and a pair of morsh streams (QUIC or TCP fallback).
/// Returns total bytes transferred: `(tcp_to_quic_bytes, quic_to_tcp_bytes)`.
pub async fn bridge_tcp_and_quic(
    mut tcp_stream: TcpStream,
    mut quic_send: MorshSendStream,
    mut quic_recv: MorshRecvStream,
) -> (u64, u64) {
    let (mut tcp_read, mut tcp_write) = tcp_stream.split();

    let client_to_quic = async {
        let res = tokio::io::copy(&mut tcp_read, &mut quic_send).await;
        let _ = quic_send.finish();
        res.unwrap_or(0)
    };

    let quic_to_client = async {
        let res = tokio::io::copy(&mut quic_recv, &mut tcp_write).await;
        let _ = tcp_write.shutdown().await;
        res.unwrap_or(0)
    };

    let (sent_to_quic, sent_to_tcp) = tokio::join!(client_to_quic, quic_to_client);
    debug!(sent_to_quic, sent_to_tcp, "Bridged TCP and QUIC streams completed");
    (sent_to_quic, sent_to_tcp)
}
