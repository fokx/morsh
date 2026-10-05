use bytes::Bytes;
use morsh_core::error::{CoreError, Result as CoreResult};
use std::collections::HashMap;
use std::io::{ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};
use tracing::{debug, warn};

pub const HEADER_LEN: usize = 9;
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024; // 16 MiB
pub const DEFAULT_CHUNK_SIZE: usize = 32 * 1024; // 32 KiB

pub const FLAG_DATA: u8 = 0x00;
pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_RST: u8 = 0x02;
pub const FLAG_DATAGRAM: u8 = 0x04;
pub const FLAG_PING: u8 = 0x08;
pub const FLAG_PONG: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFrameHeader {
    pub stream_id: u32,
    pub flags: u8,
    pub length: u32,
}

impl TcpFrameHeader {
    pub fn encode(&self, buf: &mut [u8; HEADER_LEN]) {
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4] = self.flags;
        buf[5..9].copy_from_slice(&self.length.to_be_bytes());
    }

    pub fn decode(buf: &[u8; HEADER_LEN]) -> Self {
        let stream_id = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let flags = buf[4];
        let length = u32::from_be_bytes(buf[5..9].try_into().unwrap());
        Self {
            stream_id,
            flags,
            length,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpFrame {
    pub stream_id: u32,
    pub flags: u8,
    pub payload: Bytes,
}

#[derive(Debug)]
pub enum StreamChunk {
    Data(Bytes),
    Fin,
    Rst,
}

/// Send half of a multiplexed TCP stream.
pub struct TcpSendStream {
    stream_id: u32,
    outbound_tx: mpsc::UnboundedSender<TcpFrame>,
    conn_closed: Arc<AtomicBool>,
    finished: bool,
}

impl TcpSendStream {
    pub fn new(
        stream_id: u32,
        outbound_tx: mpsc::UnboundedSender<TcpFrame>,
        conn_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            stream_id,
            outbound_tx,
            conn_closed,
            finished: false,
        }
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn index(&self) -> u64 {
        (self.stream_id / 2) as u64
    }

    pub fn id(&self) -> crate::stream::MorshStreamId {
        crate::stream::MorshStreamId(self.index())
    }

    /// Signals end-of-stream (FIN) to the peer.
    pub fn finish(&mut self) -> IoResult<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let frame = TcpFrame {
            stream_id: self.stream_id,
            flags: FLAG_FIN,
            payload: Bytes::new(),
        };
        let _ = self.outbound_tx.send(frame);
        Ok(())
    }
}

impl AsyncWrite for TcpSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if self.finished || self.conn_closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "TCP stream finished or closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = std::cmp::min(buf.len(), DEFAULT_CHUNK_SIZE);
        let payload = Bytes::copy_from_slice(&buf[..chunk_len]);
        let frame = TcpFrame {
            stream_id: self.stream_id,
            flags: FLAG_DATA,
            payload,
        };

        match self.outbound_tx.send(frame) {
            Ok(()) => Poll::Ready(Ok(chunk_len)),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "TCP connection closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let _ = self.finish();
        Poll::Ready(Ok(()))
    }
}

/// Receive half of a multiplexed TCP stream.
pub struct TcpRecvStream {
    stream_id: u32,
    inbound_rx: mpsc::Receiver<StreamChunk>,
    current_chunk: Option<Bytes>,
    offset: usize,
    eof: bool,
}

impl TcpRecvStream {
    pub fn new(stream_id: u32, inbound_rx: mpsc::Receiver<StreamChunk>) -> Self {
        Self {
            stream_id,
            inbound_rx,
            current_chunk: None,
            offset: 0,
            eof: false,
        }
    }

    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn index(&self) -> u64 {
        (self.stream_id / 2) as u64
    }

    /// Read data into `buf`, returning `Ok(None)` on clean EOF, or `Ok(Some(n))` bytes read.
    pub async fn read(&mut self, buf: &mut [u8]) -> IoResult<Option<usize>> {
        if buf.is_empty() {
            return Ok(Some(0));
        }

        if self.current_chunk.is_none() {
            if self.eof {
                return Ok(None);
            }
            match self.inbound_rx.recv().await {
                Some(StreamChunk::Data(bytes)) => {
                    self.current_chunk = Some(bytes);
                    self.offset = 0;
                }
                Some(StreamChunk::Fin) | None => {
                    self.eof = true;
                    return Ok(None);
                }
                Some(StreamChunk::Rst) => {
                    self.eof = true;
                    return Err(std::io::Error::new(
                        ErrorKind::ConnectionReset,
                        "TCP stream reset by peer",
                    ));
                }
            }
        }

        if let Some(bytes) = self.current_chunk.take() {
            let slice = &bytes[self.offset..];
            let to_read = std::cmp::min(slice.len(), buf.len());
            buf[..to_read].copy_from_slice(&slice[..to_read]);
            let new_offset = self.offset + to_read;
            if new_offset < bytes.len() {
                self.current_chunk = Some(bytes);
                self.offset = new_offset;
            } else {
                self.offset = 0;
            }
            Ok(Some(to_read))
        } else {
            Ok(None)
        }
    }
}

impl AsyncRead for TcpRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.current_chunk.is_none() {
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.inbound_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) | Poll::Ready(Some(StreamChunk::Fin)) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamChunk::Rst)) => {
                    self.eof = true;
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::ConnectionReset,
                        "TCP stream reset by peer",
                    )));
                }
                Poll::Ready(Some(StreamChunk::Data(bytes))) => {
                    self.current_chunk = Some(bytes);
                    self.offset = 0;
                }
            }
        }

        if let Some(bytes) = self.current_chunk.take() {
            let slice = &bytes[self.offset..];
            let to_read = std::cmp::min(slice.len(), buf.remaining());
            buf.put_slice(&slice[..to_read]);
            let new_offset = self.offset + to_read;
            if new_offset < bytes.len() {
                self.current_chunk = Some(bytes);
                self.offset = new_offset;
            } else {
                self.offset = 0;
            }
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

/// Multiplexed connection state running over an encrypted TLS/TCP stream.
pub struct TcpConnection {
    remote_addr: SocketAddr,
    outbound_tx: mpsc::UnboundedSender<TcpFrame>,
    incoming_streams_rx: Mutex<mpsc::Receiver<(TcpSendStream, TcpRecvStream)>>,
    datagram_rx: Mutex<mpsc::Receiver<Bytes>>,
    active_streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamChunk>>>>,
    next_stream_id: AtomicU32,
    rtt_ms: AtomicU64,
    closed: Arc<AtomicBool>,
    close_notify: Arc<Notify>,
}

impl TcpConnection {
    /// Creates a new `TcpConnection` managing the specified async read/write TLS transport.
    pub fn new<T>(stream: T, remote_addr: SocketAddr, is_client: bool) -> Arc<Self>
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<TcpFrame>();
        let (incoming_streams_tx, incoming_streams_rx) = mpsc::channel(64);
        let (datagram_tx, datagram_rx) = mpsc::channel(128);

        let active_streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamChunk>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let close_notify = Arc::new(Notify::new());

        // Client initiates streams starting at 0 (0, 2, 4...)
        // Server initiates streams starting at 1 (1, 3, 5...)
        let next_stream_id = AtomicU32::new(if is_client { 0 } else { 1 });

        let conn = Arc::new(Self {
            remote_addr,
            outbound_tx: outbound_tx.clone(),
            incoming_streams_rx: Mutex::new(incoming_streams_rx),
            datagram_rx: Mutex::new(datagram_rx),
            active_streams: Arc::clone(&active_streams),
            next_stream_id,
            rtt_ms: AtomicU64::new(1),
            closed: Arc::clone(&closed),
            close_notify: Arc::clone(&close_notify),
        });

        // Spawn write loop
        let closed_writer = Arc::clone(&closed);
        let close_notify_writer = Arc::clone(&close_notify);
        tokio::spawn(async move {
            let mut writer = write_half;
            let mut rx = outbound_rx;

            let mut header_buf = [0u8; HEADER_LEN];
            loop {
                let frame = tokio::select! {
                    biased;
                    f = rx.recv() => match f {
                        Some(frame) => frame,
                        None => break,
                    },
                    _ = close_notify_writer.notified() => {
                        while let Ok(f) = rx.try_recv() {
                            let header = TcpFrameHeader {
                                stream_id: f.stream_id,
                                flags: f.flags,
                                length: f.payload.len() as u32,
                            };
                            header.encode(&mut header_buf);
                            let _ = writer.write_all(&header_buf).await;
                            if !f.payload.is_empty() {
                                let _ = writer.write_all(&f.payload).await;
                            }
                        }
                        let _ = writer.flush().await;
                        break;
                    }
                };

                let header = TcpFrameHeader {
                    stream_id: frame.stream_id,
                    flags: frame.flags,
                    length: frame.payload.len() as u32,
                };
                header.encode(&mut header_buf);

                if let Err(e) = writer.write_all(&header_buf).await {
                    debug!(error = %e, "Failed to write TCP frame header");
                    break;
                }

                if !frame.payload.is_empty() {
                    if let Err(e) = writer.write_all(&frame.payload).await {
                        debug!(error = %e, "Failed to write TCP frame payload");
                        break;
                    }
                }

                if let Err(e) = writer.flush().await {
                    debug!(error = %e, "Failed to flush TCP frame");
                    break;
                }
            }

            let _ = writer.shutdown().await;
            closed_writer.store(true, Ordering::SeqCst);
            close_notify_writer.notify_waiters();
        });

        // Spawn read loop
        let active_streams_reader = Arc::clone(&active_streams);
        let outbound_tx_reader = outbound_tx.clone();
        let closed_reader = Arc::clone(&closed);
        let close_notify_reader = Arc::clone(&close_notify);
        let rtt_holder = Arc::clone(&conn);
        tokio::spawn(async move {
            let mut reader = read_half;
            let mut header_buf = [0u8; HEADER_LEN];

            loop {
                if let Err(_) = reader.read_exact(&mut header_buf).await {
                    break;
                }

                let header = TcpFrameHeader::decode(&header_buf);
                if header.length as usize > MAX_PAYLOAD_LEN {
                    warn!(
                        length = header.length,
                        "TCP frame exceeds maximum allowed size"
                    );
                    break;
                }

                let mut payload = vec![0u8; header.length as usize];
                if header.length > 0 {
                    if let Err(_) = reader.read_exact(&mut payload).await {
                        break;
                    }
                }
                let payload_bytes = Bytes::from(payload);

                if header.flags & FLAG_DATAGRAM != 0 {
                    let _ = datagram_tx.send(payload_bytes).await;
                    continue;
                }

                if header.flags & FLAG_PING != 0 {
                    let pong = TcpFrame {
                        stream_id: 0,
                        flags: FLAG_PONG,
                        payload: payload_bytes,
                    };
                    let _ = outbound_tx_reader.send(pong);
                    continue;
                }

                if header.flags & FLAG_PONG != 0 {
                    if payload_bytes.len() >= 8 {
                        let sent_ms =
                            u64::from_be_bytes(payload_bytes[..8].try_into().unwrap());
                        let now_ms = current_timestamp_ms();
                        if now_ms >= sent_ms {
                            let diff = (now_ms - sent_ms).max(1);
                            rtt_holder.rtt_ms.store(diff, Ordering::Relaxed);
                        }
                    }
                    continue;
                }

                // Handle stream data / FIN / RST
                let stream_id = header.stream_id;
                let mut map = active_streams_reader.lock().await;

                if let Some(tx) = map.get(&stream_id) {
                    if !payload_bytes.is_empty() {
                        let _ = tx.send(StreamChunk::Data(payload_bytes)).await;
                    }
                    if header.flags & FLAG_FIN != 0 {
                        let _ = tx.send(StreamChunk::Fin).await;
                        map.remove(&stream_id);
                    } else if header.flags & FLAG_RST != 0 {
                        let _ = tx.send(StreamChunk::Rst).await;
                        map.remove(&stream_id);
                    }
                } else {
                    // New stream initiated by peer
                    if header.flags & FLAG_FIN != 0 && payload_bytes.is_empty() {
                        continue;
                    }

                    let (chunk_tx, chunk_rx) = mpsc::channel(64);
                    let send_stream = TcpSendStream::new(
                        stream_id,
                        outbound_tx_reader.clone(),
                        Arc::clone(&closed_reader),
                    );
                    let recv_stream = TcpRecvStream::new(stream_id, chunk_rx);

                    if !payload_bytes.is_empty() {
                        let _ = chunk_tx.send(StreamChunk::Data(payload_bytes)).await;
                    }

                    if header.flags & FLAG_FIN != 0 {
                        let _ = chunk_tx.send(StreamChunk::Fin).await;
                    } else {
                        map.insert(stream_id, chunk_tx);
                    }

                    let _ = incoming_streams_tx.send((send_stream, recv_stream)).await;
                }
            }

            closed_reader.store(true, Ordering::SeqCst);
            close_notify_reader.notify_waiters();
            active_streams_reader.lock().await.clear();
        });

        conn
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn rtt(&self) -> Duration {
        Duration::from_millis(self.rtt_ms.load(Ordering::Relaxed))
    }

    /// Opens a new bidirectional stream with the peer over TCP.
    pub async fn open_bi(&self) -> CoreResult<(TcpSendStream, TcpRecvStream)> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(CoreError::Io(std::io::Error::new(
                ErrorKind::ConnectionReset,
                "TCP connection closed",
            )));
        }

        let stream_id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let (chunk_tx, chunk_rx) = mpsc::channel(64);
        self.active_streams.lock().await.insert(stream_id, chunk_tx);

        let send = TcpSendStream::new(
            stream_id,
            self.outbound_tx.clone(),
            Arc::clone(&self.closed),
        );
        let recv = TcpRecvStream::new(stream_id, chunk_rx);
        Ok((send, recv))
    }

    /// Accepts an incoming bidirectional stream initiated by the peer over TCP.
    pub async fn accept_bi(&self) -> CoreResult<(TcpSendStream, TcpRecvStream)> {
        let mut rx = self.incoming_streams_rx.lock().await;
        match rx.recv().await {
            Some(streams) => Ok(streams),
            None => Err(CoreError::Io(std::io::Error::new(
                ErrorKind::ConnectionReset,
                "TCP connection closed",
            ))),
        }
    }

    /// Sends an encapsulated datagram frame over TCP.
    pub fn send_datagram(&self, data: Bytes) -> CoreResult<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(CoreError::Io(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "TCP connection closed",
            )));
        }

        let frame = TcpFrame {
            stream_id: 0,
            flags: FLAG_DATAGRAM,
            payload: data,
        };
        self.outbound_tx.send(frame).map_err(|e| {
            CoreError::Io(std::io::Error::new(ErrorKind::BrokenPipe, e.to_string()))
        })
    }

    /// Receives an encapsulated datagram frame from TCP.
    pub async fn read_datagram(&self) -> CoreResult<Bytes> {
        let mut rx = self.datagram_rx.lock().await;
        match rx.recv().await {
            Some(data) => Ok(data),
            None => Err(CoreError::Io(std::io::Error::new(
                ErrorKind::BrokenPipe,
                "TCP connection closed",
            ))),
        }
    }

    /// Measures RTT by sending a PING frame and recording time.
    pub fn send_ping(&self) -> CoreResult<()> {
        let ts = current_timestamp_ms().to_be_bytes();
        let frame = TcpFrame {
            stream_id: 0,
            flags: FLAG_PING,
            payload: Bytes::copy_from_slice(&ts),
        };
        self.outbound_tx
            .send(frame)
            .map_err(|e| CoreError::Io(std::io::Error::new(ErrorKind::BrokenPipe, e.to_string())))
    }

    /// Closes the multiplexed connection.
    pub fn close(&self, code: u32, reason: &str) {
        debug!(code, reason, remote = %self.remote_addr, "Closing morsh TCP connection");
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.close_notify.notify_waiters();
        }
    }

    /// Awaits connection teardown.
    pub async fn closed(&self) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        self.close_notify.notified().await;
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_encoding_roundtrip() {
        let original = TcpFrameHeader {
            stream_id: 42,
            flags: FLAG_FIN | FLAG_DATAGRAM,
            length: 12345,
        };
        let mut buf = [0u8; HEADER_LEN];
        original.encode(&mut buf);

        let decoded = TcpFrameHeader::decode(&buf);
        assert_eq!(original, decoded);
    }
}
