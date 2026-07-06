use crate::{config, tcp, websocket, ResultType};
#[cfg(feature = "webrtc")]
use crate::webrtc;
use sodiumoxide::crypto::secretbox::Key;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// A stream type that can be backed by an Iroh QUIC connection.
///
/// This is a trait object wrapper that allows the Iroh transport to plug
/// into the existing Stream interface without adding an iroh dependency
/// to hbb_common itself. The concrete implementation lives in the main
/// rustdesk crate.
pub trait IrohStreamTrait: Send + Sync {
    fn set_send_timeout(&mut self, ms: u64);
    fn set_raw(&mut self);
    fn set_key(&mut self, key: Key);
    fn is_secured(&self) -> bool;
    fn local_addr(&self) -> SocketAddr;
    fn box_send(&mut self, msg_bytes: bytes::Bytes) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + Send + '_>>;
    fn box_send_bytes(&mut self, bytes: bytes::Bytes) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + Send + '_>>;
    fn box_send_raw(&mut self, bytes: Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + Send + '_>>;
    fn box_next(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Result<bytes::BytesMut, std::io::Error>>> + Send + '_>>;
    fn box_next_timeout(&mut self, timeout_ms: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Result<bytes::BytesMut, std::io::Error>>> + Send + '_>>;
}

pub struct IrohFramedStream(pub Box<dyn IrohStreamTrait>);

impl IrohFramedStream {
    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        self.0.set_send_timeout(ms);
    }

    #[inline]
    pub fn set_raw(&mut self) {
        self.0.set_raw();
    }

    #[inline]
    pub fn set_key(&mut self, key: Key) {
        self.0.set_key(key);
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        self.0.is_secured()
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.0.local_addr()
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl protobuf::Message) -> ResultType<()> {
        let bytes = bytes::Bytes::from(msg.write_to_bytes()?);
        self.0.box_send(bytes).await
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: bytes::Bytes) -> ResultType<()> {
        self.0.box_send_bytes(bytes).await
    }

    #[inline]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        self.0.box_send_raw(bytes).await
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        self.0.box_next().await
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        self.0.box_next_timeout(ms).await
    }
}

// support Websocket, tcp, and Iroh.
pub enum Stream {
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::WebRTCStream),
    WebSocket(websocket::WsFramedStream),
    Tcp(tcp::FramedStream),
    Iroh(IrohFramedStream),
}

impl Stream {
    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_send_timeout(ms),
            Stream::WebSocket(s) => s.set_send_timeout(ms),
            Stream::Tcp(s) => s.set_send_timeout(ms),
            Stream::Iroh(s) => s.set_send_timeout(ms),
        }
    }

    #[inline]
    pub fn set_raw(&mut self) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_raw(),
            Stream::WebSocket(s) => s.set_raw(),
            Stream::Tcp(s) => s.set_raw(),
            Stream::Iroh(s) => s.set_raw(),
        }
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: bytes::Bytes) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_bytes(bytes).await,
            Stream::WebSocket(s) => s.send_bytes(bytes).await,
            Stream::Tcp(s) => s.send_bytes(bytes).await,
            Stream::Iroh(s) => s.send_bytes(bytes).await,
        }
    }

    #[inline]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_raw(bytes).await,
            Stream::WebSocket(s) => s.send_raw(bytes).await,
            Stream::Tcp(s) => s.send_raw(bytes).await,
            Stream::Iroh(s) => s.send_raw(bytes).await,
        }
    }

    #[inline]
    pub fn set_key(&mut self, key: Key) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_key(key),
            Stream::WebSocket(s) => s.set_key(key),
            Stream::Tcp(s) => s.set_key(key),
            Stream::Iroh(s) => s.set_key(key),
        }
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.is_secured(),
            Stream::WebSocket(s) => s.is_secured(),
            Stream::Tcp(s) => s.is_secured(),
            // Iroh QUIC connections are always encrypted (TLS 1.3)
            Stream::Iroh(s) => s.is_secured(),
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        timeout: u64,
    ) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.next_timeout(timeout).await,
            Stream::WebSocket(s) => s.next_timeout(timeout).await,
            Stream::Tcp(s) => s.next_timeout(timeout).await,
            Stream::Iroh(s) => s.next_timeout(timeout).await,
        }
    }

    /// establish connect from websocket
    #[inline]
    pub async fn connect_websocket(
        url: impl AsRef<str>,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&config::Socks5Server>,
        timeout_ms: u64,
    ) -> ResultType<Self> {
        let ws_stream =
            websocket::WsFramedStream::new(url, local_addr, proxy_conf, timeout_ms).await?;
        log::debug!("WebSocket connection established");
        Ok(Self::WebSocket(ws_stream))
    }

    /// send message
    #[inline]
    pub async fn send(&mut self, msg: &impl protobuf::Message) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.send(msg).await,
            Self::WebSocket(ws) => ws.send(msg).await,
            Self::Tcp(tcp) => tcp.send(msg).await,
            Self::Iroh(s) => s.send(msg).await,
        }
    }

    /// receive message
    #[inline]
    pub async fn next(&mut self) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.next().await,
            Self::WebSocket(ws) => ws.next().await,
            Self::Tcp(tcp) => tcp.next().await,
            Self::Iroh(s) => s.next().await,
        }
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.local_addr(),
            Self::WebSocket(ws) => ws.local_addr(),
            Self::Tcp(tcp) => tcp.local_addr(),
            // Iroh doesn't have a traditional socket address; return unspecified
            Self::Iroh(s) => s.local_addr(),
        }
    }

    #[inline]
    pub fn from(stream: TcpStream, stream_addr: SocketAddr) -> Self {
        Self::Tcp(tcp::FramedStream::from(stream, stream_addr))
    }

    /// Create a Stream from an Iroh QUIC connection.
    ///
    /// The `peer_id` is the z-base-32 encoded public key of the remote peer.
    #[inline]
    pub fn from_iroh(stream: impl IrohStreamTrait + 'static, peer_id: String) -> Self {
        log::debug!("Iroh Stream created for peer: {}", peer_id);
        Self::Iroh(IrohFramedStream(Box::new(stream)))
    }

    #[inline]
    #[cfg(feature = "webrtc")]
    pub fn get_webrtc_stream(&self) -> Option<webrtc::WebRTCStream> {
        match self {
            Self::WebRTC(s) => Some(s.clone()),
            _ => None,
        }
    }
}
