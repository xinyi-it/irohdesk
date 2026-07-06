//! Iroh P2P transport for RustDesk.
//!
//! This module provides a decentralized connection alternative to the traditional
//! hbbs rendezvous server. Instead of registering an ID with a central server,
//! each endpoint uses its existing ed25519 key pair as its identity. The public
//! key (hex-encoded) serves as the connection address.
//!
//! Connection flow:
//! 1. Caller dials the remote endpoint by its public key (NodeId)
//! 2. Iroh resolves the address via DNS/DHT (Pkarr) and relay discovery
//! 3. Iroh establishes a QUIC connection (direct or via relay fallback)
//! 4. QUIC bidirectional streams carry RustDesk protocol messages
//!
//! This runs alongside the existing hbbs mechanism — if the input ID looks like
//! a hex-encoded public key (64 chars), the Iroh path is used. Otherwise,
//! the traditional hbbs path is used unchanged.

use std::sync::Arc;

use hbb_common::{
    anyhow::{self, bail},
    bytes::{Bytes, BytesMut},
    log,
    sodiumoxide,
    tokio,
    tokio::sync::Mutex,
    ResultType,
};

use crate::server::{ConnectionMeta, ServerPtr};
use iroh::{Endpoint, NodeId, SecretKey, PublicKey};
use iroh::endpoint::Connection;

/// ALPN protocol identifier for RustDesk over Iroh.
pub const ALPN: &[u8] = b"rustdesk/iroh/1";

/// Check if a string looks like an Iroh NodeId (hex-encoded, 64 chars).
///
/// In iroh 0.35+, PublicKey/NodeId Display uses HEXLOWER encoding.
/// 32 bytes → 64 hex characters.
pub fn is_iroh_node_id(s: &str) -> bool {
    if s.len() != 64 {
        return false;
    }
    s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Convert RustDesk's sodiumoxide key pair to an Iroh SecretKey.
///
/// RustDesk stores keys as raw bytes: `(sk_bytes[64], pk_bytes[32])`.
/// Iroh's SecretKey is ed25519 with a 32-byte secret scalar.
/// The sodiumoxide secret key is 64 bytes = 32-byte secret + 32-byte public.
/// We take the first 32 bytes (the secret scalar) for Iroh.
pub fn rustdesk_keypair_to_iroh_secret(
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> anyhow::Result<iroh::SecretKey> {
    if sk_bytes.len() < 32 || pk_bytes.len() < 32 {
        bail!("RustDesk key pair too short for Iroh conversion");
    }
    // sodiumoxide sign secret key is 64 bytes: first 32 = seed/scalar, last 32 = public key
    // Iroh SecretKey::from_bytes takes 32 bytes (the seed) and returns directly (not Option)
    let seed: [u8; 32] = sk_bytes[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to extract 32-byte seed from secret key"))?;
    let secret = SecretKey::from_bytes(&seed);

    // Verify the derived public key matches
    let derived_pk = secret.public();
    let expected_pk: [u8; 32] = pk_bytes[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to extract public key bytes"))?;
    if derived_pk.as_bytes() != &expected_pk {
        bail!(
            "Iroh derived public key does not match RustDesk public key. \
             This means the key formats are incompatible."
        );
    }

    Ok(secret)
}

/// Get the Iroh NodeId (hex-encoded public key) from RustDesk's key pair.
pub fn get_iroh_node_id() -> ResultType<String> {
    let (_, pk_bytes) = hbb_common::config::Config::get_key_pair();
    if pk_bytes.len() < 32 {
        bail!("RustDesk public key too short");
    }
    let pk: [u8; 32] = pk_bytes[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to extract public key"))?;
    let public = PublicKey::from_bytes(&pk)
        .map_err(|_| anyhow::anyhow!("failed to create Iroh PublicKey from bytes"))?;
    Ok(public.to_string())
}

/// Global Iroh endpoint (lazily initialized).
static IROH_ENDPOINT: Mutex<Option<Arc<IrohEndpoint>>> = Mutex::const_new(None);

/// Wrapper around an Iroh Endpoint for RustDesk.
pub struct IrohEndpoint {
    pub endpoint: Endpoint,
    pub node_id: String,
}

impl IrohEndpoint {
    /// Create a new Iroh endpoint using RustDesk's existing key pair.
    pub async fn new() -> ResultType<Arc<Self>> {
        let (sk_bytes, pk_bytes) = hbb_common::config::Config::get_key_pair();
        let secret = rustdesk_keypair_to_iroh_secret(&sk_bytes, &pk_bytes)?;

        let endpoint = Endpoint::builder()
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .discovery_n0()
            .bind()
            .await
            .map_err(|e| anyhow::anyhow!("failed to bind Iroh endpoint: {}", e))?;

        let node_id = endpoint.node_id().to_string();
        log::info!("Iroh endpoint started, NodeId: {}", node_id);

        Ok(Arc::new(Self { endpoint, node_id }))
    }

    /// Get the hex-encoded NodeId string for sharing as connection address.
    pub fn node_id_str(&self) -> &str {
        &self.node_id
    }
}

/// Get or create the global Iroh endpoint.
pub async fn get_or_create_endpoint() -> ResultType<Arc<IrohEndpoint>> {
    let mut guard = IROH_ENDPOINT.lock().await;
    if let Some(ep) = guard.as_ref() {
        return Ok(ep.clone());
    }
    let ep = IrohEndpoint::new().await?;
    *guard = Some(ep.clone());
    Ok(ep)
}

/// Connect to a remote RustDesk peer via Iroh using their public key (NodeId).
///
/// Returns a QUIC connection that can be used to open bidirectional streams.
pub async fn connect(peer_node_id: &str) -> ResultType<Connection> {
    let ep = get_or_create_endpoint().await?;

    // Parse the hex-encoded NodeId into a PublicKey/NodeId
    let node_id: NodeId = peer_node_id
        .parse()
        .map_err(|e| anyhow::anyhow!("failed to parse Iroh NodeId '{}': {}", peer_node_id, e))?;

    log::info!("Connecting via Iroh to NodeId: {}", peer_node_id);

    // Connect — Iroh will resolve the address via DNS/DHT and relay discovery,
    // then establish a direct QUIC connection or fall back to relay.
    let conn = ep
        .endpoint
        .connect(node_id, ALPN)
        .await
        .map_err(|e| anyhow::anyhow!("Iroh connection failed: {}", e))?;

    log::info!("Iroh connection established to {}", peer_node_id);
    Ok(conn)
}

/// Accept an incoming Iroh connection (for the server/controlled side).
///
/// This should be spawned as a background task alongside the existing
/// rendezvous mediator. It listens for incoming QUIC connections on the
/// Iroh endpoint and hands them off to the RustDesk connection handler.
pub async fn start_accept_loop(server: ServerPtr) -> ResultType<()> {
    let ep = get_or_create_endpoint().await?;
    let endpoint = ep.endpoint.clone();

    log::info!("Iroh accept loop started, waiting for connections...");

    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                log::info!("Iroh incoming connection");

                // In iroh 0.35, Incoming implements IntoFuture → Result<Connection, ConnectionError>
                match incoming.await {
                    Ok(conn) => {
                        let remote_node_id = conn
                            .remote_node_id()
                            .map(|id| id.to_string())
                            .unwrap_or_else(|_| "unknown".to_string());
                        log::info!(
                            "Iroh connection accepted from NodeId: {}",
                            remote_node_id
                        );

                        let server = server.clone();
                        // Spawn a task to handle this connection
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_iroh_connection(server, conn, remote_node_id).await
                            {
                                log::error!("Iroh connection handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::warn!("Iroh incoming connection error: {}", e);
                    }
                }
            }
            None => {
                log::info!("Iroh endpoint closed, accept loop exiting");
                break;
            }
        }
    }

    Ok(())
}

/// Handle an incoming Iroh connection by bridging it to RustDesk's server.
///
/// Accepts a bidirectional QUIC stream, wraps it as a RustDesk Stream,
/// then feeds it into the existing create_tcp_connection logic.
async fn handle_iroh_connection(
    server: ServerPtr,
    conn: Connection,
    remote_node_id: String,
) -> ResultType<()> {
    // Accept the bidirectional QUIC stream opened by the client
    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .map_err(|e| anyhow::anyhow!("failed to accept QUIC bi-stream: {}", e))?;

    log::info!(
        "Accepted QUIC bi-stream from {}, starting RustDesk protocol",
        remote_node_id
    );

    // Wrap the QUIC bi-stream in our IrohStream adapter
    let iroh_stream = IrohStream::from_bi(send_stream, recv_stream, conn, remote_node_id.clone());
    let stream = hbb_common::Stream::from_iroh(iroh_stream, remote_node_id.clone());

    // Use a dummy SocketAddr — Iroh P2P connections don't have a traditional IP.
    // 127.0.0.1:0 signals "local/P2P" to the whitelist check.
    let dummy_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let meta = ConnectionMeta {
        control_permissions: None,
        controlled_context: None,
    };

    // Feed into RustDesk's existing connection handler — this runs the
    // full protocol: key exchange, authentication, video/audio/input.
    crate::server::create_tcp_connection(server, stream, dummy_addr, true, meta)
        .await
        .map_err(|e| anyhow::anyhow!("create_tcp_connection failed: {}", e))?;

    log::info!("Iroh connection from {} closed", remote_node_id);
    Ok(())
}

/// Concrete Iroh QUIC stream wrapper implementing the IrohStreamTrait.
///
/// This bridges Iroh's QUIC bidirectional streams to RustDesk's Stream interface.
/// RustDesk uses a length-prefixed message framing codec (BytesCodec) on top
/// of the raw stream — we replicate that framing here.
pub struct IrohStream {
    conn: Connection,
    send: Option<iroh::endpoint::SendStream>,
    recv: Option<iroh::endpoint::RecvStream>,
    remote_node_id: String,
    // Encryption state (compatible with RustDesk's symmetric encryption)
    key: Option<sodiumoxide::crypto::secretbox::Key>,
    send_nonce: u64,
    recv_nonce: u64,
}

impl IrohStream {
    /// Create a new IrohStream from a QUIC connection.
    ///
    /// Opens a bidirectional stream for the initial protocol exchange.
    pub fn new(conn: Connection, remote_node_id: String) -> ResultType<Self> {
        // We don't open_bi here — the caller (client) opens it, or the
        // server accepts it. This constructor stores the connection for
        // later stream operations.
        Ok(Self {
            conn,
            send: None,
            recv: None,
            remote_node_id,
            key: None,
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    /// Create from an already-opened bi-stream (client side).
    pub fn from_bi(
        send: iroh::endpoint::SendStream,
        recv: iroh::endpoint::RecvStream,
        conn: Connection,
        remote_node_id: String,
    ) -> Self {
        Self {
            conn,
            send: Some(send),
            recv: Some(recv),
            remote_node_id,
            key: None,
            send_nonce: 0,
            recv_nonce: 0,
        }
    }
}

/// Length-prefix framing: 4 bytes big-endian length + payload
/// This matches RustDesk's BytesCodec framing.
fn encode_frame(data: &[u8]) -> bytes::Bytes {
    use bytes::{BufMut, BytesMut};
    let mut buf = BytesMut::with_capacity(4 + data.len());
    buf.put_u32(data.len() as u32);
    buf.extend_from_slice(data);
    buf.freeze()
}

/// Read a length-prefixed frame from a QUIC receive stream.
async fn read_frame(recv: &mut iroh::endpoint::RecvStream) -> std::io::Result<bytes::BytesMut> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {}", len),
        ));
    }
    let mut data = vec![0u8; len];
    recv.read_exact(&mut data)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;
    Ok(bytes::BytesMut::from(&data[..]))
}

impl hbb_common::stream::IrohStreamTrait for IrohStream {
    fn set_send_timeout(&mut self, _ms: u64) {
        // QUIC has its own timeout management; no-op for now
    }

    fn set_raw(&mut self) {
        // No-op — QUIC streams are always framed
    }

    fn set_key(&mut self, key: sodiumoxide::crypto::secretbox::Key) {
        self.key = Some(key);
    }

    fn is_secured(&self) -> bool {
        // QUIC connections are always encrypted with TLS 1.3
        true
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        // Iroh's local_addr returns LocalTransportAddr, not SocketAddr.
        // We return an unspecified address since QUIC connections don't
        // have a single traditional socket address (they may use direct
        // IP, relay, or a mix).
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    }

    fn box_send(
        &mut self,
        msg_bytes: bytes::Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + Send + '_>> {
        Box::pin(async move {
            self.box_send_bytes(msg_bytes).await
        })
    }

    fn box_send_bytes(
        &mut self,
        bytes: bytes::Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + Send + '_>> {
        Box::pin(async move {
            let send = self
                .send
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("no send stream available"))?;
            let framed = encode_frame(&bytes);
            send.write_all(&framed)
                .await
                .map_err(|e| anyhow::anyhow!("QUIC write error: {}", e))?;
            Ok(())
        })
    }

    fn box_send_raw(
        &mut self,
        bytes: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResultType<()>> + Send + '_>> {
        Box::pin(async move {
            let send = self
                .send
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("no send stream available"))?;
            let framed = encode_frame(&bytes);
            send.write_all(&framed)
                .await
                .map_err(|e| anyhow::anyhow!("QUIC write error: {}", e))?;
            Ok(())
        })
    }

    fn box_next(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<Result<bytes::BytesMut, std::io::Error>>> + Send + '_>,
    > {
        Box::pin(async move {
            let recv = match self.recv.as_mut() {
                Some(r) => r,
                None => return Some(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "no receive stream available",
                ))),
            };
            match read_frame(recv).await {
                Ok(data) => Some(Ok(data)),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        None
                    } else {
                        Some(Err(e))
                    }
                }
            }
        })
    }

    fn box_next_timeout(
        &mut self,
        timeout_ms: u64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<Result<bytes::BytesMut, std::io::Error>>> + Send + '_>,
    > {
        Box::pin(async move {
            let recv = match self.recv.as_mut() {
                Some(r) => r,
                None => return Some(Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "no receive stream available",
                ))),
            };
            match hbb_common::timeout(timeout_ms, read_frame(recv)).await {
                Ok(result) => match result {
                    Ok(data) => Some(Ok(data)),
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            None
                        } else {
                            Some(Err(e))
                        }
                    }
                },
                Err(_) => Some(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout",
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_iroh_node_id() {
        // Valid hex, 64 chars
        assert!(is_iroh_node_id("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        // Too short
        assert!(!is_iroh_node_id("short"));
        // Too long
        assert!(!is_iroh_node_id("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00"));
        // Invalid chars (z-base-32 characters, not hex)
        assert!(!is_iroh_node_id("ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1uwisza345h769"));
    }

    #[test]
    fn test_node_id_roundtrip() {
        // Generate a test key pair
        let (pk, sk) = hbb_common::sodiumoxide::crypto::sign::gen_keypair();
        let secret =
            rustdesk_keypair_to_iroh_secret(&sk.0, &pk.0).expect("conversion");
        let node_id = secret.public().to_string();
        assert_eq!(node_id.len(), 64);

        // Should parse back
        let parsed: iroh::NodeId = node_id.parse().expect("parse");
        assert_eq!(parsed.as_bytes(), secret.public().as_bytes());
    }
}

// ─── Client-side P2P connection with RustDesk handshake ─────────────────────

/// Connect to a remote peer via Iroh P2P and perform the full RustDesk
/// handshake + password authentication.
///
/// This is a standalone CLI entry point that does NOT require the Sciter GUI
/// or the Interface trait. It:
///   1. Connects via Iroh using just the peer's public key (NodeId)
///   2. Opens a QUIC bi-stream
///   3. Performs RustDesk's key exchange (SignedId / PublicKey)
///   4. Sends a LoginRequest with the provided password
///   5. Reads messages from the server (video frames, etc.)
pub async fn iroh_connect_and_handshake(
    peer_node_id: &str,
    password: &str,
) -> ResultType<()> {
    use hbb_common::{
        config::Config,
        sodiumoxide::crypto::sign,
        protobuf::Message as _,
    };

    log::info!("Connecting to peer via Iroh P2P: {}", peer_node_id);

    // 1. Connect via Iroh
    let conn = connect(peer_node_id).await?;
    log::info!("Iroh connection established");

    // 2. Open bi-stream
    let (mut send_stream, mut recv_stream) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("failed to open QUIC bi-stream: {}", e))?;

    // Get remote NodeId for verification
    let remote_node_id = conn
        .remote_node_id()
        .map(|id| id.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    log::info!("Remote NodeId: {}", remote_node_id);

    // Wrap as RustDesk Stream
    let iroh_stream = IrohStream::from_bi(
        send_stream,
        recv_stream,
        conn,
        peer_node_id.to_owned(),
    );
    let mut stream = hbb_common::Stream::from_iroh(iroh_stream, peer_node_id.to_owned());

    // 3. RustDesk key exchange handshake
    let (sk, pk) = Config::get_key_pair();
    if pk.len() == sign::PUBLICKEYBYTES && sk.len() == sign::SECRETKEYBYTES {
        let mut sk_ = [0u8; sign::SECRETKEYBYTES];
        sk_[..].copy_from_slice(&sk);
        let sign_sk = sign::SecretKey(sk_);

        // Receive server's SignedId
        log::info!("Waiting for server's SignedId...");
        let msg_bytes = hbb_common::timeout(15_000, stream.next())
            .await
            .map_err(|_| anyhow::anyhow!("timeout waiting for SignedId"))?
            .ok_or_else(|| anyhow::anyhow!("connection closed before SignedId"))?
            .map_err(|e| anyhow::anyhow!("read error: {}", e))?;

        let msg_in = hbb_common::protos::message::Message::parse_from_bytes(&msg_bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse SignedId message: {}", e))?;

        if let Some(hbb_common::message_proto::message::Union::SignedId(si)) = msg_in.union {
            // Verify signature and extract server's box_ public key
            let sign_pk = sign::PublicKey(
                pk[..sign::PUBLICKEYBYTES].try_into().unwrap_or([0u8; 32])
            );
            if let Ok((server_id, their_pk_b)) =
                crate::common::decode_id_pk(&si.id, &sign_pk)
            {
                log::info!("Server ID: {}, verified", server_id);

                // Generate our box_ keypair and create symmetric key
                let (asymmetric_value, symmetric_value, key) =
                    crate::common::create_symmetric_key_msg(their_pk_b);

                // Send our PublicKey to server
                let mut msg_out = hbb_common::protos::message::Message::new();
                msg_out.set_public_key(hbb_common::protos::message::PublicKey {
                    asymmetric_value: asymmetric_value,
                    symmetric_value: symmetric_value,
                    ..Default::default()
                });
                hbb_common::timeout(10_000, stream.send(&msg_out))
                    .await??;
                stream.set_key(key);
                log::info!("Encrypted channel established");
            } else {
                log::warn!("Failed to verify server identity, proceeding unencrypted");
                let mut msg_out = hbb_common::protos::message::Message::new();
                msg_out.set_public_key(hbb_common::protos::message::PublicKey::new());
                stream.send(&msg_out).await?;
            }
        } else {
            log::warn!("Expected SignedId, got something else. Proceeding unencrypted.");
            let mut msg_out = hbb_common::protos::message::Message::new();
            msg_out.set_public_key(hbb_common::protos::message::PublicKey::new());
            stream.send(&msg_out).await?;
        }
    } else {
        log::warn!("No valid key pair, sending empty handshake");
        let mut msg_out = hbb_common::protos::message::Message::new();
        msg_out.set_public_key(hbb_common::protos::message::PublicKey::new());
        stream.send(&msg_out).await?;
    }

    // 4. Send LoginRequest with password
    let my_id = Config::get_id();
    let my_name = crate::username();
    let my_platform = hbb_common::whoami::platform().to_string();

    let mut lr = hbb_common::protos::message::LoginRequest::new();
    lr.username = peer_node_id.to_owned(); // Use peer's NodeId as the "ID" for login
    lr.password = password.as_bytes().to_vec().into();
    lr.my_id = my_id;
    lr.my_name = my_name;
    lr.my_platform = my_platform;
    lr.version = crate::VERSION.to_string();

    let mut msg_out = hbb_common::protos::message::Message::new();
    msg_out.set_login_request(lr);
    log::info!("Sending login request with password...");
    hbb_common::timeout(10_000, stream.send(&msg_out))
        .await??;

    // 5. Read server responses
    log::info!("Waiting for server response...");
    loop {
        match hbb_common::timeout(30_000, stream.next()).await {
            Ok(Some(Ok(bytes))) => {
                if let Ok(msg) = hbb_common::protos::message::Message::parse_from_bytes(&bytes) {
                    match msg.union {
                        Some(hbb_common::message_proto::message::Union::LoginResponse(lr)) => {
                            if lr.error().is_empty() {
                                log::info!("Login successful! Connected to desktop.");
                                log::info!("  Platform: {}", lr.peer_info().platform);
                            } else {
                                log::error!("Login failed: {}", lr.error());
                                return Err(anyhow::anyhow!("Login failed: {}", lr.error()));
                            }
                        }
                        Some(hbb_common::message_proto::message::Union::VideoFrame(_)) => {
                            log::info!("Received video frame (desktop streaming active)");
                        }
                        Some(hbb_common::message_proto::message::Union::CursorData(_)) => {
                            // Cursor data — silently handle
                        }
                        Some(hbb_common::message_proto::message::Union::Cliprdr(_)) => {
                            // Clipboard data
                        }
                        Some(hbb_common::message_proto::message::Union::AudioFrame(_)) => {
                            log::info!("Received audio frame");
                        }
                        Some(other) => {
                            log::debug!("Received message: {:?}", std::mem::discriminant(&other));
                        }
                        None => {
                            log::debug!("Received empty message");
                        }
                    }
                }
            }
            Ok(Some(Err(e))) => {
                log::error!("Stream read error: {}", e);
                break;
            }
            Ok(None) => {
                log::info!("Connection closed by server");
                break;
            }
            Err(_) => {
                log::info!("Read timeout (30s no data), connection may be idle");
                break;
            }
        }
    }

    Ok(())
}
