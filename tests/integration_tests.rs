use anyhow::{anyhow, Result};
use boring::pkey::{PKey, Private};
use boring::x509::X509;
use boring_sys as bffi;
use core::fmt::{Debug, Formatter};
use once_cell::sync::Lazy;
use quinn::{Connecting, Connection, RecvStream, SendStream, WriteError, ZeroRttAccepted};
use quinn_boring::{ClientConfig, QuicSslContext, ServerConfig};
use quinn_proto::{ConnectError, ConnectionError, TransportErrorCode};
use rcgen::{BasicConstraints, CertificateParams, IsCa};
use std::io::Write;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const SERVER_NAME: &str = "server.com";
const NO_APPLICATION_PROTOCOL: u8 = bffi::SSL_AD_NO_APPLICATION_PROTOCOL as u8;
const UNKNOWN_CA: u8 = bffi::SSL_AD_UNKNOWN_CA as u8;
const PING_MSG: &[u8; 4] = b"ping";
const PONG_MSG: &[u8; 4] = b"pong";

#[tokio::test]
async fn simple() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the client.
    let client = server.connect_1rtt(client_config(client_crypto())).await?;
    client.send_ping().await?;
    client.receive_pong().await?;
    assert_eq!(SERVER_NAME, server.conn_info().server_name().as_str());
    assert_eq!(b"h3", client.conn_info().alpn_protocol().as_slice());
    assert_eq!(b"h3", server.conn_info().alpn_protocol().as_slice());
    Ok(())
}

#[tokio::test]
async fn alpn_success() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let mut server_crypto = server_crypto();
    server_crypto.set_alpn(&["foo".into(), "bar".into()])?;
    let server = Server::run(server_config(server_crypto)?)?;

    // Create the client.
    let mut client_crypto = client_crypto();
    client_crypto.set_alpn(&["bar".into()])?;
    let client = server.connect_1rtt(client_config(client_crypto)).await?;
    client.send_ping().await?;
    client.receive_pong().await?;
    assert_eq!(SERVER_NAME, server.conn_info().server_name().as_str());
    assert_eq!(b"bar", client.conn_info().alpn_protocol().as_slice());
    assert_eq!(b"bar", server.conn_info().alpn_protocol().as_slice());
    Ok(())
}

#[tokio::test]
async fn alpn_failure() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let mut server_crypto = server_crypto();
    server_crypto.set_alpn(&["foo".into()])?;
    let server = Server::run(server_config(server_crypto)?)?;

    // Create the client.
    let mut client_crypto = client_crypto();
    client_crypto.set_alpn(&["bar".into()])?;

    // Expect the connection to fail.
    let err = server
        .connect_1rtt(client_config(client_crypto))
        .await
        .expect_err("expected connection failure");
    match err {
        ConnectionError::ConnectionClosed(e) => {
            assert_eq!(
                TransportErrorCode::crypto(NO_APPLICATION_PROTOCOL),
                e.error_code
            );
            Ok(())
        }
        _ => Err(anyhow!("unexpected error: {err}")),
    }
}

#[tokio::test]
async fn draft_version_compat() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the client.
    let mut client_config = client_config(client_crypto());
    client_config.version(0xff00_0020);

    let client = server.connect_1rtt(client_config).await?;
    client.send_ping().await?;
    client.receive_pong().await?;
    assert_eq!(SERVER_NAME, server.conn_info().server_name().as_str());
    assert_eq!(b"h3", client.conn_info().alpn_protocol().as_slice());
    assert_eq!(b"h3", server.conn_info().alpn_protocol().as_slice());
    Ok(())
}

#[tokio::test]
async fn stateless_retry() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server_config = server_config(server_crypto())?;
    let server = Server::run_with_retry(server_config, true)?;

    // Connect the client.
    let client_config = client_config(client_crypto());
    let client = server.connect_1rtt(client_config).await?;
    client.send_ping().await?;
    client.receive_pong().await?;
    Ok(())
}

#[tokio::test]
async fn export_keyring_material() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the client.
    let client = server.connect_1rtt(client_config(client_crypto())).await?;
    client.send_ping().await?;
    client.receive_pong().await?;
    assert_eq!(
        &client.conn_info().keyring_material,
        &server.conn_info().keyring_material
    );
    Ok(())
}

#[tokio::test]
async fn untrusted_server() -> Result<()> {
    let _guard = subscribe();

    // Run the server with an unknown CA.
    let mut server_crypto = ServerConfig::new().unwrap();
    let ctx = server_crypto.ctx_mut();
    UNTRUSTED_SERVER_CERT.set_cert_for(ctx);
    CLIENT_CERT.set_trusted_by(ctx);
    let server = Server::run(server_config(server_crypto)?)?;

    // Create the client with no server certs configured.
    let err = server
        .connect_1rtt(client_config(client_crypto()))
        .await
        .expect_err("expected connection failure");
    match err {
        ConnectionError::TransportError(e) => {
            assert_eq!(TransportErrorCode::crypto(UNKNOWN_CA), e.code);
            Ok(())
        }
        _ => Err(anyhow!("unexpected error: {err}")),
    }
}

#[tokio::test]
async fn untrusted_client() -> Result<()> {
    let _guard = subscribe();

    // Run the server with client auth enabled.
    let mut server_crypto = server_crypto();
    server_crypto.verify_peer(true);
    let server = Server::run(server_config(server_crypto)?)?;

    // Create the client with an unknown CA.
    let mut client_crypto = ClientConfig::new().unwrap();
    let ctx = client_crypto.ctx_mut();
    UNTRUSTED_CLIENT_CERT.set_cert_for(ctx);
    SERVER_CERT.set_trusted_by(ctx);
    let client = server.connect_1rtt(client_config(client_crypto)).await?;
    let err = client
        .send_ping()
        .await
        .expect_err("expected connection failure");
    match err {
        WriteError::ConnectionLost(ConnectionError::ConnectionClosed(e)) => {
            assert_eq!(TransportErrorCode::crypto(UNKNOWN_CA), e.error_code);
            Ok(())
        }
        _ => Err(anyhow!("unexpected error: {err}")),
    }
}

#[tokio::test]
async fn zero_rtt_success() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the first connection (1-RTT).
    info!("sending 1-RTT");
    let cc1 = client_crypto();
    let session_cache = cc1.get_session_cache();
    let client1 = server.connect_1rtt(client_config(cc1)).await?;
    client1.send_ping().await?;
    client1.receive_pong().await?;

    // Create the second connection with the shared session cache (0-RTT).
    info!("sending 0-RTT");
    let mut cc2 = client_crypto();
    cc2.set_session_cache(session_cache);
    let (client2, zero_rtt) = server.connect_0rtt(client_config(cc2)).await?;
    client2.send_ping().await?;
    assert!(zero_rtt.await);
    client2.receive_pong().await?;
    Ok(())
}

#[tokio::test]
async fn zero_rtt_rejected() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the first 1-RTT connection.
    info!("sending 1-RTT");
    let cc1 = client_crypto();
    let session_cache = cc1.get_session_cache();
    let client1 = server.connect_1rtt(client_config(cc1)).await?;
    client1.send_ping().await?;
    client1.receive_pong().await?;

    // Start a new server, to ensure that it does not have a session cached for this client. This
    // will force the server to reject the 0-RTT attempt.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the second client with the shared session cache.
    info!("sending 0-RTT with downgrade to 1-RTT");
    let mut cc2 = client_crypto();
    cc2.set_session_cache(session_cache);
    let (client2, zero_rtt) = server.connect_0rtt(client_config(cc2)).await?;

    let send = client2.conn.open_uni().await?;

    // TODO(nmittler): Investigate why this is needed. Seeing a 10s delay without it (m1 macbook).
    tokio::time::sleep_until(Instant::now() + Duration::from_millis(100)).await;

    // Hack to allow us to sleep between creating the stream and sending the message.
    async fn send_ping(mut send: SendStream) -> std::result::Result<(), WriteError> {
        send.write_all(PING_MSG).await?;
        send.finish()?;
        send.stopped().await?;
        Ok(())
    }

    let err = send_ping(send).await.expect_err("expected 0-RTT rejected");
    match err {
        WriteError::ZeroRttRejected => {
            assert!(!zero_rtt.await, "expected 1-RTT");
            Ok(())
        }
        _ => Err(anyhow!("unexpected error: {err}")),
    }
}

#[derive(Clone, Debug)]
struct ConnectionInfo {
    handshake_data: Box<quinn_boring::HandshakeData>,
    keyring_material: [u8; 64],
}

impl ConnectionInfo {
    const KEYRING_LABEL: &'static [u8] = b"test_label";
    const KEYRING_CONTEXT: &'static [u8] = b"test_context";

    fn new(conn: &Connection) -> Result<Self> {
        let handshake_data = handshake_data(conn)?;
        let mut keyring_material = [0u8; 64];
        conn.export_keying_material(
            &mut keyring_material,
            Self::KEYRING_LABEL,
            Self::KEYRING_CONTEXT,
        )
        .unwrap();

        Ok(Self {
            handshake_data,
            keyring_material,
        })
    }

    fn server_name(&self) -> String {
        self.handshake_data.server_name.clone().unwrap()
    }

    fn alpn_protocol(&self) -> Vec<u8> {
        self.handshake_data.protocol.clone().unwrap()
    }
}

struct Client {
    conn: Connection,
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client").field("conn", &self.conn).finish()
    }
}

impl Client {
    fn conn_info(&self) -> ConnectionInfo {
        ConnectionInfo::new(&self.conn).unwrap()
    }

    async fn send_ping(&self) -> std::result::Result<(), WriteError> {
        let mut send = self.conn.open_uni().await?;
        send.write_all(PING_MSG).await?;
        send.finish()?;
        send.stopped().await?;
        Ok(())
    }

    async fn receive_pong(&self) -> Result<()> {
        let mut recv = self.conn.accept_uni().await?;
        let resp = recv.read_to_end(usize::MAX).await?;
        assert_eq!(PONG_MSG, resp.as_slice());
        Ok(())
    }
}

struct Server {
    addr: SocketAddr,
    conn_info: Mutex<Option<ConnectionInfo>>,
}

impl Server {
    fn run(server_config: quinn::ServerConfig) -> Result<Arc<Self>> {
        Self::run_with_retry(server_config, false)
    }
    fn run_with_retry(server_config: quinn::ServerConfig, use_retry: bool) -> Result<Arc<Self>> {
        let endpoint = quinn_boring::helpers::server_endpoint(server_config, local_address())?;
        let addr = endpoint.local_addr()?;

        let server = Arc::new(Self {
            addr,
            conn_info: Mutex::new(None),
        });

        let server2 = server.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let server: Arc<Server> = server2.clone();
                if use_retry && !incoming.remote_address_validated() {
                    if let Err(e) = incoming.retry() {
                        error!(
                            "server: connection retry failed: {reason}",
                            reason = e.to_string()
                        )
                    }
                    continue;
                }
                let conn = match incoming.accept() {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(
                            "server: connection accept failed: {reason}",
                            reason = e.to_string()
                        );
                        continue;
                    }
                };
                tokio::spawn(async move {
                    let fut = server.handle_connection(conn);
                    if let Err(e) = fut.await {
                        error!(
                            "server: connection failed: {reason}",
                            reason = e.to_string()
                        )
                    }
                });
            }
        });

        Ok(server)
    }

    async fn connect(
        &self,
        client_config: quinn::ClientConfig,
    ) -> std::result::Result<Connecting, ConnectError> {
        let mut endpoint = quinn_boring::helpers::client_endpoint(local_address()).unwrap();
        endpoint.set_default_client_config(client_config);

        // Connect to the server.
        endpoint.connect(self.addr, SERVER_NAME)
    }

    async fn connect_0rtt(
        &self,
        client_config: quinn::ClientConfig,
    ) -> std::result::Result<(Client, ZeroRttAccepted), ConnectionError> {
        let (conn, zero_rtt) = self
            .connect(client_config)
            .await
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("missing 0-RTT keys"));
        Ok((Client { conn }, zero_rtt))
    }

    async fn connect_1rtt(
        &self,
        client_config: quinn::ClientConfig,
    ) -> std::result::Result<Client, ConnectionError> {
        let conn = self
            .connect(client_config)
            .await
            .unwrap()
            .into_0rtt()
            .err()
            .expect("0-RTT succeeded but should have failed")
            .await?;
        Ok(Client { conn })
    }

    fn conn_info(self: &Arc<Self>) -> ConnectionInfo {
        self.conn_info.lock().unwrap().clone().unwrap()
    }

    async fn handle_connection(self: &Arc<Self>, incoming: Connecting) -> Result<()> {
        let conn = incoming.await?;

        let conn_info = ConnectionInfo::new(&conn)?;
        self.conn_info.lock().unwrap().replace(conn_info);

        // Accept the incoming stream for the request.
        let recv = match conn.accept_uni().await {
            Ok(s) => s,
            Err(ConnectionError::ApplicationClosed { .. }) => {
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        // Create an outgoing stream for the response.
        let send = match conn.open_uni().await {
            Ok(s) => s,
            Err(ConnectionError::ApplicationClosed { .. }) => {
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        Self::receive_ping(recv).await?;
        Self::send_pong(send).await?;
        Ok(())
    }

    async fn receive_ping(mut recv: RecvStream) -> Result<()> {
        let req = recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| anyhow!("failed reading request: {}", e))?;
        assert_eq!(PING_MSG, req.as_slice());
        Ok(())
    }

    async fn send_pong(mut send: SendStream) -> Result<()> {
        send.write_all(PONG_MSG)
            .await
            .map_err(|e| anyhow!("failed to send response: {}", e))?;
        // Gracefully terminate the stream
        send.finish()
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        send.stopped()
            .await
            .map_err(|e| anyhow!("failed to stop stream: {}", e))?;
        Ok(())
    }
}

fn local_address() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn handshake_data(conn: &Connection) -> Result<Box<quinn_boring::HandshakeData>> {
    Ok(conn
        .handshake_data()
        .unwrap()
        .downcast::<quinn_boring::HandshakeData>()
        .unwrap())
}

fn client_config(client_crypto: ClientConfig) -> quinn::ClientConfig {
    quinn::ClientConfig::new(Arc::new(client_crypto))
}

fn server_config(server_crypto: ServerConfig) -> Result<quinn::ServerConfig> {
    Ok(quinn_boring::helpers::server_config(Arc::new(
        server_crypto,
    ))?)
}

fn client_crypto() -> ClientConfig {
    let mut out = ClientConfig::new().unwrap();
    let ctx = out.ctx_mut();

    // Set the cert and key.
    CLIENT_CERT.set_cert_for(ctx);

    // Configure peer cert verification.
    SERVER_CERT.set_trusted_by(ctx);

    // Check that everything is configured correctly.
    ctx.check_private_key().unwrap();

    out
}

fn server_crypto() -> ServerConfig {
    let mut out = ServerConfig::new().unwrap();
    let ctx = out.ctx_mut();

    // Set the cert and key.
    SERVER_CERT.set_cert_for(ctx);

    // Configure peer cert verification.
    CLIENT_CERT.set_trusted_by(ctx);

    // Check that everything is configured correctly.
    ctx.check_private_key().unwrap();

    out
}

/// Certificate Authority utility that can create new leaf certs.
struct Ca(rcgen::CertifiedKey);

impl Ca {
    /// Creates a new CA.
    fn new() -> Self {
        let key_pair = rcgen::KeyPair::generate().expect("key pair generated");

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
            rcgen::KeyUsagePurpose::ContentCommitment,
        ];

        Self(rcgen::CertifiedKey {
            cert: params.self_signed(&key_pair).unwrap(),
            key_pair,
        })
    }

    /// Creates a new leaf cert signed by this CA.
    fn new_leaf(&self, subject_alt_names: impl Into<Vec<String>>) -> Leaf {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(subject_alt_names)
            .unwrap()
            .signed_by(&key_pair, &self.0.cert, &self.0.key_pair)
            .unwrap();
        let private_key = key_pair.serialize_der();
        let cert = certificate.der().to_vec();
        let ca_cert = self.0.cert.der().to_vec();
        Leaf {
            private_key,
            cert,
            ca_cert,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Leaf {
    cert: Vec<u8>,
    ca_cert: Vec<u8>,
    private_key: Vec<u8>,
}

impl Leaf {
    fn key(&self) -> PKey<Private> {
        PKey::private_key_from_der(&self.private_key).unwrap()
    }

    fn cert(&self) -> X509 {
        X509::from_der(&self.cert).unwrap()
    }

    fn ca_cert(&self) -> X509 {
        X509::from_der(&self.ca_cert).unwrap()
    }

    /// Sets this to be the cert represented by the context.
    fn set_cert_for(&self, ctx: &mut boring::ssl::SslContext) {
        ctx.set_certificate(self.cert()).unwrap();
        ctx.set_private_key(self.key()).unwrap();
    }

    /// Configures the given context to trust this cert.
    fn set_trusted_by(&self, ctx: &mut boring::ssl::SslContext) {
        let cert_store = ctx.cert_store_mut();
        cert_store.add_cert(self.cert()).unwrap();
        cert_store.add_cert(self.ca_cert()).unwrap();
    }
}

struct TestWriter;

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

pub fn subscribe() -> tracing::subscriber::DefaultGuard {
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(|| TestWriter)
        .finish();
    tracing::subscriber::set_default(sub)
}

static CA: Lazy<Ca> = Lazy::new(Ca::new);
static SERVER_CERT: Lazy<Leaf> = Lazy::new(|| CA.new_leaf(vec![SERVER_NAME.into()]));
static CLIENT_CERT: Lazy<Leaf> = Lazy::new(|| CA.new_leaf(vec!["client.com".into()]));
static UNTRUSTED_CA: Lazy<Ca> = Lazy::new(Ca::new);
static UNTRUSTED_SERVER_CERT: Lazy<Leaf> =
    Lazy::new(|| UNTRUSTED_CA.new_leaf(vec![SERVER_NAME.into()]));
static UNTRUSTED_CLIENT_CERT: Lazy<Leaf> =
    Lazy::new(|| UNTRUSTED_CA.new_leaf(vec!["client.com".into()]));
