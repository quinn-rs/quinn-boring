use anyhow::{anyhow, Result};
use boring::pkey::{PKey, Private};
use boring::x509::X509;
use boring_sys as bffi;
use core::fmt::{Debug, Formatter};
use lazy_static::lazy_static;
use quinn::{
    Connection, Endpoint, ReadToEndError, RecvStream, SendStream, WriteError, ZeroRttAccepted,
};
use quinn_boring::{ClientConfig, ServerConfig};
use quinn_proto::{ConnectionError, TransportErrorCode};
use rcgen::{BasicConstraints, CertificateParams, IsCa};
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const SERVER_NAME: &str = "localhost";
const NO_APPLICATION_PROTOCOL: u8 = bffi::SSL_AD_NO_APPLICATION_PROTOCOL as u8;
const UNKNOWN_CA: u8 = bffi::SSL_AD_UNKNOWN_CA as u8;

#[tokio::test]
async fn simple() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the client.
    let client = Client::connect(client_config(client_crypto()), server.addr).await?;
    client.ping_pong().await?;
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
    let client = Client::connect(client_config(client_crypto), server.addr).await?;
    client.ping_pong().await?;
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
    let err = Client::connect(client_config(client_crypto), server.addr)
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

    let client = Client::connect(client_config, server.addr).await?;
    client.ping_pong().await?;
    assert_eq!(SERVER_NAME, server.conn_info().server_name().as_str());
    assert_eq!(b"h3", client.conn_info().alpn_protocol().as_slice());
    assert_eq!(b"h3", server.conn_info().alpn_protocol().as_slice());
    Ok(())
}

#[tokio::test]
async fn stateless_retry() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let mut server_config = server_config(server_crypto())?;
    server_config.use_retry(true);
    let server = Server::run(server_config)?;

    // Connect the client.
    let client_config = client_config(client_crypto());
    let client = Client::connect(client_config, server.addr).await?;
    client.ping_pong().await?;
    Ok(())
}

#[tokio::test]
async fn export_keyring_material() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the client.
    let client = Client::connect(client_config(client_crypto()), server.addr).await?;
    client.ping_pong().await?;
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
    server_crypto
        .set_cert(UNTRUSTED_SERVER_CERT.chain(), UNTRUSTED_SERVER_CERT.key())
        .unwrap();
    for cert in CLIENT_CERT.chain() {
        server_crypto.add_trusted_cert(cert).unwrap();
    }
    let server = Server::run(server_config(server_crypto)?)?;

    // Create the client with no server certs configured.
    let err = Client::connect(client_config(client_crypto()), server.addr)
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
    server_crypto.enable_client_auth(true);
    let server = Server::run(server_config(server_crypto)?)?;

    // Create the client with an unknown CA.
    let mut client_crypto = ClientConfig::new().unwrap();
    client_crypto
        .set_cert(UNTRUSTED_CLIENT_CERT.chain(), UNTRUSTED_CLIENT_CERT.key())
        .unwrap();
    for cert in SERVER_CERT.chain() {
        client_crypto.add_trusted_cert(cert).unwrap();
    }
    let client = Client::connect(client_config(client_crypto), server.addr).await?;
    let (send, _) = client.conn.open_bi().await?;
    let request = &b"hello world"[..];
    let err = Client::send_request(send, request)
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

    let cc1 = client_crypto();
    let session_cache = cc1.get_session_cache();
    let client1 = Client::connect_no_zero_rtt(client_config(cc1), server.addr).await?;
    client1.ping_pong().await?;

    info!("initial connection complete");

    // Create the second client with the shared session cache.
    let mut cc2 = client_crypto();
    cc2.set_session_cache(session_cache);
    let (client2, zero_rtt) = Client::connect_zero_rtt(client_config(cc2), server.addr).await?;
    client2.ping_pong().await?;
    assert!(zero_rtt.await, "expected 0-RTT");
    Ok(())
}

#[tokio::test]
async fn zero_rtt_rejected() -> Result<()> {
    let _guard = subscribe();

    // Run the server.
    let server = Server::run(server_config(server_crypto())?)?;

    let cc1 = client_crypto();
    let session_cache = cc1.get_session_cache();
    let client1 = Client::connect_no_zero_rtt(client_config(cc1), server.addr).await?;
    client1.ping_pong().await?;

    info!("initial connection complete");

    // Start a new server, to ensure that it does not have a session cached for this client. This
    // will force the server to reject the 0-RTT attempt.
    let server = Server::run(server_config(server_crypto())?)?;

    // Create the second client with the shared session cache.
    let mut cc2 = client_crypto();
    cc2.set_session_cache(session_cache);
    let (client2, zero_rtt) = Client::connect_zero_rtt(client_config(cc2), server.addr).await?;

    // Buy time for the driver to process the server's NewSessionTicket
    //tokio::time::sleep_until(Instant::now() + Duration::from_millis(100)).await;

    let (send, _) = client2.conn.open_bi().await?;
    let err = Client::send_request(send, &b"hello world"[..])
        .await
        .expect_err("expected 0-RTT rejected");
    match err {
        WriteError::ZeroRttRejected => {
            error!("NM: zero-rtt rejected");
        }
        _ => return Err(anyhow!("unexpected error: {err}")),
    }
    assert!(!zero_rtt.await, "expected 1-RTT");
    Ok(())
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
    async fn connect(
        client_config: quinn::ClientConfig,
        server_addr: SocketAddr,
    ) -> std::result::Result<Self, ConnectionError> {
        let endpoint = Self::new_endpoint(client_config);

        // Connect to the server.
        let conn = endpoint.connect(server_addr, SERVER_NAME).unwrap().await?;

        Ok(Self { conn })
    }

    async fn connect_no_zero_rtt(
        client_config: quinn::ClientConfig,
        server_addr: SocketAddr,
    ) -> std::result::Result<Self, ConnectionError> {
        let endpoint = Self::new_endpoint(client_config);

        // Connect to the server.
        let conn = endpoint
            .connect(server_addr, SERVER_NAME)
            .unwrap()
            .into_0rtt()
            .err()
            .expect("0-RTT succeeded but should have failed")
            .await?;

        Ok(Self { conn })
    }

    async fn connect_zero_rtt(
        client_config: quinn::ClientConfig,
        server_addr: SocketAddr,
    ) -> std::result::Result<(Self, ZeroRttAccepted), ConnectionError> {
        let endpoint = Self::new_endpoint(client_config);

        // Connect to the server.
        let (conn, zero_rtt) = endpoint
            .connect(server_addr, SERVER_NAME)
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("missing 0-RTT keys"));
        Ok((Self { conn }, zero_rtt))
    }

    fn new_endpoint(client_config: quinn::ClientConfig) -> Endpoint {
        let mut endpoint =
            quinn_boring::helpers::client_endpoint("[::]:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    fn conn_info(&self) -> ConnectionInfo {
        ConnectionInfo::new(&self.conn).unwrap()
    }

    async fn ping_pong(&self) -> Result<()> {
        let (send, recv) = self.conn.open_bi().await?;

        // Send the request.
        let request = &b"hello world"[..];
        Self::send_request(send, request).await?;

        // Read the response.
        let resp = Self::recv_response(recv).await?;
        assert_eq!(request, resp.as_slice());
        Ok(())
    }

    async fn send_request(
        mut send: SendStream,
        request: &[u8],
    ) -> std::result::Result<(), WriteError> {
        send.write_all(request).await?;
        send.finish().await
    }

    async fn recv_response(mut recv: RecvStream) -> std::result::Result<Vec<u8>, ReadToEndError> {
        recv.read_to_end(usize::MAX).await
    }
}

struct Server {
    addr: SocketAddr,
    conn_info: Mutex<Option<ConnectionInfo>>,
}

impl Server {
    fn run(server_config: quinn::ServerConfig) -> Result<Arc<Self>> {
        let endpoint =
            quinn_boring::helpers::server_endpoint(server_config, "[::1]:0".parse().unwrap())?;
        let addr = endpoint.local_addr()?;

        let server = Arc::new(Self {
            addr,
            conn_info: Mutex::new(None),
        });

        let server2 = server.clone();
        tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let server = server2.clone();
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

    fn conn_info(self: &Arc<Self>) -> ConnectionInfo {
        self.conn_info.lock().unwrap().clone().unwrap()
    }

    async fn handle_connection(self: &Arc<Self>, conn: quinn::Connecting) -> Result<()> {
        let conn = conn.await?;

        let conn_info = ConnectionInfo::new(&conn)?;
        self.conn_info.lock().unwrap().replace(conn_info);

        async {
            // Each stream initiated by the client constitutes a new request.
            loop {
                let stream = conn.accept_bi().await;
                let stream = match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e);
                    }
                    Ok(s) => s,
                };
                let fut = Self::handle_request(stream);
                tokio::spawn(async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
                });
            }
        }
        .await?;
        Ok(())
    }

    async fn handle_request(
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    ) -> Result<()> {
        let req = recv
            .read_to_end(64 * 1024)
            .await
            .map_err(|e| anyhow!("failed reading request: {}", e))?;
        // Write the response
        send.write_all(&req)
            .await
            .map_err(|e| anyhow!("failed to send response: {}", e))?;
        // Gracefully terminate the stream
        send.finish()
            .await
            .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
        Ok(())
    }
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

    // Configure the cert.
    out.set_cert(CLIENT_CERT.chain(), CLIENT_CERT.key())
        .unwrap();

    // Configure server cert verification.
    for cert in SERVER_CERT.chain() {
        out.add_trusted_cert(cert).unwrap();
    }

    out
}

// fn rustls_client_crypto() -> rustls::ClientConfig {
//     let mut roots = rustls::RootCertStore::empty();
//     for cert in &CLIENT_CERT.chain {
//         roots.add(&rustls::Certificate(cert.clone())).unwrap();
//     }
//
//     let mut cfg = rustls::ClientConfig::builder()
//         .with_safe_default_cipher_suites()
//         .with_safe_default_kx_groups()
//         .with_protocol_versions(&[&rustls::version::TLS13])
//         .unwrap()
//         .with_root_certificates(roots)
//         .with_no_client_auth();
//     cfg.enable_early_data = true;
//     cfg
// }
//
// fn rustls_server_crypto() -> rustls::ServerConfig {
//     let mut cfg = rustls::ServerConfig::builder()
//         .with_safe_default_cipher_suites()
//         .with_safe_default_kx_groups()
//         .with_protocol_versions(&[&rustls::version::TLS13])
//         .unwrap()
//         .with_no_client_auth()
//         .with_single_cert(
//             SERVER_CERT
//                 .chain
//                 .iter()
//                 .map(|x| rustls::Certificate(x.clone()))
//                 .collect(),
//             rustls::PrivateKey(SERVER_CERT.private_key.clone()),
//         )
//         .unwrap();
//     cfg.max_early_data_size = u32::MAX;
//     cfg
// }

fn server_crypto() -> ServerConfig {
    let mut out = ServerConfig::new().unwrap();

    // Configure the cert.
    out.set_cert(SERVER_CERT.chain(), SERVER_CERT.key())
        .unwrap();

    // Configure client cert verification.
    for cert in CLIENT_CERT.chain() {
        out.add_trusted_cert(cert).unwrap();
    }

    out
}

/// Certificate Authority utility that can create new leaf certs.
struct Ca(rcgen::Certificate);

impl Ca {
    /// Creates a new CA.
    fn new() -> Self {
        let mut params = CertificateParams::new(&[] as &[String]);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self(rcgen::Certificate::from_params(params).unwrap())
    }

    /// Gets this CA's certificate.
    fn cert(&self) -> Vec<u8> {
        self.0.serialize_der().unwrap()
    }

    /// Creates a new leaf cert signed by this CA.
    fn new_leaf(&self, subject_alt_names: impl Into<Vec<String>>) -> Leaf {
        let cert = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let private_key = cert.serialize_private_key_der();
        let cert = cert.serialize_der_with_signer(&self.0).unwrap();
        Leaf {
            private_key,
            chain: vec![cert, self.cert()],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Leaf {
    /// The certificate chain, starting with the leaf certificate and ending with the root CA.
    chain: Vec<Vec<u8>>,
    private_key: Vec<u8>,
}

impl Leaf {
    fn key(&self) -> PKey<Private> {
        PKey::private_key_from_der(&self.private_key).unwrap()
    }

    fn chain(&self) -> Vec<X509> {
        let mut out = Vec::new();
        for cert in &self.chain {
            out.push(X509::from_der(cert).unwrap());
        }
        out
    }
}

struct TestWriter;

impl std::io::Write for TestWriter {
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

lazy_static! {
    static ref CA: Ca = Ca::new();
    static ref SERVER_CERT: Leaf = CA.new_leaf(vec![SERVER_NAME.into()]);
    static ref CLIENT_CERT: Leaf = CA.new_leaf(vec!["client.com".into()]);
    static ref UNTRUSTED_CA: Ca = Ca::new();
    static ref UNTRUSTED_SERVER_CERT: Leaf = UNTRUSTED_CA.new_leaf(vec![SERVER_NAME.into()]);
    static ref UNTRUSTED_CLIENT_CERT: Leaf = UNTRUSTED_CA.new_leaf(vec!["client.com".into()]);
}
