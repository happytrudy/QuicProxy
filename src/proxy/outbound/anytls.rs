use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use rand::Rng;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};
use tokio_rustls::{TlsConnector, rustls};
use tracing::{debug, info, warn};

use crate::{
    config::OutboundConfig,
    proxy::{
        QuicTlsConfig, SessionCloser, SourceAddr, TargetAddr,
        anytls_proto::*,
        outbound::{AnyOutbound, AnyPacket, AnyStream, PacketInfo, select_outbound_interface},
    },
    utils::{new_io_other_error, new_io_timeout_error},
};

// ─── Protocol Constants ───────────────────────────────────────────────────────

const CLIENT_NAME: &str = AGENT_NAME;

const DEFAULT_PADDING_SCHEME: &str = "\
stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

// ─── Padding Scheme ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum PaddingPolicy {
    Chunks(Vec<(usize, usize, bool)>),
}

impl PaddingPolicy {
    fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(',').collect();
        let mut chunks = Vec::new();
        let mut i = 0;
        while i < parts.len() {
            let part = parts[i].trim();
            let mut can_skip = false;
            if i + 1 < parts.len() && parts[i + 1].trim() == "c" {
                can_skip = true;
                i += 1;
            }
            if let Some(dash_pos) = part.find('-') {
                let min: usize = part[..dash_pos]
                    .trim()
                    .parse()
                    .context("invalid padding min")?;
                let max: usize = part[dash_pos + 1..]
                    .trim()
                    .parse()
                    .context("invalid padding max")?;
                chunks.push((min, max, can_skip));
            }
            i += 1;
        }
        Ok(PaddingPolicy::Chunks(chunks))
    }

    #[allow(dead_code)]
    fn apply(&self, payload_len: usize, rng: &mut impl Rng) -> Vec<usize> {
        match self {
            PaddingPolicy::Chunks(chunks) => {
                let mut remaining = payload_len;
                let mut result = Vec::new();
                for &(min, max, can_skip) in chunks.iter() {
                    if remaining == 0 {
                        if !can_skip {
                            let pad_size = if min == max {
                                min
                            } else {
                                rng.gen_range(min..=max)
                            };
                            result.push(pad_size);
                        }
                        break;
                    }
                    let max_for_this = max.min(remaining);
                    let size = if min >= remaining {
                        remaining
                    } else {
                        rng.gen_range(min..=max_for_this)
                    };
                    result.push(size);
                    remaining = remaining.saturating_sub(size);
                }
                if remaining > 0 {
                    result.push(remaining);
                }
                result
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PaddingScheme {
    #[allow(dead_code)]
    stop_at: u8,
    policies: HashMap<u8, PaddingPolicy>,
    hash: String,
}

impl PaddingScheme {
    fn parse(raw: &str) -> Result<Self> {
        let mut stop_at: u8 = 0;
        let mut policies = HashMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                if key == "stop" {
                    stop_at = value.parse().context("invalid stop value")?;
                } else if let Ok(pkt_idx) = key.parse::<u8>() {
                    policies.insert(pkt_idx, PaddingPolicy::parse(value)?);
                }
            }
        }
        let hash = Self::compute_hash(raw);
        Ok(Self {
            stop_at,
            policies,
            hash,
        })
    }

    fn compute_hash(raw: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn get_default() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME).expect("default padding scheme must be valid")
    }
}

// ─── Stream Event ─────────────────────────────────────────────────────────────

enum StreamEvent {
    Data(Bytes),
    Fin,
    SynAckError(Vec<u8>),
}

// ─── Session (Hub) ────────────────────────────────────────────────────────────

/// A session is one TLS connection to the anytls server that multiplexes streams.
///
/// It owns:
/// - A `streams` map: stream_id -> sender to push incoming data to the stream
/// - A write channel: streams push outgoing frames here, a write task drains it
struct Session {
    session_seq: u64,
    /// Map from stream_id to event sender for routing incoming frames
    streams: DashMap<u32, tokio::sync::mpsc::UnboundedSender<StreamEvent>>,
    /// Write channel: (stream_id, cmd, data)
    write_tx: tokio::sync::mpsc::UnboundedSender<(u32, u8, Bytes)>,
    next_stream_id: AtomicU32,
    server_version: AtomicU8,
    is_dead: AtomicBool,
    packet_count: AtomicU64,
    padding_scheme: Mutex<PaddingScheme>,
    closer: Arc<SessionCloser>,
}

impl Session {
    async fn new(
        tcp_stream: tokio::net::TcpStream,
        tls_cfg: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        password_hash: &[u8; 32],
        tls_connect_timeout: Duration,
        session_seq: u64,
        padding_scheme: PaddingScheme,
    ) -> Result<Arc<Self>> {
        // TLS handshake
        let connector = TlsConnector::from(tls_cfg);
        let tls_stream = tokio::time::timeout(
            tls_connect_timeout,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .context("Anytls TLS handshake timeout")?
        .context("Anytls TLS handshake failed")?;

        let (write_tx, write_rx) = tokio::sync::mpsc::unbounded_channel();

        let session = Arc::new(Self {
            session_seq,
            streams: DashMap::new(),
            write_tx,
            next_stream_id: AtomicU32::new(1),
            server_version: AtomicU8::new(1),
            is_dead: AtomicBool::new(false),
            packet_count: AtomicU64::new(0),
            padding_scheme: Mutex::new(padding_scheme),
            closer: Arc::new(SessionCloser::new()),
        });

        // Authenticate
        let scheme = session.padding_scheme.lock().await.clone();
        let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
        Self::authenticate(&mut tls_write, password_hash, &scheme).await?;

        // Send cmdSettings
        Self::send_settings(&mut tls_write).await?;

        // Spawn write loop
        let session_w = session.clone();
        tokio::spawn(async move {
            if let Err(e) = session_w.write_loop(tls_write, write_rx).await {
                debug!("Anytls session {} write loop ended: {:?}", session_seq, e);
            }
            session_w.is_dead.store(true, Ordering::Release);
            session_w.closer.close();
        });

        // Spawn read loop
        let session_r = session.clone();
        tokio::spawn(async move {
            if let Err(e) = session_r.read_loop(tls_read).await {
                debug!("Anytls session {} read loop ended: {:?}", session_seq, e);
            }
            session_r.is_dead.store(true, Ordering::Release);
            session_r.closer.close();
        });

        Ok(session)
    }

    async fn authenticate<S: AsyncWrite + Unpin>(
        tls: &mut S,
        password_hash: &[u8; 32],
        scheme: &PaddingScheme,
    ) -> Result<()> {
        let padding0_size: usize = scheme
            .policies
            .get(&0)
            .and_then(|p| match p {
                PaddingPolicy::Chunks(chunks) => chunks.first(),
            })
            .map(|&(min, max, _can_skip)| {
                let mut rng = rand::thread_rng();
                if min == max {
                    min
                } else {
                    rng.gen_range(min..=max)
                }
            })
            .unwrap_or(30);

        let mut auth_packet =
            Vec::with_capacity(AUTH_HASH_SIZE + AUTH_LENGTH_FIELD_SIZE + padding0_size);
        auth_packet.extend_from_slice(password_hash);
        auth_packet.extend_from_slice(&(padding0_size as u16).to_be_bytes());
        auth_packet.resize(auth_packet.len() + padding0_size, 0);

        tls.write_all(&auth_packet).await?;
        tls.flush().await?;
        Ok(())
    }

    async fn send_settings<S: AsyncWrite + Unpin>(tls: &mut S) -> Result<()> {
        let scheme = PaddingScheme::get_default();
        let settings = format!(
            "v={}\nclient={}\npadding-md5={}\n",
            PROTOCOL_VERSION, CLIENT_NAME, scheme.hash
        );
        Self::write_frame(tls, Command::Settings, 0, settings.as_bytes()).await?;
        Ok(())
    }

    // ── Frame I/O ─────────────────────────────────────────────────────────

    async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Command, u32, Bytes)> {
        let cmd = stream.read_u8().await.context("read frame cmd")?;
        let stream_id = stream.read_u32().await.context("read frame stream_id")?;
        let data_len = stream.read_u16().await.context("read frame data_len")?;
        let mut data = vec![0u8; data_len as usize];
        if data_len > 0 {
            stream
                .read_exact(&mut data)
                .await
                .context("read frame data")?;
        }
        Ok((Command::from(cmd), stream_id, Bytes::from(data)))
    }

    async fn write_frame<S: AsyncWrite + Unpin>(
        stream: &mut S,
        cmd: Command,
        stream_id: u32,
        data: &[u8],
    ) -> Result<()> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = u8::from(cmd);
        header[1..5].copy_from_slice(&stream_id.to_be_bytes());
        header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        stream.write_all(&header).await?;
        if !data.is_empty() {
            stream.write_all(data).await?;
        }
        stream.flush().await?;
        Ok(())
    }

    // ── Loops ─────────────────────────────────────────────────────────────

    async fn read_loop(&self, mut tls: impl AsyncRead + Unpin + Send) -> Result<()> {
        loop {
            let (cmd, stream_id, data) = match Self::read_frame(&mut tls).await {
                Ok(frame) => frame,
                Err(e) => return Err(e),
            };

            match cmd {
                Command::Waste => {}
                Command::Psh => {
                    if let Some(tx) = self.streams.get(&stream_id) {
                        let _ = tx.send(StreamEvent::Data(data));
                    }
                }
                Command::Fin => {
                    if let Some(tx) = self.streams.get(&stream_id) {
                        let _ = tx.send(StreamEvent::Fin);
                    }
                }
                Command::SynAck => {
                    if !data.is_empty() {
                        if let Some(tx) = self.streams.get(&stream_id) {
                            let _ = tx.send(StreamEvent::SynAckError(data.to_vec()));
                        }
                    }
                }
                Command::Alert => {
                    let msg = String::from_utf8_lossy(&data);
                    warn!(
                        "Anytls session {} received alert: {}",
                        self.session_seq, msg
                    );
                    // Notify all streams
                    for entry in self.streams.iter() {
                        let _ = entry.value().send(StreamEvent::SynAckError(
                            format!("server alert: {}", msg).into_bytes(),
                        ));
                    }
                    return Err(new_io_other_error(format!("server alert: {}", msg)).into());
                }
                Command::UpdatePaddingScheme => {
                    let scheme_str = String::from_utf8_lossy(&data);
                    match PaddingScheme::parse(&scheme_str) {
                        Ok(new_scheme) => {
                            debug!("Anytls session {} updated padding scheme", self.session_seq);
                            *self.padding_scheme.lock().await = new_scheme;
                        }
                        Err(e) => {
                            warn!(
                                "Anytls session {} invalid padding scheme: {:?}",
                                self.session_seq, e
                            );
                        }
                    }
                }
                Command::HeartRequest => {
                    // Send heart response via write channel
                    let _ = self.write_tx.send((0, Command::HeartResponse as u8, Bytes::new()));
                }
                Command::HeartResponse => {}
                Command::ServerSettings => {
                    let text = String::from_utf8_lossy(&data);
                    if let Some(ver) = Self::parse_server_version(&text) {
                        self.server_version.store(ver, Ordering::Release);
                        debug!(
                            "Anytls session {} server version: {}",
                            self.session_seq, ver
                        );
                    }
                }
                _ => {
                    debug!("Anytls session {} unknown cmd: {:?}", self.session_seq, cmd);
                }
            }
            self.packet_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn write_loop(
        &self,
        mut tls: impl AsyncWrite + Unpin + Send,
        mut write_rx: tokio::sync::mpsc::UnboundedReceiver<(u32, u8, Bytes)>,
    ) -> Result<()> {
        while let Some((stream_id, cmd, data)) = write_rx.recv().await {
            Self::write_frame(&mut tls, Command::from(cmd), stream_id, &data).await?;
        }
        Ok(())
    }

    fn parse_server_version(settings: &str) -> Option<u8> {
        for line in settings.lines() {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "v" {
                    return value.trim().parse().ok();
                }
            }
        }
        None
    }

    fn is_dead(&self) -> bool {
        self.is_dead.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    fn server_version(&self) -> u8 {
        self.server_version.load(Ordering::Acquire)
    }

    fn next_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a new stream and get its event receiver
    fn register_stream(&self, stream_id: u32) -> tokio::sync::mpsc::UnboundedReceiver<StreamEvent> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.streams.insert(stream_id, tx);
        rx
    }

    /// Unregister a stream (called when stream is dropped)
    fn unregister_stream(&self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }
}

// ─── AnytlsClient (Session Manager) ──────────────────────────────────────────

struct IdleSession {
    session: Arc<Session>,
    idle_since: Instant,
}

pub struct AnytlsClient {
    address: TargetAddr,
    password_hash: [u8; 32],
    tls_client_config: Arc<rustls::ClientConfig>,
    tls_server_name: rustls::pki_types::ServerName<'static>,
    connect_timeout: Duration,
    bind_interface: Option<String>,
    dns_server_name: Option<String>,

    active_sessions: Mutex<Vec<Arc<Session>>>,
    idle_sessions: Arc<Mutex<Vec<IdleSession>>>,
    session_seq: AtomicU64,
    padding_scheme: Mutex<PaddingScheme>,

    #[allow(dead_code)]
    idle_session_check_interval: Duration,
    #[allow(dead_code)]
    idle_session_timeout: Duration,
    #[allow(dead_code)]
    min_idle_session: usize,
}

impl AnytlsClient {
    pub fn new(
        address: TargetAddr,
        password: &str,
        tls: &QuicTlsConfig,
        connect_timeout: Duration,
        bind_interface: Option<String>,
        dns_server_name: Option<String>,
    ) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_hash: [u8; 32] = hasher.finalize().into();

        let tls_client_config = Self::build_tls_client_config(tls)?;

        let host = address.host();
        let sni = tls.sni.as_deref().unwrap_or(&host);
        let tls_server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|e| new_io_other_error(e))?
            .to_owned();

        let idle_sessions = Arc::new(Mutex::new(Vec::new()));

        // Spawn cleanup task
        let idle_sessions_c = idle_sessions.clone();
        let check_interval = Duration::from_secs(30);
        let session_timeout = Duration::from_secs(60);
        let min_idle = 1usize;
        tokio::spawn(async move {
            Self::cleanup_loop(idle_sessions_c, check_interval, session_timeout, min_idle).await;
        });

        Ok(Self {
            address,
            password_hash,
            tls_client_config: Arc::new(tls_client_config),
            tls_server_name,
            connect_timeout,
            bind_interface,
            dns_server_name,
            active_sessions: Mutex::new(Vec::new()),
            idle_sessions,
            session_seq: AtomicU64::new(0),
            padding_scheme: Mutex::new(PaddingScheme::get_default()),
            idle_session_check_interval: check_interval,
            idle_session_timeout: session_timeout,
            min_idle_session: min_idle,
        })
    }

    fn build_tls_client_config(tls: &QuicTlsConfig) -> Result<rustls::ClientConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        if !tls.insecure {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(cert_path) = tls.cert.as_deref() {
                for cert in load_certs(cert_path)? {
                    root_store.add(cert).map_err(|e| new_io_other_error(e))?;
                }
            } else {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            Ok(rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth())
        } else {
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipServerVerification));
            Ok(config)
        }
    }

    async fn get_session(&self) -> Result<Arc<Session>> {
        // Try to get an idle session (prefer highest seq)
        {
            let mut idle = self.idle_sessions.lock().await;
            if !idle.is_empty() {
                idle.sort_by(|a, b| b.session.session_seq.cmp(&a.session.session_seq));
                let idle_session = idle.remove(0);
                let session = idle_session.session;
                if !session.is_dead() {
                    self.active_sessions.lock().await.push(session.clone());
                    debug!("Anytls reusing idle session seq={}", session.session_seq);
                    return Ok(session);
                }
            }
        }

        self.create_session().await
    }

    async fn create_session(&self) -> Result<Arc<Session>> {
        let seq = self.session_seq.fetch_add(1, Ordering::Relaxed);

        let socket_addr =
            crate::dns::resolve_target(&self.address, self.dns_server_name.as_deref()).await?;

        let used_interface =
            select_outbound_interface(self.bind_interface.as_deref(), Some(socket_addr));

        let tcp_stream = tokio::time::timeout(
            self.connect_timeout,
            crate::utils::socket::socket_helpers::new_tcp_stream(socket_addr, used_interface, None),
        )
        .await
        .map_err(|_| new_io_timeout_error("connect timeout"))?
        .context("TCP connect failed")?;

        let padding_scheme = self.padding_scheme.lock().await.clone();
        let session = Session::new(
            tcp_stream,
            self.tls_client_config.clone(),
            self.tls_server_name.clone(),
            &self.password_hash,
            self.connect_timeout,
            seq,
            padding_scheme,
        )
        .await?;

        self.active_sessions.lock().await.push(session.clone());
        info!("Anytls created new session seq={}", seq);
        Ok(session)
    }

    #[allow(dead_code)]
    async fn mark_idle(&self, session: Arc<Session>) {
        {
            let mut active = self.active_sessions.lock().await;
            active.retain(|s| s.session_seq != session.session_seq);
        }
        if session.is_dead() {
            return;
        }
        self.idle_sessions.lock().await.push(IdleSession {
            session,
            idle_since: Instant::now(),
        });
    }

    async fn cleanup_loop(
        idle_sessions: Arc<Mutex<Vec<IdleSession>>>,
        check_interval: Duration,
        session_timeout: Duration,
        min_idle: usize,
    ) {
        loop {
            tokio::time::sleep(check_interval).await;
            let mut idle = idle_sessions.lock().await;
            let now = Instant::now();
            idle.sort_by(|a, b| a.idle_since.cmp(&b.idle_since));
            let keep_count = min_idle.min(idle.len());
            let remove_count = idle.len().saturating_sub(keep_count);
            let mut removed = 0;
            idle.retain(|s| {
                if removed >= remove_count {
                    return true;
                }
                if now.duration_since(s.idle_since) > session_timeout {
                    debug!(
                        "Anytls cleaning up idle session seq={}, idle for {:?}",
                        s.session.session_seq,
                        now.duration_since(s.idle_since)
                    );
                    s.session.is_dead.store(true, Ordering::Release);
                    s.session.closer.close();
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }
    }
}

// ─── AnytlsUdpSocket ─────────────────────────────────────────────────────────

pub struct AnytlsUdpSocket {
    stream_id: u32,
    session: Arc<Session>,
    write_tx: tokio::sync::mpsc::UnboundedSender<(u32, u8, Bytes)>,
    event_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<StreamEvent>>,
    read_buffer: Mutex<Vec<u8>>,
}

impl AnytlsUdpSocket {
    fn new(
        stream_id: u32,
        session: Arc<Session>,
        event_rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
    ) -> Self {
        Self {
            stream_id,
            write_tx: session.write_tx.clone(),
            session,
            event_rx: Mutex::new(event_rx),
            read_buffer: Mutex::new(Vec::new()),
        }
    }

    async fn read_next_msg(&self) -> Result<Bytes> {
        loop {
            {
                let mut buf = self.read_buffer.lock().await;
                if buf.len() >= 2 {
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_needed = 2 + len;
                    if buf.len() >= total_needed {
                        let msg = Bytes::copy_from_slice(&buf[2..total_needed]);
                        buf.drain(..total_needed);
                        return Ok(msg);
                    }
                }
            }

            let mut rx = self.event_rx.lock().await;
            match rx.recv().await {
                Some(StreamEvent::Data(data)) => {
                    let mut buf = self.read_buffer.lock().await;
                    buf.extend_from_slice(&data);
                }
                Some(StreamEvent::Fin) => bail!("UDP stream closed by remote"),
                Some(StreamEvent::SynAckError(e)) => {
                    bail!("UDP stream error: {}", String::from_utf8_lossy(&e));
                }
                None => bail!("UDP stream channel closed"),
            }
        }
    }
}

impl Drop for AnytlsUdpSocket {
    fn drop(&mut self) {
        // Send FIN
        let _ = self.write_tx.send((self.stream_id, Command::Fin as u8, Bytes::new()));
        self.session.unregister_stream(self.stream_id);
    }
}

#[async_trait]
impl AnyPacket for AnytlsUdpSocket {
    async fn send_to(&self, buf: Bytes, _from: &SourceAddr, _target: &TargetAddr) -> Result<usize> {
        let mut packet = Vec::with_capacity(2 + buf.len());
        packet.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        packet.extend_from_slice(&buf);

        self.write_tx
            .send((self.stream_id, Command::Psh as u8, Bytes::from(packet)))
            .map_err(|_| new_io_other_error("UDP write channel closed"))?;
        Ok(buf.len())
    }

    async fn recv_from(&self) -> Result<PacketInfo> {
        let data = self.read_next_msg().await?;
        Ok((TargetAddr::dummy(), TargetAddr::dummy(), data))
    }

    fn closer(&self) -> Arc<SessionCloser> {
        self.session.closer.clone()
    }
}

// ─── AnytlsOutbound ───────────────────────────────────────────────────────────

pub struct AnytlsOutbound {
    tag: String,
    client: AnytlsClient,
    connect_timeout: Duration,
    dns_server_name: Option<String>,
    bind_interface: Option<String>,
}

impl AnytlsOutbound {
    pub fn new(tag: String, cfg: &OutboundConfig) -> Result<Arc<dyn AnyOutbound>> {
        let address = cfg
            .address
            .clone()
            .context(format!("anytls outbound '{}' requires address", tag))?;
        let port = cfg
            .port
            .context(format!("anytls outbound '{}' requires port", tag))?;
        let address = TargetAddr::from_str2(&address, port)?;

        let password = cfg
            .password
            .clone()
            .context(format!("anytls outbound '{}' requires password", tag))?;

        let tls = QuicTlsConfig::from_outbound(cfg)?;
        let connect_timeout = Duration::from_secs(cfg.connect_timeout.unwrap_or(30));

        let client = AnytlsClient::new(
            address,
            &password,
            &tls,
            connect_timeout,
            cfg.bind_interface.clone(),
            cfg.dns.clone(),
        )?;

        Ok(Arc::new(Self {
            tag,
            client,
            connect_timeout,
            dns_server_name: cfg.dns.clone(),
            bind_interface: cfg.bind_interface.clone(),
        }))
    }
}

#[async_trait]
impl AnyOutbound for AnytlsOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn protocol(&self) -> &str {
        "anytls"
    }

    fn dns_server_name(&self) -> Option<&str> {
        self.dns_server_name.as_deref()
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    async fn connect_stream_base(&self) -> Result<AnyStream> {
        bail!("anytls uses session-based connections; use connect_stream instead");
    }

    async fn connect_stream_with(
        &self,
        _target: &TargetAddr,
        _stream: AnyStream,
    ) -> Result<AnyStream> {
        bail!("anytls uses session-based connections; use connect_stream instead");
    }

    async fn connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        let session = self.client.get_session().await?;
        let stream_id = session.next_stream_id();

        // Register stream to receive incoming data
        let event_rx = session.register_stream(stream_id);

        // Send cmdSYN with target address
        let syn_data = target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::copy_from_slice(&syn_data)))
            .map_err(|_| new_io_other_error("session write channel closed"))?;

        let proxy = AnytlsProxyStream::new(stream_id, session.clone(), event_rx);
        Ok(Box::new(proxy))
    }

    async fn connect_packet(&self, target: &TargetAddr) -> Result<Arc<dyn AnyPacket>> {
        let udp_target = TargetAddr::Domain(UDP_OVER_TCP_TARGET.to_string(), target.port());

        let session = self.client.get_session().await?;
        let stream_id = session.next_stream_id();

        let event_rx = session.register_stream(stream_id);

        // Send cmdSYN with udp-over-tcp target
        let syn_data = udp_target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::copy_from_slice(&syn_data)))
            .map_err(|_| new_io_other_error("session write channel closed"))?;

        Ok(Arc::new(AnytlsUdpSocket::new(stream_id, session, event_rx)))
    }

    async fn retry_connect_stream(&self, target: &TargetAddr) -> Result<AnyStream> {
        self.connect_stream(target).await
    }
}

// ─── AnytlsProxyStream: a TCP stream tunneled through anytls session ──────────

struct AnytlsProxyStream {
    stream_id: u32,
    session: Arc<Session>,
    write_tx: tokio::sync::mpsc::UnboundedSender<(u32, u8, Bytes)>,
    event_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<StreamEvent>>,
    read_buffer: Mutex<Vec<u8>>,
    fin_received: AtomicBool,
    fin_sent: AtomicBool,
}

impl AnytlsProxyStream {
    fn new(
        stream_id: u32,
        session: Arc<Session>,
        event_rx: tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
    ) -> Self {
        Self {
            stream_id,
            write_tx: session.write_tx.clone(),
            session,
            event_rx: Mutex::new(event_rx),
            read_buffer: Mutex::new(Vec::new()),
            fin_received: AtomicBool::new(false),
            fin_sent: AtomicBool::new(false),
        }
    }
}

impl AsyncRead for AnytlsProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Serve from read buffer first
        {
            let mut rb = match this.read_buffer.try_lock() {
                Ok(guard) => guard,
                Err(_) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            };

            if !rb.is_empty() {
                let to_copy = rb.len().min(buf.remaining());
                buf.put_slice(&rb[..to_copy]);
                rb.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }
        }

        if this.fin_received.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        // Try to get an event
        let mut rx = match this.event_rx.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match rx.try_recv() {
            Ok(StreamEvent::Data(data)) => {
                drop(rx);
                // Put data into the output buffer first, remainder into read_buffer
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    if let Ok(mut rb) = this.read_buffer.try_lock() {
                        rb.extend_from_slice(&data[to_copy..]);
                    }
                }
                return Poll::Ready(Ok(()));
            }
            Ok(StreamEvent::Fin) => {
                this.fin_received.store(true, Ordering::Release);
                return Poll::Ready(Ok(()));
            }
            Ok(StreamEvent::SynAckError(e)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    String::from_utf8_lossy(&e).to_string(),
                )));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                this.fin_received.store(true, Ordering::Release);
                return Poll::Ready(Ok(()));
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for AnytlsProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.fin_sent.load(Ordering::Acquire) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream already closed",
            )));
        }
        match this
            .write_tx
            .send((this.stream_id, Command::Psh as u8, Bytes::copy_from_slice(buf)))
        {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.fin_sent.swap(true, Ordering::AcqRel) {
            let _ = this.write_tx.send((this.stream_id, Command::Fin as u8, Bytes::new()));
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnytlsProxyStream {
    fn drop(&mut self) {
        if !self.fin_sent.load(Ordering::Acquire) {
            let _ = self.write_tx.send((self.stream_id, Command::Fin as u8, Bytes::new()));
        }
        self.session.unregister_stream(self.stream_id);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open certificate file: {}", path))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .map(|r| {
            r.map(|c| c.into_owned())
                .context("Failed to parse PEM certificate")
        })
        .collect()
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::QuicTlsConfig;
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    const TEST_PASSWORD: &str = "test_password_123";
    const TEST_TIMEOUT_S: u64 = 15;

    fn password_hash(password: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.finalize().into()
    }

    fn generate_tls_config() -> (rustls::ServerConfig, rustls::ClientConfig) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate cert");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let server_cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
        let server_key =
            rustls::pki_types::PrivateKeyDer::try_from(key_der.clone()).expect("convert key");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .expect("server config");

        let client_cert = rustls::pki_types::CertificateDer::from(cert_der);
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(client_cert).expect("add root cert");

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        (server_config, client_config)
    }

    /// Read a frame from an async reader: (cmd, stream_id, data)
    async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(Command, u32, Bytes)> {
        let cmd = r.read_u8().await?;
        let stream_id = r.read_u32().await?;
        let data_len = r.read_u16().await?;
        let mut data = vec![0u8; data_len as usize];
        if data_len > 0 {
            r.read_exact(&mut data).await?;
        }
        Ok((Command::from(cmd), stream_id, Bytes::from(data)))
    }

    /// Write a frame: cmd | stream_id(BE u32) | data_len(BE u16) | data
    async fn write_frame<W: AsyncWrite + Unpin>(
        w: &mut W,
        cmd: Command,
        stream_id: u32,
        data: &[u8],
    ) -> Result<()> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0] = u8::from(cmd);
        header[1..5].copy_from_slice(&stream_id.to_be_bytes());
        header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        w.write_all(&header).await?;
        if !data.is_empty() {
            w.write_all(data).await?;
        }
        w.flush().await?;
        Ok(())
    }

    /// Run a mock anytls server that:
    /// 1. Accepts TLS connection
    /// 2. Verifies auth (password hash match)
    /// 3. Reads cmdSettings, sends cmdServerSettings
    /// 4. Reads cmdSYN, echoes target data back as SYNACK data
    /// 5. Echoes all cmdPSH data back
    /// 6. Closes on cmdFIN
    async fn mock_anytls_server(
        listener: TcpListener,
        expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // 1. Read auth header
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;
        assert_eq!(
            &auth_hash, &expected_password_hash,
            "password hash mismatch"
        );

        // Read padding length and padding
        let pad_len = rd.read_u16().await? as usize;
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rd.read_exact(&mut pad).await?;
        }

        // 2. Read cmdSettings
        let (settings_cmd, _, _settings_data) = read_frame(&mut rd).await?;
        assert_eq!(settings_cmd, Command::Settings, "expected Command::Settings");

        // 3. Send cmdServerSettings (v=2)
        let server_settings = format!("v={}\n", PROTOCOL_VERSION);
        write_frame(&mut wr, Command::ServerSettings, 0, server_settings.as_bytes()).await?;

        // 4. Read cmdSYN, respond with SYNACK (empty = success)
        let (syn_cmd, stream_id, _target) = read_frame(&mut rd).await?;
        assert_eq!(syn_cmd, Command::Syn, "expected Command::Syn");
        write_frame(&mut wr, Command::SynAck, stream_id, b"").await?;

        // 5. Echo loop: read frames, echo PSH data back, break on FIN
        loop {
            let (cmd, sid, data) = read_frame(&mut rd).await?;
            match cmd {
                Command::Psh => {
                    write_frame(&mut wr, Command::Psh, sid, &data).await?;
                }
                Command::Fin => {
                    break;
                }
                cmd => {
                    eprintln!("Mock server received unexpected cmd: {:?}", cmd);
                }
            }
        }

        Ok(())
    }

    /// Run a mock anytls UDP server: same auth flow, but responds with SYNACK
    /// and then echoes UDP messages (PSH frames)
    async fn mock_anytls_udp_server(
        listener: TcpListener,
        expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // Auth
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;
        assert_eq!(&auth_hash, &expected_password_hash);

        let pad_len = rd.read_u16().await? as usize;
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rd.read_exact(&mut pad).await?;
        }

        // Settings
        let (settings_cmd, _, _) = read_frame(&mut rd).await?;
        assert_eq!(settings_cmd, Command::Settings);
        write_frame(&mut wr, Command::ServerSettings, 0, b"v=2\n").await?;

        // SYN (expecting UDP-over-TCP target)
        let (syn_cmd, stream_id, _) = read_frame(&mut rd).await?;
        assert_eq!(syn_cmd, Command::Syn);
        write_frame(&mut wr, Command::SynAck, stream_id, b"").await?;

        // Echo UDP messages
        loop {
            let (cmd, sid, data) = read_frame(&mut rd).await?;
            match cmd {
                Command::Psh => {
                    write_frame(&mut wr, Command::Psh, sid, &data).await?;
                }
                Command::Fin => break,
                _ => {}
            }
        }

        Ok(())
    }

    /// Create a TLS client config for testing
    #[allow(dead_code)]
    fn test_tls_client_config(_client_cfg: rustls::ClientConfig) -> QuicTlsConfig {
        QuicTlsConfig {
            enable: true,
            insecure: false,
            zero_rtt: false,
            sni: Some("localhost".to_string()),
            cert: None,
            key: None,
            alpns: None,
            enable_jls: false,
            jls_username: String::new(),
            jls_password: String::new(),
        }
    }

    /// Run a mock anytls server that mismatches on auth and closes the connection.
    async fn mock_anytls_auth_fail_server(
        listener: TcpListener,
        _expected_password_hash: [u8; 32],
        acceptor: TlsAcceptor,
        ready_tx: oneshot::Sender<SocketAddr>,
    ) -> Result<()> {
        let addr = listener.local_addr()?;
        let _ = ready_tx.send(addr);

        let (tcp_stream, _peer) = listener.accept().await?;
        let tls_stream = acceptor.accept(tcp_stream).await?;
        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        // Read auth header
        let mut auth_hash = [0u8; AUTH_HASH_SIZE];
        rd.read_exact(&mut auth_hash).await?;

        // Close connection immediately - don't read further
        drop(rd);
        let _ = wr.shutdown().await;
        Ok(())
    }

    // ── TCP Echo Test ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anytls_tcp_echo() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, client_tls_cfg) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let phash = password_hash(TEST_PASSWORD);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (ready_tx, ready_rx) = oneshot::channel();

        // Spawn mock server
        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(TEST_TIMEOUT_S),
                mock_anytls_server(listener, phash, acceptor, ready_tx),
            )
            .await;
        });

        let server_addr = ready_rx.await.expect("server ready");

        // Create AnytlsClient
        let address = TargetAddr::Ip(server_addr);
        let tls_cfg = QuicTlsConfig {
            enable: true,
            insecure: false,
            zero_rtt: false,
            sni: Some("localhost".to_string()),
            cert: None,
            key: None,
            alpns: None,
            enable_jls: false,
            jls_username: String::new(),
            jls_password: String::new(),
        };

        let _client = AnytlsClient::new(
            address,
            TEST_PASSWORD,
            &tls_cfg,
            Duration::from_secs(10),
            None,
            None,
        )
        .expect("create client");

        // We connect directly using Session::new with our test TLS config
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], server_addr.port()));
        let tcp_stream = TcpStream::connect(socket_addr).await.expect("connect");

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        let session = Session::new(
            tcp_stream,
            Arc::new(client_tls_cfg),
            server_name,
            &phash,
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("create session");

        // Wait for server to process settings and be ready
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create stream
        let stream_id = session.next_stream_id();
        let event_rx = session.register_stream(stream_id);

        let target = TargetAddr::Domain("example.com".to_string(), 80);
        let syn_data = target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::copy_from_slice(&syn_data)))
            .expect("send SYN");

        let proxy = AnytlsProxyStream::new(stream_id, session.clone(), event_rx);

        let (mut rd, mut wr) = tokio::io::split(proxy);

        // Send data
        let test_data = b"hello anytls!";
        wr.write_all(test_data).await.expect("write");
        wr.flush().await.expect("flush");

        // Read echo
        let mut buf = vec![0u8; test_data.len()];
        rd.read_exact(&mut buf).await.expect("read echo");

        assert_eq!(&buf, test_data, "echo should match sent data");

        // Shutdown
        drop(wr);
        drop(rd);

        server_handle.abort();
    }

    // ── UDP Echo Test ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anytls_udp_echo() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, client_tls_cfg) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let phash = password_hash(TEST_PASSWORD);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (ready_tx, ready_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(TEST_TIMEOUT_S),
                mock_anytls_udp_server(listener, phash, acceptor, ready_tx),
            )
            .await;
        });

        let server_addr = ready_rx.await.expect("server ready");

        let socket_addr = SocketAddr::from(([127, 0, 0, 1], server_addr.port()));
        let tcp_stream = TcpStream::connect(socket_addr).await.expect("connect");

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        let session = Session::new(
            tcp_stream,
            Arc::new(client_tls_cfg),
            server_name,
            &phash,
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("create session");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let stream_id = session.next_stream_id();
        let event_rx = session.register_stream(stream_id);

        // Use UDP-over-TCP target
        let udp_target = TargetAddr::Domain(UDP_OVER_TCP_TARGET.to_string(), 12345);
        let syn_data = udp_target.to_bytes();
        session
            .write_tx
            .send((stream_id, Command::Syn as u8, Bytes::copy_from_slice(&syn_data)))
            .expect("send SYN");

        let udp_socket = AnytlsUdpSocket::new(stream_id, session.clone(), event_rx);

        // Send a UDP packet
        let test_data = Bytes::from_static(b"hello udp!");
        udp_socket
            .send_to(
                test_data.clone(),
                &SourceAddr::dummy(),
                &TargetAddr::dummy(),
            )
            .await
            .expect("send UDP");

        // Receive echo
        let (_from, _to, recv_data) = udp_socket.recv_from().await.expect("recv UDP");

        assert_eq!(
            &recv_data, &test_data,
            "echoed UDP payload should match sent data"
        );

        server_handle.abort();
    }

    // ── Auth Failure Test ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anytls_auth_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (server_tls_cfg, client_tls_cfg) = generate_tls_config();
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));
        let correct_phash = password_hash(TEST_PASSWORD);
        let wrong_phash = password_hash("wrong_password");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let (ready_tx, ready_rx) = oneshot::channel();

        // Server closes connection after reading auth header (no auth check needed)
        let server_handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(TEST_TIMEOUT_S),
                mock_anytls_auth_fail_server(listener, correct_phash, acceptor, ready_tx),
            )
            .await;
        });

        let server_addr = ready_rx.await.expect("server ready");

        let socket_addr = SocketAddr::from(([127, 0, 0, 1], server_addr.port()));
        let tcp_stream = TcpStream::connect(socket_addr).await.expect("connect");

        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();

        // Session::new only writes auth + settings, so it succeeds even with wrong password
        let session = Session::new(
            tcp_stream,
            Arc::new(client_tls_cfg),
            server_name,
            &wrong_phash,
            Duration::from_secs(10),
            0,
            PaddingScheme::get_default(),
        )
        .await
        .expect("session creation should succeed (auth is async)");

        // The server closes the connection → read_loop fails → session becomes dead
        let closer = session.closer.clone();
        let wait_result = tokio::time::timeout(Duration::from_secs(5), closer.wait()).await;

        assert!(
            wait_result.is_ok(),
            "session should die within 5s after server closes connection"
        );

        server_handle.abort();
    }
}
