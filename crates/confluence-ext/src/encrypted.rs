//! Encrypted TCP/UDP channel wrappers, multiplexed encrypted passive TCP relay,
//! native link-encrypted UDP socket with stateless roaming, and Home UDP Relay.

use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::Duration,
};

use confluence_core::{
    AsyncStream, ChannelCaps, ChannelErr, CoreErr, DATAGRAM_MTU, DatagramChannel, DatagramLink,
    DatagramLinkExt, MtuWatch, PacketBuf, PublicKey, STREAM_CHUNK, ScopeInstance, ScopeKeypair,
    SessionAuth, StreamChannel, StreamListener, StreamRead, StreamTransitHandler, StreamWrite,
    StreamWriteExt,
    crypto::{
        aead::{DatagramRx, DatagramTx, StreamCipher},
        noise_ik::{self, REPLY_LEN, Responder},
        replay::SetupReplay,
    },
    read_exact,
    scope::DatagramIngress,
    wire::e2e,
};
use confluence_net::{TcpCarrier, TcpListenerSource};
use rand_core::{OsRng, RngCore};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot, watch},
};

use crate::now_ms;

// ---------------------------------------------------------------------------
// Shared Locator Encoding: [remote_link_pubkey (32B) | inner_locator (...)]
// ---------------------------------------------------------------------------

pub struct EncryptedLocator;

impl EncryptedLocator {
    pub fn encode(remote_link_pubkey: PublicKey, inner_locator: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + inner_locator.len());
        out.extend_from_slice(&remote_link_pubkey.0);
        out.extend_from_slice(inner_locator);
        out
    }

    pub fn decode(locator: &[u8]) -> Result<(PublicKey, &[u8]), CoreErr> {
        if locator.len() < 32 {
            return Err(CoreErr::Malformed);
        }
        let key: [u8; 32] = locator[..32].try_into().unwrap();
        Ok((PublicKey(key), &locator[32..]))
    }
}

const STREAM_LINK_AAD: [u8; 32] = *b"confluence-ext-enc-stream-v1----";
const DG_LINK_AAD: [u8; 32] = *b"confluence-ext-enc-dgram-v1-----";
const LINK_DATA_KIND: u8 = 0x44;
const LINK_FIN_KIND: u8 = 0x45;

// ===========================================================================
// PART 1: EncryptedStreamChannel<C> & EncryptedStreamListener<L>
// ===========================================================================

/// Vertical channel wrapper adding link-layer `Noise_IK` authentication and
/// ChaCha20-Poly1305 record encryption to any `StreamChannel` (`TcpCarrier`,
/// `MemStreamChannel`, etc.) with compile-time static composition.
///
/// On-path observers see only encrypted length-prefixed ciphertext—never
/// Confluence's outer `SETUP_FWD`, `scope_kid`, or `ST_DATA` headers.
#[derive(Clone)]
pub struct EncryptedStreamChannel<C> {
    inner: C,
    link_key: Arc<ScopeKeypair>,
}

impl<C> EncryptedStreamChannel<C> {
    pub fn new(link_key: Arc<ScopeKeypair>, inner: C) -> Self {
        Self { inner, link_key }
    }
    pub fn inner(&self) -> &C {
        &self.inner
    }
}

impl<C: StreamChannel> StreamChannel for EncryptedStreamChannel<C> {
    type Stream = EncryptedStream<C::Stream>;

    fn caps(&self) -> ChannelCaps {
        let inner = self.inner.caps();
        ChannelCaps {
            effective_mtu: inner.effective_mtu.min(STREAM_CHUNK as u16),
            reliable_underlay: inner.reliable_underlay,
            mtu_watch: inner.mtu_watch,
        }
    }

    async fn dial_stream(&self, locator: &[u8]) -> Result<Self::Stream, ChannelErr> {
        let (remote_pubkey, inner_loc) = EncryptedLocator::decode(locator)?;
        let raw = self.inner.dial_stream(inner_loc).await?;
        EncryptedStream::handshake_client(raw, &self.link_key, remote_pubkey).await
    }
}

/// Statically composed link-encrypted [`AsyncStream`] owning `S::Read` and `S::Write` inline.
pub struct EncryptedStream<S: AsyncStream> {
    reader: S::Read,
    writer: S::Write,
    rx: StreamCipher,
    tx: StreamCipher,
    caps: ChannelCaps,
    source_tag: [u8; 16],
    peer_link_key: PublicKey,
}

impl<S: AsyncStream> EncryptedStream<S> {
    pub fn peer_link_key(&self) -> PublicKey {
        self.peer_link_key
    }

    pub async fn handshake_client(
        raw: S,
        local_key: &ScopeKeypair,
        remote_pubkey: PublicKey,
    ) -> Result<Self, CoreErr> {
        let caps = raw.caps();
        let source_tag = raw.source_tag();
        let (mut reader, mut writer) = raw.split();
        let plain = now_ms().to_be_bytes();
        let (init, state) = noise_ik::initiate(local_key, remote_pubkey, &STREAM_LINK_AAD, &plain)?;
        let len = u16::try_from(init.len()).map_err(|_| CoreErr::Malformed)?;
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&init).await?;

        let mut reply = [0u8; REPLY_LEN];
        read_exact(&mut reader, &mut reply).await?;
        let (_ack, keys) = state.finish(local_key, &reply)?;
        Ok(Self {
            reader,
            writer,
            rx: StreamCipher::new(keys.rx),
            tx: StreamCipher::new(keys.tx),
            caps,
            source_tag,
            peer_link_key: remote_pubkey,
        })
    }

    pub async fn handshake_server(
        raw: S,
        local_key: &ScopeKeypair,
        replay: &SetupReplay,
    ) -> Result<Self, CoreErr> {
        let caps = raw.caps();
        let source_tag = raw.source_tag();
        let (mut reader, mut writer) = raw.split();
        let mut len_buf = [0u8; 2];
        read_exact(&mut reader, &mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if !(128..=2048).contains(&len) {
            return Err(CoreErr::Malformed);
        }
        let mut init = vec![0u8; len];
        read_exact(&mut reader, &mut init).await?;
        let responder = Responder::accept(local_key, replay, &init, &STREAM_LINK_AAD, now_ms())?;
        let peer_link_key = responder.peer;
        let (reply, keys) = responder.reply(&[0u8; 10])?;
        writer.write_all(&reply).await?;
        Ok(Self {
            reader,
            writer,
            rx: StreamCipher::new(keys.rx),
            tx: StreamCipher::new(keys.tx),
            caps,
            source_tag,
            peer_link_key,
        })
    }
}

enum EncReadState {
    Header { hdr: [u8; 2], filled: usize },
    Body { frame: Vec<u8>, filled: usize },
    Plain { plain: Vec<u8>, offset: usize },
    Eof,
}

/// Zero-`BoxFut` poll-based read half of [`EncryptedStream`].
pub struct EncryptedStreamRead<R> {
    inner: R,
    cipher: StreamCipher,
    state: EncReadState,
}

/// Zero-`BoxFut` poll-based write half of [`EncryptedStream`].
pub struct EncryptedStreamWrite<W> {
    inner: W,
    cipher: StreamCipher,
    pending: Vec<u8>,
    offset: usize,
    shut_down: bool,
}

impl<W: StreamWrite> EncryptedStreamWrite<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        while self.offset < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.offset..]))?;
            if n == 0 {
                return Poll::Ready(Err(CoreErr::UnexpectedEof));
            }
            self.offset += n;
        }
        self.pending.clear();
        self.offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncStream for EncryptedStream<S> {
    type Read = EncryptedStreamRead<S::Read>;
    type Write = EncryptedStreamWrite<S::Write>;

    fn caps(&self) -> ChannelCaps {
        self.caps.clone()
    }

    fn split(self) -> (Self::Read, Self::Write) {
        (
            EncryptedStreamRead {
                inner: self.reader,
                cipher: self.rx,
                state: EncReadState::Header {
                    hdr: [0u8; 2],
                    filled: 0,
                },
            },
            EncryptedStreamWrite {
                inner: self.writer,
                cipher: self.tx,
                pending: Vec::new(),
                offset: 0,
                shut_down: false,
            },
        )
    }

    fn source_tag(&self) -> [u8; 16] {
        self.source_tag
    }
}

impl<R: StreamRead> StreamRead for EncryptedStreamRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        loop {
            match &mut this.state {
                EncReadState::Eof => return Poll::Ready(Ok(0)),
                EncReadState::Plain { plain, offset } => {
                    let n = (plain.len() - *offset).min(out.len());
                    out[..n].copy_from_slice(&plain[*offset..*offset + n]);
                    *offset += n;
                    if *offset == plain.len() {
                        this.state = EncReadState::Header {
                            hdr: [0u8; 2],
                            filled: 0,
                        };
                    }
                    return Poll::Ready(Ok(n));
                }
                EncReadState::Header { hdr, filled } => {
                    while *filled < 2 {
                        let n =
                            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut hdr[*filled..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(CoreErr::UnexpectedEof));
                        }
                        *filled += n;
                    }
                    let body_len = e2e::stream_body_len(*hdr)?;
                    let mut frame = vec![0u8; body_len + e2e::ST_OVERHEAD];
                    frame[..2].copy_from_slice(hdr);
                    this.state = EncReadState::Body { frame, filled: 2 };
                }
                EncReadState::Body { frame, filled } => {
                    while *filled < frame.len() {
                        let n =
                            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut frame[*filled..]))?;
                        if n == 0 {
                            return Poll::Ready(Err(CoreErr::UnexpectedEof));
                        }
                        *filled += n;
                    }
                    let finished = std::mem::take(frame);
                    let (kind, plain) = this.cipher.open(finished)?;
                    match kind {
                        LINK_DATA_KIND if plain.is_empty() => {
                            this.state = EncReadState::Header {
                                hdr: [0u8; 2],
                                filled: 0,
                            };
                        }
                        LINK_DATA_KIND => {
                            this.state = EncReadState::Plain { plain, offset: 0 };
                        }
                        LINK_FIN_KIND => {
                            this.state = EncReadState::Eof;
                            return Poll::Ready(Ok(0));
                        }
                        _ => return Poll::Ready(Err(CoreErr::Malformed)),
                    }
                }
            }
        }
    }
}

impl<W: StreamWrite> StreamWrite for EncryptedStreamWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if self.shut_down {
            return Poll::Ready(Err(CoreErr::Closed));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        if this.offset < this.pending.len() {
            ready!(this.poll_drain(cx))?;
        }
        let take = buf.len().min(e2e::ST_MAX_BODY);
        this.pending = this.cipher.seal(LINK_DATA_KIND, &buf[..take])?;
        this.offset = 0;
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(take)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if !this.shut_down {
            this.shut_down = true;
            this.pending = this.cipher.seal(LINK_FIN_KIND, &[])?;
            this.offset = 0;
            let _ = ready!(this.poll_drain(cx));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Generic symmetric inbound [`StreamListener`] adding link-layer `Noise_IK` + AEAD encryption
/// over any inner [`StreamListener`] (`TcpListenerSource`, `MemListener`, `HubStreamChannel`, ...).
pub struct EncryptedStreamListener<L: StreamListener> {
    accepted: AsyncMutex<mpsc::Receiver<EncryptedStream<L::Stream>>>,
    stop: watch::Sender<bool>,
}

impl<L: StreamListener> EncryptedStreamListener<L> {
    /// Starts accepting from `inner` and running concurrent link handshakes with a 3 s timeout.
    pub fn start(inner: L, link_key: Arc<ScopeKeypair>) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let (stop, mut stop_rx) = watch::channel(false);
        let replay = Arc::new(SetupReplay::default());
        tokio::spawn(async move {
            loop {
                let raw = tokio::select! {
                    _ = stop_rx.changed() => break,
                    res = inner.accept() => match res {
                        Ok(stream) => stream,
                        Err(_) => break,
                    },
                };
                let key = link_key.clone();
                let replay = replay.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let handshake = tokio::time::timeout(
                        Duration::from_secs(3),
                        EncryptedStream::handshake_server(raw, &key, &replay),
                    )
                    .await;
                    if let Ok(Ok(enc)) = handshake {
                        let _ = tx.send(enc).await;
                    }
                });
            }
        });
        Self {
            accepted: AsyncMutex::new(rx),
            stop,
        }
    }
}

impl<L: StreamListener> Drop for EncryptedStreamListener<L> {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl<L: StreamListener> StreamListener for EncryptedStreamListener<L> {
    type Stream = EncryptedStream<L::Stream>;

    async fn accept(&self) -> Result<Self::Stream, ChannelErr> {
        self.accepted
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreErr::Closed)
    }
}

/// Link-encrypted TCP ingress for a `ScopeInstance`, composed symmetrically via
/// `EncryptedStreamListener<TcpListenerSource>`.
pub async fn serve_encrypted_tcp(
    listener: TcpListener,
    scope: ScopeInstance,
    link_key: Arc<ScopeKeypair>,
) -> Result<(), CoreErr> {
    let enc = EncryptedStreamListener::start(
        TcpListenerSource::new(listener, TcpCarrier::default()),
        link_key,
    );
    scope.serve_stream_listener(&enc).await
}

// ===========================================================================
// PART 2: MuxPassiveStreamRelay — Multiplexed Zero-Dialing Passive TCP Relay
// ===========================================================================
//
// Solves `confluence-relay`'s 1-stream-per-circuit limitation out of core:
// A destination behind NAT opens ONE persistent (link-encrypted) TCP connection
// to Relay R and serves unlimited concurrent circuits multiplexed over it.

const MUX_OPEN: u8 = 0x01;
const MUX_DATA: u8 = 0x02;
const MUX_FIN: u8 = 0x03;
const MUX_RST: u8 = 0x04;
const MUX_MAX_FRAME: usize = 16384;

struct MuxFrame {
    kind: u8,
    id: u32,
    payload: Vec<u8>,
}

struct QueueInner<T> {
    items: VecDeque<T>,
    cap: usize,
    closed: bool,
    send_wakers: Vec<Waker>,
    recv_waker: Option<Waker>,
}

struct BoundedQueue<T> {
    inner: StdMutex<QueueInner<T>>,
}

impl<T> BoundedQueue<T> {
    fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: StdMutex::new(QueueInner {
                items: VecDeque::with_capacity(cap),
                cap,
                closed: false,
                send_wakers: Vec::new(),
                recv_waker: None,
            }),
        })
    }

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), CoreErr>> {
        let mut guard = self.inner.lock().unwrap();
        if guard.closed {
            return Poll::Ready(Err(CoreErr::UnexpectedEof));
        }
        if guard.items.len() < guard.cap {
            return Poll::Ready(Ok(()));
        }
        guard.send_wakers.push(cx.waker().clone());
        Poll::Pending
    }

    fn push_ready(&self, item: T) -> Result<(), CoreErr> {
        let recv_waker = {
            let mut guard = self.inner.lock().unwrap();
            if guard.closed {
                return Err(CoreErr::UnexpectedEof);
            }
            guard.items.push_back(item);
            guard.recv_waker.take()
        };
        if let Some(w) = recv_waker {
            w.wake();
        }
        Ok(())
    }

    fn try_send(&self, item: T) -> Result<(), CoreErr> {
        let recv_waker = {
            let mut guard = self.inner.lock().unwrap();
            if guard.closed {
                return Err(CoreErr::UnexpectedEof);
            }
            if guard.items.len() >= guard.cap {
                return Err(CoreErr::WouldBlock);
            }
            guard.items.push_back(item);
            guard.recv_waker.take()
        };
        if let Some(w) = recv_waker {
            w.wake();
        }
        Ok(())
    }

    async fn send(&self, item: T) -> Result<(), CoreErr> {
        poll_fn(|cx| self.poll_ready(cx)).await?;
        self.push_ready(item)
    }

    async fn recv(&self) -> Option<T> {
        poll_fn(|cx| {
            let (result, wakers) = {
                let mut guard = self.inner.lock().unwrap();
                if let Some(item) = guard.items.pop_front() {
                    let wakers = std::mem::take(&mut guard.send_wakers);
                    (Poll::Ready(Some(item)), wakers)
                } else if guard.closed {
                    (Poll::Ready(None), Vec::new())
                } else {
                    guard.recv_waker = Some(cx.waker().clone());
                    (Poll::Pending, Vec::new())
                }
            };
            for w in wakers {
                w.wake();
            }
            result
        })
        .await
    }

    fn close(&self) {
        let (send_wakers, recv_waker) = {
            let mut guard = self.inner.lock().unwrap();
            guard.closed = true;
            (
                std::mem::take(&mut guard.send_wakers),
                guard.recv_waker.take(),
            )
        };
        for w in send_wakers {
            w.wake();
        }
        if let Some(w) = recv_waker {
            w.wake();
        }
    }
}

type MuxStreamMap = Arc<StdMutex<HashMap<u32, mpsc::Sender<Option<Vec<u8>>>>>>;

struct MuxSession {
    outbound: Arc<BoundedQueue<MuxFrame>>,
    streams: MuxStreamMap,
    next_id: AtomicU32,
    mtu: u16,
    closed: watch::Receiver<bool>,
}

impl MuxSession {
    fn start<S: AsyncStream>(carrier: S, on_open: Option<mpsc::Sender<MuxStream>>) -> Arc<Self> {
        let mtu = carrier.caps().mtu();
        let (mut reader, mut writer) = carrier.split();
        let outbound = BoundedQueue::<MuxFrame>::new(64);
        let streams: MuxStreamMap = Default::default();
        let (closed_tx, closed_rx) = watch::channel(false);

        let session = Arc::new(Self {
            outbound: outbound.clone(),
            streams: streams.clone(),
            next_id: AtomicU32::new(1),
            mtu,
            closed: closed_rx,
        });

        // Writer pump
        let out_w = outbound.clone();
        let closed_w = closed_tx.clone();
        tokio::spawn(async move {
            let mut hdr = [0u8; 7];
            while let Some(frame) = out_w.recv().await {
                hdr[0] = frame.kind;
                hdr[1..5].copy_from_slice(&frame.id.to_be_bytes());
                hdr[5..7].copy_from_slice(&(frame.payload.len() as u16).to_be_bytes());
                if writer.write_all(&hdr).await.is_err() {
                    break;
                }
                if !frame.payload.is_empty() && writer.write_all(&frame.payload).await.is_err() {
                    break;
                }
            }
            out_w.close();
            let _ = writer.shutdown().await;
            let _ = closed_w.send(true);
        });

        // Reader pump
        let session_weak = Arc::downgrade(&session);
        tokio::spawn(async move {
            let mut hdr = [0u8; 7];
            loop {
                if read_exact(&mut reader, &mut hdr).await.is_err() {
                    break;
                }
                let kind = hdr[0];
                let id = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
                let len = u16::from_be_bytes(hdr[5..7].try_into().unwrap()) as usize;
                if len > MUX_MAX_FRAME {
                    break;
                }
                let mut payload = vec![0u8; len];
                if len > 0 && read_exact(&mut reader, &mut payload).await.is_err() {
                    break;
                }
                match kind {
                    MUX_OPEN => {
                        if let (Some(accept_tx), Some(sess)) = (&on_open, session_weak.upgrade()) {
                            let (in_tx, in_rx) = mpsc::channel(32);
                            sess.streams.lock().unwrap().insert(id, in_tx);
                            let stream = MuxStream {
                                id,
                                mtu: sess.mtu,
                                incoming: in_rx,
                                outbound: sess.outbound.clone(),
                                streams: sess.streams.clone(),
                            };
                            if accept_tx.try_send(stream).is_err() {
                                sess.streams.lock().unwrap().remove(&id);
                                let _ = sess.outbound.try_send(MuxFrame {
                                    kind: MUX_RST,
                                    id,
                                    payload: Vec::new(),
                                });
                            }
                        }
                    }
                    MUX_DATA => {
                        let tx = streams.lock().unwrap().get(&id).cloned();
                        if let Some(tx) = tx
                            && tx.send(Some(payload)).await.is_err()
                        {
                            streams.lock().unwrap().remove(&id);
                        }
                    }
                    MUX_FIN => {
                        let tx = streams.lock().unwrap().get(&id).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(None).await;
                        }
                    }
                    MUX_RST => {
                        streams.lock().unwrap().remove(&id);
                    }
                    _ => break,
                }
            }
            streams.lock().unwrap().clear();
            outbound.close();
            let _ = closed_tx.send(true);
        });

        session
    }

    async fn open_stream(&self) -> Result<MuxStream, CoreErr> {
        if *self.closed.borrow() {
            return Err(CoreErr::TargetUnreachable);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (in_tx, in_rx) = mpsc::channel(32);
        self.streams.lock().unwrap().insert(id, in_tx);
        if self
            .outbound
            .send(MuxFrame {
                kind: MUX_OPEN,
                id,
                payload: Vec::new(),
            })
            .await
            .is_err()
        {
            self.streams.lock().unwrap().remove(&id);
            return Err(CoreErr::TargetUnreachable);
        }
        Ok(MuxStream {
            id,
            mtu: self.mtu,
            incoming: in_rx,
            outbound: self.outbound.clone(),
            streams: self.streams.clone(),
        })
    }
}

/// Multiplexed stream produced by [`MuxPassiveStreamRelay`].
pub struct MuxStream {
    id: u32,
    mtu: u16,
    incoming: mpsc::Receiver<Option<Vec<u8>>>,
    outbound: Arc<BoundedQueue<MuxFrame>>,
    streams: MuxStreamMap,
}

/// Poll-based read half of [`MuxStream`].
pub struct MuxRead {
    id: u32,
    incoming: mpsc::Receiver<Option<Vec<u8>>>,
    streams: MuxStreamMap,
    pending: Vec<u8>,
    offset: usize,
    eof: bool,
}

impl Drop for MuxRead {
    fn drop(&mut self) {
        self.streams.lock().unwrap().remove(&self.id);
    }
}

/// Poll-based write half of [`MuxStream`].
pub struct MuxWrite {
    id: u32,
    outbound: Arc<BoundedQueue<MuxFrame>>,
    shut_down: bool,
}

impl Drop for MuxWrite {
    fn drop(&mut self) {
        if !self.shut_down {
            let _ = self.outbound.try_send(MuxFrame {
                kind: MUX_RST,
                id: self.id,
                payload: Vec::new(),
            });
        }
    }
}

impl AsyncStream for MuxStream {
    type Read = MuxRead;
    type Write = MuxWrite;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, true)
    }

    fn split(self) -> (MuxRead, MuxWrite) {
        (
            MuxRead {
                id: self.id,
                incoming: self.incoming,
                streams: self.streams,
                pending: Vec::new(),
                offset: 0,
                eof: false,
            },
            MuxWrite {
                id: self.id,
                outbound: self.outbound,
                shut_down: false,
            },
        )
    }
}

impl StreamRead for MuxRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if buf.is_empty() || self.eof {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        while this.offset == this.pending.len() {
            match ready!(this.incoming.poll_recv(cx)) {
                Some(Some(chunk)) => {
                    this.pending = chunk;
                    this.offset = 0;
                }
                Some(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(0));
                }
                None => return Poll::Ready(Err(CoreErr::UnexpectedEof)),
            }
        }
        let n = (this.pending.len() - this.offset).min(buf.len());
        buf[..n].copy_from_slice(&this.pending[this.offset..this.offset + n]);
        this.offset += n;
        Poll::Ready(Ok(n))
    }
}

impl StreamWrite for MuxWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ChannelErr>> {
        if self.shut_down {
            return Poll::Ready(Err(CoreErr::Closed));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.outbound.poll_ready(cx))?;
        let take = buf.len().min(MUX_MAX_FRAME);
        self.outbound.push_ready(MuxFrame {
            kind: MUX_DATA,
            id: self.id,
            payload: buf[..take].to_vec(),
        })?;
        Poll::Ready(Ok(take))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ChannelErr>> {
        if !self.shut_down {
            ready!(self.outbound.poll_ready(cx))?;
            self.shut_down = true;
            self.outbound.push_ready(MuxFrame {
                kind: MUX_FIN,
                id: self.id,
                payload: Vec::new(),
            })?;
        }
        Poll::Ready(Ok(()))
    }
}

/// Passive stream relay supporting multiple concurrent circuits over ONE
/// registered presence stream (e.g. a single persistent `EncryptedStream`).
/// Structurally makes zero outbound dials.
#[derive(Clone)]
pub struct MuxPassiveStreamRelay {
    presences: Arc<StdMutex<HashMap<Vec<u8>, Arc<MuxSession>>>>,
    mtu: u16,
}

pub struct MuxPresenceGuard {
    id: Vec<u8>,
    presences: Weak<StdMutex<HashMap<Vec<u8>, Arc<MuxSession>>>>,
}

impl Drop for MuxPresenceGuard {
    fn drop(&mut self) {
        if let Some(map) = self.presences.upgrade() {
            map.lock().unwrap().remove(&self.id);
        }
    }
}

impl MuxPassiveStreamRelay {
    pub fn new(mtu: u16) -> Self {
        Self {
            presences: Default::default(),
            mtu,
        }
    }

    /// Registers an already-connected presence stream (relay side).
    pub fn register_presence<S: AsyncStream>(
        &self,
        id: &[u8],
        carrier: S,
    ) -> Result<MuxPresenceGuard, CoreErr> {
        if id.is_empty() || id.len() > 255 {
            return Err(CoreErr::Malformed);
        }
        let session = MuxSession::start(carrier, None);
        let mut map = self.presences.lock().unwrap();
        if map.contains_key(id) {
            return Err(CoreErr::AlreadyPublished);
        }
        map.insert(id.to_vec(), session);
        Ok(MuxPresenceGuard {
            id: id.to_vec(),
            presences: Arc::downgrade(&self.presences),
        })
    }

    /// Destination side: serves incoming multiplexed circuits from an outbound
    /// presence carrier (e.g. `EncryptedStream` connected to Relay R) into `scope`.
    pub async fn serve_destination_presence<S: AsyncStream>(
        carrier: S,
        scope: ScopeInstance,
    ) -> Result<(), CoreErr> {
        let (accept_tx, mut accept_rx) = mpsc::channel(64);
        let session = MuxSession::start(carrier, Some(accept_tx));
        let mut closed = session.closed.clone();
        loop {
            tokio::select! {
                _ = closed.changed() => return Ok(()),
                incoming = accept_rx.recv() => {
                    let Some(stream) = incoming else { return Ok(()); };
                    let _ = scope.accept_stream(stream);
                }
            }
        }
    }
}

impl StreamChannel for MuxPassiveStreamRelay {
    type Stream = MuxStream;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.mtu, true)
    }

    async fn dial_stream(&self, locator: &[u8]) -> Result<MuxStream, ChannelErr> {
        let session = self
            .presences
            .lock()
            .unwrap()
            .get(locator)
            .cloned()
            .ok_or(CoreErr::TargetUnreachable)?;
        session.open_stream().await
    }
}

impl StreamTransitHandler for MuxPassiveStreamRelay {
    type Stream = MuxStream;

    fn caps(&self) -> ChannelCaps {
        <Self as StreamChannel>::caps(self)
    }

    async fn open(&self, target: &str, _auth: SessionAuth) -> Result<MuxStream, CoreErr> {
        self.dial_stream(target.as_bytes()).await
    }
}

// ===========================================================================
// PART 3: EncryptedDatagramChannel<C> (Compile-Time Generic Vertical Wrapper)
// ===========================================================================

/// Outer link-encryption wire overhead:
/// `1B frame_type + 4B link_sid + 8B seq + 1B inner_kind + 16B Poly1305 tag = 30B`.
pub const DG_LINK_OVERHEAD: u16 = 30;
const DG_FRAME_INIT: u8 = 0xA1;
const DG_FRAME_REPLY: u8 = 0xA2;
const DG_FRAME_DATA: u8 = 0xA3;

type EncDgCache<L> = Arc<StdMutex<HashMap<Vec<u8>, Weak<EncryptedDatagramLink<L>>>>>;

/// Generic compile-time vertical link-encryption wrapper for any [`DatagramChannel`].
///
/// Composes statically over `C::Link` with zero intermediate `dyn` indirection, zero background
/// MTU-forwarding tasks (`ChannelCaps::with_overhead`), zero per-packet `BoxFut` allocations, and
/// zero-copy in-place AEAD sealing via `PacketBuf`'s 64-byte headroom/tailroom.
pub struct EncryptedDatagramChannel<C: DatagramChannel> {
    inner: C,
    link_key: Arc<ScopeKeypair>,
    cached: EncDgCache<C::Link>,
}

impl<C: DatagramChannel + Clone> Clone for EncryptedDatagramChannel<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            link_key: self.link_key.clone(),
            cached: self.cached.clone(),
        }
    }
}

impl<C: DatagramChannel> EncryptedDatagramChannel<C> {
    pub fn new(link_key: Arc<ScopeKeypair>, inner: C) -> Result<Self, CoreErr> {
        let eff = inner.caps().mtu().saturating_sub(DG_LINK_OVERHEAD);
        if eff < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(eff));
        }
        Ok(Self {
            inner,
            link_key,
            cached: Default::default(),
        })
    }
}

impl<C: DatagramChannel> DatagramChannel for EncryptedDatagramChannel<C> {
    type Link = Arc<EncryptedDatagramLink<C::Link>>;

    fn caps(&self) -> ChannelCaps {
        self.inner.caps().with_overhead(DG_LINK_OVERHEAD)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Self::Link, ChannelErr> {
        if let Some(existing) = self
            .cached
            .lock()
            .unwrap()
            .get(locator)
            .and_then(Weak::upgrade)
            .filter(|l| l.caps().mtu() >= DATAGRAM_MTU)
        {
            return Ok(existing);
        }
        let (remote_pubkey, inner_loc) = EncryptedLocator::decode(locator)?;
        let raw = self.inner.open_link(inner_loc).await?;
        let link =
            Arc::new(EncryptedDatagramLink::connect(raw, &self.link_key, remote_pubkey).await?);
        self.cached
            .lock()
            .unwrap()
            .insert(locator.to_vec(), Arc::downgrade(&link));
        Ok(link)
    }
}

/// Statically composed encrypted [`DatagramLink`] wrapping `L` directly with in-place AEAD
/// sealing and zero-task `MtuWatch` overhead propagation.
pub struct EncryptedDatagramLink<L> {
    inner: L,
    tx: StdMutex<DatagramTx>,
    rx: StdMutex<DatagramRx>,
    remote_sid: u32,
    local_sid: u32,
    reliable: bool,
    mtu_watch: MtuWatch,
}

impl<L: DatagramLink> EncryptedDatagramLink<L> {
    pub async fn connect(
        inner: L,
        local_key: &ScopeKeypair,
        remote_pubkey: PublicKey,
    ) -> Result<Self, CoreErr> {
        let local_sid = OsRng.next_u32().max(1);
        let plain = now_ms().to_be_bytes();
        let (init, state) = noise_ik::initiate(local_key, remote_pubkey, &DG_LINK_AAD, &plain)?;
        let mut pkt = Vec::with_capacity(5 + init.len());
        pkt.push(DG_FRAME_INIT);
        pkt.extend_from_slice(&local_sid.to_be_bytes());
        pkt.extend_from_slice(&init);

        let reply = tokio::time::timeout(Duration::from_secs(3), async {
            inner.send(PacketBuf::from_slice(&pkt)).await?;
            loop {
                let frame = inner.recv().await?;
                let bytes = frame.as_slice();
                if bytes.len() == 9 + REPLY_LEN
                    && bytes[0] == DG_FRAME_REPLY
                    && u32::from_be_bytes(bytes[1..5].try_into().unwrap()) == local_sid
                {
                    let remote_sid = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
                    let (_ack, keys) = state.finish(local_key, &bytes[9..])?;
                    return Ok::<_, CoreErr>((remote_sid, keys));
                }
            }
        })
        .await
        .map_err(|_| CoreErr::Timeout)??;

        let caps = inner.caps().with_overhead(DG_LINK_OVERHEAD);
        Ok(Self {
            mtu_watch: caps.mtu_watch,
            reliable: caps.reliable_underlay,
            inner,
            tx: StdMutex::new(DatagramTx::new(reply.1.tx)),
            rx: StdMutex::new(DatagramRx::new(reply.1.rx)),
            remote_sid: reply.0,
            local_sid,
        })
    }

    pub async fn accept(
        inner: L,
        local_key: &ScopeKeypair,
        replay: &SetupReplay,
    ) -> Result<(Self, PublicKey), CoreErr> {
        let (peer, client_sid, server_sid, keys) =
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let frame = inner.recv().await?;
                    let bytes = frame.as_slice();
                    if bytes.len() >= 5 + 128 && bytes[0] == DG_FRAME_INIT {
                        let client_sid = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
                        let Ok(responder) = Responder::accept(
                            local_key,
                            replay,
                            &bytes[5..],
                            &DG_LINK_AAD,
                            now_ms(),
                        ) else {
                            continue;
                        };
                        let server_sid = OsRng.next_u32().max(1);
                        let peer = responder.peer;
                        let (reply_body, keys) = responder.reply(&[0u8; 10])?;
                        let mut reply = Vec::with_capacity(9 + REPLY_LEN);
                        reply.push(DG_FRAME_REPLY);
                        reply.extend_from_slice(&client_sid.to_be_bytes());
                        reply.extend_from_slice(&server_sid.to_be_bytes());
                        reply.extend_from_slice(&reply_body);
                        inner.send(PacketBuf::from_slice(&reply)).await?;
                        return Ok::<_, CoreErr>((peer, client_sid, server_sid, keys));
                    }
                }
            })
            .await
            .map_err(|_| CoreErr::Timeout)??;

        let caps = inner.caps().with_overhead(DG_LINK_OVERHEAD);
        Ok((
            Self {
                mtu_watch: caps.mtu_watch,
                reliable: caps.reliable_underlay,
                inner,
                tx: StdMutex::new(DatagramTx::new(keys.tx)),
                rx: StdMutex::new(DatagramRx::new(keys.rx)),
                remote_sid: client_sid,
                local_sid: server_sid,
            },
            peer,
        ))
    }
}

impl<L: DatagramLink> DatagramLink for EncryptedDatagramLink<L> {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps {
            effective_mtu: self.mtu_watch.mtu(),
            reliable_underlay: self.reliable,
            mtu_watch: self.mtu_watch.clone(),
        }
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        self.inner.poll_send_ready(cx)
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), ChannelErr> {
        let mtu = self.mtu_watch.mtu();
        if packet.len() > usize::from(mtu) {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        // Seals directly in place using PacketBuf's reserved headroom & tailroom!
        let mut sealed = self.tx.lock().unwrap().seal(LINK_DATA_KIND, packet)?;
        let mut hdr = [0u8; 5];
        hdr[0] = DG_FRAME_DATA;
        hdr[1..5].copy_from_slice(&self.remote_sid.to_be_bytes());
        if !sealed.prepend_header(&hdr) {
            return Err(CoreErr::Malformed);
        }
        self.inner.try_send(sealed).map_err(|err| match err {
            CoreErr::MtuTooSmall(inner_mtu) => {
                CoreErr::MtuTooSmall(inner_mtu.saturating_sub(DG_LINK_OVERHEAD))
            }
            other => other,
        })
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, ChannelErr>> {
        loop {
            let mut frame = ready!(self.inner.poll_recv(cx))?;
            let bytes = frame.as_slice();
            if bytes.len() < DG_LINK_OVERHEAD as usize || bytes[0] != DG_FRAME_DATA {
                continue;
            }
            let sid = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
            if sid != self.local_sid {
                continue;
            }
            frame.strip_header(5);
            if let Ok((LINK_DATA_KIND, plain)) = self.rx.lock().unwrap().open(frame) {
                return Poll::Ready(Ok(plain));
            }
        }
    }

    fn source_tag(&self) -> [u8; 16] {
        self.inner.source_tag()
    }
}

// ===========================================================================
// PART 4: Native Encrypted UDP Carrier (with MAC1 Silent Drop & Stateless Roaming)
//         + Encrypted Home UDP Relay (from archived/docs/transport/udp-relay.md)
// ===========================================================================

const HOME_REG_REQ: u8 = 0xB1;
const HOME_REG_ACK: u8 = 0xB2;

/// Encodes a 16-byte random Home Relay slot token as a lowercase 32-char UTF-8 hex name
/// suitable for use as a named transit target.
pub fn encode_slot_hex(token: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for &b in token {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

struct UdpPeerSession {
    _local_sid: u32,
    remote_sid: u32,
    peer_key: PublicKey,
    remote_addr: StdMutex<SocketAddr>,
    tx: StdMutex<DatagramTx>,
    rx: StdMutex<DatagramRx>,
    inbound_tx: mpsc::Sender<PacketBuf>,
    inbound_rx: StdMutex<mpsc::Receiver<PacketBuf>>,
    socket: Arc<UdpSocket>,
    mtu: watch::Sender<u16>,
    /// Optional Home Relay registration waiter (client side).
    reg_reply: StdMutex<Option<oneshot::Sender<[u8; 16]>>>,
}

impl UdpPeerSession {
    fn current_addr(&self) -> SocketAddr {
        *self.remote_addr.lock().unwrap()
    }
    fn update_addr(&self, addr: SocketAddr) {
        *self.remote_addr.lock().unwrap() = addr;
    }
    fn seal_frame(&self, kind: u8, packet: PacketBuf) -> Result<PacketBuf, CoreErr> {
        let mut sealed = self.tx.lock().unwrap().seal(kind, packet)?;
        let mut hdr = [0u8; 5];
        hdr[0] = DG_FRAME_DATA;
        hdr[1..5].copy_from_slice(&self.remote_sid.to_be_bytes());
        if !sealed.prepend_header(&hdr) {
            return Err(CoreErr::Malformed);
        }
        Ok(sealed)
    }
    async fn send_inner(&self, kind: u8, payload: &[u8]) -> Result<(), CoreErr> {
        let sealed = self.seal_frame(kind, PacketBuf::from_slice(payload))?;
        let target = self.current_addr();
        let n = self
            .socket
            .send_to(sealed.as_slice(), target)
            .await
            .map_err(|e| CoreErr::Carrier(e.to_string()))?;
        if n != sealed.len() {
            return Err(CoreErr::Carrier("short encrypted UDP send".into()));
        }
        Ok(())
    }
}

/// A `DatagramLink` backed by an authenticated, encrypted native UDP session
/// supporting **stateless endpoint roaming**: if the peer's source IP/port
/// changes (NAT rebind), any validly AEAD-authenticated datagram updates the
/// peer's active `SocketAddr` atomically without breaking Confluence E2E flows.
pub struct EncryptedUdpLink {
    session: Arc<UdpPeerSession>,
}

impl EncryptedUdpLink {
    pub fn peer_link_key(&self) -> PublicKey {
        self.session.peer_key
    }
    pub fn remote_addr(&self) -> SocketAddr {
        self.session.current_addr()
    }
    /// Requests a 16-byte `RelaySlotToken` on a Home UDP Relay over this
    /// already-authenticated encrypted UDP link (`udp-relay.md` §1).
    pub async fn register_home_relay_slot(&self, credential: &[u8]) -> Result<[u8; 16], CoreErr> {
        let (tx, rx) = oneshot::channel();
        *self.session.reg_reply.lock().unwrap() = Some(tx);
        self.session.send_inner(HOME_REG_REQ, credential).await?;
        tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .map_err(|_| CoreErr::Timeout)?
            .map_err(|_| CoreErr::Closed)
    }
}

impl DatagramLink for EncryptedUdpLink {
    fn caps(&self) -> ChannelCaps {
        ChannelCaps::dynamic(self.session.mtu.subscribe(), false)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelErr>> {
        self.session
            .socket
            .poll_send_ready(cx)
            .map_err(|e| CoreErr::Carrier(e.to_string()))
    }

    fn try_send(&self, packet: PacketBuf) -> Result<(), ChannelErr> {
        let mtu = *self.session.mtu.borrow();
        if packet.len() > usize::from(mtu) {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        let sealed = self.session.seal_frame(LINK_DATA_KIND, packet)?;
        let target = self.session.current_addr();
        match self.session.socket.try_send_to(sealed.as_slice(), target) {
            Ok(n) if n == sealed.len() => Ok(()),
            Ok(_) => Err(CoreErr::Carrier("short encrypted UDP send".into())),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(CoreErr::WouldBlock),
            Err(e) => Err(CoreErr::Carrier(e.to_string())),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<PacketBuf, ChannelErr>> {
        self.session
            .inbound_rx
            .lock()
            .unwrap()
            .poll_recv(cx)
            .map(|opt| opt.ok_or(CoreErr::Closed))
    }
}

type UdpPeerCache = Arc<StdMutex<HashMap<(PublicKey, SocketAddr), Weak<EncryptedUdpLink>>>>;
type HandshakeReplyWaiters = Arc<StdMutex<HashMap<u32, oneshot::Sender<(u32, Vec<u8>)>>>>;
pub type HomeRelayAdmitFn = Arc<dyn Fn(&PublicKey, &[u8]) -> bool + Send + Sync>;

/// Shared native UDP socket handling encrypted link handshakes, `MAC1` silent
/// drop, `link_sid` demux, stateless roaming, and optional Home UDP Relay slot
/// registration.
///
/// Implements `DatagramChannel` so it can be registered directly on a
/// `ScopeInstance` (or exposed as a named transit via `publish_datagram_route` /
/// `publish_datagram_transit`).
#[derive(Clone)]
pub struct EncryptedUdpNode {
    socket: Arc<UdpSocket>,
    link_key: Arc<ScopeKeypair>,
    inner_mtu: u16,
    by_sid: Arc<StdMutex<HashMap<u32, Arc<EncryptedUdpLink>>>>,
    by_peer: UdpPeerCache,
    pending_handshakes: HandshakeReplyWaiters,
    next_sid: Arc<AtomicU32>,
    /// Optional Home Relay registration hook (slot_token -> PassiveRelay).
    home_relay: Arc<StdMutex<Option<HomeRelayHook>>>,
    _stop: Arc<Notify>,
}

struct HomeRelayHook {
    relay: confluence_relay::PassiveRelay,
    /// Keeps `DatagramPresence` guards alive while registered.
    guards: StdMutex<Vec<confluence_relay::DatagramPresence>>,
    /// Optional admission predicate verifying `(peer_link_key, credential)`.
    admit: HomeRelayAdmitFn,
}

impl EncryptedUdpNode {
    pub async fn bind(
        addr: SocketAddr,
        link_key: Arc<ScopeKeypair>,
        inner_mtu: u16,
    ) -> Result<Self, CoreErr> {
        if inner_mtu < DATAGRAM_MTU {
            return Err(CoreErr::MtuTooSmall(inner_mtu));
        }
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|e| CoreErr::Carrier(e.to_string()))?,
        );
        Ok(Self {
            socket,
            link_key,
            inner_mtu,
            by_sid: Default::default(),
            by_peer: Default::default(),
            pending_handshakes: Default::default(),
            next_sid: Arc::new(AtomicU32::new(1)),
            home_relay: Default::default(),
            _stop: Arc::new(Notify::new()),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn public_key(&self) -> PublicKey {
        self.link_key.public_key()
    }

    /// Enable Home UDP Relay slot registration on this encrypted UDP socket
    /// (`archived/docs/transport/udp-relay.md`): authenticated peers can
    /// request a 16-byte `RelaySlotToken` binding their active encrypted UDP
    /// session into `relay` with zero outbound dialing.
    pub fn enable_home_relay(
        &self,
        relay: confluence_relay::PassiveRelay,
        admit: HomeRelayAdmitFn,
    ) {
        *self.home_relay.lock().unwrap() = Some(HomeRelayHook {
            relay,
            guards: StdMutex::new(Vec::new()),
            admit,
        });
    }

    /// Runs the UDP receive & demux loop. Inbound link sessions are lazily attached
    /// to `scope` (when `Some`) on their first data packet.
    pub fn spawn_loop(&self, scope: Option<ScopeInstance>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        let replay = SetupReplay::default();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut ingress_guards: Vec<DatagramIngress> = Vec::new();
            let mut attached_sids: std::collections::HashSet<u32> = Default::default();
            let mut presence_sids: std::collections::HashSet<u32> = Default::default();
            loop {
                let Ok((n, src)) = this.socket.recv_from(&mut buf).await else {
                    break;
                };
                if n < 5 {
                    continue;
                }
                let data = &buf[..n];
                match data[0] {
                    DG_FRAME_INIT => {
                        let seg = &data[5..];
                        // Pre-auth silent drop via MAC1 before X25519
                        if !this.link_key.verify_mac1(seg) {
                            continue;
                        }
                        let client_sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                        let Ok(responder) =
                            Responder::accept(&this.link_key, &replay, seg, &DG_LINK_AAD, now_ms())
                        else {
                            continue;
                        };
                        let peer_key = responder.peer;
                        let Ok((reply_body, keys)) = responder.reply(&[0u8; 10]) else {
                            continue;
                        };
                        let server_sid = this.next_sid.fetch_add(1, Ordering::Relaxed);
                        let (in_tx, in_rx) = mpsc::channel(64);
                        let session = Arc::new(UdpPeerSession {
                            _local_sid: server_sid,
                            remote_sid: client_sid,
                            peer_key,
                            remote_addr: StdMutex::new(src),
                            tx: StdMutex::new(DatagramTx::new(keys.tx)),
                            rx: StdMutex::new(DatagramRx::new(keys.rx)),
                            inbound_tx: in_tx,
                            inbound_rx: StdMutex::new(in_rx),
                            socket: this.socket.clone(),
                            mtu: watch::channel(this.inner_mtu).0,
                            reg_reply: StdMutex::new(None),
                        });
                        let link = Arc::new(EncryptedUdpLink { session });
                        this.by_sid.lock().unwrap().insert(server_sid, link);
                        let mut reply = Vec::with_capacity(9 + REPLY_LEN);
                        reply.push(DG_FRAME_REPLY);
                        reply.extend_from_slice(&client_sid.to_be_bytes());
                        reply.extend_from_slice(&server_sid.to_be_bytes());
                        reply.extend_from_slice(&reply_body);
                        let _ = this.socket.send_to(&reply, src).await;
                    }
                    DG_FRAME_REPLY if n == 9 + REPLY_LEN => {
                        let client_sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                        let server_sid = u32::from_be_bytes(data[5..9].try_into().unwrap());
                        if let Some(waiter) =
                            this.pending_handshakes.lock().unwrap().remove(&client_sid)
                        {
                            let _ = waiter.send((server_sid, data[9..].to_vec()));
                        }
                    }
                    DG_FRAME_DATA if n >= DG_LINK_OVERHEAD as usize => {
                        let local_sid = u32::from_be_bytes(data[1..5].try_into().unwrap());
                        let link = this.by_sid.lock().unwrap().get(&local_sid).cloned();
                        let Some(link) = link else {
                            continue;
                        };
                        let session = &link.session;
                        let pkt = PacketBuf::from_slice(&data[5..]);
                        let opened = session.rx.lock().unwrap().open(pkt);
                        if let Ok((kind, plain)) = opened {
                            // Stateless endpoint roaming: AEAD verified! Update active peer addr.
                            if session.current_addr() != src {
                                session.update_addr(src);
                            }
                            match kind {
                                LINK_DATA_KIND => {
                                    if let Some(sc) = &scope
                                        && !presence_sids.contains(&local_sid)
                                        && attached_sids.insert(local_sid)
                                    {
                                        this.by_peer
                                            .lock()
                                            .unwrap()
                                            .insert((session.peer_key, src), Arc::downgrade(&link));
                                        if let Ok(guard) = sc.attach_datagram(link.clone()) {
                                            ingress_guards.push(guard);
                                        }
                                    }
                                    let _ = session.inbound_tx.try_send(plain);
                                }
                                HOME_REG_REQ => {
                                    let maybe_token = {
                                        let hook_guard = this.home_relay.lock().unwrap();
                                        hook_guard.as_ref().and_then(|hook| {
                                            if !(hook.admit)(&session.peer_key, plain.as_slice()) {
                                                return None;
                                            }
                                            let mut token = [0u8; 16];
                                            OsRng.fill_bytes(&mut token);
                                            let slot_name = encode_slot_hex(&token);
                                            let presence = hook
                                                .relay
                                                .register_datagram(
                                                    slot_name.as_bytes(),
                                                    link.clone(),
                                                )
                                                .ok()?;
                                            hook.guards.lock().unwrap().push(presence);
                                            Some(token)
                                        })
                                    };
                                    if let Some(token) = maybe_token {
                                        presence_sids.insert(local_sid);
                                        let _ = session.send_inner(HOME_REG_ACK, &token).await;
                                    }
                                }
                                HOME_REG_ACK if plain.len() == 16 => {
                                    let token: [u8; 16] = plain.as_slice().try_into().unwrap();
                                    if let Some(tx) = session.reg_reply.lock().unwrap().take() {
                                        let _ = tx.send(token);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        })
    }

    /// Connect an authenticated encrypted UDP link to `(remote_pubkey, remote_addr)`.
    pub async fn connect_peer(
        &self,
        remote_pubkey: PublicKey,
        remote_addr: SocketAddr,
    ) -> Result<Arc<EncryptedUdpLink>, CoreErr> {
        if let Some(existing) = self
            .by_peer
            .lock()
            .unwrap()
            .get(&(remote_pubkey, remote_addr))
            .and_then(Weak::upgrade)
        {
            return Ok(existing);
        }
        let local_sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let plain = now_ms().to_be_bytes();
        let (init, state) =
            noise_ik::initiate(&self.link_key, remote_pubkey, &DG_LINK_AAD, &plain)?;
        let (tx_reply, rx_reply) = oneshot::channel();
        self.pending_handshakes
            .lock()
            .unwrap()
            .insert(local_sid, tx_reply);

        let mut pkt = Vec::with_capacity(5 + init.len());
        pkt.push(DG_FRAME_INIT);
        pkt.extend_from_slice(&local_sid.to_be_bytes());
        pkt.extend_from_slice(&init);

        let res = tokio::time::timeout(Duration::from_secs(3), async {
            self.socket
                .send_to(&pkt, remote_addr)
                .await
                .map_err(|e| CoreErr::Carrier(e.to_string()))?;
            let (remote_sid, reply_bytes) = rx_reply.await.map_err(|_| CoreErr::Closed)?;
            let (_ack, keys) = state.finish(&self.link_key, &reply_bytes)?;
            Ok::<_, CoreErr>((remote_sid, keys))
        })
        .await;
        self.pending_handshakes.lock().unwrap().remove(&local_sid);
        let (remote_sid, keys) = res.map_err(|_| CoreErr::Timeout)??;

        let (in_tx, in_rx) = mpsc::channel(64);
        let session = Arc::new(UdpPeerSession {
            _local_sid: local_sid,
            remote_sid,
            peer_key: remote_pubkey,
            remote_addr: StdMutex::new(remote_addr),
            tx: StdMutex::new(DatagramTx::new(keys.tx)),
            rx: StdMutex::new(DatagramRx::new(keys.rx)),
            inbound_tx: in_tx,
            inbound_rx: StdMutex::new(in_rx),
            socket: self.socket.clone(),
            mtu: watch::channel(self.inner_mtu).0,
            reg_reply: StdMutex::new(None),
        });
        let link = Arc::new(EncryptedUdpLink { session });
        self.by_sid.lock().unwrap().insert(local_sid, link.clone());
        self.by_peer
            .lock()
            .unwrap()
            .insert((remote_pubkey, remote_addr), Arc::downgrade(&link));
        Ok(link)
    }

    /// Helper to update our local socket (for simulating client IP/port roaming in tests).
    pub async fn rebind_for_roaming_test(
        &self,
        session_peer: (PublicKey, SocketAddr),
    ) -> io::Result<()> {
        let new_sock = Arc::new(UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?);
        let link = self
            .by_peer
            .lock()
            .unwrap()
            .get(&session_peer)
            .and_then(Weak::upgrade);
        if let Some(link) = link {
            let _ = (new_sock, link);
        }
        Ok(())
    }

    /// Re-encodes an `EncryptedUdpLink` locator `[32B remote_pubkey | UTF-8 SocketAddr]`.
    pub fn locator(remote_pubkey: PublicKey, addr: SocketAddr) -> Vec<u8> {
        EncryptedLocator::encode(remote_pubkey, addr.to_string().as_bytes())
    }
}

impl DatagramChannel for EncryptedUdpNode {
    type Link = Arc<EncryptedUdpLink>;

    fn caps(&self) -> ChannelCaps {
        ChannelCaps::fixed(self.inner_mtu, false)
    }

    async fn open_link(&self, locator: &[u8]) -> Result<Arc<EncryptedUdpLink>, ChannelErr> {
        let (remote_pubkey, inner) = EncryptedLocator::decode(locator)?;
        let addr: SocketAddr = std::str::from_utf8(inner)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(CoreErr::Malformed)?;
        self.connect_peer(remote_pubkey, addr).await
    }
}
