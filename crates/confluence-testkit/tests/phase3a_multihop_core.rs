use async_trait::async_trait;
use confluence_core::seams::channel::{
    BoxedAsyncStream, BoxedDatagramForwardHandle, ChannelCaps, DatagramChannel,
    DatagramForwardChannel, DatagramForwardHandle, SetupOutcome, StreamChannel,
    StreamForwardChannel,
};
use confluence_core::seams::edge::DatagramSession;
use confluence_core::seams::routing::{ExplicitPath, PathHop};
use confluence_core::security::cookie::{seal_handshake_envelope, EnvelopeCheck, CookieProtector};
use confluence_core::security::noise::{
    VerifiedInitiation, DATAGRAM_WIRE_OVERHEAD_BYTES, DEFAULT_PROLOGUE,
};
use confluence_core::wire::HopHandshakeReq;
use confluence_core::{
    ChannelAddr, ChannelId, EndpointName, Node, Plane, Result, ScopeId, StaticKeypair, TargetTag,
    TrustScope,
};
use confluence_testkit::{AuditAccessControl, MemDatagramHub, MemStreamHub, StaticMapPathSource};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

/// Minimal test forward channel to exercise Core's blind single-pass Path Engine directly.
struct DummyDgramFwd {
    kp: StaticKeypair,
    protector: CookieProtector,
    carrier: Arc<dyn DatagramChannel>,
    closed_tx: watch::Sender<bool>,
}

struct DummyDgramHandle {
    carrier: Arc<dyn DatagramChannel>,
    next_addr: ChannelAddr,
    closed_rx: watch::Receiver<bool>,
}

#[async_trait]
impl DatagramForwardHandle for DummyDgramHandle {
    async fn send(&self, packet: &[u8]) -> Result<()> {
        self.carrier.send_to(&self.next_addr, packet).await
    }

    fn check_and_record_reverse(&self, _byte_len: usize) -> Result<()> {
        Ok(())
    }

    fn closed(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }
}

#[async_trait]
impl DatagramForwardChannel for DummyDgramFwd {
    fn target_tag(&self) -> TargetTag {
        self.kp.target_tag()
    }

    fn caps(&self) -> ChannelCaps {
        self.carrier.caps()
    }

    fn underlying_carrier(&self) -> Option<Arc<dyn DatagramChannel>> {
        Some(Arc::clone(&self.carrier))
    }

    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedDatagramForwardHandle>> {
        let inner = match self
            .protector
            .verify_envelope(source_addr.as_bytes(), setup_payload)
        {
            EnvelopeCheck::Verified(b) => b,
            EnvelopeCheck::Challenge(ch) => return Ok(SetupOutcome::Challenge(ch)),
            EnvelopeCheck::Drop => return Ok(SetupOutcome::Reject("bad mac1".into())),
        };
        let verified = VerifiedInitiation::read_msg1(&self.kp, DEFAULT_PROLOGUE, inner)?;
        let req = HopHandshakeReq::decode(verified.payload())?;
        Ok(SetupOutcome::Accept {
            handle: Arc::new(DummyDgramHandle {
                carrier: Arc::clone(&self.carrier),
                next_addr: req.next_addr,
                closed_rx: self.closed_tx.subscribe(),
            }),
            reply_hint: None,
        })
    }
}

struct DummyStreamFwd {
    kp: StaticKeypair,
    protector: CookieProtector,
    carrier: Arc<dyn StreamChannel>,
}

#[async_trait]
impl StreamForwardChannel for DummyStreamFwd {
    fn target_tag(&self) -> TargetTag {
        self.kp.target_tag()
    }

    fn caps(&self) -> ChannelCaps {
        self.carrier.caps()
    }

    async fn handle_setup(
        &self,
        source_addr: &ChannelAddr,
        setup_payload: &[u8],
    ) -> Result<SetupOutcome<BoxedAsyncStream>> {
        let inner = match self
            .protector
            .verify_envelope(source_addr.as_bytes(), setup_payload)
        {
            EnvelopeCheck::Verified(b) => b,
            EnvelopeCheck::Challenge(ch) => return Ok(SetupOutcome::Challenge(ch)),
            EnvelopeCheck::Drop => return Ok(SetupOutcome::Reject("bad mac1".into())),
        };
        let verified = VerifiedInitiation::read_msg1(&self.kp, DEFAULT_PROLOGUE, inner)?;
        let req = HopHandshakeReq::decode(verified.payload())?;
        let out = self.carrier.open(&req.next_addr).await?;
        Ok(SetupOutcome::Accept {
            handle: out,
            reply_hint: None,
        })
    }
}

#[tokio::test]
async fn blind_single_pass_two_hop_label_switching_and_stream_splicing() {
    let _ = seal_handshake_envelope;
    let dgram_hub = MemDatagramHub::new(1400);
    let stream_hub = MemStreamHub::new();

    let scope_id = ScopeId::new("mesh").unwrap();
    let alice_kp = StaticKeypair::generate();
    let bob_kp = StaticKeypair::generate();
    let h1_dgram_kp = StaticKeypair::generate();
    let h1_stream_kp = StaticKeypair::generate();

    // Hop H1 has ZERO TrustScopes mounted — purely a blind intermediate node!
    let h1_node = Node::new(StaticMapPathSource::new());
    let h1_udp = dgram_hub.bind("udp0", "h1:1000");
    let h1_tcp = stream_hub.bind("tcp0", "h1:2000");
    h1_node.attach_datagram_channel(h1_udp.clone()).unwrap();
    h1_node.attach_stream_channel(h1_tcp.clone()).unwrap();

    let (closed_tx, _) = watch::channel(false);
    let h1_dgram_fwd = Arc::new(DummyDgramFwd {
        protector: CookieProtector::new(h1_dgram_kp.peer_id(), Duration::from_secs(60)),
        kp: h1_dgram_kp.clone(),
        carrier: h1_udp,
        closed_tx,
    });
    // Also exercise mid-chain MAC2 flood challenge at Hop 1!
    h1_dgram_fwd.protector.set_under_load(true);
    h1_node.mount_datagram_forward_channel(h1_dgram_fwd).unwrap();

    let h1_stream_fwd = Arc::new(DummyStreamFwd {
        protector: CookieProtector::new(h1_stream_kp.peer_id(), Duration::from_secs(60)),
        kp: h1_stream_kp.clone(),
        carrier: h1_tcp,
    });
    h1_stream_fwd.protector.set_under_load(true);
    h1_node
        .mount_stream_forward_channel(h1_stream_fwd)
        .unwrap();

    // Endpoint B
    let bob_node = Node::new(StaticMapPathSource::new());
    bob_node
        .add_scope(TrustScope::new(
            scope_id.clone(),
            bob_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    bob_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "bob:1000"))
        .unwrap();
    bob_node
        .attach_stream_channel(stream_hub.bind("tcp0", "bob:2000"))
        .unwrap();

    let ep = EndpointName::new("echo").unwrap();
    let mut b_dgram_ep = bob_node
        .publish_datagram_endpoint(&scope_id, ep.clone())
        .unwrap();
    let mut b_stream_ep = bob_node
        .publish_stream_endpoint(&scope_id, ep.clone())
        .unwrap();

    // Originator A configured with explicit path A -> H1 -> B
    let routes = StaticMapPathSource::new();
    routes.insert(
        scope_id.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Datagram,
            entry_channel: ChannelId::new("udp0").unwrap(),
            entry_addr: ChannelAddr::new("h1:1000").unwrap(),
            hops: vec![PathHop {
                target_tag: h1_dgram_kp.target_tag(),
                channel_pubkey: h1_dgram_kp.peer_id(),
                next_addr: ChannelAddr::new("bob:1000").unwrap(),
                credential: None,
            }],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );
    routes.insert(
        scope_id.clone(),
        bob_kp.peer_id(),
        ExplicitPath {
            plane: Plane::Stream,
            entry_channel: ChannelId::new("tcp0").unwrap(),
            entry_addr: ChannelAddr::new("h1:2000").unwrap(),
            hops: vec![PathHop {
                target_tag: h1_stream_kp.target_tag(),
                channel_pubkey: h1_stream_kp.peer_id(),
                next_addr: ChannelAddr::new("bob:2000").unwrap(),
                credential: None,
            }],
            target_scope_tag: bob_kp.target_tag(),
            target_pubkey: bob_kp.peer_id(),
            target_credential: None,
        },
    );

    let alice_node = Node::new(routes);
    alice_node
        .add_scope(TrustScope::new(
            scope_id.clone(),
            alice_kp.clone(),
            AuditAccessControl::allow_all(Duration::from_secs(60)),
        ))
        .unwrap();
    alice_node
        .attach_datagram_channel(dgram_hub.bind("udp0", "alice:1000"))
        .unwrap();
    alice_node
        .attach_stream_channel(stream_hub.bind("tcp0", "alice:2000"))
        .unwrap();

    // 1. Datagram Plane via H1: flat 29B overhead on both A->H1 and H1->B!
    let a_sess = alice_node
        .open_datagram(&scope_id, bob_kp.peer_id(), ep.clone())
        .await
        .unwrap();
    let b_sess = b_dgram_ep.accept().await.unwrap();
    assert_eq!(h1_node.active_label_switch_count(), 2);

    let idx_ah1 = dgram_hub.captured_packets("alice:1000", "h1:1000").len();
    let idx_h1b = dgram_hub.captured_packets("h1:1000", "bob:1000").len();

    a_sess.send(b"blind-hop-payload").await.unwrap();
    assert_eq!(&b_sess.recv().await.unwrap()[..], b"blind-hop-payload");

    b_sess.send(b"reverse-hop-reply").await.unwrap();
    assert_eq!(&a_sess.recv().await.unwrap()[..], b"reverse-hop-reply");

    let pkt_ah1 = &dgram_hub.captured_packets("alice:1000", "h1:1000")[idx_ah1];
    let pkt_h1b = &dgram_hub.captured_packets("h1:1000", "bob:1000")[idx_h1b];
    // Exact same length (29 + 17 = 46 bytes), identical ciphertext body [4..], swapped 4B HopLabel!
    assert_eq!(
        pkt_ah1.len(),
        DATAGRAM_WIRE_OVERHEAD_BYTES + b"blind-hop-payload".len()
    );
    assert_eq!(pkt_ah1.len(), pkt_h1b.len());
    assert_eq!(&pkt_ah1[4..], &pkt_h1b[4..]);

    // 2. Stream Plane via H1: raw bidirectional byte splicing!
    let mut a_stream = alice_node
        .open_stream(&scope_id, bob_kp.peer_id(), ep)
        .await
        .unwrap();
    let mut b_stream = b_stream_ep.accept().await.unwrap();
    assert_eq!(b_stream.remote_peer, alice_kp.peer_id());

    a_stream.write_all(b"pipelined-stream-data").await.unwrap();
    let mut buf = [0u8; 64];
    let n = b_stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pipelined-stream-data");
}
