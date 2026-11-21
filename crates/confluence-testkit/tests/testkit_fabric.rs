use confluence_core::seams::channel::{DatagramChannel, StreamChannel};
use confluence_core::{ChannelAddr, CoreError};
use confluence_testkit::{MemDatagramHub, MemStreamHub};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn mem_datagram_mtu_drop_reorder_and_wire_tap() {
    let hub = MemDatagramHub::new(128);
    let ch_a = hub.bind("udp_a", "node-a:1000");
    let ch_b = hub.bind("udp_b", "node-b:1000");
    let addr_b = ChannelAddr::new("node-b:1000").unwrap();

    // 1. Oversized payload exceeding MTU is rejected explicitly.
    let too_big = vec![0xFF; 129];
    assert!(matches!(
        ch_a.send_to(&addr_b, &too_big).await,
        Err(CoreError::CapabilityMismatch(_))
    ));

    // 2. Drop next 1 packet -> dropped deterministically.
    hub.drop_next("node-a:1000", "node-b:1000", 1);
    ch_a.send_to(&addr_b, b"dropped").await.unwrap();
    ch_a.send_to(&addr_b, b"arrives").await.unwrap();

    let mut buf = [0u8; 128];
    let (n, src) = ch_b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"arrives");
    assert_eq!(src.as_str(), "node-a:1000");

    // 3. Adjacent reorder -> [first, second] arrives as [second, first].
    hub.set_reorder_adjacent("node-a:1000", "node-b:1000", true);
    ch_a.send_to(&addr_b, b"first").await.unwrap();
    ch_a.send_to(&addr_b, b"second").await.unwrap();

    let (n1, _) = ch_b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n1], b"second");
    let (n2, _) = ch_b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n2], b"first");

    // 4. Wire tap captured all 4 attempted on-wire transmissions.
    assert_eq!(hub.captured_packets("node-a:1000", "node-b:1000").len(), 4);
}

#[tokio::test]
async fn mem_stream_dial_counter_wire_tap_and_instant_link_cut() {
    let hub = MemStreamHub::new();
    let ch_a = hub.bind("tcp_a", "node-a:2000");
    let ch_b = hub.bind("tcp_b", "node-b:2000");
    let addr_b = ChannelAddr::new("node-b:2000").unwrap();

    assert_eq!(ch_a.outbound_dial_count(), 0);
    assert_eq!(ch_b.outbound_dial_count(), 0);

    let mut s_a = ch_a.open(&addr_b).await.unwrap();
    let (mut s_b, peer_addr) = ch_b.accept().await.unwrap();
    assert_eq!(peer_addr.as_str(), "node-a:2000");
    assert_eq!(ch_a.outbound_dial_count(), 1);
    assert_eq!(ch_b.outbound_dial_count(), 0);

    s_a.write_all(b"opaque-stream-bytes").await.unwrap();
    s_a.flush().await.unwrap();

    let mut buf = [0u8; 64];
    let n = s_b.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"opaque-stream-bytes");
    assert_eq!(
        hub.captured_bytes("node-a:2000", "node-b:2000"),
        b"opaque-stream-bytes"
    );

    // Sever link mid-stream -> idle read on s_b wakes immediately with ConnectionReset!
    let hub_killer = hub.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        hub_killer.set_symmetric_link_down("node-a:2000", "node-b:2000", true);
    });

    let err = tokio::time::timeout(Duration::from_secs(1), s_b.read(&mut buf))
        .await
        .expect("severed stream must wake promptly")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
}
