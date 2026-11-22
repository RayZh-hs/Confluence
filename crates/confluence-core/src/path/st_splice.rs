use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use super::{below_floor, best_effort, inbound::HopSession};
use crate::{
    CoreErr, Direction, MtuWatch, STREAM_CHUNK, StreamAction, StreamRead, StreamReadExt,
    StreamWrite, StreamWriteExt,
    crypto::aead::ControlCipher,
    node::NodeInner,
    read_exact,
    scope::Scope,
    wire::{e2e, hop, setup, u16_at},
};

const MAX_SETUP_SEGMENT: usize = 2048;

pub(crate) type Reader = Box<dyn StreamRead>;

pub(crate) struct Carrier {
    pub reader: Reader,
    pub writer: Box<dyn StreamWrite>,
    pub mtu: MtuWatch,
}

pub(crate) type Writer = Arc<AsyncMutex<Box<dyn StreamWrite>>>;

pub(crate) async fn read_opening(
    scope: &Scope,
    reader: &mut dyn StreamRead,
) -> Result<Vec<u8>, CoreErr> {
    read_setup(reader, |seg, has_mac2| {
        scope.precheck_stream_segment(seg, has_mac2)
    })
    .await
}

pub(crate) async fn read_opening_for_node(
    node: &NodeInner,
    reader: &mut dyn StreamRead,
) -> Result<(Arc<Scope>, Vec<u8>), CoreErr> {
    let mut resolved = None;
    let frame = read_setup(reader, |seg, has_mac2| {
        resolved = node.resolve_stream_scope(seg, has_mac2);
        resolved.is_some()
    })
    .await?;
    let scope = resolved.ok_or(CoreErr::Authentication)?;
    Ok((scope, frame))
}

async fn read_setup<F>(reader: &mut dyn StreamRead, mut precheck: F) -> Result<Vec<u8>, CoreErr>
where
    F: FnMut(&[u8], bool) -> bool,
{
    let mut header = [0; 16];
    read_exact(reader, &mut header[..14]).await?;
    setup::ForwardHeader::parse(&header[..8])?;
    let prefix_len = setup::prefix_size(header[8])?;
    let has_mac2 = setup::mode_has_mac2(header[8]);
    if prefix_len == 8 {
        read_exact(reader, &mut header[14..16]).await?;
    }
    let end = 8 + prefix_len;
    let prefix = &header[8..end];
    let total = setup::encoded_size(prefix)?;
    let length = 8 + total;
    let seg_len = u16_at(prefix, 4) as usize;
    if seg_len > MAX_SETUP_SEGMENT || length > STREAM_CHUNK {
        return Err(CoreErr::Malformed);
    }
    let mut segment = [0; MAX_SETUP_SEGMENT];
    read_exact(reader, &mut segment[..seg_len]).await?;
    if !precheck(&segment[..seg_len], has_mac2) {
        return Err(CoreErr::Authentication);
    }
    let mut frame = vec![0; length];
    frame[..end].copy_from_slice(&header[..end]);
    frame[end..end + seg_len].copy_from_slice(&segment[..seg_len]);
    read_exact(reader, &mut frame[end + seg_len..]).await?;
    Ok(frame)
}

pub(crate) async fn read_reply(reader: &mut dyn StreamRead) -> Result<Vec<u8>, CoreErr> {
    let mut kind = [0; 1];
    read_exact(reader, &mut kind).await?;
    if kind[0] == setup::OK {
        let mut hdr = [0; 12];
        hdr[0] = kind[0];
        read_exact(reader, &mut hdr[1..]).await?;
        let ok = setup::OkHeader::parse_header(&hdr)?;
        let total = setup::OK_SIZE + usize::from(ok.hop_acks) * setup::HOP_ACK_SIZE;
        if total > STREAM_CHUNK {
            return Err(CoreErr::Malformed);
        }
        let mut frame = vec![0; total];
        frame[..12].copy_from_slice(&hdr);
        read_exact(reader, &mut frame[12..]).await?;
        return Ok(frame);
    }
    let size = match kind[0] {
        setup::ERR => setup::ERR_SIZE,
        setup::COOKIE => setup::COOKIE_SIZE,
        _ => return Err(CoreErr::Malformed),
    };
    let mut frame = vec![kind[0]; size];
    read_exact(reader, &mut frame[1..]).await?;
    Ok(frame)
}

pub(crate) async fn write_chunk(
    writer: &Writer,
    kind: u8,
    ttl: u8,
    body: &[u8],
) -> Result<(), CoreErr> {
    let header = hop::stream_header(kind, ttl, body.len())?;
    let mut writer = writer.lock().await;
    writer.write_all(&header).await?;
    writer.write_all(body).await
}

pub(crate) async fn splice(
    left: Carrier,
    right: Carrier,
    mut auth: HopSession,
    floor: u16,
) -> Result<(), CoreErr> {
    auth.pending.take();
    let left_write = Arc::new(AsyncMutex::new(left.writer));
    let right_write = Arc::new(AsyncMutex::new(right.writer));
    let cipher = Mutex::new(auth.hop_key.control(false));
    let (renew, mut requests) = mpsc::channel(1);
    let forward = half(
        left.reader,
        &right_write,
        &auth,
        Direction::Ingress,
        Some((&cipher, renew)),
        &right.mtu,
    );
    let reverse = half(
        right.reader,
        &left_write,
        &auth,
        Direction::Egress,
        None,
        &left.mtu,
    );
    let left_floor = below_floor(left.mtu.clone(), floor);
    let right_floor = below_floor(right.mtu.clone(), floor);
    let renewals = async {
        while let Some(credential) = requests.recv().await {
            let lease_wire = auth.renewal(credential).await?;
            let body = cipher.lock().seal(hop::ST_RENEW_OK, &lease_wire)?;
            write_chunk(&left_write, hop::ST_RENEW_OK, 0, &body).await?;
        }
        Ok(())
    };

    let result = tokio::select! {
        error = auth.lease.cancelled() => Err(error),
        error = left_floor => Err(error),
        error = right_floor => Err(error),
        res = forward => res,
        res = reverse => res,
        res = renewals => res,
    };

    if let Err(error) = &result {
        let (code, argument) = setup::error_code(error);
        let mut body = [0; 4];
        body[..2].copy_from_slice(&code.to_be_bytes());
        body[2..].copy_from_slice(&argument.to_be_bytes());
        let encrypted = cipher.lock().seal(hop::ST_CLOSE, &body);
        if let Ok(encrypted) = encrypted {
            best_effort(write_chunk(&left_write, hop::ST_CLOSE, 0, &encrypted)).await;
        }
    }
    result
}

type ForwardControl<'a> = (&'a Mutex<ControlCipher>, mpsc::Sender<Vec<u8>>);

async fn half(
    mut reader: Reader,
    writer: &Writer,
    auth: &HopSession,
    dir: Direction,
    forward: Option<ForwardControl<'_>>,
    mtu: &MtuWatch,
) -> Result<(), CoreErr> {
    let mut prefix = [0; 4];
    let mut quantum = [0; 4096];
    let mut gate = auth.lease.gate_cache();
    loop {
        read_exact(&mut *reader, &mut prefix).await?;
        let (kind, ttl, length) = hop::parse_stream(prefix)?;
        if kind == hop::ST_DATA {
            let mut remaining = length;
            while remaining > 0 {
                let limit = usize::from(mtu.mtu()).max(1);
                let count = remaining.min(limit).min(quantum.len());
                let read = reader.read(&mut quantum[..count]).await?;
                if read == 0 {
                    return Err(CoreErr::UnexpectedEof);
                }
                if read > count {
                    return Err(CoreErr::Malformed);
                }
                auth.lease.remaining()?;
                if let Some(active_gate) = gate.current(&auth.lease) {
                    match active_gate.charge_stream(dir, read) {
                        StreamAction::Allow => {}
                        StreamAction::Delay(delay) => {
                            tokio::time::sleep(delay).await;
                            auth.lease.remaining()?;
                        }
                        StreamAction::Close(err) => return Err(err),
                    }
                }
                let mut writer = writer.lock().await;
                writer
                    .write_all(&hop::stream_header(kind, ttl, read)?)
                    .await?;
                writer.write_all(&quantum[..read]).await?;
                remaining -= read;
            }
            continue;
        }

        read_exact(&mut *reader, &mut quantum[..length]).await?;
        let body = &quantum[..length];
        if let Some((cipher, renew)) = &forward {
            if ttl > 0 {
                write_chunk(writer, kind, ttl - 1, body).await?;
            } else if let Ok(body) = cipher.lock().open(kind, body) {
                match kind {
                    hop::ST_RENEW => {
                        e2e::credential(&body)?;
                        let _ = renew.try_send(body);
                    }
                    hop::ST_CLOSE => return Ok(()),
                    _ => {}
                }
            }
        } else if let Some(distance) = ttl.checked_add(1) {
            write_chunk(writer, kind, distance, body).await?;
        }
    }
}
