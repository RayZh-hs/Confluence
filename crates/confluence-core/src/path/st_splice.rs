use super::{below_floor, best_effort};
use crate::{
    CoreErr, Either, HopAuthCtx, STREAM_CHUNK, StreamRead, StreamWrite,
    crypto::aead::ControlCipher,
    race, read_exact,
    scope::Scope,
    wire::{e2e, hop, setup, u16_at, u64_at},
};
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

const MAX_SETUP_SEGMENT: usize = 2048;

pub(crate) type Reader = Box<dyn StreamRead>;
pub(crate) struct Carrier {
    pub reader: Reader,
    pub writer: Box<dyn StreamWrite>,
    pub mtu: watch::Receiver<u16>,
}

pub(crate) type Writer = Arc<AsyncMutex<Box<dyn StreamWrite>>>;

pub(crate) async fn read_setup(
    scope: &Scope,
    reader: &mut dyn StreamRead,
) -> Result<Vec<u8>, CoreErr> {
    let mut header = [0; 24];
    read_exact(reader, &mut header[..14]).await?;
    setup::ForwardHeader::parse(&header[..8])?;
    let prefix_len = setup::prefix_size(header[8])?;
    if prefix_len == 16 {
        read_exact(reader, &mut header[14..24]).await?;
    }
    let end = 8 + prefix_len;
    let prefix = &header[8..end];
    let total = setup::encoded_size(prefix)?;
    let length = 8 + total;
    let seg_len = u16_at(prefix, if prefix_len == 16 { 12 } else { 4 }) as usize;
    if seg_len > MAX_SETUP_SEGMENT || length > STREAM_CHUNK {
        return Err(CoreErr::Malformed);
    }
    let channel = (prefix_len == 16).then(|| u64_at(prefix, 4));
    let mut segment = [0; MAX_SETUP_SEGMENT];
    read_exact(reader, &mut segment[..seg_len]).await?;
    if !scope.precheck_stream_segment(channel, &segment[..seg_len]) {
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
    let size = match kind[0] {
        setup::OK => setup::OK_SIZE,
        setup::ERR => setup::ERR_SIZE,
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
    mut auth: HopAuthCtx,
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
        Some((&cipher, renew)),
        &right.mtu,
    );
    let reverse = half(right.reader, &left_write, &auth, None, &left.mtu);
    let link_failure = async {
        match race(
            below_floor(left.mtu.clone(), floor),
            below_floor(right.mtu.clone(), floor),
        )
        .await
        {
            Either::Left(error) | Either::Right(error) => error,
        }
    };
    let renewals = async {
        while let Some(credential) = requests.recv().await {
            let grant = auth.renewal(credential).await?;
            let body = cipher.lock().unwrap().seal(hop::ST_RENEW_OK, &grant)?;
            write_chunk(&left_write, hop::ST_RENEW_OK, 0, &body).await?;
        }
        Ok(())
    };
    let result = match race(
        race(auth.grant.cancelled(), link_failure),
        race(race(forward, reverse), renewals),
    )
    .await
    {
        Either::Left(Either::Left(error) | Either::Right(error)) => Err(error),
        Either::Right(Either::Right(result)) => result,
        Either::Right(Either::Left(Either::Left(result) | Either::Right(result))) => result,
    };
    if let Err(error) = &result {
        let (code, argument) = setup::error_code(error);
        let mut body = [0; 4];
        body[..2].copy_from_slice(&code.to_be_bytes());
        body[2..].copy_from_slice(&argument.to_be_bytes());
        let encrypted = cipher.lock().unwrap().seal(hop::ST_CLOSE, &body);
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
    auth: &HopAuthCtx,
    forward: Option<ForwardControl<'_>>,
    mtu: &watch::Receiver<u16>,
) -> Result<(), CoreErr> {
    let mut prefix = [0; 4];
    let mut quantum = [0; 4096];
    loop {
        read_exact(&mut *reader, &mut prefix).await?;
        let (kind, ttl, length) = hop::parse_stream(prefix)?;
        if kind == hop::ST_DATA {
            let mut remaining = length;
            while remaining > 0 {
                let limit = usize::from(*mtu.borrow()).max(1);
                let count = remaining.min(limit).min(quantum.len());
                let read = reader.read(&mut quantum[..count]).await?;
                if read == 0 {
                    return Err(CoreErr::UnexpectedEof);
                }
                if read > count {
                    return Err(CoreErr::Malformed);
                }
                auth.grant.wait_charge(read).await?;
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
            } else if let Ok(body) = cipher.lock().unwrap().open(kind, body) {
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
