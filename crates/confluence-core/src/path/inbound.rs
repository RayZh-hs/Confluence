use std::sync::Arc;

use super::{
    before, best_effort,
    dg_switch::{DatagramPort, Transit},
    setup_deadline, st_splice, timed,
};
use crate::{
    AsyncStream, CoreErr, Either, HopReject, PacketBuf, PendingSetup, Plane,
    cid::Cid,
    crypto::noise_ik::{self, HopKey, Responder},
    e2e::{self, AwaitingConfirm, datagram, stream},
    grant::{GrantEnforcer, GrantSpec},
    now_ms, race,
    scope::{Published, Scope},
    seams::ActionRef,
    wire::setup::{self, ForwardHeader, OkHeader, Segment},
};
use tokio::sync::OwnedSemaphorePermit;

struct Endpoint {
    publication: Arc<Published>,
    authorization: e2e::EndpointAuth,
    spec: GrantSpec,
    pending: PendingSetup,
    mtu: u16,
}
async fn admit(
    scope: &Arc<Scope>,
    responder: &Responder,
    seg: &Segment<'_>,
    mtu: u16,
) -> Result<Endpoint, CoreErr> {
    let (name, credential) = noise_ik::parse_endpoint(&responder.plaintext)?;
    let peer = responder.peer;
    let pending = scope.policy.pending(peer)?;
    let epoch = scope.policy.epoch_for(peer, Some(name));
    let publication = scope
        .endpoints
        .lock()
        .unwrap()
        .get(name)
        .cloned()
        .ok_or(CoreErr::Unpublished)?;
    if publication.plane() != seg.plane {
        return Err(CoreErr::WrongPlane);
    }
    if mtu
        < publication
            .min_mtu()
            .max(seg.min_mtu)
            .max(seg.plane.minimum_mtu())
    {
        return Err(CoreErr::MtuTooSmall(mtu));
    }
    let spec = scope
        .policy
        .verify(
            &peer,
            ActionRef::EndpointOpen {
                ep: name,
                plane: seg.plane,
            },
            credential,
        )
        .await?;
    let grant = Arc::new(GrantEnforcer::new(spec)?);
    {
        let registry = scope.endpoints.lock().unwrap();
        if !registry
            .get(name)
            .is_some_and(|entry| Arc::ptr_eq(entry, &publication))
        {
            return Err(CoreErr::Unpublished);
        }
        scope.policy.track(epoch, peer, Some(name), &grant)?;
    }
    Ok(Endpoint {
        authorization: e2e::EndpointAuth {
            scope: scope.clone(),
            name: name.to_owned(),
            peer,
            plane: seg.plane,
            grant,
            terminal_key: responder.hop_key(),
        },
        spec,
        pending,
        publication,
        mtu,
    })
}
impl Endpoint {
    fn ack(&self) -> [u8; 18] {
        let mut ack = [0; 18];
        ack[..2].copy_from_slice(&self.mtu.to_be_bytes());
        ack[2..].copy_from_slice(&self.spec.to_wire());
        ack
    }
}

fn setup_error(key: &HopKey, error: &CoreErr, cid: Cid) -> Vec<u8> {
    let (code, mtu) = setup::error_code(error);
    let mut plaintext = [0; 4];
    plaintext[..2].copy_from_slice(&code.to_be_bytes());
    plaintext[2..].copy_from_slice(&mtu.to_be_bytes());
    let mut wire = setup::error_header(0, cid).to_vec();
    wire.extend_from_slice(&key.setup_error(plaintext));
    wire
}
fn reply(header: OkHeader, payload: &[u8; 66]) -> Vec<u8> {
    let mut wire = header.encode().to_vec();
    wire.extend_from_slice(payload);
    wire
}
fn retransmit_error(wire: &mut [u8], cid: Cid) -> Result<(), CoreErr> {
    let (distance, _, _) = setup::parse_error(wire)?;
    let distance = distance.checked_add(1).ok_or(CoreErr::Malformed)?;
    wire[..8].copy_from_slice(&setup::error_header(distance, cid));
    Ok(())
}

pub(crate) async fn stream(
    scope: Arc<Scope>,
    stream: Box<dyn AsyncStream>,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_caps = stream.caps();
    let inbound_mtu = inbound_caps.mtu();
    let (mut left, mut up) = stream.split();
    let wire = timed(st_splice::read_setup(&scope, &mut *left)).await?;
    let hdr = ForwardHeader::parse(&wire)?;
    if hdr.upstream != Cid::UNBOUND {
        return Err(CoreErr::Malformed);
    }
    let segment = Segment::parse(&wire[8..])?;

    if let Some(tag) = segment.channel {
        if segment.plane != Plane::Stream {
            return Err(CoreErr::WrongPlane);
        }
        let channel = scope.stream_channel(tag)?;
        let (out, auth) = match tokio::time::timeout(
            crate::SETUP_TIMEOUT,
            channel.accept_hop_stream(segment.encrypted, &segment.aad(), segment.min_mtu),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(HopReject::Authenticated(key, error))) => {
                best_effort(up.write_all(&setup_error(&key, &error, Cid::UNBOUND))).await;
                return Err(error);
            }
            Ok(Err(HopReject::Silent)) => return Err(CoreErr::Authentication),
            Err(_) => return Err(CoreErr::Timeout),
        };
        let outbound_caps = out.caps();
        let outbound_mtu = outbound_caps.mtu();
        let floor = segment.min_mtu.max(Plane::Stream.minimum_mtu());
        if outbound_mtu < floor || inbound_mtu < floor {
            let error = CoreErr::MtuTooSmall(outbound_mtu.min(inbound_mtu));
            best_effort(up.write_all(&setup_error(&auth.hop_key, &error, Cid::UNBOUND))).await;
            return Err(error);
        }
        let (mut right, mut down) = out.split();
        let deadline = setup_deadline();
        let bound = async {
            down.write_all(
                &ForwardHeader {
                    max_mtu: hdr.max_mtu.min(inbound_mtu).min(outbound_mtu),
                    upstream: Cid::UNBOUND,
                }
                .encode(),
            )
            .await?;
            down.write_all(segment.tail).await?;
            st_splice::read_reply(&mut *right).await
        };
        let mut ret = match race(auth.grant.cancelled(), before(deadline, bound)).await {
            Either::Left(error) | Either::Right(Err(error)) => {
                best_effort(up.write_all(&setup_error(&auth.hop_key, &error, Cid::UNBOUND))).await;
                return Err(error);
            }
            Either::Right(Ok(wire)) => wire,
        };
        if ret[0] == setup::ERR {
            retransmit_error(&mut ret, Cid::UNBOUND)?;
            return before(deadline, up.write_all(&ret)).await;
        }
        let mut hdr = OkHeader::parse(&ret)?;
        if hdr.target != Cid::UNBOUND || hdr.responder != Cid::UNBOUND {
            return Err(CoreErr::Malformed);
        }
        hdr.reverse_mtu = hdr.reverse_mtu.min(inbound_mtu).min(outbound_mtu);
        ret[..12].copy_from_slice(&hdr.encode());
        let session = scope.session()?;
        before(deadline, up.write_all(&ret)).await?;
        drop(pending);
        let _session = session;
        return st_splice::splice(
            st_splice::Carrier {
                reader: left,
                writer: up,
                mtu: inbound_caps.mtu_watch,
            },
            st_splice::Carrier {
                reader: right,
                writer: down,
                mtu: outbound_caps.mtu_watch,
            },
            auth,
            floor,
        )
        .await;
    }

    let responder = Responder::accept(
        &scope.identity,
        &scope.replay,
        segment.encrypted,
        &segment.aad(),
        now_ms(),
    )?;
    let key = responder.hop_key();
    let authorized = if segment.plane == Plane::Stream {
        admit(&scope, &responder, &segment, hdr.max_mtu.min(inbound_mtu)).await
    } else {
        Err(CoreErr::WrongPlane)
    };
    let (endpoint, session) = match authorized.and_then(|endpoint| Ok((endpoint, scope.session()?)))
    {
        Ok(result) => result,
        Err(error) => {
            best_effort(up.write_all(&setup_error(&key, &error, Cid::UNBOUND))).await;
            return Err(error);
        }
    };
    let (payload, keys) = responder.reply(&endpoint.ack())?;
    let Published::Stream(handler) = &*endpoint.publication else {
        unreachable!()
    };
    let pending = AwaitingConfirm::new(pending, endpoint.pending);
    before(
        pending.deadline,
        up.write_all(&reply(
            OkHeader {
                reverse_mtu: inbound_mtu,
                target: Cid::UNBOUND,
                responder: Cid::UNBOUND,
            },
            &payload,
        )),
    )
    .await?;
    stream::serve(
        st_splice::Carrier {
            reader: left,
            writer: up,
            mtu: inbound_caps.mtu_watch,
        },
        keys,
        (
            endpoint.mtu,
            segment.min_mtu.max(Plane::Stream.minimum_mtu()),
        ),
        handler.clone(),
        endpoint.authorization,
        pending,
        session,
    )
    .await
}

struct RejectOnDrop<'a>(&'a DatagramPort);
impl Drop for RejectOnDrop<'_> {
    fn drop(&mut self) {
        self.0.mark_rejected();
    }
}

pub(crate) async fn datagram(
    scope: Arc<Scope>,
    port: Arc<DatagramPort>,
    packet: PacketBuf,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let _reject_if_unadmitted = RejectOnDrop(&port);
    let wire = packet.as_slice();
    let hdr = ForwardHeader::parse(wire)?;
    if hdr.upstream == Cid::UNBOUND {
        return Err(CoreErr::Malformed);
    }
    let segment = Segment::parse(&wire[8..])?;
    let inbound_mtu = port.link.caps().mtu();
    if let Some(tag) = segment.channel {
        if segment.plane != Plane::Datagram {
            return Err(CoreErr::WrongPlane);
        }
        let channel = scope.datagram_channel(tag)?;
        let (out, auth) = match tokio::time::timeout(
            crate::SETUP_TIMEOUT,
            channel.accept_hop_datagram(segment.encrypted, &segment.aad(), segment.min_mtu),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(HopReject::Authenticated(key, error))) => {
                best_effort(port.link.send(PacketBuf::from_slice(&setup_error(
                    &key,
                    &error,
                    hdr.upstream,
                ))))
                .await;
                return Err(error);
            }
            Ok(Err(HopReject::Silent)) => return Err(CoreErr::Authentication),
            Err(_) => return Err(CoreErr::Timeout),
        };
        port.mark_admitted();
        let (tail_len, min_mtu) = (
            segment.tail.len(),
            segment.min_mtu.max(Plane::Datagram.minimum_mtu()),
        );
        let deadline = setup_deadline();
        let bound = async {
            let right_port = DatagramPort::attach(&scope, out)?;
            let left = port.bind()?;
            let mut right = right_port.bind()?;
            let outbound_mtu = right.mtu();
            let physical = inbound_mtu.min(outbound_mtu);
            if physical < min_mtu || 8 + tail_len > usize::from(outbound_mtu) {
                return Err(CoreErr::MtuTooSmall(physical));
            }
            let mut forward = packet;
            let strip = forward.len() - tail_len;
            forward.strip_header(strip);
            forward.prepend_header(
                &ForwardHeader {
                    max_mtu: hdr.max_mtu.min(physical),
                    upstream: right.cid,
                }
                .encode(),
            );
            right.send(forward).await?;
            let response = loop {
                let mut response = right.recv().await?;
                if let Ok(mut ok) = OkHeader::parse(response.as_slice()) {
                    if ok.target != right.cid || ok.responder == Cid::UNBOUND {
                        continue;
                    }
                    let next = ok.responder;
                    ok.reverse_mtu = ok.reverse_mtu.min(physical);
                    ok.target = hdr.upstream;
                    ok.responder = left.cid;
                    response.as_mut_slice()[..12].copy_from_slice(&ok.encode());
                    break (response, Some(next));
                }
                if let Ok((_, target, _)) = setup::parse_error(response.as_slice())
                    && target == right.cid
                {
                    retransmit_error(response.as_mut_slice(), hdr.upstream)?;
                    break (response, None);
                }
            };
            Ok((left, right, response))
        };
        let (left, right, (ret, next)) =
            match race(auth.grant.cancelled(), before(deadline, bound)).await {
                Either::Left(error) | Either::Right(Err(error)) => {
                    best_effort(port.link.send(PacketBuf::from_slice(&setup_error(
                        &auth.hop_key,
                        &error,
                        hdr.upstream,
                    ))))
                    .await;
                    return Err(error);
                }
                Either::Right(Ok(result)) => result,
            };
        let Some(next) = next else {
            return before(deadline, left.send(ret)).await;
        };
        let session = match scope.session() {
            Ok(session) => session,
            Err(error) => {
                best_effort(left.send(PacketBuf::from_slice(&setup_error(
                    &auth.hop_key,
                    &error,
                    hdr.upstream,
                ))))
                .await;
                return Err(error);
            }
        };
        before(deadline, left.send(ret)).await?;
        drop(pending);
        return Transit {
            left,
            right,
            caller: hdr.upstream,
            next,
            min_mtu,
            auth,
            _session: session,
        }
        .run()
        .await;
    }

    let responder = Responder::accept(
        &scope.identity,
        &scope.replay,
        segment.encrypted,
        &segment.aad(),
        now_ms(),
    )?;
    let key = responder.hop_key();
    let authorized = if segment.plane == Plane::Datagram {
        admit(&scope, &responder, &segment, hdr.max_mtu.min(inbound_mtu)).await
    } else {
        Err(CoreErr::WrongPlane)
    };
    let (endpoint, session, binding) =
        match authorized.and_then(|endpoint| Ok((endpoint, scope.session()?, port.bind()?))) {
            Ok(result) => {
                port.mark_admitted();
                result
            }
            Err(error) => {
                best_effort(port.link.send(PacketBuf::from_slice(&setup_error(
                    &key,
                    &error,
                    hdr.upstream,
                ))))
                .await;
                return Err(error);
            }
        };
    let (payload, keys) = responder.reply(&endpoint.ack())?;
    let Published::Datagram(floor, handler) = &*endpoint.publication else {
        unreachable!()
    };
    let mtu = endpoint.mtu;
    let min = (*floor).max(segment.min_mtu);
    let pending = AwaitingConfirm::new(pending, endpoint.pending);
    before(
        pending.deadline,
        binding.send(PacketBuf::from_slice(&reply(
            OkHeader {
                reverse_mtu: inbound_mtu,
                target: hdr.upstream,
                responder: binding.cid,
            },
            &payload,
        ))),
    )
    .await?;
    datagram::serve(
        datagram::Wire::new(binding, hdr.upstream, keys),
        datagram::Mtu {
            ceiling: mtu,
            floor: min,
        },
        handler.clone(),
        endpoint.authorization,
        pending,
        session,
    )
    .await
}
