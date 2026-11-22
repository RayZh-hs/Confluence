use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;

use super::{
    before, best_effort,
    dg_switch::{DatagramPort, Transit},
    setup_deadline, st_splice, timed,
};
use crate::{
    AuthRequest, BoxFut, CoreErr, DatagramLink, DatagramLinkExt, DynAsyncStream, PacketBuf,
    PendingSetup, Plane, PublicKey, StreamWriteExt, TargetRef,
    cid::Cid,
    crypto::{
        cookie::CookieCheck,
        noise_ik::{self, HopKey, REPLY_LEN, Responder},
    },
    e2e::{self, AwaitingConfirm, datagram, stream},
    lease::{Lease, LeaseHandle},
    node::NodeInner,
    now_ms,
    scope::{PublishedEndpoint, Scope},
    wire::setup::{self, ForwardHeader, OkHeader, Segment},
};

/// Internal authorized transit session state managed by Core's path engine.
pub(crate) struct HopSession {
    pub scope: Arc<Scope>,
    pub peer: PublicKey,
    pub hop_key: HopKey,
    pub lease: Arc<LeaseHandle>,
    pub target: String,
    pub plane: Plane,
    pub pending: Option<PendingSetup>,
}

impl HopSession {
    /// Re-verifies named transit authorization in-band during live `HOP_RENEW`.
    pub fn renewal(&self, credential: Vec<u8>) -> BoxFut<'static, Result<[u8; 8], CoreErr>> {
        let (scope, peer, target, plane, lease) = (
            self.scope.clone(),
            self.peer,
            self.target.clone(),
            self.plane,
            self.lease.clone(),
        );
        Box::pin(async move {
            let renewed = scope
                .auth
                .authorize(AuthRequest {
                    peer,
                    target: TargetRef::Transit {
                        name: &target,
                        plane,
                    },
                    credential: &credential,
                    is_renewal: true,
                })
                .await?;
            let wire_ttl = Lease::wire_ttl_bytes(renewed.ttl);
            scope.auth.renew_lease_from(&lease, renewed)?;
            Ok(wire_ttl)
        })
    }
}

struct AdmittedEndpoint {
    publication: Arc<PublishedEndpoint>,
    authorization: e2e::EndpointAuth,
    ttl: Duration,
    pending: PendingSetup,
    mtu: u16,
}

async fn admit_endpoint(
    scope: &Arc<Scope>,
    responder: &Responder,
    seg: &Segment<'_>,
    mtu: u16,
) -> Result<AdmittedEndpoint, CoreErr> {
    let (name, credential) = noise_ik::parse_endpoint(&responder.plaintext)?;
    let peer = responder.peer;
    let pending = scope.auth.pending(peer)?;
    let epoch = scope.auth.epoch_for_endpoint(peer, Some(name));
    let publication = scope
        .endpoints
        .lock()
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
    let lease_spec = scope
        .auth
        .authorize(AuthRequest {
            peer,
            target: TargetRef::Endpoint {
                name,
                plane: seg.plane,
            },
            credential,
            is_renewal: false,
        })
        .await?;
    let ttl = lease_spec.ttl;
    let lease = Arc::new(scope.auth.new_lease_from(lease_spec)?);
    {
        let registry = scope.endpoints.lock();
        if !registry
            .get(name)
            .is_some_and(|entry| Arc::ptr_eq(entry, &publication))
        {
            return Err(CoreErr::Unpublished);
        }
        scope.auth.track_endpoint(epoch, peer, Some(name), &lease)?;
    }
    Ok(AdmittedEndpoint {
        authorization: e2e::EndpointAuth {
            scope: scope.clone(),
            name: name.to_owned(),
            peer,
            plane: seg.plane,
            lease,
            terminal_key: responder.hop_key(),
        },
        ttl,
        pending,
        publication,
        mtu,
    })
}

impl AdmittedEndpoint {
    fn ack(&self) -> [u8; 10] {
        let mut ack = [0; 10];
        ack[..2].copy_from_slice(&self.mtu.to_be_bytes());
        ack[2..].copy_from_slice(&Lease::wire_ttl_bytes(self.ttl));
        ack
    }
}

async fn admit_stream_transit(
    scope: &Arc<Scope>,
    responder: &Responder,
    seg_min_mtu: u16,
) -> Result<(Box<dyn DynAsyncStream>, HopSession), CoreErr> {
    let (target_name, credential) = noise_ik::parse_hop(&responder.plaintext)?;
    let peer = responder.peer;
    let pending = scope.auth.pending(peer)?;
    let resolved = scope.resolve_stream_transit(target_name)?;
    let floor = seg_min_mtu.max(Plane::Stream.minimum_mtu());
    let limit = resolved.handler.dyn_caps().mtu();
    if limit < floor {
        return Err(CoreErr::MtuTooSmall(limit));
    }
    let epoch =
        scope
            .auth
            .epoch_for_transit(peer, Plane::Stream, target_name, resolved.prefix.as_deref());
    let lease_spec = scope
        .auth
        .authorize(AuthRequest {
            peer,
            target: TargetRef::Transit {
                name: target_name,
                plane: Plane::Stream,
            },
            credential,
            is_renewal: false,
        })
        .await?;
    let lease = Arc::new(scope.auth.new_lease_from(lease_spec)?);
    if !scope.is_stream_transit_published(
        target_name,
        resolved.prefix.as_deref(),
        &resolved.handler,
    ) {
        return Err(CoreErr::Unpublished);
    }
    scope.auth.track_transit(
        epoch,
        peer,
        Plane::Stream,
        target_name,
        resolved.prefix.as_deref(),
        &lease,
    )?;
    let session_auth = lease.session_auth(peer);
    let stream = tokio::select! {
        err = lease.cancelled() => return Err(err),
        res = timed(resolved.handler.dyn_open(&resolved.subtarget, session_auth)) => res?,
    };
    lease.remaining()?;
    Ok((
        stream,
        HopSession {
            scope: scope.clone(),
            peer,
            hop_key: responder.hop_key(),
            lease,
            target: target_name.to_owned(),
            plane: Plane::Stream,
            pending: Some(pending),
        },
    ))
}

async fn admit_datagram_transit(
    scope: &Arc<Scope>,
    responder: &Responder,
    seg_min_mtu: u16,
) -> Result<(Arc<dyn DatagramLink>, HopSession), CoreErr> {
    let (target_name, credential) = noise_ik::parse_hop(&responder.plaintext)?;
    let peer = responder.peer;
    let pending = scope.auth.pending(peer)?;
    let resolved = scope.resolve_datagram_transit(target_name)?;
    let floor = seg_min_mtu.max(Plane::Datagram.minimum_mtu());
    let limit = resolved.handler.dyn_caps().mtu();
    if limit < floor {
        return Err(CoreErr::MtuTooSmall(limit));
    }
    let epoch = scope.auth.epoch_for_transit(
        peer,
        Plane::Datagram,
        target_name,
        resolved.prefix.as_deref(),
    );
    let lease_spec = scope
        .auth
        .authorize(AuthRequest {
            peer,
            target: TargetRef::Transit {
                name: target_name,
                plane: Plane::Datagram,
            },
            credential,
            is_renewal: false,
        })
        .await?;
    let lease = Arc::new(scope.auth.new_lease_from(lease_spec)?);
    if !scope.is_datagram_transit_published(
        target_name,
        resolved.prefix.as_deref(),
        &resolved.handler,
    ) {
        return Err(CoreErr::Unpublished);
    }
    scope.auth.track_transit(
        epoch,
        peer,
        Plane::Datagram,
        target_name,
        resolved.prefix.as_deref(),
        &lease,
    )?;
    let session_auth = lease.session_auth(peer);
    let link = tokio::select! {
        err = lease.cancelled() => return Err(err),
        res = timed(resolved.handler.dyn_open(&resolved.subtarget, session_auth)) => res?,
    };
    lease.remaining()?;
    Ok((
        link,
        HopSession {
            scope: scope.clone(),
            peer,
            hop_key: responder.hop_key(),
            lease,
            target: target_name.to_owned(),
            plane: Plane::Datagram,
            pending: Some(pending),
        },
    ))
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

fn reply(header: OkHeader, payload: &[u8; REPLY_LEN]) -> Vec<u8> {
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

fn retransmit_cookie(wire: &mut [u8], cid: Cid) -> Result<(), CoreErr> {
    let (distance, _, _) = setup::parse_cookie(wire)?;
    let distance = distance.checked_add(1).ok_or(CoreErr::Malformed)?;
    wire[1] = distance;
    wire[4..8].copy_from_slice(&cid.raw().to_be_bytes());
    Ok(())
}

pub(crate) async fn stream(
    scope: Arc<Scope>,
    stream: Box<dyn DynAsyncStream>,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_caps = stream.dyn_caps();
    let source_tag = stream.dyn_source_tag();
    let (mut left, up) = stream.split_boxed();
    let wire = timed(st_splice::read_opening(&scope, &mut *left)).await?;
    stream_dispatch(scope, inbound_caps, source_tag, left, up, wire, pending).await
}

pub(crate) async fn stream_from_node(
    node: Arc<NodeInner>,
    stream: Box<dyn DynAsyncStream>,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_caps = stream.dyn_caps();
    let source_tag = stream.dyn_source_tag();
    let (mut left, up) = stream.split_boxed();
    let (scope, wire) = timed(st_splice::read_opening_for_node(&node, &mut *left)).await?;
    stream_dispatch(scope, inbound_caps, source_tag, left, up, wire, pending).await
}

async fn stream_dispatch(
    scope: Arc<Scope>,
    inbound_caps: crate::ChannelCaps,
    source_tag: [u8; 16],
    left: Box<dyn crate::StreamRead>,
    mut up: Box<dyn crate::StreamWrite>,
    wire: Vec<u8>,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let hdr = ForwardHeader::parse(&wire)?;
    if hdr.upstream != Cid::UNBOUND {
        return Err(CoreErr::Malformed);
    }
    let segment = Segment::parse(&wire[8..])?;
    let base_seg =
        match scope
            .cookies
            .verify_segment(&source_tag, segment.encrypted, segment.has_mac2)
        {
            CookieCheck::Verified(base) => base,
            CookieCheck::Challenge(challenge) => {
                let frame = setup::encode_cookie(0, Cid::UNBOUND, &challenge);
                best_effort(up.write_all(&frame)).await;
                return Err(CoreErr::Authentication);
            }
            CookieCheck::Drop => return Err(CoreErr::Authentication),
        };
    let responder = Responder::accept(
        &scope.identity,
        &scope.replay,
        base_seg,
        &segment.aad(),
        now_ms(),
    )?;
    if segment.is_hop {
        stream_transit(
            scope,
            inbound_caps,
            left,
            up,
            hdr,
            &segment,
            responder,
            pending,
        )
        .await
    } else {
        stream_destination(
            scope,
            inbound_caps,
            left,
            up,
            hdr,
            &segment,
            responder,
            pending,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream_transit(
    scope: Arc<Scope>,
    inbound_caps: crate::ChannelCaps,
    left: Box<dyn crate::StreamRead>,
    mut up: Box<dyn crate::StreamWrite>,
    hdr: ForwardHeader,
    segment: &Segment<'_>,
    responder: Responder,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_mtu = inbound_caps.mtu();
    let key = responder.hop_key();
    let (out, auth) = match if segment.plane == Plane::Stream {
        admit_stream_transit(&scope, &responder, segment.min_mtu).await
    } else {
        Err(CoreErr::WrongPlane)
    } {
        Ok(pair) => pair,
        Err(error) => {
            best_effort(up.write_all(&setup_error(&key, &error, Cid::UNBOUND))).await;
            return Err(error);
        }
    };
    let outbound_caps = out.dyn_caps();
    let outbound_mtu = outbound_caps.mtu();
    let floor = segment.min_mtu.max(Plane::Stream.minimum_mtu());
    if outbound_mtu < floor || inbound_mtu < floor {
        let error = CoreErr::MtuTooSmall(outbound_mtu.min(inbound_mtu));
        best_effort(up.write_all(&setup_error(&auth.hop_key, &error, Cid::UNBOUND))).await;
        return Err(error);
    }
    let (mut right, mut down) = out.split_boxed();
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
    let mut ret = tokio::select! {
        error = auth.lease.cancelled() => {
            best_effort(up.write_all(&setup_error(&auth.hop_key, &error, Cid::UNBOUND))).await;
            return Err(error);
        }
        res = before(deadline, bound) => match res {
            Ok(wire) => wire,
            Err(error) => {
                best_effort(up.write_all(&setup_error(&auth.hop_key, &error, Cid::UNBOUND))).await;
                return Err(error);
            }
        }
    };
    if ret[0] == setup::ERR {
        retransmit_error(&mut ret, Cid::UNBOUND)?;
        return before(deadline, up.write_all(&ret)).await;
    }
    if ret[0] == setup::COOKIE {
        retransmit_cookie(&mut ret, Cid::UNBOUND)?;
        return before(deadline, up.write_all(&ret)).await;
    }
    let mut ok = OkHeader::parse(&ret)?;
    if ok.target != Cid::UNBOUND || ok.responder != Cid::UNBOUND {
        return Err(CoreErr::Malformed);
    }
    ok.hop_acks = ok.hop_acks.checked_add(1).ok_or(CoreErr::Malformed)?;
    ok.reverse_mtu = ok.reverse_mtu.min(inbound_mtu).min(outbound_mtu);
    let trailer = auth.hop_key.setup_lease(auth.lease.wire_lease());
    if ret.len() + trailer.len() > crate::STREAM_CHUNK {
        return Err(CoreErr::Malformed);
    }
    ret[..12].copy_from_slice(&ok.encode());
    ret.extend_from_slice(&trailer);
    let session = scope.session()?;
    before(deadline, up.write_all(&ret)).await?;
    drop(pending);
    let _session = session;
    st_splice::splice(
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
    .await
}

#[allow(clippy::too_many_arguments)]
async fn stream_destination(
    scope: Arc<Scope>,
    inbound_caps: crate::ChannelCaps,
    left: Box<dyn crate::StreamRead>,
    mut up: Box<dyn crate::StreamWrite>,
    hdr: ForwardHeader,
    segment: &Segment<'_>,
    responder: Responder,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_mtu = inbound_caps.mtu();
    let key = responder.hop_key();
    let authorized = if segment.plane == Plane::Stream {
        admit_endpoint(&scope, &responder, segment, hdr.max_mtu.min(inbound_mtu)).await
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
    let PublishedEndpoint::Stream(handler) = &*endpoint.publication else {
        unreachable!()
    };
    let pending = AwaitingConfirm::new(pending, endpoint.pending);
    before(
        pending.deadline,
        up.write_all(&reply(
            OkHeader {
                hop_acks: 0,
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
    let source_tag = port.link.source_tag();
    let (hdr, is_hop, plane, seg_min_mtu, tail_len, responder) = {
        let wire = packet.as_slice();
        let hdr = ForwardHeader::parse(wire)?;
        if hdr.upstream == Cid::UNBOUND {
            return Err(CoreErr::Malformed);
        }
        let segment = Segment::parse(&wire[8..])?;
        let base_seg =
            match scope
                .cookies
                .verify_segment(&source_tag, segment.encrypted, segment.has_mac2)
            {
                CookieCheck::Verified(base) => base,
                CookieCheck::Challenge(challenge) => {
                    let frame = setup::encode_cookie(0, hdr.upstream, &challenge);
                    best_effort(port.link.send(PacketBuf::from_slice(&frame))).await;
                    return Err(CoreErr::Authentication);
                }
                CookieCheck::Drop => return Err(CoreErr::Authentication),
            };
        let responder = Responder::accept(
            &scope.identity,
            &scope.replay,
            base_seg,
            &segment.aad(),
            now_ms(),
        )?;
        (
            hdr,
            segment.is_hop,
            segment.plane,
            segment.min_mtu,
            segment.tail.len(),
            responder,
        )
    };
    if is_hop {
        datagram_transit(
            scope,
            port.clone(),
            packet,
            hdr,
            plane,
            seg_min_mtu,
            tail_len,
            responder,
            pending,
        )
        .await
    } else {
        datagram_destination(
            scope,
            port.clone(),
            hdr,
            plane,
            seg_min_mtu,
            responder,
            pending,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn datagram_transit(
    scope: Arc<Scope>,
    port: Arc<DatagramPort>,
    packet: PacketBuf,
    hdr: ForwardHeader,
    plane: Plane,
    seg_min_mtu: u16,
    tail_len: usize,
    responder: Responder,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_mtu = port.link.caps().mtu();
    let key = responder.hop_key();
    let (out, auth) = match if plane == Plane::Datagram {
        admit_datagram_transit(&scope, &responder, seg_min_mtu).await
    } else {
        Err(CoreErr::WrongPlane)
    } {
        Ok(pair) => pair,
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
    port.mark_admitted();
    let min_mtu = seg_min_mtu.max(Plane::Datagram.minimum_mtu());
    let deadline = setup_deadline();
    let bound = async {
        let right_port = DatagramPort::attach_scope(&scope, out)?;
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
                ok.hop_acks = ok.hop_acks.checked_add(1).ok_or(CoreErr::Malformed)?;
                ok.reverse_mtu = ok.reverse_mtu.min(physical);
                ok.target = hdr.upstream;
                ok.responder = left.cid;
                let trailer = auth.hop_key.setup_lease(auth.lease.wire_lease());
                if response.len() + trailer.len() > usize::from(physical) {
                    return Err(CoreErr::MtuTooSmall(physical));
                }
                response.as_mut_slice()[..12].copy_from_slice(&ok.encode());
                if !response.extend_tail(&trailer) {
                    let mut grown = PacketBuf::with_payload_cap(response.len() + trailer.len());
                    grown.spare_payload()[..response.len()].copy_from_slice(response.as_slice());
                    grown.advance_payload(response.len());
                    grown.spare_payload()[..trailer.len()].copy_from_slice(&trailer);
                    grown.advance_payload(trailer.len());
                    response = grown;
                }
                break (response, Some(next));
            }
            if let Ok((_, target, _)) = setup::parse_error(response.as_slice())
                && target == right.cid
            {
                retransmit_error(response.as_mut_slice(), hdr.upstream)?;
                break (response, None);
            }
            if let Ok((_, target, _)) = setup::parse_cookie(response.as_slice())
                && target == right.cid
            {
                retransmit_cookie(response.as_mut_slice(), hdr.upstream)?;
                break (response, None);
            }
        };
        Ok((left, right, response))
    };
    let (left, right, (ret, next)) = tokio::select! {
        error = auth.lease.cancelled() => {
            best_effort(port.link.send(PacketBuf::from_slice(&setup_error(
                &auth.hop_key,
                &error,
                hdr.upstream,
            )))).await;
            return Err(error);
        }
        res = before(deadline, bound) => match res {
            Ok(result) => result,
            Err(error) => {
                best_effort(port.link.send(PacketBuf::from_slice(&setup_error(
                    &auth.hop_key,
                    &error,
                    hdr.upstream,
                )))).await;
                return Err(error);
            }
        }
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
    Transit {
        left,
        right,
        caller: hdr.upstream,
        next,
        min_mtu,
        auth,
        _session: session,
    }
    .run()
    .await
}

async fn datagram_destination(
    scope: Arc<Scope>,
    port: Arc<DatagramPort>,
    hdr: ForwardHeader,
    plane: Plane,
    seg_min_mtu: u16,
    responder: Responder,
    pending: OwnedSemaphorePermit,
) -> Result<(), CoreErr> {
    let inbound_mtu = port.link.caps().mtu();
    let key = responder.hop_key();
    let dummy_seg = Segment {
        is_hop: false,
        plane,
        min_mtu: seg_min_mtu,
        has_mac2: false,
        prefix: &[],
        encrypted: &[],
        tail: &[],
    };
    let authorized = if plane == Plane::Datagram {
        admit_endpoint(&scope, &responder, &dummy_seg, hdr.max_mtu.min(inbound_mtu)).await
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
    let PublishedEndpoint::Datagram(floor, handler) = &*endpoint.publication else {
        unreachable!()
    };
    let mtu = endpoint.mtu;
    let min = (*floor).max(seg_min_mtu);
    let pending = AwaitingConfirm::new(pending, endpoint.pending);
    before(
        pending.deadline,
        binding.send(PacketBuf::from_slice(&reply(
            OkHeader {
                hop_acks: 0,
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
