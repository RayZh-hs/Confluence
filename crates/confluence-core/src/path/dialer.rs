use std::sync::Arc;

use super::{dg_switch::DatagramPort, st_splice, timed};
use crate::{
    CoreErr, DATAGRAM_MTU, E2eDatagram, E2eStream, ExplicitPath, PacketBuf, PathOutcome, Plane,
    PublicKey,
    cid::Cid,
    crypto::noise_ik::{self, HopKey, Initiator, SessionKeys},
    e2e::{datagram, renewal::Renewals, stream},
    grant::{GrantEnforcer, GrantSpec},
    now_ms,
    scope::Scope,
    wire::{setup, u16_at},
};

struct Setup {
    tail: Vec<u8>,
    destination: Initiator,
    hops: Vec<HopKey>,
}
impl Setup {
    fn build(
        scope: &Scope,
        path: &ExplicitPath,
        peer: PublicKey,
        ep: &str,
        cred: &[u8],
        plane: Plane,
        min: u16,
    ) -> Result<Self, CoreErr> {
        if path.hops.len() > 255 {
            return Err(CoreErr::Malformed);
        }
        let timestamp = now_ms();
        let plain = noise_ik::endpoint_plaintext(timestamp, ep, cred)?;
        let mut tail = setup::prefix(plane, min, None, setup::SEGMENT_OVERHEAD + plain.len(), 0)?;
        let (seg, destination) =
            noise_ik::initiate(&scope.identity, peer, &setup::tail_aad(&tail, &[]), &plain)?;
        tail.extend_from_slice(&seg);

        let mut hops = Vec::with_capacity(path.hops.len());
        for hop in path.hops.iter().rev() {
            let plain = noise_ik::hop_plaintext(timestamp, &hop.credential, &hop.locator)?;
            let mut prefix = setup::prefix(
                plane,
                min,
                Some(hop.channel),
                setup::SEGMENT_OVERHEAD + plain.len(),
                tail.len(),
            )?;
            let (seg, state) = noise_ik::initiate(
                &scope.identity,
                hop.peer,
                &setup::tail_aad(&prefix, &tail),
                &plain,
            )?;
            prefix.extend_from_slice(&seg);
            prefix.extend_from_slice(&tail);
            tail = prefix;
            hops.push(state.hop_key());
        }
        hops.reverse();
        Ok(Self {
            tail,
            destination,
            hops,
        })
    }

    fn forward(&self, max: u16, cid: Cid) -> Vec<u8> {
        let mut wire = Vec::with_capacity(8 + self.tail.len());
        wire.extend_from_slice(
            &setup::ForwardHeader {
                max_mtu: max,
                upstream: cid,
            }
            .encode(),
        );
        wire.extend_from_slice(&self.tail);
        wire
    }

    fn rejection(&self, reply: &[u8], expected_cid: Cid) -> Result<CoreErr, CoreErr> {
        let (index, cid, body) = setup::parse_error(reply)?;
        if cid != expected_cid {
            return Err(CoreErr::Malformed);
        }
        let key = if usize::from(index) == self.hops.len() {
            self.destination.hop_key()
        } else {
            self.hops
                .get(usize::from(index))
                .cloned()
                .ok_or(CoreErr::Authentication)?
        };
        let rejection = setup::decode_error(&key.open_setup_error(body)?)?;
        Ok(if usize::from(index) == self.hops.len() {
            rejection
        } else {
            CoreErr::HopRejected {
                index,
                reason: Box::new(rejection),
            }
        })
    }
    fn opened(
        &self,
        scope: &Scope,
        reply: &[u8],
        header: setup::OkHeader,
        local: u16,
        min: u16,
    ) -> Result<(u16, GrantSpec, SessionKeys, Vec<HopKey>, HopKey), CoreErr> {
        let terminal = self.destination.hop_key();
        let (ack, keys) = self.destination.finish(&scope.identity, &reply[12..])?;
        let mtu = u16_at(&ack, 0).min(header.reverse_mtu).min(local);
        if mtu < min {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        Ok((
            mtu,
            GrantSpec::from_wire(&ack[2..])?,
            keys,
            self.hops.clone(),
            terminal,
        ))
    }
}

pub(crate) async fn stream(
    scope: &Arc<Scope>,
    path: &ExplicitPath,
    peer: PublicKey,
    ep: &str,
    cred: &[u8],
) -> Result<E2eStream, CoreErr> {
    if scope.policy.is_vetoed(&peer) {
        return Err(CoreErr::Revoked);
    }
    let epoch = scope.policy.epoch_for(peer, None);
    let session = scope.session()?;
    let min = path.min_mtu.max((crate::wire::e2e::ST_OVERHEAD + 1) as u16);
    let channel = scope.stream_channel(path.first_channel)?;
    if channel.caps().mtu() < min {
        return Err(CoreErr::MtuTooSmall(channel.caps().mtu()));
    }
    let setup = Setup::build(scope, path, peer, ep, cred, Plane::Stream, min)?;
    let (io, mtu, spec, keys, hops, terminal) = timed(async {
        let stream = channel.dial_stream(&path.first_locator).await?;
        let caps = stream.caps();
        let local = caps.mtu();
        if local < min {
            return Err(CoreErr::MtuTooSmall(local));
        }
        let (mut reader, mut writer) = stream.split();
        writer
            .write_all(&setup.forward(local, Cid::UNBOUND))
            .await?;
        let reply = st_splice::read_reply(&mut *reader).await?;
        if reply[0] == setup::ERR {
            return Err(setup.rejection(&reply, Cid::UNBOUND)?);
        }
        let header = setup::OkHeader::parse(&reply)?;
        if header.target != Cid::UNBOUND || header.responder != Cid::UNBOUND {
            return Err(CoreErr::Malformed);
        }
        let (mtu, spec, keys, hops, terminal) = setup.opened(scope, &reply, header, local, min)?;
        Ok((
            st_splice::Carrier {
                reader,
                writer,
                mtu: caps.mtu_watch,
            },
            mtu,
            spec,
            keys,
            hops,
            terminal,
        ))
    })
    .await?;
    let grant = Arc::new(GrantEnforcer::new(spec)?);
    scope.policy.track(epoch, peer, None, &grant)?;
    let renewals = Renewals::new(
        scope.source.clone(),
        path,
        Plane::Stream,
        cred,
        hops,
        terminal,
        spec,
    );
    let connected = stream::connect(scope, io, keys, (mtu, min), grant, renewals, session).await?;
    scope
        .source
        .report_outcome(path.id, PathOutcome::Established { mtu });
    Ok(connected)
}

pub(crate) async fn datagram(
    scope: &Arc<Scope>,
    path: &ExplicitPath,
    peer: PublicKey,
    ep: &str,
    min_mtu: u16,
    cred: &[u8],
) -> Result<E2eDatagram, CoreErr> {
    if scope.policy.is_vetoed(&peer) {
        return Err(CoreErr::Revoked);
    }
    let epoch = scope.policy.epoch_for(peer, None);
    let session = scope.session()?;
    let min = path.min_mtu.max(min_mtu).max(DATAGRAM_MTU);
    let channel = scope.datagram_channel(path.first_channel)?;
    let cap = channel.caps().mtu();
    if cap < min {
        return Err(CoreErr::MtuTooSmall(cap));
    }
    let setup = Setup::build(scope, path, peer, ep, cred, Plane::Datagram, min)?;
    if setup.tail.len() + 8 > usize::from(cap) {
        return Err(CoreErr::MtuTooSmall(cap));
    }
    let (binding, remote, mtu, spec, keys, hops, terminal) = timed(async {
        let link = channel.open_link(&path.first_locator).await?;
        let mut binding = DatagramPort::attach(scope, link)?.bind()?;
        let local = binding.mtu();
        if local < min || setup.tail.len() + 8 > usize::from(local) {
            return Err(CoreErr::MtuTooSmall(local));
        }
        binding
            .send(PacketBuf::from_slice(&setup.forward(local, binding.cid)))
            .await?;
        loop {
            let reply = binding.recv().await?;
            let bytes = reply.as_slice();
            if bytes[0] == setup::ERR {
                if let Ok(error) = setup.rejection(bytes, binding.cid) {
                    return Err(error);
                }
            } else if let Ok(header) = setup::OkHeader::parse(bytes)
                && header.target == binding.cid
                && header.responder != Cid::UNBOUND
            {
                match setup.opened(scope, bytes, header, local, min) {
                    Ok((mtu, spec, keys, hops, terminal)) => {
                        return Ok((binding, header.responder, mtu, spec, keys, hops, terminal));
                    }
                    Err(CoreErr::Authentication) => continue,
                    Err(error) => return Err(error),
                }
            }
        }
    })
    .await?;
    let grant = Arc::new(GrantEnforcer::new(spec)?);
    scope.policy.track(epoch, peer, None, &grant)?;
    let renewals = Renewals::new(
        scope.source.clone(),
        path,
        Plane::Datagram,
        cred,
        hops,
        terminal,
        spec,
    );
    let connected = datagram::connect(
        scope,
        datagram::Wire::new(binding, remote, keys),
        datagram::Mtu {
            ceiling: mtu,
            floor: min,
        },
        grant,
        renewals,
        session,
    )
    .await?;
    scope
        .source
        .report_outcome(path.id, PathOutcome::Established { mtu });
    Ok(connected)
}
