use std::{collections::HashMap, sync::Arc, time::Duration};

use super::{dg_switch::DatagramPort, st_splice, timed};
use crate::{
    CoreErr, CredentialRequest, DATAGRAM_MTU, ExplicitPath, PacketBuf, Plane, PublicKey,
    StagedDatagram, StagedStream, StreamWriteExt, TargetRef,
    cid::Cid,
    crypto::{
        cookie::{COOKIE_LEN, MAC_LEN, append_mac2, unseal_cookie_challenge},
        noise_ik::{self, HopKey, Initiator, SessionKeys},
    },
    e2e::{datagram, renewal::Renewals},
    lease::{Lease, LeaseHandle, MAX_WIRE_LEASE_TTL},
    now_ms,
    scope::Scope,
    wire::{e2e, setup, u16_at},
};

async fn fetch_credentials(
    scope: &Scope,
    path: &ExplicitPath,
    peer: PublicKey,
    ep: &str,
    plane: Plane,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), CoreErr> {
    let timeout = scope.auth.limits().auth_timeout;
    let dest_cred = tokio::time::timeout(
        timeout,
        scope.credentials.credential(CredentialRequest {
            verifier: peer,
            target: TargetRef::Endpoint { name: ep, plane },
            destination: peer,
            endpoint: ep,
            path_id: path.id,
            is_refresh: false,
            previous: &[],
        }),
    )
    .await
    .map_err(|_| CoreErr::Timeout)??;
    e2e::credential(&dest_cred)?;

    let mut hop_creds = Vec::with_capacity(path.hops.len());
    for hop in &path.hops {
        let cred = tokio::time::timeout(
            timeout,
            scope.credentials.credential(CredentialRequest {
                verifier: hop.peer,
                target: TargetRef::Transit {
                    name: &hop.target,
                    plane,
                },
                destination: peer,
                endpoint: ep,
                path_id: path.id,
                is_refresh: false,
                previous: &[],
            }),
        )
        .await
        .map_err(|_| CoreErr::Timeout)??;
        e2e::credential(&cred)?;
        hop_creds.push(cred);
    }
    Ok((dest_cred, hop_creds))
}

struct Setup {
    tail: Vec<u8>,
    destination: Initiator,
    hops: Vec<HopKey>,
    sent_mac1s: Vec<(PublicKey, [u8; MAC_LEN])>,
}

impl Setup {
    #[allow(clippy::too_many_arguments)]
    fn build(
        scope: &Scope,
        path: &ExplicitPath,
        peer: PublicKey,
        ep: &str,
        dest_cred: &[u8],
        hop_creds: &[Vec<u8>],
        plane: Plane,
        min: u16,
        cookies: &HashMap<usize, [u8; COOKIE_LEN]>,
    ) -> Result<Self, CoreErr> {
        if path.hops.len() > 255 || hop_creds.len() != path.hops.len() {
            return Err(CoreErr::Malformed);
        }
        let timestamp = now_ms();
        let dest_idx = path.hops.len();
        let dest_cookie = cookies.get(&dest_idx);
        let plain = noise_ik::endpoint_plaintext(timestamp, ep, dest_cred)?;
        let dest_seg_len =
            setup::SEGMENT_OVERHEAD + plain.len() + if dest_cookie.is_some() { MAC_LEN } else { 0 };
        let mut tail =
            setup::prefix_with_mac2(plane, min, false, dest_cookie.is_some(), dest_seg_len, 0)?;
        let (mut seg, destination) =
            noise_ik::initiate(&scope.identity, peer, &setup::tail_aad(&tail, &[]), &plain)?;
        let dest_mac1: [u8; MAC_LEN] = seg[seg.len() - MAC_LEN..]
            .try_into()
            .expect("segment always carries 16B mac1");
        if let Some(cookie) = dest_cookie {
            append_mac2(&mut seg, cookie);
        }
        tail.extend_from_slice(&seg);

        let mut hops = Vec::with_capacity(path.hops.len());
        let mut sent_mac1s = vec![(peer, dest_mac1)];
        for (rev_pos, hop) in path.hops.iter().rev().enumerate() {
            let hop_idx = path.hops.len() - 1 - rev_pos;
            let hop_cookie = cookies.get(&hop_idx);
            let plain = noise_ik::hop_plaintext(timestamp, &hop.target, &hop_creds[hop_idx])?;
            let seg_len = setup::SEGMENT_OVERHEAD
                + plain.len()
                + if hop_cookie.is_some() { MAC_LEN } else { 0 };
            let mut prefix = setup::prefix_with_mac2(
                plane,
                min,
                true,
                hop_cookie.is_some(),
                seg_len,
                tail.len(),
            )?;
            let (mut seg, state) = noise_ik::initiate(
                &scope.identity,
                hop.peer,
                &setup::tail_aad(&prefix, &tail),
                &plain,
            )?;
            let hop_mac1: [u8; MAC_LEN] = seg[seg.len() - MAC_LEN..]
                .try_into()
                .expect("segment always carries 16B mac1");
            if let Some(cookie) = hop_cookie {
                append_mac2(&mut seg, cookie);
            }
            prefix.extend_from_slice(&seg);
            prefix.extend_from_slice(&tail);
            tail = prefix;
            hops.push(state.hop_key());
            sent_mac1s.push((hop.peer, hop_mac1));
        }
        hops.reverse();
        sent_mac1s.reverse();
        Ok(Self {
            tail,
            destination,
            hops,
            sent_mac1s,
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

    fn unseal_cookie(
        &self,
        reply: &[u8],
        expected_cid: Cid,
    ) -> Result<(usize, [u8; COOKIE_LEN]), CoreErr> {
        let (index, cid, challenge) = setup::parse_cookie(reply)?;
        if cid != expected_cid {
            return Err(CoreErr::Malformed);
        }
        let idx = usize::from(index);
        let (target_pk, sent_mac1) = self.sent_mac1s.get(idx).ok_or(CoreErr::Authentication)?;
        let cookie = unseal_cookie_challenge(*target_pk, sent_mac1, challenge)?;
        Ok((idx, cookie))
    }

    #[allow(clippy::type_complexity)]
    fn opened(
        &self,
        scope: &Scope,
        reply: &[u8],
        header: setup::OkHeader,
        local: u16,
        min: u16,
    ) -> Result<
        (
            u16,
            Duration,
            Vec<Duration>,
            SessionKeys,
            Vec<HopKey>,
            HopKey,
        ),
        CoreErr,
    > {
        if usize::from(header.hop_acks) != self.hops.len() {
            return Err(CoreErr::Authentication);
        }
        let terminal = self.destination.hop_key();
        let (ack, keys) = self
            .destination
            .finish(&scope.identity, &reply[12..setup::OK_SIZE])?;
        let mtu = u16_at(&ack, 0).min(header.reverse_mtu).min(local);
        if mtu < min {
            return Err(CoreErr::MtuTooSmall(mtu));
        }
        let dest_ttl = Lease::from_wire_ttl(&ack[2..])?;
        let mut hop_ttls = Vec::with_capacity(self.hops.len());
        let n = self.hops.len();
        for (i, hop_key) in self.hops.iter().enumerate() {
            let offset = setup::OK_SIZE + (n - 1 - i) * setup::HOP_ACK_SIZE;
            let trailer = &reply[offset..offset + setup::HOP_ACK_SIZE];
            let plain = hop_key.open_setup_lease(trailer)?;
            hop_ttls.push(Lease::from_wire_ttl(&plain)?);
        }
        Ok((mtu, dest_ttl, hop_ttls, keys, self.hops.clone(), terminal))
    }
}

pub(crate) async fn stream_staged(
    scope: &Arc<Scope>,
    path: &ExplicitPath,
    peer: PublicKey,
    ep: &str,
) -> Result<StagedStream, CoreErr> {
    if scope.auth.is_vetoed(&peer) {
        return Err(CoreErr::Revoked);
    }
    let epoch = scope.auth.epoch_for_endpoint(peer, None);
    let session = scope.session()?;
    let min = path.min_mtu.max((crate::wire::e2e::ST_OVERHEAD + 1) as u16);
    let carrier = scope.stream_carrier(&path.first_channel)?;
    if carrier.dyn_caps().mtu() < min {
        return Err(CoreErr::MtuTooSmall(carrier.dyn_caps().mtu()));
    }

    let (dest_cred, hop_creds) = fetch_credentials(scope, path, peer, ep, Plane::Stream).await?;

    let mut cookies = HashMap::new();
    let max_attempts = path.hops.len() + 2;
    let (io, mtu, dest_ttl, hop_ttls, keys, hops, terminal) = timed(async {
        for _ in 0..max_attempts {
            let setup = Setup::build(
                scope,
                path,
                peer,
                ep,
                &dest_cred,
                &hop_creds,
                Plane::Stream,
                min,
                &cookies,
            )?;
            let stream = carrier.dyn_dial_stream(&path.first_locator).await?;
            let caps = stream.dyn_caps();
            let local = caps.mtu();
            if local < min {
                return Err(CoreErr::MtuTooSmall(local));
            }
            let (mut reader, mut writer) = stream.split_boxed();
            writer
                .write_all(&setup.forward(local, Cid::UNBOUND))
                .await?;
            let reply = st_splice::read_reply(&mut *reader).await?;
            if reply[0] == setup::ERR {
                return Err(setup.rejection(&reply, Cid::UNBOUND)?);
            }
            if reply[0] == setup::COOKIE {
                let (idx, cookie) = setup.unseal_cookie(&reply, Cid::UNBOUND)?;
                if cookies.insert(idx, cookie).is_some() {
                    return Err(CoreErr::Authentication);
                }
                tracing::debug!(
                    hop = idx,
                    "retrying stream setup with stateless MAC2 cookie"
                );
                continue;
            }
            let header = setup::OkHeader::parse(&reply)?;
            if header.target != Cid::UNBOUND || header.responder != Cid::UNBOUND {
                return Err(CoreErr::Malformed);
            }
            let (mtu, dest_ttl, hop_ttls, keys, hops, terminal) =
                setup.opened(scope, &reply, header, local, min)?;
            return Ok((
                st_splice::Carrier {
                    reader,
                    writer,
                    mtu: caps.mtu_watch,
                },
                mtu,
                dest_ttl,
                hop_ttls,
                keys,
                hops,
                terminal,
            ));
        }
        Err(CoreErr::Authentication)
    })
    .await?;

    let lease = Arc::new(LeaseHandle::new_with_max_ttl(dest_ttl, MAX_WIRE_LEASE_TTL)?);
    scope.auth.track_endpoint(epoch, peer, None, &lease)?;
    let renewals = Renewals::new(
        peer,
        ep.to_owned(),
        scope.source.clone(),
        scope.credentials.clone(),
        scope.auth.limits().auth_timeout,
        path,
        Plane::Stream,
        dest_cred,
        hop_creds,
        hops,
        hop_ttls,
        terminal,
        dest_ttl,
    );
    Ok(StagedStream::new(
        scope.clone(),
        io,
        keys,
        (mtu, min),
        lease,
        renewals,
        session,
    ))
}

pub(crate) async fn datagram_staged(
    scope: &Arc<Scope>,
    path: &ExplicitPath,
    peer: PublicKey,
    ep: &str,
    min_mtu: u16,
) -> Result<StagedDatagram, CoreErr> {
    if scope.auth.is_vetoed(&peer) {
        return Err(CoreErr::Revoked);
    }
    let epoch = scope.auth.epoch_for_endpoint(peer, None);
    let session = scope.session()?;
    let min = path.min_mtu.max(min_mtu).max(DATAGRAM_MTU);
    let carrier = scope.datagram_carrier(&path.first_channel)?;
    let cap = carrier.dyn_caps().mtu();
    if cap < min {
        return Err(CoreErr::MtuTooSmall(cap));
    }

    let (dest_cred, hop_creds) = fetch_credentials(scope, path, peer, ep, Plane::Datagram).await?;

    let mut cookies = HashMap::new();
    let max_attempts = path.hops.len() + 2;
    let (binding, remote, mtu, dest_ttl, hop_ttls, keys, hops, terminal) = timed(async {
        let link = carrier.dyn_open_link(&path.first_locator).await?;
        let mut binding = DatagramPort::attach_scope(scope, link)?.bind()?;
        let local = binding.mtu();
        if local < min {
            return Err(CoreErr::MtuTooSmall(local));
        }

        for _ in 0..max_attempts {
            let setup = Setup::build(
                scope,
                path,
                peer,
                ep,
                &dest_cred,
                &hop_creds,
                Plane::Datagram,
                min,
                &cookies,
            )?;
            if setup.tail.len() + 8 > usize::from(local) {
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
                } else if bytes[0] == setup::COOKIE {
                    if let Ok((idx, cookie)) = setup.unseal_cookie(bytes, binding.cid) {
                        if cookies.insert(idx, cookie).is_some() {
                            return Err(CoreErr::Authentication);
                        }
                        tracing::debug!(
                            hop = idx,
                            "retrying datagram setup with stateless MAC2 cookie"
                        );
                        break;
                    }
                } else if let Ok(header) = setup::OkHeader::parse(bytes)
                    && header.target == binding.cid
                    && header.responder != Cid::UNBOUND
                {
                    match setup.opened(scope, bytes, header, local, min) {
                        Ok((mtu, dest_ttl, hop_ttls, keys, hops, terminal)) => {
                            return Ok((
                                binding,
                                header.responder,
                                mtu,
                                dest_ttl,
                                hop_ttls,
                                keys,
                                hops,
                                terminal,
                            ));
                        }
                        Err(CoreErr::Authentication) => continue,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Err(CoreErr::Authentication)
    })
    .await?;

    let lease = Arc::new(LeaseHandle::new_with_max_ttl(dest_ttl, MAX_WIRE_LEASE_TTL)?);
    scope.auth.track_endpoint(epoch, peer, None, &lease)?;
    let renewals = Renewals::new(
        peer,
        ep.to_owned(),
        scope.source.clone(),
        scope.credentials.clone(),
        scope.auth.limits().auth_timeout,
        path,
        Plane::Datagram,
        dest_cred,
        hop_creds,
        hops,
        hop_ttls,
        terminal,
        dest_ttl,
    );
    Ok(StagedDatagram::new(
        scope.clone(),
        datagram::Wire::new(binding, remote, keys),
        datagram::Mtu {
            ceiling: mtu,
            floor: min,
        },
        lease,
        renewals,
        session,
    ))
}
