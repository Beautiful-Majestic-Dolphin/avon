//! Forwarding. Three directions meet here: packets arriving from a session,
//! packets arriving from the local TUN, and in-tunnel control frames.
//!
//! A packet from session S with destination D is:
//!   * dropped if S does not own its source address (anti-spoofing),
//!   * dropped if policy says no,
//!   * relayed to session T if D routes to some other session,
//!   * handed to the TUN if D is outside the overlay (the kernel routes it),
//!   * otherwise dropped — D is inside the overlay but nobody is home.

use std::sync::Arc;

use avon_common::ids::SessionId;
use avon_protocol::v2::{tunnel_frame, MtuProbeAck, RekeyAck, TunnelFrame};
use avon_tunnel::{EndpointEvent, Inner, PacketSink, PacketSource};
use tokio::sync::mpsc;

use crate::policy_hook::parse_flow;
use crate::state::GatewayState;

pub async fn run_dataplane(
    state: Arc<GatewayState>,
    mut events: mpsc::Receiver<EndpointEvent>,
    tun: Arc<dyn PacketSink>,
    tun_src: Arc<dyn PacketSource>,
) -> anyhow::Result<()> {
    let from_tun = tokio::spawn(tun_loop(state.clone(), tun_src));

    while let Some(ev) = events.recv().await {
        match ev {
            EndpointEvent::Ip { session, packet } => {
                handle_ip(&state, &session, &packet, tun.as_ref()).await;
            }
            EndpointEvent::Control { session, frame } => {
                handle_control(&state, &session, frame).await;
            }
            EndpointEvent::Idle(session) => {
                state.close_session(&session.id(), "idle").await;
            }
            EndpointEvent::PeerEndpointChanged { session, endpoint } => {
                tracing::info!(session = %session.id(), %endpoint, "peer endpoint updated");
                crate::redis_mirror::mirror_endpoint(&state, &session.id(), endpoint).await;
            }
            // Gateways answer rekeys; the device drives them.
            EndpointEvent::RekeyDue(_) => {}
        }
    }

    from_tun.abort();
    Ok(())
}

fn drop_packet(reason: &'static str) {
    metrics::counter!("avon_gateway_packets_dropped_total", "reason" => reason).increment(1);
}

async fn handle_ip(
    state: &Arc<GatewayState>,
    session: &Arc<avon_tunnel::Session>,
    packet: &[u8],
    tun: &dyn PacketSink,
) {
    let sid = session.id();
    let Some(flow) = parse_flow(sid, packet) else {
        drop_packet("malformed");
        return;
    };
    let Some(meta) = state.sessions_meta.get(&sid).map(|m| m.clone()) else {
        drop_packet("unknown_session");
        return;
    };
    if !meta.owns_source(flow.src) {
        drop_packet("spoofed_source");
        return;
    }
    let decision = state.policy.allow(&flow);
    if !decision.allow {
        metrics::counter!("avon_gateway_flows_denied_total", "reason" => decision.reason)
            .increment(1);
        return;
    }

    match state.routes.lookup(flow.dst) {
        Some(target) if target != sid => {
            let Some(t) = state.table.by_id(&target) else {
                drop_packet("no_route");
                return;
            };
            if let Err(e) = state.endpoint.send_inner(&t, &Inner::Ip(packet)).await {
                tracing::debug!(error = %e, session = %target, "relay failed");
                drop_packet("relay_failed");
                return;
            }
            metrics::counter!("avon_gateway_packets_relayed_total").increment(1);
        }
        // Destination routes back to the sender: nothing to do with it.
        Some(_) => drop_packet("hairpin"),
        None => {
            if state.is_protected_or_external(flow.dst) {
                if let Err(e) = tun.deliver(packet).await {
                    tracing::debug!(error = %e, "tun deliver failed");
                    drop_packet("tun_failed");
                    return;
                }
                metrics::counter!("avon_gateway_packets_egressed_total").increment(1);
            } else {
                drop_packet("no_route");
            }
        }
    }
}

async fn handle_control(
    state: &Arc<GatewayState>,
    session: &Arc<avon_tunnel::Session>,
    frame: TunnelFrame,
) {
    match frame.msg {
        Some(tunnel_frame::Msg::Rekey(r)) => {
            let (ct, next) = match session.answer_rekey(&r.eph_kem_pk) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, session = %session.id(), "rekey answer failed");
                    return;
                }
            };
            let new_local = match state.table.allocate_index() {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(error = %e, "no receiver index for rekey");
                    return;
                }
            };
            let ack = TunnelFrame {
                msg: Some(tunnel_frame::Msg::RekeyAck(RekeyAck {
                    new_epoch: r.new_epoch,
                    ct,
                    new_index: new_local,
                })),
            };
            // Acknowledge under the old epoch, then rotate: the peer must be
            // able to read the answer that tells it we rotated.
            if let Err(e) = state.endpoint.send_frame(session, &ack).await {
                tracing::debug!(error = %e, "rekey ack send failed");
                state.table.release_index(new_local);
                return;
            }
            session.rotate(next, new_local, r.new_index);
            state.table.rebind_index(session, new_local);
            metrics::counter!("avon_gateway_rekeys_total").increment(1);
        }
        Some(tunnel_frame::Msg::Close(c)) => {
            state.close_session(&session.id(), &c.reason).await;
        }
        Some(tunnel_frame::Msg::MtuProbe(p)) => {
            let ack = TunnelFrame {
                msg: Some(tunnel_frame::Msg::MtuProbeAck(MtuProbeAck { size: p.size })),
            };
            if let Err(e) = state.endpoint.send_frame(session, &ack).await {
                tracing::debug!(error = %e, "mtu probe ack failed");
            }
        }
        // IndexUpdate/RekeyAck are initiator-side; a gateway never gets them.
        _ => {}
    }
}

/// Packets the kernel routed into the gateway's TUN, headed for a device.
async fn tun_loop(state: Arc<GatewayState>, tun_src: Arc<dyn PacketSource>) {
    let mut buf = Vec::with_capacity(2048);
    loop {
        let n = match tun_src.next_packet(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::info!(error = %e, "tun source closed");
                return;
            }
        };
        let packet = &buf[..n];
        let Some(flow) = parse_flow(SessionId::ZERO, packet) else {
            drop_packet("malformed");
            continue;
        };
        let Some(sid) = state.routes.lookup(flow.dst) else {
            drop_packet("no_route");
            continue;
        };
        let Some(session) = state.table.by_id(&sid) else {
            drop_packet("no_route");
            continue;
        };
        if let Err(e) = state
            .endpoint
            .send_inner(&session, &Inner::Ip(packet))
            .await
        {
            tracing::debug!(error = %e, session = %sid, "send to session failed");
            drop_packet("send_failed");
            continue;
        }
        metrics::counter!("avon_gateway_packets_ingressed_total").increment(1);
    }
}
