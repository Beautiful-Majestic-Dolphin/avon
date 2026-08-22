//! Batches decisions back to control. Records are dropped rather than blocking
//! the data plane if control is unreachable — an audit gap is recoverable, a
//! stalled forwarder is not (the drop is counted so it is visible).

use avon_protocol::v2::{gateway_up, DecisionRecord, Decisions, GatewayUp};
use tokio::sync::mpsc;

const BATCH: usize = 200;
const INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

pub fn spawn(control: mpsc::Sender<GatewayUp>) -> mpsc::Sender<DecisionRecord> {
    let (tx, mut rx) = mpsc::channel::<DecisionRecord>(4096);
    tokio::spawn(async move {
        let mut buffer: Vec<DecisionRecord> = Vec::with_capacity(BATCH);
        let mut tick = tokio::time::interval(INTERVAL);
        loop {
            tokio::select! {
                received = rx.recv() => match received {
                    Some(record) => {
                        buffer.push(record);
                        if buffer.len() >= BATCH {
                            flush(&control, &mut buffer).await;
                        }
                    }
                    None => { flush(&control, &mut buffer).await; break; }
                },
                _ = tick.tick() => flush(&control, &mut buffer).await,
            }
        }
    });
    tx
}

pub fn spawn_for_state(
    state: std::sync::Arc<crate::state::GatewayState>,
) -> mpsc::Sender<DecisionRecord> {
    let (tx, mut rx) = mpsc::channel::<DecisionRecord>(4096);
    tokio::spawn(async move {
        let mut buffer: Vec<DecisionRecord> = Vec::with_capacity(BATCH);
        let mut tick = tokio::time::interval(INTERVAL);
        loop {
            tokio::select! {
                received = rx.recv() => match received {
                    Some(record) => {
                        buffer.push(record);
                        if buffer.len() >= BATCH {
                            flush_state(&state, &mut buffer).await;
                        }
                    }
                    None => { flush_state(&state, &mut buffer).await; break; }
                },
                _ = tick.tick() => flush_state(&state, &mut buffer).await,
            }
        }
    });
    tx
}

async fn flush_state(state: &crate::state::GatewayState, buffer: &mut Vec<DecisionRecord>) {
    if buffer.is_empty() {
        return;
    }
    let records = std::mem::take(buffer);
    let count = records.len();
    let tx_opt = state.up.read().await.clone();
    if let Some(tx) = tx_opt {
        if tx
            .send(GatewayUp {
                msg: Some(gateway_up::Msg::Decisions(Decisions { records })),
            })
            .await
            .is_err()
        {
            metrics::counter!("avon_gateway_decisions_dropped_total").increment(count as u64);
        }
    } else {
        metrics::counter!("avon_gateway_decisions_dropped_total").increment(count as u64);
    }
}

async fn flush(control: &mpsc::Sender<GatewayUp>, buffer: &mut Vec<DecisionRecord>) {
    if buffer.is_empty() {
        return;
    }
    let records = std::mem::take(buffer);
    let count = records.len();
    if control
        .send(GatewayUp {
            msg: Some(gateway_up::Msg::Decisions(Decisions { records })),
        })
        .await
        .is_err()
    {
        metrics::counter!("avon_gateway_decisions_dropped_total").increment(count as u64);
    }
}
