//! Cron via claims: every node evaluates every live worker's cron
//! expressions each minute; the tick task is claimed cluster-wide, so
//! (converged) exactly one node fires it. Semantics are at-least-once
//! — CF parity — because a partition can double-claim.
//!
//! Task id: cron/<worker>/<expr-digest8>/<minute-epoch>. The claim's
//! TTL outlives the minute so a crashed winner's tick is NOT retried
//! by someone else mid-minute (better a missed tick than a storm);
//! the next minute reopens naturally.

use crate::node::Node;
use rf_core::cron::CronExpr;
use std::sync::Arc;
use std::time::Duration;

/// How long after claiming we wait for gossip to converge before
/// checking we actually won. ~2 gossip rounds.
fn settle_delay(node: &Node) -> Duration {
    Duration::from_millis((node.cfg.gossip.interval_ms * 2).clamp(500, 5000))
}

pub fn spawn(node: Arc<Node>) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client");
        loop {
            // Sleep to the next minute boundary (+ small jitter so the
            // cluster doesn't thundering-herd its own gossip).
            let now_ms = crate::node::now_ms();
            let next_minute = (now_ms / 60_000 + 1) * 60_000;
            let jitter = (rand::random::<u64>() % 500) as u64;
            tokio::time::sleep(Duration::from_millis(next_minute - now_ms + jitter)).await;

            let minute_epoch_secs = next_minute / 1000;
            for m in node.live_manifests() {
                for expr_src in &m.crons {
                    let Ok(expr) = CronExpr::parse(expr_src) else {
                        continue;
                    };
                    if !expr.matches(minute_epoch_secs) {
                        continue;
                    }
                    let task = cron_task_id(&m.name, expr_src, minute_epoch_secs / 60);
                    // 抢单: claim, settle, verify, fire, release.
                    match node.claim_try(&task, 120_000) {
                        Ok(true) => {}
                        _ => continue, // someone already holds it
                    }
                    let node2 = node.clone();
                    let client2 = client.clone();
                    let worker = m.name.clone();
                    let expr2 = expr_src.clone();
                    let delay = settle_delay(&node);
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        if !node2.holds(&task) {
                            return; // lost adjudication — winner fires
                        }
                        fire(&node2, &client2, &worker, &expr2).await;
                        let _ = node2.claim_renew(&task, true); // release
                    });
                }
            }
        }
    });
}

pub fn cron_task_id(worker: &str, expr: &str, minute: u64) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(expr.as_bytes());
    format!("cron/{worker}/{}/{minute}", hex::encode(&d[..4]))
}

async fn fire(node: &Node, client: &reqwest::Client, worker: &str, expr: &str) {
    let Some(port) = node.worker_port(worker) else {
        tracing::debug!("cron {worker}: no local runtime, skipping fire");
        return;
    };
    let res = client
        .get(format!("http://127.0.0.1:{port}/__rf/cron"))
        .header("x-edge-cron-expression", expr)
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => {
            tracing::info!("cron fired: {worker} ({expr})");
        }
        Ok(r) => tracing::warn!("cron {worker} handler returned {}", r.status()),
        Err(e) => tracing::warn!("cron {worker} fire failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_ids_are_stable_and_distinct() {
        let a = cron_task_id("w", "* * * * *", 100);
        let b = cron_task_id("w", "* * * * *", 100);
        let c = cron_task_id("w", "*/5 * * * *", 100);
        let d = cron_task_id("w", "* * * * *", 101);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }
}
