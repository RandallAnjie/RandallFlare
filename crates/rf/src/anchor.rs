//! Anchoring: periodically publish a digest of every manifest head so
//! the deploy history gains an external, tamper-evident timestamp.
//!
//! One claimed task per period ("anchor/<period-index>") — 抢单 picks
//! a single publisher per period. The winner:
//!   1. writes the anchor record into the replicated `__rf` KV
//!      namespace (every node ends up holding the anchor history), and
//!   2. optionally POSTs it to a webhook — point that at anything:
//!      a log collector, OpenTimestamps relayer, or an on-chain
//!      submitter. Publishing a digest is idempotent, so the
//!      at-least-once claim semantics are safe here.

use crate::config::AnchorConfig;
use crate::node::{now_ms, Node};
use std::sync::Arc;
use std::time::Duration;

pub const ANCHOR_NS: &str = "__rf";

pub fn period_index(now_ms: u64, interval_hours: u64) -> u64 {
    now_ms / (interval_hours.max(1) * 3_600_000)
}

pub fn anchor_key(period: u64) -> String {
    format!("anchor/{period}")
}

pub fn spawn(node: Arc<Node>, cfg: AnchorConfig) {
    if !cfg.enabled {
        return;
    }
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("reqwest client");
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            if let Err(e) = tick(&node, &cfg, &http).await {
                tracing::warn!("anchor tick: {e:#}");
            }
        }
    });
}

async fn tick(node: &Arc<Node>, cfg: &AnchorConfig, http: &reqwest::Client) -> anyhow::Result<()> {
    let period = period_index(now_ms(), cfg.interval_hours);
    let key = anchor_key(period);
    // Already anchored this period (any node) → nothing to do.
    if node.kv_get(ANCHOR_NS, &key).is_some() {
        return Ok(());
    }
    let task = format!("anchor/{period}");
    if !node.claim_try(&task, 600_000)? {
        return Ok(());
    }
    tokio::time::sleep(Duration::from_millis(
        (node.cfg.gossip.interval_ms * 2).clamp(500, 5000),
    ))
    .await;
    if !node.holds(&task) {
        return Ok(());
    }

    let (digest, heads) = node.anchor_digest();
    let record = serde_json::json!({
        "period": period,
        "digest": digest,
        "heads": heads,
        "node": node.id_hex(),
        "ts_ms": now_ms(),
    });
    node.kv_put(ANCHOR_NS, &key, Some(record.to_string().into_bytes()), None)?;
    tracing::info!("anchored period {period}: {digest} ({heads} heads)");

    if let Some(url) = &cfg.webhook {
        match http.post(url).json(&record).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::info!("anchor webhook delivered");
            }
            Ok(r) => tracing::warn!("anchor webhook returned {}", r.status()),
            Err(e) => tracing::warn!("anchor webhook failed: {e}"),
        }
    }
    node.claim_renew(&task, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_math() {
        assert_eq!(period_index(0, 24), 0);
        assert_eq!(period_index(24 * 3_600_000 - 1, 24), 0);
        assert_eq!(period_index(24 * 3_600_000, 24), 1);
        assert_eq!(period_index(3 * 3_600_000, 1), 3);
        // zero interval clamps instead of dividing by zero
        assert_eq!(period_index(7_200_000, 0), 2);
    }
}
