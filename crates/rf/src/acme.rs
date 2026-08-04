//! ACME certificate issuance as a claimed task (抢单).
//!
//! One task per hostname ("acme/<file-stem>") opens whenever the
//! stored cert is missing or inside the renewal window. The winner
//! runs a DNS-01 order (TXT via the Cloudflare API), then writes the
//! issued chain+key into the replicated `__rf` KV namespace; every
//! node's materializer loop writes those records into <data>/certs,
//! where the TLS store hot-reloads them. Duplicate issuance (a
//! partition race) only wastes a rate-limit slot — safe by 抢单 rules.
//!
//! The ACME account (credentials JSON) also lives in `__rf` KV, so
//! the whole cluster shares one account regardless of who wins.
//!
//! Expiry bookkeeping: LE certs are 90 days; we record issued+90d and
//! renew at <30d left rather than parsing NotAfter. Certbot-managed
//! files dropped in <data>/certs are untouched — this loop only
//! manages hostnames listed in [acme].

use crate::config::AcmeConfig;
use crate::dns::DnsApi;
use crate::node::{now_ms, Node, NodeEvent};
use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, AuthorizedIdentifier, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

pub const NS: &str = "__rf";
const ACCOUNT_KEY: &str = "acme/account";
const DAY_MS: u64 = 24 * 3600 * 1000;
const LIFETIME_MS: u64 = 90 * DAY_MS;
const RENEW_AT_LEFT_MS: u64 = 30 * DAY_MS;

#[derive(Debug, Serialize, Deserialize)]
pub struct CertRecord {
    pub hostname: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

/// "*.edge.example.com" → "_wildcard.edge.example.com" (the tls.rs
/// file-stem convention); plain hostnames map to themselves.
pub fn file_stem(hostname: &str) -> String {
    match hostname.strip_prefix("*.") {
        Some(rest) => format!("_wildcard.{rest}"),
        None => hostname.to_string(),
    }
}

pub fn cert_kv_key(hostname: &str) -> String {
    format!("cert/{}", file_stem(hostname))
}

/// RFC 8555 represents a wildcard authorization as the base DNS name plus a
/// separate `wildcard` flag. `AuthorizedIdentifier`'s Display implementation
/// intentionally adds `*.` back for humans, but DNS-01 must always publish at
/// `_acme-challenge.<base-name>`.
fn dns_challenge_record(identifier: &AuthorizedIdentifier<'_>) -> Result<String> {
    let Identifier::Dns(name) = identifier.identifier else {
        bail!("dns-01 authorization did not contain a DNS identifier");
    };
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.contains('*') {
        bail!("invalid DNS authorization identifier");
    }
    Ok(format!("_acme-challenge.{name}"))
}

fn needs_renewal(node: &Node, hostname: &str) -> bool {
    match node.kv_get(NS, &cert_kv_key(hostname)) {
        Some(raw) => match serde_json::from_slice::<CertRecord>(&raw) {
            Ok(rec) => rec.expires_ms.saturating_sub(now_ms()) < RENEW_AT_LEFT_MS,
            Err(_) => true,
        },
        None => true,
    }
}

/// Write every KV cert record into <data>/certs so the TLS store can
/// pick it up. Runs on ALL nodes.
pub fn spawn_materializer(node: Arc<Node>) {
    tokio::spawn(async move {
        let dir = node.cfg.data_dir.join("certs");
        let _ = std::fs::create_dir_all(&dir);
        let mut rx = node.subscribe();
        loop {
            for key in node.kv_list(NS, "cert/", 10_000) {
                let Some(raw) = node.kv_get(NS, &key) else {
                    continue;
                };
                let Ok(rec) = serde_json::from_slice::<CertRecord>(&raw) else {
                    continue;
                };
                let stem = key.trim_start_matches("cert/");
                let crt = dir.join(format!("{stem}.crt"));
                let fresh = std::fs::read_to_string(&crt)
                    .map(|cur| cur != rec.cert_pem)
                    .unwrap_or(true);
                if fresh {
                    let _ = std::fs::write(&crt, &rec.cert_pem);
                    let _ = std::fs::write(dir.join(format!("{stem}.key")), &rec.key_pem);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            dir.join(format!("{stem}.key")),
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                    tracing::info!("materialized cert {stem} from cluster KV");
                }
            }
            // Wake on KV change or every 60s.
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(NodeEvent::Kv(ns)) if ns == NS => {}
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return,
                },
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
        }
    });
}

/// Renewal driver — claims and issues. Needs the CF token; nodes
/// without it simply never win usefully (they don't run this loop).
pub fn spawn_renewer(node: Arc<Node>, cfg: AcmeConfig, dns: DnsApi) {
    tokio::spawn(async move {
        loop {
            let configured: BTreeSet<String> = cfg
                .hostnames
                .iter()
                .map(|hostname| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect();
            let mut hostnames = configured.clone();
            if cfg.include_worker_hostnames {
                if let Some(zone) = cfg.zone.as_deref() {
                    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
                    for manifest in node.live_manifests() {
                        for hostname in node.effective_worker_hostnames(&manifest) {
                            let hostname =
                                hostname.trim().trim_end_matches('.').to_ascii_lowercase();
                            if hostname == zone || hostname.ends_with(&format!(".{zone}")) {
                                let covered_by_configured_wildcard = hostname
                                    .split_once('.')
                                    .map(|(_, suffix)| format!("*.{suffix}"))
                                    .is_some_and(|wildcard| configured.contains(&wildcard));
                                if covered_by_configured_wildcard {
                                    continue;
                                }
                                hostnames.insert(hostname);
                            }
                        }
                    }
                }
            }
            for hostname in hostnames {
                if !needs_renewal(&node, &hostname) {
                    continue;
                }
                let task = format!("acme/{}", file_stem(&hostname));
                match node.claim_try(&task, 15 * 60 * 1000) {
                    Ok(true) => {}
                    _ => continue,
                }
                tokio::time::sleep(Duration::from_millis(
                    (node.cfg.gossip.interval_ms * 2).clamp(500, 5000),
                ))
                .await;
                if !node.holds(&task) {
                    continue;
                }
                match issue(&node, &cfg, &dns, &hostname).await {
                    Ok(()) => tracing::info!("acme: issued cert for {hostname}"),
                    Err(e) => tracing::warn!("acme: {hostname}: {e:#}"),
                }
                let _ = node.claim_renew(&task, true);
            }
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
    });
}

async fn account(node: &Node, cfg: &AcmeConfig) -> Result<Account> {
    let builder = || -> Result<instant_acme::AccountBuilder> {
        Ok(match &cfg.ca_root {
            Some(path) => Account::builder_with_root(path)?,
            None => Account::builder()?,
        })
    };
    if let Some(raw) = node.kv_get(NS, ACCOUNT_KEY) {
        if let Ok(creds) = serde_json::from_slice(&raw) {
            if let Ok(acct) = builder()?.from_credentials(creds).await {
                return Ok(acct);
            }
            tracing::warn!("acme: stored account rejected, creating a fresh one");
        }
    }
    let directory = cfg
        .directory_url
        .clone()
        .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".into());
    let contact = format!("mailto:{}", cfg.email);
    let (acct, creds) = builder()?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await
        .context("creating ACME account")?;
    node.kv_put(NS, ACCOUNT_KEY, Some(serde_json::to_vec(&creds)?), None)?;
    Ok(acct)
}

async fn issue(node: &Node, cfg: &AcmeConfig, dns: &DnsApi, hostname: &str) -> Result<()> {
    let acct = account(node, cfg).await?;
    let identifiers = vec![Identifier::Dns(hostname.to_string())];
    let mut order = acct.new_order(&NewOrder::new(&identifiers)).await?;

    // TXT records we created, for cleanup.
    let mut txt_created: Vec<(String, String)> = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("unexpected authorization status {other:?}"),
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| anyhow::anyhow!("no dns-01 challenge offered"))?;
            let record = dns_challenge_record(challenge.identifier())?;
            let value = challenge.key_authorization().dns_value();
            dns.create_txt_record(&record, &value)
                .await
                .context("creating TXT")?;
            txt_created.push((record, value));
            if cfg.dns_propagation_seconds > 0 {
                tracing::info!(
                    seconds = cfg.dns_propagation_seconds,
                    hostname,
                    "acme: waiting for DNS-01 propagation"
                );
                tokio::time::sleep(Duration::from_secs(cfg.dns_propagation_seconds)).await;
            }
            challenge.set_ready().await?;
        }
    }

    let result = async {
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            let mut reasons = Vec::new();
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                match result {
                    Ok(mut authz) => {
                        if let Err(error) = authz.refresh().await {
                            reasons.push(format!("authorization refresh failed: {error}"));
                            continue;
                        }
                        let identifier = authz.identifier().to_string();
                        let reason_count = reasons.len();
                        for challenge in &authz.challenges {
                            if let Some(error) = &challenge.error {
                                reasons.push(format!(
                                    "{identifier} {:?} challenge: {error}",
                                    challenge.r#type
                                ));
                            }
                        }
                        if reasons.len() == reason_count {
                            reasons.push(format!(
                                "{identifier} authorization status {:?}",
                                authz.status
                            ));
                        }
                    }
                    Err(error) => reasons.push(format!("authorization lookup failed: {error}")),
                }
            }
            let detail = if reasons.is_empty() {
                "ACME server returned no authorization details".to_string()
            } else {
                reasons.join("; ")
            };
            bail!("ACME order became {status:?}: {detail}");
        }
        let key_pem = order.finalize().await?;
        let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok::<(String, String), anyhow::Error>((cert_pem, key_pem))
    }
    .await;

    // Best-effort TXT cleanup either way.
    for (name, value) in txt_created {
        if let Err(e) = dns.delete_txt_record(&name, &value).await {
            tracing::warn!("acme: TXT cleanup {name}: {e}");
        }
    }

    let (cert_pem, key_pem) = result?;
    let now = now_ms();
    let rec = CertRecord {
        hostname: hostname.to_string(),
        cert_pem,
        key_pem,
        issued_ms: now,
        expires_ms: now + LIFETIME_MS,
    };
    node.kv_put(
        NS,
        &cert_kv_key(hostname),
        Some(serde_json::to_vec(&rec)?),
        None,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stems() {
        assert_eq!(file_stem("a.example.com"), "a.example.com");
        assert_eq!(
            file_stem("*.edge.example.com"),
            "_wildcard.edge.example.com"
        );
        assert_eq!(cert_kv_key("*.x.y"), "cert/_wildcard.x.y");
    }

    #[test]
    fn wildcard_dns_challenge_uses_base_identifier() {
        let identifier = Identifier::Dns("FreeChip.EU.org.".to_string());
        assert_eq!(
            dns_challenge_record(&identifier.authorized(true)).unwrap(),
            "_acme-challenge.freechip.eu.org"
        );
        assert_eq!(
            dns_challenge_record(&identifier.authorized(false)).unwrap(),
            "_acme-challenge.freechip.eu.org"
        );
    }
}
