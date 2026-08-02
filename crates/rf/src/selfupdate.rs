//! Self-update from GitHub Releases: check latest, download the
//! matching target asset, verify its .sha256 sidecar, atomic-rename
//! over the current binary, re-exec. No node is special, so there is
//! no "update server" — GitHub is the (external, already-trusted-for-
//! code) distribution point.
//!
//! Disabled by default (`[update] enabled = true` once the repo is
//! public). The check loop jitters so the fleet doesn't stampede.

use anyhow::{bail, Context, Result};

pub fn target_asset_name() -> String {
    format!("rf-{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// "v0.3.1" > "v0.1.0" — plain semver triple compare, tolerant of a
/// leading v.
pub fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<[u64; 3]> {
        let v = v.trim().trim_start_matches('v');
        let mut it = v.split('.').map(|p| p.parse::<u64>());
        Some([
            it.next()?.ok()?,
            it.next()?.ok()?,
            it.next().and_then(|r| r.ok()).unwrap_or(0),
        ])
    }
    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

pub struct Release {
    pub tag: String,
    pub asset_url: Option<String>,
    pub sha_url: Option<String>,
}

pub async fn fetch_latest(http: &reqwest::Client, api_base: &str, repo: &str) -> Result<Release> {
    let v: serde_json::Value = http
        .get(format!("{api_base}/repos/{repo}/releases/latest"))
        .header("user-agent", "rf-selfupdate")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let tag = v["tag_name"].as_str().unwrap_or_default().to_string();
    if tag.is_empty() {
        bail!("release has no tag_name");
    }
    let want = target_asset_name();
    let mut asset_url = None;
    let mut sha_url = None;
    if let Some(assets) = v["assets"].as_array() {
        for a in assets {
            let name = a["name"].as_str().unwrap_or_default();
            let url = a["browser_download_url"].as_str().unwrap_or_default();
            if name == want {
                asset_url = Some(url.to_string());
            } else if name == format!("{want}.sha256") {
                sha_url = Some(url.to_string());
            }
        }
    }
    Ok(Release {
        tag,
        asset_url,
        sha_url,
    })
}

pub async fn apply(http: &reqwest::Client, release: &Release) -> Result<()> {
    let (Some(asset_url), Some(sha_url)) = (&release.asset_url, &release.sha_url) else {
        bail!(
            "release {} lacks an asset for {}",
            release.tag,
            target_asset_name()
        );
    };
    let bytes = http
        .get(asset_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let sha_line = http
        .get(sha_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let expected = sha_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let actual = crate::blob::sha256_hex(&bytes);
    if expected != actual {
        bail!("update rejected: sha mismatch (expected {expected}, got {actual})");
    }
    let exe = std::env::current_exe().context("current_exe")?;
    let tmp = exe.with_extension("update-tmp");
    std::fs::write(&tmp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &exe).context("atomic swap")?;
    tracing::info!("updated to {} — re-exec", release.tag);
    // Re-exec with identical args; systemd Restart=always also covers us.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let err = std::process::Command::new(&exe).args(args).exec();
        bail!("re-exec failed: {err}");
    }
    #[cfg(not(unix))]
    {
        std::process::exit(0);
    }
}

/// Background loop; no-op unless enabled.
pub fn spawn(config: crate::config::UpdateConfig) {
    if !config.enabled {
        return;
    }
    tokio::spawn(async move {
        let http = reqwest::Client::new();
        loop {
            let base = config.interval_minutes.max(1) * 60;
            let jitter = rand::random::<u64>() % (base / 3).max(1);
            tokio::time::sleep(std::time::Duration::from_secs(base + jitter)).await;
            match fetch_latest(&http, &config.api_base, &config.repo).await {
                Ok(rel) if is_newer(&rel.tag, env!("CARGO_PKG_VERSION")) => {
                    if let Err(e) = apply(&http, &rel).await {
                        tracing::warn!("self-update failed: {e:#}");
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::debug!("self-update check: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "v0.2.0"));
        assert!(!is_newer("garbage", "0.1.0"));
    }

    #[test]
    fn asset_name_shape() {
        let n = target_asset_name();
        assert!(n.starts_with("rf-"));
    }
}
