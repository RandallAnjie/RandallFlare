//! Decentralized management authorization.
//!
//! A browser asks any node for a short-lived challenge. The operator CLI
//! fetches that challenge over the encrypted peer API and signs the exact
//! payload. The resulting [`ConsoleGrant`] is stored in an HttpOnly cookie;
//! every node can verify it using the configured operator public identity,
//! so there is no account database or central session service.
//!
//! Worker manifests use the same approval queue, but the signed payload is
//! the canonical postcard-encoded [`WorkerManifest`] itself. Nodes never hold
//! the operator private key.

use crate::node::now_ms;
use anyhow::{bail, Result};
use base64::Engine as _;
use rand::RngCore;
use rf_core::envelope::Envelope;
use rf_core::identity::SignerId;
use rf_core::manifest::WorkerManifest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const CONSOLE_GRANT_VERSION: u8 = 1;
pub const LOGIN_APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;
pub const MANIFEST_APPROVAL_TTL_MS: u64 = 10 * 60 * 1000;
pub const SOURCE_APPROVAL_TTL_MS: u64 = 10 * 60 * 1000;
pub const CONSOLE_SESSION_TTL_MS: u64 = 60 * 60 * 1000;
pub const MAX_CONSOLE_SESSION_TTL_MS: u64 = 12 * 60 * 60 * 1000;
const MAX_PENDING: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleGrant {
    pub version: u8,
    pub cluster_id: String,
    pub session_id: [u8; 32],
    pub csrf: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl ConsoleGrant {
    pub fn validate(&self, cluster_id: &str, at_ms: u64) -> Result<()> {
        if self.version != CONSOLE_GRANT_VERSION {
            bail!("unsupported console grant version");
        }
        if self.cluster_id != cluster_id {
            bail!("console grant belongs to a different cluster");
        }
        if self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_CONSOLE_SESSION_TTL_MS
        {
            bail!("invalid console grant lifetime");
        }
        // Tolerate a small wall-clock skew between the approving CLI and node.
        if self.issued_at_ms > at_ms.saturating_add(30_000) {
            bail!("console grant is not active yet");
        }
        if self.expires_at_ms <= at_ms {
            bail!("console grant expired");
        }
        Ok(())
    }

    pub fn session_hex(&self) -> String {
        hex::encode(self.session_id)
    }

    pub fn csrf_hex(&self) -> String {
        hex::encode(self.csrf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Login,
    Manifest,
    Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedApproval {
    pub id: String,
    pub code: String,
    pub kind: ApprovalKind,
    pub summary: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: String,
    pub code: String,
    pub kind: ApprovalKind,
    pub summary: String,
    pub payload_base64: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    pub signer: SignerId,
    pub signature_base64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ApprovalPoll {
    pub state: ApprovalState,
    pub envelope: Option<Envelope>,
    pub error: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct ApprovedPayload {
    pub id: String,
    pub kind: ApprovalKind,
    pub envelope: Envelope,
}

#[derive(Debug, Clone)]
enum Status {
    Pending,
    Approved(Envelope),
    Completed(Envelope),
    Failed(String),
}

#[derive(Debug, Clone)]
struct PendingApproval {
    id: String,
    code: String,
    kind: ApprovalKind,
    summary: String,
    payload: Vec<u8>,
    session_id: Option<[u8; 32]>,
    expires_at_ms: u64,
    status: Status,
}

#[derive(Debug, Default)]
struct Inner {
    by_id: HashMap<String, PendingApproval>,
    by_code: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct Management {
    inner: Arc<Mutex<Inner>>,
}

impl Management {
    pub fn create_login(&self, cluster_id: &str, label: &str) -> Result<CreatedApproval> {
        let issued_at_ms = now_ms();
        let grant = ConsoleGrant {
            version: CONSOLE_GRANT_VERSION,
            cluster_id: cluster_id.to_string(),
            session_id: random_bytes(),
            csrf: random_bytes(),
            issued_at_ms,
            expires_at_ms: issued_at_ms + CONSOLE_SESSION_TTL_MS,
        };
        let payload = postcard::to_stdvec(&grant)?;
        self.create(
            ApprovalKind::Login,
            format!("Sign in to RandallFlare cluster {cluster_id} via {label}"),
            payload,
            Some(grant.session_id),
            LOGIN_APPROVAL_TTL_MS,
        )
    }

    pub fn create_manifest(
        &self,
        session_id: [u8; 32],
        manifest: &WorkerManifest,
        summary: String,
    ) -> Result<CreatedApproval> {
        manifest
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid manifest: {error}"))?;
        let payload = postcard::to_stdvec(manifest)?;
        self.create(
            ApprovalKind::Manifest,
            summary,
            payload,
            Some(session_id),
            MANIFEST_APPROVAL_TTL_MS,
        )
    }

    /// A manifest produced without a browser session (for example by a
    /// verified GitHub webhook) is still safe: the operator signs the exact
    /// canonical manifest, while any authenticated console may observe it.
    pub fn create_manifest_scoped(
        &self,
        session_id: Option<[u8; 32]>,
        manifest: &WorkerManifest,
        summary: String,
    ) -> Result<CreatedApproval> {
        manifest
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid manifest: {error}"))?;
        let payload = postcard::to_stdvec(manifest)?;
        self.create(
            ApprovalKind::Manifest,
            summary,
            payload,
            session_id,
            MANIFEST_APPROVAL_TTL_MS,
        )
    }

    pub fn create_source(
        &self,
        session_id: [u8; 32],
        source: &crate::build::WorkerSource,
        summary: String,
    ) -> Result<CreatedApproval> {
        source.validate()?;
        self.create(
            ApprovalKind::Source,
            summary,
            postcard::to_stdvec(source)?,
            Some(session_id),
            SOURCE_APPROVAL_TTL_MS,
        )
    }

    fn create(
        &self,
        kind: ApprovalKind,
        summary: String,
        payload: Vec<u8>,
        session_id: Option<[u8; 32]>,
        ttl_ms: u64,
    ) -> Result<CreatedApproval> {
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        cleanup(&mut inner, now);
        if inner.by_id.len() >= MAX_PENDING {
            bail!("too many pending management approvals");
        }
        let id = unique_token(&inner.by_id);
        let code = unique_code(&inner.by_code);
        let expires_at_ms = now + ttl_ms;
        let approval = PendingApproval {
            id: id.clone(),
            code: code.clone(),
            kind,
            summary: summary.clone(),
            payload,
            session_id,
            expires_at_ms,
            status: Status::Pending,
        };
        inner.by_code.insert(code.clone(), id.clone());
        inner.by_id.insert(id.clone(), approval);
        Ok(CreatedApproval {
            id,
            code,
            kind,
            summary,
            expires_at_ms,
        })
    }

    pub fn view_by_code(&self, code: &str) -> Result<ApprovalView> {
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        cleanup(&mut inner, now);
        let normalized = normalize_code(code);
        let id = inner
            .by_code
            .get(&normalized)
            .ok_or_else(|| anyhow::anyhow!("approval code not found or expired"))?;
        let approval = inner.by_id.get(id).expect("code index points at approval");
        if !matches!(approval.status, Status::Pending) {
            bail!("approval code has already been used");
        }
        Ok(ApprovalView {
            id: approval.id.clone(),
            code: approval.code.clone(),
            kind: approval.kind,
            summary: approval.summary.clone(),
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&approval.payload),
            expires_at_ms: approval.expires_at_ms,
        })
    }

    pub fn approve(
        &self,
        code: &str,
        signer: SignerId,
        signature: Vec<u8>,
        operator: &SignerId,
    ) -> Result<ApprovedPayload> {
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        cleanup(&mut inner, now);
        let normalized = normalize_code(code);
        let id = inner
            .by_code
            .get(&normalized)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("approval code not found or expired"))?;
        let approval = inner
            .by_id
            .get_mut(&id)
            .expect("code index points at approval");
        if !matches!(approval.status, Status::Pending) {
            bail!("approval code has already been used");
        }
        if signer != *operator || !signer.verify(&approval.payload, &signature) {
            bail!("approval signature is not from the configured operator");
        }
        let envelope = Envelope {
            payload: approval.payload.clone(),
            signer,
            sig: signature,
        };
        match approval.kind {
            ApprovalKind::Login => {
                let grant: ConsoleGrant = envelope
                    .open(Some(operator))
                    .map_err(|error| anyhow::anyhow!("invalid console grant: {error}"))?;
                grant.validate(&grant.cluster_id, now)?;
                approval.status = Status::Completed(envelope.clone());
            }
            ApprovalKind::Manifest => {
                let manifest: WorkerManifest = envelope
                    .open(Some(operator))
                    .map_err(|error| anyhow::anyhow!("invalid manifest approval: {error}"))?;
                manifest
                    .validate()
                    .map_err(|error| anyhow::anyhow!("invalid manifest: {error}"))?;
                approval.status = Status::Approved(envelope.clone());
            }
            ApprovalKind::Source => {
                let source: crate::build::WorkerSource = envelope
                    .open(Some(operator))
                    .map_err(|error| anyhow::anyhow!("invalid source approval: {error}"))?;
                source.validate()?;
                approval.status = Status::Approved(envelope.clone());
            }
        }
        Ok(ApprovedPayload {
            id,
            kind: approval.kind,
            envelope,
        })
    }

    pub fn complete(&self, id: &str, result: Result<()>) {
        let mut inner = self.inner.lock().unwrap();
        let Some(approval) = inner.by_id.get_mut(id) else {
            return;
        };
        let envelope = match &approval.status {
            Status::Approved(envelope) | Status::Completed(envelope) => envelope.clone(),
            _ => return,
        };
        approval.status = match result {
            Ok(()) => Status::Completed(envelope),
            Err(error) => Status::Failed(error.to_string()),
        };
    }

    pub fn poll_login(&self, id: &str) -> Result<ApprovalPoll> {
        self.poll(id, None, ApprovalKind::Login)
    }

    pub fn poll_manifest(&self, id: &str, session_id: [u8; 32]) -> Result<ApprovalPoll> {
        self.poll(id, Some(session_id), ApprovalKind::Manifest)
    }

    pub fn poll_source(&self, id: &str, session_id: [u8; 32]) -> Result<ApprovalPoll> {
        self.poll(id, Some(session_id), ApprovalKind::Source)
    }

    /// Internal build-manager observation, never exposed without console auth.
    pub fn poll_internal(&self, id: &str) -> Result<ApprovalPoll> {
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        cleanup(&mut inner, now);
        let approval = inner
            .by_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("approval not found or expired"))?;
        Ok(poll_value(approval))
    }

    /// An authenticated console may observe unscoped webhook approvals, or
    /// approvals created by its own session.
    pub fn poll_console(&self, id: &str, session_id: [u8; 32]) -> Result<ApprovalPoll> {
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        cleanup(&mut inner, now);
        let approval = inner
            .by_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("approval not found or expired"))?;
        if approval.kind == ApprovalKind::Login
            || (approval.session_id.is_some() && approval.session_id != Some(session_id))
        {
            bail!("approval does not belong to this session");
        }
        Ok(poll_value(approval))
    }

    fn poll(
        &self,
        id: &str,
        session_id: Option<[u8; 32]>,
        expected_kind: ApprovalKind,
    ) -> Result<ApprovalPoll> {
        let now = now_ms();
        let mut inner = self.inner.lock().unwrap();
        cleanup(&mut inner, now);
        let approval = inner
            .by_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("approval not found or expired"))?;
        if approval.kind != expected_kind
            || (expected_kind != ApprovalKind::Login && approval.session_id != session_id)
        {
            bail!("approval does not belong to this session");
        }
        Ok(poll_value(approval))
    }
}

fn poll_value(approval: &PendingApproval) -> ApprovalPoll {
    let (state, envelope, error) = match &approval.status {
        Status::Pending | Status::Approved(_) => (ApprovalState::Pending, None, None),
        Status::Completed(envelope) => (ApprovalState::Completed, Some(envelope.clone()), None),
        Status::Failed(error) => (ApprovalState::Failed, None, Some(error.clone())),
    };
    ApprovalPoll {
        state,
        envelope,
        error,
        summary: approval.summary.clone(),
    }
}

fn cleanup(inner: &mut Inner, now: u64) {
    let expired: Vec<String> = inner
        .by_id
        .iter()
        .filter(|(_, approval)| approval.expires_at_ms <= now)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        if let Some(approval) = inner.by_id.remove(&id) {
            inner.by_code.remove(&approval.code);
        }
    }
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn unique_token(existing: &HashMap<String, PendingApproval>) -> String {
    loop {
        let token = hex::encode(random_bytes());
        if !existing.contains_key(&token) {
            return token;
        }
    }
}

fn unique_code(existing: &HashMap<String, String>) -> String {
    loop {
        let mut bytes = [0u8; 5];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let raw = hex::encode_upper(bytes);
        let code = format!("{}-{}", &raw[..5], &raw[5..]);
        if !existing.contains_key(&code) {
            return code;
        }
    }
}

pub fn normalize_code(code: &str) -> String {
    let compact: String = code
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if compact.len() == 10 {
        format!("{}-{}", &compact[..5], &compact[5..])
    } else {
        code.trim().to_ascii_uppercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::identity::{AnyKeypair, Keypair};
    use std::collections::BTreeMap;

    fn manifest() -> WorkerManifest {
        WorkerManifest {
            name: "admin-test".into(),
            version: 1,
            prev: None,
            deleted: false,
            main: String::new(),
            modules: vec![],
            assets: vec![rf_core::manifest::AssetFile {
                path: "index.html".into(),
                sha256: [1; 32],
                size: 1,
            }],
            hostnames: vec!["admin-test.example".into()],
            env: BTreeMap::new(),
            kv_bindings: BTreeMap::new(),
            crons: vec![],
            compatibility_date: "2026-08-04".into(),
        }
    }

    #[test]
    fn operator_approves_cluster_wide_login_grant() {
        let management = Management::default();
        let operator = AnyKeypair::Ed(Keypair::from_seed([7; 32]));
        let created = management.create_login("cluster-a", "node-a").unwrap();
        let view = management.view_by_code(&created.code).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(view.payload_base64)
            .unwrap();
        let approved = management
            .approve(
                &created.code,
                operator.signer_id(),
                operator.sign(&payload),
                &operator.signer_id(),
            )
            .unwrap();
        assert_eq!(approved.kind, ApprovalKind::Login);
        let poll = management.poll_login(&created.id).unwrap();
        assert_eq!(poll.state, ApprovalState::Completed);
        let grant: ConsoleGrant = poll
            .envelope
            .unwrap()
            .open(Some(&operator.signer_id()))
            .unwrap();
        assert_eq!(grant.cluster_id, "cluster-a");
    }

    #[test]
    fn wrong_signer_and_cross_session_poll_are_rejected() {
        let management = Management::default();
        let operator = AnyKeypair::Ed(Keypair::from_seed([7; 32]));
        let mallory = AnyKeypair::Ed(Keypair::from_seed([8; 32]));
        let session = [3; 32];
        let created = management
            .create_manifest(session, &manifest(), "deploy admin-test v1".into())
            .unwrap();
        let view = management.view_by_code(&created.code).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(view.payload_base64)
            .unwrap();
        assert!(management
            .approve(
                &created.code,
                mallory.signer_id(),
                mallory.sign(&payload),
                &operator.signer_id(),
            )
            .is_err());
        assert!(management.poll_manifest(&created.id, [4; 32]).is_err());
        assert_eq!(
            management
                .poll_manifest(&created.id, session)
                .unwrap()
                .state,
            ApprovalState::Pending
        );
    }

    #[test]
    fn manifest_completion_is_visible_only_after_commit() {
        let management = Management::default();
        let operator = AnyKeypair::Ed(Keypair::from_seed([7; 32]));
        let session = [9; 32];
        let created = management
            .create_manifest(session, &manifest(), "deploy admin-test v1".into())
            .unwrap();
        let view = management.view_by_code(&created.code).unwrap();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(view.payload_base64)
            .unwrap();
        let approved = management
            .approve(
                &created.code,
                operator.signer_id(),
                operator.sign(&payload),
                &operator.signer_id(),
            )
            .unwrap();
        assert_eq!(
            management
                .poll_manifest(&created.id, session)
                .unwrap()
                .state,
            ApprovalState::Pending
        );
        management.complete(&approved.id, Ok(()));
        assert_eq!(
            management
                .poll_manifest(&created.id, session)
                .unwrap()
                .state,
            ApprovalState::Completed
        );
    }
}
