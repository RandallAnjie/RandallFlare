# Security, automation API, and S3 access

RandallFlare has no account database and no central credential issuer. The
offline operator key remains the root of authority. Browser sessions, quota
policies, API-token digests, and S3 credential records are all independently
verifiable by every node.

Never commit an operator key, cluster secret, API token, S3 Secret Access Key,
Cloudflare token, rclone configuration, or GitHub token. Use HTTPS for every
public management and credential-creation operation.

## Cluster policy

Open **安全与访问** in the Chinese console. The signed cluster policy controls:

- maximum live Workers and bytes in each Worker deployment;
- maximum custom hostnames shared across Workers, R2, Pipelines, and Flows;
- maximum aggregate R2 object count and locally stored logical bytes;
- maximum public Worker requests per minute; and
- whether arbitrary outbound networking is exposed to Worker runtimes.

The defaults are 50 Workers, 10 custom hostnames, 50 MiB per Worker, 10,000
requests per minute, 1 GiB of local R2 data, 10,000 R2 objects, and outbound
networking enabled. rclone-backed object bytes are excluded from the local-byte
limit, while their object records still count toward the object limit.

Each converged live public node deterministically receives a share of the
global request budget. The shares sum to the configured budget. A network
partition may temporarily enforce each partition's view, so this is an
availability-oriented edge admission control rather than centralized billing.
Invalid signed policy data fails closed.

## Personal API tokens

Create a token under **安全与访问 → API 访问令牌**. Choose only the required
scopes and optionally set an expiry time. The raw `rfp_…` token is shown once;
only its SHA-256 digest and a safe display prefix enter the signed resource
history. Revocation is another signed version and therefore converges to every
node.

The API accepts only an Authorization bearer token. A browser session cookie
cannot substitute for it:

```bash
RF_API_ORIGIN=https://edge.example.com
RF_API_TOKEN='rfp_value-shown-once'

curl --fail-with-body \
  -H "Authorization: Bearer ${RF_API_TOKEN}" \
  "${RF_API_ORIGIN}/api/v1/status"
```

Available exact scopes are `worker`, `kv`, `d1`, `r2`, `queue`, `analytics`,
`pipeline`, `workflow`, `flow`, `email`, `binary`, `storage`, and `network`, each with `:read` and `:write`,
plus `node:read`, `node:write`, `quota:read`, `quota:write`, and `audit:read`.
The standalone `*` scope grants every API permission. Access-token and S3
credential creation are intentionally unavailable through bearer-token
resource submission; those operations require the console's operator approval
flow.

### API routes

| Area | Representative routes |
| --- | --- |
| Discovery and nodes | `GET /api/v1`, `GET /api/v1/status` |
| Workers | `GET /api/v1/workers`, `GET/POST /api/v1/workers/{name}` |
| Signed resources | `GET/POST /api/v1/resources`, `GET /api/v1/resources/{kind}/{name}` |
| KV | `GET /api/v1/kv/{namespace}`, `GET/PUT/DELETE /api/v1/kv/{namespace}/{key}` |
| D1 | `GET /api/v1/d1`, `POST /api/v1/d1/{database}/query`, `POST /api/v1/d1/{database}/exec`, `POST /api/v1/d1/{database}/batch` |
| R2 | `GET /api/v1/r2`, `GET /api/v1/r2/{bucket}`, `GET/PUT/DELETE /api/v1/r2/{bucket}/{key}` |
| Queues and Analytics | `/api/v1/queues/…`, `/api/v1/analytics/…` |
| Pipelines | `/api/v1/pipelines/…` including ingest, status, batches, and flush |
| Workflows and Flows | `/api/v1/workflows/…`, `/api/v1/flows/…` |
| Email | `/api/v1/email/…` including message metadata, sending, and raw source |
| Device network | `GET /api/v1/network` returns redacted rules, devices, and live exit endpoints |
| Audit | `GET /api/v1/audit` |

Worker and generic resource writes accept an operator-signed binary envelope,
not unsigned JSON. Admission rechecks the signature, hash-chain relationship,
resource validation, and cluster quota before replication. `d1:read` accepts
only SELECT, read-only WITH/EXPLAIN, and a conservative read-only PRAGMA
whitelist. KV writes can never address the internal `__rf` namespace.
KV list responses include `entries`, `list_complete` and `cursor`; the legacy
`keys` array remains for compatibility. `prefix`, `cursor` and `limit` are
bounded by the node. Browser-admin JSON import/export is documented in
[去中心化 KV](./KV.md) and is not exposed to bearer tokens as an unbounded
bulk bypass.

D1 batch accepts 1–100 statements and requires `d1:write`; the entire batch
is one replicated SQLite transaction. Schema browsing, SQL-file import, and
SQLite snapshot download stay behind the interactive administrator session.
See [去中心化 D1](./D1.md).

## S3-compatible R2 credentials

Create a credential under **安全与访问 → R2 / S3 凭据**. A credential can either
access every bucket or use explicit per-bucket read/write grants. The Access
Key ID remains visible; the Secret Access Key is shown once. Its encrypted
XChaCha20-Poly1305 value is bound to the signed credential identity and can be
opened only by a node possessing the cluster secret. Revocation and grant
changes are signed resource versions.

The endpoint is path-style:

```bash
RF_S3_ENDPOINT=https://edge.example.com/s3
AWS_ACCESS_KEY_ID='RFR2…'
AWS_SECRET_ACCESS_KEY='value-shown-once'

aws --endpoint-url "${RF_S3_ENDPOINT}" \
  --region auto \
  s3api list-buckets

aws --endpoint-url "${RF_S3_ENDPOINT}" \
  --region auto \
  s3 cp ./archive.bin s3://backups/archive.bin
```

The endpoint implements AWS Signature Version 4 header and query/presigned authentication,
bucket/object listing, HEAD, conditional and ranged GET, streamed PUT, DELETE,
and multipart initiate/upload/list-parts/list-uploads/complete/abort. It verifies
the declared payload SHA-256 before committing data and follows R2 multipart
part-size and MD5/composite-ETag semantics. CopyObject preserves metadata by
default or replaces it on request; UploadPartCopy supports an authenticated
source range. Presigned URLs are limited to SigV4, a maximum seven-day lifetime,
active non-STS credentials and the same bucket grants as header-authenticated calls.

An R2 bucket may use local content-addressed storage or a configured rclone
remote. The S3 protocol is identical in both cases; provider credentials remain
only in the mode-0600 node-local rclone configuration and are never placed in a
signed bucket resource.

## Audit and local telemetry

The security page shows redacted signed history for Workers and platform
resources. Token digests, sealed S3 ciphertext, Worker Secret ciphertext,
Pipeline/Flow token hashes, private keys, and raw credentials are not returned
by console audit views. Last-used timestamps are node-local operational
telemetry and are not authorization state; losing them does not make a revoked
credential valid again.
