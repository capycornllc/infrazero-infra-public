# Epic 4 Appendix: Infisical Bootstrap (Node1)

## Goal
Run Infisical bootstrap as a **separate script on node1** after k3s/Argo CD are up. The script must:
- Decide whether to bootstrap based on `infisical_restore_from_s3` and the presence of a backup in S3.
- If bootstrapping: create admin + read-only tokens, store both encrypted in S3 (using the same Age public key as backups), and write a JSON manifest.
- Load secrets from GitHub secret `infisical_bootstrap_secrets` into Infisical, creating folders as needed.
- Create a Kubernetes Secret with the read-only token for the CSI provider.

This appendix defines the workflow and required inputs; implementation will be in a dedicated node1 script (e.g., `bootstrap/infisical-bootstrap.sh`), invoked by `bootstrap/node1.sh` after k3s is healthy.

---

## Inputs (environment variables)
Required on node1:
- `INFISICAL_SITE_URL` (or `INFISICAL_FQDN` to build it)
- `INFISICAL_EMAIL`, `INFISICAL_PASSWORD`, `INFISICAL_ORGANIZATION`, `INFISICAL_NAME`, `INFISICAL_SURNAME`
- `INFISICAL_RESTORE_FROM_S3` (`true`/`false`)
- `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_ENDPOINT`, `S3_REGION`
- `DB_BACKUP_BUCKET`
- `DB_BACKUP_AGE_PUBLIC_KEY` (Age pubkey used for Infisical backups)
- `INFISICAL_BOOTSTRAP_SECRETS` (JSON payload from GitHub secret `infisical_bootstrap_secrets`)
- `ENVIRONMENT` (e.g., `dev`, `staging`, `prod`)

Optional:
- `PROJECT_SLUG`
- `INFISICAL_READONLY_SECRET_NAME` (default: `infisical-readonly-token`)
- `INFISICAL_READONLY_SECRET_NAMESPACE` (default: `kube-system`)

---

## Decision Flow (Restore vs Bootstrap)
1) **Read `INFISICAL_RESTORE_FROM_S3`.**
2) **Check S3 for backup manifest** at:
   - `s3://$DB_BACKUP_BUCKET/infisical/latest-dump.json`
3) **If** `INFISICAL_RESTORE_FROM_S3=true` **and** `latest-dump.json` exists:
   - **Do not bootstrap** on node1. (Restore runs on egress.)
   - Exit successfully.
4) **Else**, proceed with bootstrap.

Rationale: If a backup exists and restore is requested, bootstrap should not override restored state.

---

## Bootstrap Flow (Node1 Script)
### 1) Wait for Infisical API
Ensure **`INFISICAL_FQDN`** is reachable first, then verify `INFISICAL_SITE_URL` is healthy (HTTPS).
Do not proceed until the FQDN responds successfully.

### 2) Bootstrap Admin Account (API)
Call the Infisical bootstrap endpoint:
```
POST https://<infisical-domain>/api/v1/admin/bootstrap
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "StrongPassw0rd!",
  "organization": "MyOrganizationName"
}
```

Example:
```
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"StrongPassw0rd!","organization":"MyOrg"}' \
  https://<infisical-domain>/api/v1/admin/bootstrap
```

Result: JSON with admin user, organization, and an **Instance Admin Machine Identity token**.

### 3) Idempotency (Already Bootstrapped)
If bootstrap already happened, the API may return an error. The script must handle this as a non-fatal condition.

CLI alternative (if used):
```
infisical bootstrap \
  --domain=https://<infisical-domain> \
  --email=admin@example.com \
  --password=StrongPassw0rd! \
  --organization=MyOrg \
  --ignore-if-bootstrapped
```

### 4) Extract Machine Identity Token
From bootstrap response:
```json
{
  "identity": {
    "credentials": {
      "token": "<JWT_TOKEN_HERE>"
    }
  }
}
```

Extract the token for authenticated API calls:
```
TOKEN=$(curl ... | jq -r '.identity.credentials.token')
```

This token is **admin-level** and must be securely stored (encrypted in S3 as described below).

### 5) Use Token for Further API Actions
All subsequent Infisical API calls must use:
```
Authorization: Bearer <JWT_TOKEN_HERE>
```

Example:
```
curl -H "Authorization: Bearer $TOKEN" \
  https://<infisical-domain>/api/v1/projects
```

### 6) Create Tokens
Create:
- **Admin token** (full access)
- **Read-only token** (read-only permissions for CSI usage)

### 7) Encrypt and Store Tokens in S3
Encrypt each token with Age using `DB_BACKUP_AGE_PUBLIC_KEY`:
- `admin.token.age`
- `readonly.token.age`

Upload to:
- `s3://$DB_BACKUP_BUCKET/infisical/bootstrap/`

Create a **manifest** (JSON) and upload to:
- `s3://$DB_BACKUP_BUCKET/infisical/bootstrap/latest-tokens.json`

Example manifest:
```json
{
  "created_at": "2026-02-01T18:07:00Z",
  "infisical_site_url": "https://infisical.example.com",
  "admin_token_key": "infisical/bootstrap/admin.token.age",
  "admin_token_sha256": "sha256-hex",
  "readonly_token_key": "infisical/bootstrap/readonly.token.age",
  "readonly_token_sha256": "sha256-hex"
}
```

### 8) Populate Infisical Secrets
`INFISICAL_BOOTSTRAP_SECRETS` JSON structure:
```json
{
  "folder_name": [
    {
      "secret_name": {
        "dev": "dev_secret_value",
        "staging": "staging_secret_value",
        "prod": "prod_secret_value"
      }
    }
  ]
}
```

Process:
- For each `folder_name`, ensure folder exists (create if missing).
- For each `secret_name`, select value using `ENVIRONMENT` key.
- Upsert secrets in the target folder.

### 9) Create Kubernetes Secret for CSI
Create a k8s secret containing the **read-only token** for the Infisical CSI provider.

Suggested shape:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: infisical-readonly-token
  namespace: kube-system
type: Opaque
stringData:
  token: "<readonly_token>"
  host: "https://infisical.example.com"
```

---

## Idempotency Rules
- If `infisical/bootstrap/latest-tokens.json` exists, **do not create new tokens** (skip bootstrap to avoid token churn).
- The Kubernetes secret is created only when a read-only token is generated; if you skip bootstrap, you must already have the secret in the cluster.
- If secrets already exist in Infisical, **upsert** (no failure).

---

## Failure Handling
Hard-fail if:
- Required env vars are missing.
- S3 writes fail.

Soft-fail (log + continue) if:
- Secrets upsert encounters already-existing data.

---

## Expected Script Name + Location
- `bootstrap/infisical-bootstrap.sh` (called from `bootstrap/node1.sh` after k3s ready)
