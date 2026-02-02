# Epic 2 Appendix: Infisical Bootstrap (Egress)

## Goal
Run Infisical bootstrap as a **separate script on egress** after Infisical is up. The script must:
- Decide whether to bootstrap based on `infisical_restore_from_s3` and the presence of a backup in S3.
- If bootstrapping: create the admin token, store it encrypted in S3 (using the same Age public key as backups), and write a JSON manifest.
- Create the Infisical project (if missing) and add the admin user to the project.
- Load secrets from GitHub secret `infisical_bootstrap_secrets` into Infisical, creating folders as needed.

This appendix defines the workflow and required inputs; implementation will be in `bootstrap/infisical-bootstrap.sh`, invoked by `bootstrap/egress.sh` after Infisical is healthy.

---

## Inputs (environment variables)
Required on egress:
- `INFISICAL_SITE_URL` (or `INFISICAL_FQDN` to build it)
- `INFISICAL_EMAIL`, `INFISICAL_PASSWORD`, `INFISICAL_ORGANIZATION`, `INFISICAL_NAME`, `INFISICAL_SURNAME`
- `INFISICAL_PROJECT_NAME` (project to create in Infisical)
- `INFISICAL_RESTORE_FROM_S3` (`true`/`false`)
- `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_ENDPOINT`, `S3_REGION`
- `DB_BACKUP_BUCKET`
- `DB_BACKUP_AGE_PUBLIC_KEY` (Age pubkey used for Infisical backups)

Optional:
- `INFISICAL_BOOTSTRAP_SECRETS` (JSON payload from GitHub secret `infisical_bootstrap_secrets`)
- `ENVIRONMENT` (e.g., `dev`, `staging`, `prod`)
- `PROJECT_SLUG`
- `INFISICAL_PROJECT_SLUG`
- `INFISICAL_PROJECT_DESCRIPTION`

---

## Decision Flow (Restore vs Bootstrap)
1) **Read `INFISICAL_RESTORE_FROM_S3`.**
2) **Check S3 for backup manifest** at:
   - `s3://$DB_BACKUP_BUCKET/infisical/latest-dump.json`
3) **If** `INFISICAL_RESTORE_FROM_S3=true` **and** `latest-dump.json` exists:
   - **Do not bootstrap** on egress. (Restore runs on egress.)
   - Exit successfully.
4) **Else**, proceed with bootstrap.

Rationale: If a backup exists and restore is requested, bootstrap should not override restored state.

---

## Bootstrap Flow (Egress Script)
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
If bootstrap already happened, the API may return an error. The script must handle this as a non-fatal condition **only if** `infisical/bootstrap/latest-tokens.json` already exists in S3.

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

### 6) Create Project + Add Admin Membership
- Create the project if it does not exist.
- After the project is created, add the admin user to the project (membership) so the admin can manage it directly.

### 7) Encrypt and Store Admin Token in S3
Encrypt the admin token with Age using `DB_BACKUP_AGE_PUBLIC_KEY`:
- `admin.token.age`

Upload to:
- `s3://$DB_BACKUP_BUCKET/infisical/bootstrap/<timestamp>/admin.token.age`

Create a **manifest** (JSON) and upload to:
- `s3://$DB_BACKUP_BUCKET/infisical/bootstrap/latest-tokens.json`

Example manifest:
```json
{
  "created_at": "2026-02-01T18:07:00Z",
  "infisical_site_url": "https://infisical.example.com",
  "admin_token_key": "infisical/bootstrap/20260201T180700Z/admin.token.age",
  "admin_token_sha256": "sha256-hex"
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

---

## Idempotency Rules
- If `infisical/bootstrap/latest-tokens.json` exists and the instance is already bootstrapped, exit successfully.
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
- `bootstrap/infisical-bootstrap.sh` (called from `bootstrap/egress.sh` after Infisical is healthy)
