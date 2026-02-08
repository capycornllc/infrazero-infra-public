# infrazero-infra-public

Reusable OpenTofu template for Hetzner Cloud that builds the full topology (bastion, egress, k3s control planes + workers, db, LBs, firewalls, and persistent DB volume) from a single config file and GitHub Actions workflows.

## Quick start
1) Edit `config/infra.yaml` for your project/env.
2) Add GitHub Actions secrets (see below).
3) Run `build.yml`.

## Config
- Single source of truth: `config/infra.yaml`
- Schema: `config/schema.json`
- `s3_backend.state_prefix` is derived from `PROJECT_SLUG` + `ENVIRONMENT` at render time (falls back to config when unset); `s3_endpoint` + `s3_region` come from secrets.
- `name_prefix` is derived from `PROJECT_SLUG` + `ENVIRONMENT` at render time (falls back to config `environment` when unset).
- `location` is derived from `cloud_region` at render time.

Render and validate locally:
```bash
python scripts/validate-config.py --config config/infra.yaml --schema config/schema.json
# render-config.py expects the GitHub Actions secrets as env vars (see list below).
python scripts/render-config.py --config config/infra.yaml --output tofu/tofu.tfvars.json
```

## Required GitHub Actions secrets
- `hetzner_cloud_token`
- `s3_access_key_id`
- `s3_secret_access_key`
- `infra_state_bucket`
- `s3_endpoint`
- `s3_region` (optional; falls back to `cloud_region`, then `us-east-1`)
- `cloud_region` (used as fallback for backend region when `s3_region` is empty)
- `gh_token`
- `gh_owner`
- `gh_infra_repo`
- `gh_gitops_repo`
- `OPS_SSH_KEYS_JSON` (JSON map of admin -> list of SSH public keys)
- `db_backup_bucket`
- `databases_json` (JSON array of databases; see below)
- `db_type` (currently `postgresql`)
- `db_version` (currently `14.20`)
- `k3s_control_planes_count` (`1`, `3`, or `5`; must be <= the number of `k3s_control_planes` entries in `config/infra.yaml`)
- `k3s_workers_count` (must be <= the number of `k3s_workers` entries in `config/infra.yaml`)
- `k3s_join_token`
- `infisical_password`
- `infisical_project_name`
- `infisical_email`
- `infisical_organization`
- `infisical_name`
- `infisical_surname`
- `infisical_postgres_db`
- `infisical_postgres_user`
- `infisical_postgres_password`
- `infisical_encryption_key`
- `infisical_auth_secret`
- `infisical_db_backup_age_public_key`
- `infisical_db_backup_age_private_key`
- `infisical_restore_from_s3` (optional; `true` to restore from S3 before bootstrap)
- `infisical_bootstrap_secrets` (optional JSON payload for Infisical bootstrap secrets)
- `argocd_admin_password`
- `argocd_fqdn`
- `kubernetes_fqdn`
- `wg_server_private_key`
- `wg_server_public_key`
- `wg_server_address`
- `wg_listen_port`
- `WG_ADMIN_PEERS_JSON`
- `WG_PRESHARED_KEYS_JSON`

### databases_json
`databases_json` is a JSON array of database definitions:
- `name`, `user`, `password`
- `backup_age_public_key`, `backup_age_private_key`
- `restore_latest` (optional boolean; default `true`)
- `restore_dump_path` (optional string; used only when `restore_latest` is `false`)
  - If empty/missing, DB bootstrap skips restore for that DB.
  - Accepts any S3 key (relative to `db_backup_bucket`) or a full `s3://<bucket>/<key>`.
  - If it ends with `/`, it's treated as a prefix containing `latest-dump.json`.

Example:
```json
[
  {
    "name": "messenger",
    "user": "messenger",
    "password": "REDACTED",
    "backup_age_public_key": "age1...",
    "backup_age_private_key": "AGE-SECRET-KEY-1...",
    "restore_latest": true
  }
]
```

DB backups are stored under:
- `s3://$db_backup_bucket/db/<db_name>/<timestamp>.sql.gz.age`
- `s3://$db_backup_bucket/db/<db_name>/latest-dump.json`

### Debug / break-glass access (optional)
- `DEBUG_ROOT_PASSWORD`: if set, bootstraps set the root password on all servers, enable SSH password auth + PermitRootLogin, and bastion listens on all interfaces. Bastion SSH is opened to `0.0.0.0/0` while this is set. The value is embedded in cloud-init user data; remove the secret after troubleshooting.
- If `DEBUG_ROOT_PASSWORD` is empty/unset, password auth stays disabled and bastion SSH remains restricted to WireGuard/private interfaces + allowed CIDRs.

### Cloud-init overlays (optional)
Each value must be a YAML mapping (cloud-init snippet). Lists are appended for `packages`, `write_files`, and `runcmd`.
- `bastion_cloud_init`
- `egress_cloud_init`
- `db_cloud_init`
- `node_primary_cloud_init`
- `nodes_secondary_cloud_init`

### WireGuard runtime toggles (optional)
- `WG_SNAT_ENABLED=true`: SNAT WG client traffic to the bastion private IP (fallback when route-based WG isn’t working).
- `WG_ALLOW_WAN=true`: allow WG clients to reach WAN via bastion (full-tunnel). Default is off.

Full list (including future epics): `docs/secrets-list.md`

## Workflows
- `build.yml`: packages bootstraps, uploads to S3, presigns artifacts, destroys/recreates infra (preserves DB volume), and applies.
- `rebuild-bastion.yml`: replace only bastion.
- `rebuild-egress.yml`: replace only egress.
- `rebuild-db.yml`: replace only db server (volume preserved).
- `rebuild-nodes.yml`: replace all k3s nodes (control planes + workers).

## Notes
- DB volume is protected with `prevent_destroy` and imported automatically if it already exists.
- DB bootstrap mounts the attached volume at `/mnt/db` when present.
- If `db_fqdn` and `cloudflare_api_token` are set, DB bootstrap will obtain a Let's Encrypt cert via DNS-01 and enable PostgreSQL TLS.
- `kubernetes_fqdn` points to egress (public IP). Egress terminates TLS and proxies `https://kubernetes_fqdn` to the k3s API (private k3s API LB when HA, otherwise node1).
- Bootstrap artifacts are uploaded to `s3://$infra_state_bucket/bootstrap/` and referenced in cloud-init via presigned URLs.
- `bootstrap/*.sh` are placeholders for Epic 2+ and will be extended.
- If `s3_endpoint` is missing a scheme, the workflows will prepend `https://`.
- Backend config skips AWS region validation to allow Hetzner regions (e.g. `fsn1`).

## Bootstrap scripts (manual re-run)
If cloud-init fails or you need to re-run a role bootstrap, the scripts are designed to be **idempotent** and can be run manually on the target host. After the initial run, the extracted scripts live under `/opt/infrazero/bootstrap/`.

Common + role scripts:
```bash
sudo /opt/infrazero/bootstrap/common.sh
sudo /opt/infrazero/bootstrap/bastion.sh   # bastion host
sudo /opt/infrazero/bootstrap/egress.sh    # egress host
sudo /opt/infrazero/bootstrap/node1.sh     # first k3s server node
sudo /opt/infrazero/bootstrap/node2.sh     # second k3s node (if present)
sudo /opt/infrazero/bootstrap/db.sh        # database host
```

Infisical bootstrap (runs from egress, safe to re-run):
```bash
sudo /opt/infrazero/bootstrap/infisical-bootstrap.sh
```

Infisical admin token sync (runs from node1, safe to re-run):
```bash
sudo /opt/infrazero/bootstrap/infisical-admin-secret.sh
```

## Bootstrap logs
On each server, check these logs first:
- `/var/log/infrazero-bootstrap.log` (aggregated bootstrap output)
- `/var/log/cloud-init.log`
- `/var/log/cloud-init-output.log`

## Infisical backup (on-demand)
On the **egress** node you can trigger an immediate Infisical backup:
```bash
sudo /opt/infrazero/infisical/backup.sh
```

This writes an encrypted dump to `s3://$db_backup_bucket/infisical/` and updates `infisical/latest-dump.json`.
Logs are written to:
```
/var/log/infrazero-infisical-backup.log
```

Optional one-off systemd run:
```bash
sudo systemd-run --unit=infisical-backup-once --wait /opt/infrazero/infisical/backup.sh
```

## DB restore (manual)
On the **db** node you can restore a specific database backup from S3. The script will:
- Download the object from S3
- Detect whether it is age-encrypted or plaintext
- Prompt for an Age private key if needed (or set `DB_RESTORE_AGE_PRIVATE_KEY` to avoid the prompt)
- Reapply Infrazero PostgreSQL settings (listen address + HBA block for k3s/WG)
- Wipe and recreate the target database before restoring

```bash
sudo /opt/infrazero/db/restore.sh messenger db/messenger/20260201T120000Z.sql.gz.age
# or full path:
sudo /opt/infrazero/db/restore.sh messenger s3://<bucket>/db/messenger/20260201T120000Z.sql.gz.age
```

Notes:
- During restore, PostgreSQL listen addresses are set to the node private IP (derived from `PRIVATE_CIDR`) plus `localhost`.
- Override with `DB_LISTEN_ADDRESS` (comma-separated values accepted by PostgreSQL).

### Role mapping / ACL handling
If your dump references old roles (for example `awa`) that do not exist on the rebuilt server, you have two options:

- **Map old roles to new ones** (recommended for ownership preservation):
  - Set `DB_RESTORE_ROLE_MAP='old:new,old2:new2'`.
  - The script will create missing old roles as `NOLOGIN`, restore, reassign ownership to the new role(s), and drop the old roles by default.
  - To keep old roles, set `DB_RESTORE_DROP_MAPPED_ROLES=false`.

Example:
```bash
sudo DB_RESTORE_ROLE_MAP='awa:awa-messenger' /opt/infrazero/db/restore.sh messenger db/messenger/20260201T120000Z.sql.gz.age
```

- **Skip ACLs** (works when you only care about data + schema):
  - If no `DB_RESTORE_ROLE_MAP` is set, the script skips ACLs by default and reassigns ownership to the target DB user.
  - You can explicitly control this with `DB_RESTORE_SKIP_ACL=true|false`.

### Post-restore grants
After restore, the script grants the app user privileges across all non-system schemas:
- `GRANT USAGE, CREATE` on schemas
- `GRANT ALL` on all tables and sequences
- `ALTER DEFAULT PRIVILEGES` for tables and sequences

To disable this behavior, set `DB_RESTORE_GRANT_APP_USER=false`.
