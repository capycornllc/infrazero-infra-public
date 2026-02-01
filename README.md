# infrazero-infra-public

Reusable OpenTofu template for Hetzner Cloud that builds the full topology (bastion, egress, node1, node2, db, LB, firewalls, and persistent DB volume) from a single config file and GitHub Actions workflows.

## Quick start
1) Edit `config/infra.yaml` for your project/env.
2) Add GitHub Actions secrets (see below).
3) Run `build.yml`.

## Config
- Single source of truth: `config/infra.yaml`
- Schema: `config/schema.json`
- `s3_backend.state_prefix` lives in config; `s3_endpoint` + `s3_region` come from secrets.
- `name_prefix` is derived from `PROJECT_SLUG` + `environment` at render time.
- `location` is derived from `cloud_region` at render time.

Render and validate locally:
```bash
python scripts/validate-config.py --config config/infra.yaml --schema config/schema.json
OPS_SSH_KEYS_JSON='{"admin":["ssh-ed25519 AAA..."]}' python scripts/render-config.py --config config/infra.yaml --output tofu/tofu.tfvars.json
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
- `db_backup_age_public_key`
- `db_backup_age_private_key`
- `k3s_join_token`
- `infisical_password`
- `infisical_email`
- `infisical_organization`
- `infisical_name`
- `infisical_surname`
- `infisical_postgres_db`
- `infisical_postgres_user`
- `infisical_postgres_password`
- `infisical_encryption_key`
- `infisical_auth_secret`
- `argocd_admin_password`
- `wg_server_private_key`
- `wg_server_public_key`
- `wg_server_address`
- `wg_listen_port`
- `WG_ADMIN_PEERS_JSON`
- `WG_PRESHARED_KEYS_JSON`

### Debug / break-glass access (optional)
- `DEBUG_ROOT_PASSWORD`: if set, bootstraps set the root password on all servers, enable SSH password auth + PermitRootLogin, and bastion listens on all interfaces. Bastion SSH is opened to `0.0.0.0/0` while this is set. The value is embedded in cloud-init user data; remove the secret after troubleshooting.
- If `DEBUG_ROOT_PASSWORD` is empty/unset, password auth stays disabled and bastion SSH remains restricted to WireGuard/private interfaces + allowed CIDRs.

### WireGuard runtime toggles (optional)
- `WG_SNAT_ENABLED=true`: SNAT WG client traffic to the bastion private IP (fallback when route-based WG isn’t working).
- `WG_ALLOW_WAN=true`: allow WG clients to reach WAN via bastion (full-tunnel). Default is off.

Full list (including future epics): `docs/secrets-list.md`

## Workflows
- `build.yml`: packages bootstraps, uploads to S3, presigns artifacts, destroys/recreates infra (preserves DB volume), and applies.
- `rebuild-bastion.yml`: replace only bastion.
- `rebuild-egress.yml`: replace only egress.
- `rebuild-db.yml`: replace only db server (volume preserved).
- `rebuild-nodes.yml`: replace node1 and node2.

## Notes
- DB volume is protected with `prevent_destroy` and imported automatically if it already exists.
- DB bootstrap mounts the attached volume at `/mnt/db` when present.
- Bootstrap artifacts are uploaded to `s3://$infra_state_bucket/bootstrap/` and referenced in cloud-init via presigned URLs.
- `bootstrap/*.sh` are placeholders for Epic 2+ and will be extended.
- If `s3_endpoint` is missing a scheme, the workflows will prepend `https://`.
- Backend config skips AWS region validation to allow Hetzner regions (e.g. `fsn1`).
