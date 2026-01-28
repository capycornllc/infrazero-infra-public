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
- `s3_region`
- `cloud_region` (used as fallback for backend region when `s3_region` is empty)
- `OPS_SSH_KEYS_JSON` (JSON map of admin -> list of SSH public keys)

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
