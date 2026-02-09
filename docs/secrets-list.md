# Secrets & Inputs (Epic 1)

This list reflects the Epic-1 web UI inputs and generated values that will be stored as GitHub Actions secrets for infra repos. Some entries are not sensitive but are still stored as secrets for consistent automation.

## 1) Project Basics
- `project_slug` (used to derive `name_prefix` as `<project_slug>-<environment>`)
- `env` (optional; sets `ENVIRONMENT` for naming + bootstrap; e.g. `dev`, `test`, `prod`)
- `cloud_region` (e.g. `nbg1`, `fsn1`, `hel1`, `ash`, `hil`, `sin`; used as fallback if `s3_region` is empty)
- `s3_endpoint` (include scheme; workflows will prepend `https://` if missing)

## 1.1) Server sizing
- `bastion_server_type`
- `egress_server_type`
- `db_server_type`
- `k3s_node_server_type`
- `k3s_control_planes_count` (`1`, `3`, or `5`)
- `k3s_workers_count`
- `k3s_join_token`
- `load_balancer_config` (optional JSON array overriding LB services: `[{ protocol, source, destination }, ...]`)

## 2) GitHub Access
- `gh_token` (GitHub PAT for repo/bootstrap automation)
- `gh_owner` (default GitHub owner/org)
- `gh_infra_repo` (infra repo name or owner/repo)
- `gh_gitops_repo` (gitops repo name or owner/repo)
- `ghcr_token` (GitHub PAT for pulling images from GHCR; creates `ghcr-pull` in `default` namespace)

## 3) Hetzner Cloud Token
- `hetzner_cloud_token`

## 4) ArgoCD + Infisical Access
- `argocd_admin_password`
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
- `infisical_db_backup_age_public_key`
- `infisical_db_backup_age_private_key`
- `infisical_project_name`
- `infisical_restore_from_s3` (`true` to restore from S3 before bootstrap)
- `infisical_bootstrap_secrets` (JSON payload for Infisical bootstrap secrets)
- `infisical_spc_namespace` (namespace for Infisical SecretProviderClass; defaults to `default` if unset or set to `example`)

## 4.1) Service FQDNs & DNS (Cloudflare)
- `bastion_fqdn`
- `argocd_fqdn`
- `grafana_fqdn`
- `loki_fqdn`
- `infisical_fqdn`
- `kubernetes_fqdn`
- `db_fqdn`
- `internal_services_domains_json`
- `deployed_apps_json`
- `additional_hostnames` (optional JSON array of `{ id, hostname, ip }` to create extra Cloudflare A records)
- `cloudflare_api_token`

Note: Deployed app FQDNs (`deployed_apps_json`) are created as **DNS-only** records (Cloudflare proxy off / `proxied=false`).

## 5) Object Storage / S3
- `s3_access_key_id`
- `s3_secret_access_key`
- `infra_state_bucket`
- `db_backup_bucket`
- `app_private_bucket`
- `app_public_bucket`
- `s3_region` (optional; falls back to `cloud_region`, then `us-east-1`)

## 6) Databases
- `db_type` (currently `postgresql`)
- `db_version` (currently `14.20`)
- `databases_json` (JSON array: `{ name, user, password, backup_age_public_key, backup_age_private_key, restore_latest?, restore_dump_path? }`)

Legacy (deprecated; ignored by this repo):
- `app_db_name`
- `app_db_user`
- `app_db_password`
- `db_backup_age_public_key`
- `db_backup_age_private_key`

## 7) Admin Access (Multi-user)
- `OPS_SSH_KEYS_JSON` (map username -> list of SSH public keys)
- `WG_ADMIN_PEERS_JSON` (map username -> `{ publicKey, ip }`)
- `WG_PRESHARED_KEYS_JSON` (map username -> preshared key)

Global WireGuard settings:
- `wg_listen_port`
- `wg_server_address`
- `wg_server_private_key`
- `wg_server_public_key`

## 8) WireGuard Config Download
- `wg_server_endpoint`

## 9) Debug / Break-glass access (optional)
- `DEBUG_ROOT_PASSWORD` (enables root password auth; bastion SSH opened to `0.0.0.0/0` while set; stored in cloud-init user data)

## 10) Cloud-init overlays (optional)
Each value must be a YAML mapping (cloud-init snippet). Lists are appended for `packages`, `write_files`, and `runcmd`.
- `bastion_cloud_init`
- `egress_cloud_init`
- `db_cloud_init`
- `node_primary_cloud_init`
- `nodes_secondary_cloud_init`
