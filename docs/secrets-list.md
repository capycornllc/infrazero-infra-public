# Secrets & Inputs (Epic 1)

This list reflects the Epic-1 web UI inputs and generated values that will be stored as GitHub Actions secrets for infra repos. Some entries are not sensitive but are still stored as secrets for consistent automation.

## 1) Project Basics
- `project_slug` (used to derive `name_prefix` as `<project_slug>-<environment>`)
- `cloud_region` (e.g. `nbg1`, `fsn1`, `hel1`, `ash`, `hil`, `sin`; used as fallback if `s3_region` is empty)
- `s3_endpoint` (include scheme; workflows will prepend `https://` if missing)

## 1.1) Server sizing
- `bastion_server_type`
- `egress_server_type`
- `db_server_type`
- `k3s_node_server_type`
- `k3s_node_count`
- `k3s_join_token`

## 2) GitHub Access
- `gh_token` (GitHub PAT for repo/bootstrap automation)
- `gh_owner` (default GitHub owner/org)
- `gh_infra_repo` (infra repo name or owner/repo)
- `gh_gitops_repo` (gitops repo name or owner/repo)

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
- `infisical_restore_from_s3` (`true` to restore from S3 before bootstrap)
- `infisical_bootstrap_secrets` (JSON payload for Infisical bootstrap secrets)

## 4.1) Service FQDNs & DNS (Cloudflare)
- `bastion_fqdn`
- `argocd_fqdn`
- `grafana_fqdn`
- `loki_fqdn`
- `infisical_fqdn`
- `db_fqdn`
- `internal_services_domains_json`
- `deployed_apps_json`
- `cloudflare_api_token`

## 5) Object Storage / S3
- `s3_access_key_id`
- `s3_secret_access_key`
- `infra_state_bucket`
- `db_backup_bucket`
- `app_private_bucket`
- `app_public_bucket`
- `s3_region` (optional; falls back to `cloud_region`, then `us-east-1`)

## 6) Application Database
- `app_db_name`
- `app_db_user`
- `app_db_password`

## 7) DB Backup Age Keys
- `db_backup_age_public_key`
- `db_backup_age_private_key`

## 8) Admin Access (Multi-user)
- `OPS_SSH_KEYS_JSON` (map username -> list of SSH public keys)
- `WG_ADMIN_PEERS_JSON` (map username -> `{ publicKey, ip }`)
- `WG_PRESHARED_KEYS_JSON` (map username -> preshared key)

Global WireGuard settings:
- `wg_listen_port`
- `wg_server_address`
- `wg_server_private_key`
- `wg_server_public_key`

## 9) WireGuard Config Download
- `wg_server_endpoint`

## 10) Debug / Break-glass access (optional)
- `DEBUG_ROOT_PASSWORD` (enables root password auth; bastion SSH opened to `0.0.0.0/0` while set; stored in cloud-init user data)
