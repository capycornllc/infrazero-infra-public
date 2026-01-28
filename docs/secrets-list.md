# Secrets & Inputs (Epic 1)

This list reflects the Epic-1 web UI inputs and generated values that will be stored as GitHub Actions secrets for infra repos. Some entries are not sensitive but are still stored as secrets for consistent automation.

## 1) Project Basics
- `project_slug`
- `cloud_region` (e.g. `nbg1`, `fsn1`, `hel1`, `ash`, `hil`, `sin`)
- `s3_endpoint` (include scheme; workflows will prepend `https://` if missing)

## 2) GitHub Access
- `github_username`
- `github_infra_repo`
- `github_gitops_repo`
- `github_infra_recreate`
- `github_gitops_recreate`
- `github_token`

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

## 5) Object Storage / S3
- `s3_access_key_id`
- `s3_secret_access_key`
- `infra_state_bucket`
- `db_backup_bucket`
- `app_private_bucket`
- `app_public_bucket`
- `s3_region`

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
