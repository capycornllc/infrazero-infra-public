# infrazero-infra-public - Repository Description

## Purpose
`infrazero-infra-public` is the infrastructure engine. It renders runtime config from secrets, provisions Hetzner resources via OpenTofu, and bootstraps all nodes (bastion, egress, k3s, db) with platform services such as WireGuard, Loki/Grafana, Infisical, and PostgreSQL operations.

## What This Repo Owns
- Infrastructure lifecycle workflows:
  - full build (`build.yml`)
  - targeted node rebuilds (bastion/egress/db/nodes)
- Runtime config rendering and validation from environment variables/GitHub secrets.
- Cloud-init templating and node bootstrap script packaging.
- OpenTofu topology creation (servers, load balancers, network/firewall, persistent DB volume).
- Operational scripts for backups/restores and post-bootstrap automation.

## Pipeline Overview
1. GitHub Actions loads many `secrets.*` values into workflow environment.
2. `scripts/render-config.py` validates/parses inputs and creates `tofu/tofu.tfvars.json`.
3. Bootstrap artifacts are packaged and uploaded to S3, then referenced by presigned URLs.
4. OpenTofu creates/rebuilds resources and injects cloud-init user-data.
5. On each VM, `run.sh` executes role scripts:
  - `common.sh` + role-specific script (`bastion.sh`, `egress.sh`, `node1.sh`, `nodecp.sh`, `node2.sh`, `db.sh`).

## Secret Handling Model (Current)
- Primary source at runtime: GitHub Actions secrets in infra repo.
- `render-config.py` maps secrets into role-specific secret dictionaries:
  - `egress_secrets`
  - `bastion_secrets`
  - `db_secrets`
  - `k3s_secrets`
  - `k3s_server_secrets`
  - `k3s_agent_secrets`
- Cloud-init template writes secrets to:
  - exported env vars in `/opt/infrazero/bootstrap/run.sh`
  - role env files under `/etc/infrazero/*.env`
- Bootstrap scripts consume those env files and pass selected values onward to:
  - S3 backup manifests/artifacts
  - Kubernetes secrets
  - Infisical API bootstrap routines

## Platform Components Bootstrapped Here
- Bastion:
  - WireGuard server setup
  - SSH hardening / admin keys
  - Promtail -> Loki
- Egress:
  - Loki + Grafana containers
  - NGINX/Haproxy edge routing
  - Infisical + Redis + Postgres (compose)
  - Infisical backup/restore to S3
- k3s nodes:
  - k3s control plane/agent setup
  - ArgoCD bootstrap and repo auth secret
  - Infisical admin token sync into cluster
  - Promtail -> Loki
- DB:
  - PostgreSQL install/config
  - Multi-database bootstrap
  - backup/restore automation with Age encryption

## Key Files
- `.github/workflows/*.yml`: workflow entry points.
- `scripts/render-config.py`: environment/secret normalization and tfvars generation.
- `tofu/templates/cloud-init.tftpl`: cloud-init with secret/env injection.
- `bootstrap/*.sh`: role bootstrap + operational scripts.

## Current Risks / Constraints
- Very high number of GitHub secrets loaded into workflow env.
- Secret duplication across multiple layers (workflow env, tfvars, cloud-init, VM env files, Kubernetes secrets).
- Long-lived credentials (GitHub PAT, S3 keys, bootstrap tokens) exposed to multiple execution contexts.
- GitHub secret size limits for large JSON payloads (partially mitigated only for Infisical bootstrap payload compression).
- No native real-time stream from bootstrap logs to UI even though Loki/Promtail exists.
