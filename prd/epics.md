# Epics

## EPIC-1: Core infra template + automation (topology build)
Goal: Deliver the universal repo template, OpenTofu stack, CI workflows, and bootstrap delivery system.

Definition of done:
- A fresh clone requires only config/infra.yaml edits.
- build.yml creates the full topology (bastion, egress, node1, node2, db, LB, firewalls, volume).
- Bootstraps are uploaded to S3, presigned URLs + SHA256 are injected into cloud-init.

## EPIC-2: Egress bootstrap (logging + NAT + Infisical)
Goal: Make egress the first fully-bootstrapped role and the logging/egress/Infisical hub.

Must include (order-sensitive):
- Hardening baseline (users, SSH, auditd, journald, DNS fallback).
- Grafana + Loki first; all other roles forward logs here.
- NAT/egress setup with persistence.
- Self-hosted Infisical with local Postgres; UI served over HTTPS on the Infisical service FQDN using Let's Encrypt (Cloudflare DNS-01).
- Grafana and Loki exposed via service FQDNs with valid HTTPS certificates.
- Infisical DB backups to S3; restore from latest-dump manifest only when GitHub secret `infisical_restore_from_s3` is `true`.
- Infisical bootstrap runs on egress after restore checks, stores the admin token manifest in S3.
- Admin access path to Infisical UI (port forwarding or restricted ingress).
- Age private key is short-lived and deleted after restore or if no dump exists.

Appendix:
- `prd/epic4-appendix-infisical-bootstrap.md`

## EPIC-3: Bastion bootstrap
Goal: Secure admin ingress with hardened access and logging to egress.

Definition of done:
- Hardening baseline.
- WireGuard or restricted SSH configured.
- SSH bound to WG and default-deny public SSH.
- Logs forwarded to egress.

## EPIC-4: Node1 bootstrap (k3s server + Argo CD)
Goal: Stand up the k3s server and Argo CD from config-only repo inputs.

Definition of done:
- Hardening baseline.
- k3s server installed and NodePorts 30080/30443 ready.
- Argo CD bootstrapped using repo URLs/paths from config.
- Infisical admin token secret synced from S3 into `kube-system`.
- Logs forwarded to egress.

## EPIC-5: Node2 bootstrap (k3s agent)
Goal: Join node2 to the cluster with hardened baseline and logging.

Definition of done:
- Hardening baseline.
- k3s agent joins node1.
- Logs forwarded to egress.

## EPIC-6: DB bootstrap (PostgreSQL + backups)
Goal: Provide a durable DB setup with backup/restore and volume persistence.

Definition of done:
- Hardening baseline.
- DB volume mounted without reformatting if it already exists.
- Postgres configured with private allowlist (all k3s nodes; count is 1+).
- Backups via cron to S3 (uses S3 creds, backup bucket, Age public key, DB creds).
- Restore via latest-dump manifest; Age private key is short-lived and deleted after restore or if no dump exists.
- Secrets stored securely on the server (root-only).

Inputs:
- `db_type` (currently `postgresql`).
- `db_version` (currently `14.20`).
