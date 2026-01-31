# Stories

## EPIC-1: Core infra template + automation
- As a platform engineer, I can deploy a full topology by editing only config/infra.yaml and running build.yml.
  - Acceptance: build.yml completes and all five servers + LB + network + firewalls + DB volume exist.
- As a platform engineer, I can rebuild the stack while preserving the DB volume.
  - Acceptance: build.yml destroys and recreates all resources except the DB volume; volume remains attached after apply.
- As a platform engineer, I can publish bootstrap artifacts to S3 and inject presigned URLs + SHA256 into cloud-init.
  - Acceptance: cloud-init downloads, verifies SHA256, decompresses, and runs the role script.
- As a platform engineer, I can set server types and k3s node count via GitHub secrets (no config edits).
  - Acceptance: secrets override server types; OpenTofu creates the requested k3s node count using the provided node type.
- As a platform engineer, I can provide internal service FQDNs and app FQDNs via secrets and have Cloudflare DNS records created/updated automatically.
  - Acceptance: internal service FQDNs (bastion/grafana/loki/infisical/db) resolve to private IPs; deployed app FQDNs resolve to the LB public IP; DNS changes are idempotent.
- As a platform engineer, I can pass structured JSON secrets for internal services and deployed apps without leaking them in logs.
  - Acceptance: JSON is validated for shape; malformed JSON fails fast; secrets are not echoed in workflow logs.

## EPIC-2: Egress bootstrap
- As an operator, I get Grafana + Loki installed before any other services so logs can be forwarded immediately.
  - Acceptance: Loki endpoint is reachable from other private nodes and logs are ingested.
- As an operator, I get NAT/egress configured for private nodes.
  - Acceptance: node1/node2/db can reach the internet through egress.
- As an operator, I get a self-hosted Infisical with local Postgres on egress.
  - Acceptance: Infisical service is healthy and UI is accessible via the approved access path.
- As an operator, I get Infisical DB backups and auto-restore using latest-dump manifest.
  - Acceptance: on boot, restore uses latest manifest if present; Age private key is deleted after restore or if no dump exists.
- As an operator, egress can obtain and renew Let's Encrypt certificates for internal service FQDNs via Cloudflare DNS-01.
  - Acceptance: valid certs are issued for infisical/grafana/loki FQDNs using the Cloudflare token with no manual steps.
- As an operator, Infisical, Grafana, and Loki are reachable over HTTPS via their FQDNs.
  - Acceptance: accessing the service FQDNs shows valid TLS with no browser warnings from trusted internal clients.

## EPIC-3: Bastion bootstrap
- As an operator, I have hardened bastion access with WireGuard (or restricted SSH) only.
  - Acceptance: public SSH is blocked; access works via WG or approved CIDRs.
- As an operator, bastion logs are forwarded to egress.
  - Acceptance: bastion logs appear in Loki.

## EPIC-4: Node1 bootstrap
- As an operator, node1 installs k3s server and exposes NodePorts 30080/30443 for LB forwarding.
  - Acceptance: k3s server is Ready and NodePorts are open internally.
- As an operator, Argo CD bootstraps using repo from GitHub secrets (gh_gitops_repo) and path from config/infra.yaml.
  - Acceptance: Argo CD is installed and syncs the configured root app.
- As an operator, Argo CD UI is reachable via argocd_fqdn with valid TLS.
  - Acceptance: argocd_fqdn serves Argo CD over HTTPS with Let's Encrypt certs.
- As an operator, node1 bootstraps Infisical when no restore is requested.
  - Acceptance: admin + read-only tokens are generated, stored encrypted in S3, and referenced in latest-dump manifest.
- As an operator, node1 logs are forwarded to egress.
  - Acceptance: node1 logs appear in Loki.

## EPIC-5: Node2 bootstrap
- As an operator, node2 joins the k3s cluster as an agent.
  - Acceptance: node2 appears in k3s node list and is Ready.
- As an operator, node2 logs are forwarded to egress.
  - Acceptance: node2 logs appear in Loki.

## EPIC-6: DB bootstrap
- As an operator, the DB volume is mounted without reformatting if it already exists.
  - Acceptance: existing data is preserved and mounted at the correct path.
- As an operator, Postgres is configured with private access only from node1/node2.
  - Acceptance: pg_hba allows only node1/node2; public access is denied.
- As an operator, DB backups run via cron to S3 using Age encryption.
  - Acceptance: backups appear in the bucket and a latest-dump manifest is updated.
- As an operator, DB restore uses the latest-dump manifest and deletes Age private keys after use.
  - Acceptance: restore succeeds if a dump exists; keys are removed after restore or if no dump exists.
