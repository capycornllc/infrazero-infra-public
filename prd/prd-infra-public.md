# PRD: infra-public (template for automated infra repos)

## 1) Summary
Build a reusable infrastructure repository template (Hetzner Cloud + OpenTofu) that supports fully automated, GitHub Actions-driven deployments. The repo must be universal: the only required customization for a new app/environment is editing a single config file. All secrets are provided via GitHub Actions secrets.

This PRD is adapted for:
- Separate **bastion** and **egress** servers (egress also hosts Infisical/Log services).
- **Bootstrap scripts** stored in a repo `bootstrap/` folder, uploaded to S3 in GitHub Actions, and executed via minimal cloud-init using pre-signed URLs and SHA256 verification.
- **OpenTofu** (not Terraform).

## 2) Goals
1) Provide a **template** infra repo that can be cloned for any future deployment with **config-only changes**.
2) Support **fully automated** provisioning via GitHub Actions (no manual local runs).
3) Preserve DB data across rebuilds (DB volume is never destroyed).
4) Achieve **secure-by-default** networking: private nodes, bastion-only admin access, default-deny firewalls.
5) Support **deterministic bootstrap** from S3 with integrity verification (SHA256).

## 3) Non-goals
- Implementing application-level GitOps workflows or app manifests.
- Designing the Infisical/logging stack itself (egress server will host it later).
- Supporting cloud providers other than Hetzner Cloud in v1.

## 4) Constraints and assumptions
- **OpenTofu** is required (tofu CLI).
- All infrastructure actions run from **GitHub Actions**.
- **No Infisical connection** for infra operations. All secrets come from GitHub Secrets.
- **Single config file** is the only user-editable input for new deployments.
- State and bootstrap artifacts are stored in **S3-compatible object storage** (Hetzner Object Storage or equivalent).

## 5) Users and stakeholders
- Platform/infra engineers who run the GitHub Actions workflows.
- Application teams who clone this repo and only edit the config file.

## 6) Architecture overview

### 6.1 Servers
Five fixed servers (naming prefix from config):
1) **bastion**
   - Admin ingress (WireGuard or restricted SSH).
   - Public IPv4 enabled.
2) **egress**
   - NAT/egress gateway for private nodes.
   - Hosts Infisical/Log services (future, not used for infra secrets).
   - Public IPv4 enabled.
3) **node1**
   - k3s server + worker (public entrypoint via load balancer).
   - Private only.
4) **node2**
   - k3s agent.
   - Private only.
5) **db**
   - PostgreSQL primary.
   - Private only.
   - Attached persistent volume.

### 6.2 Network and subnet
- Single private network and subnet (CIDR from config).
- Fixed private IPs (configurable, but deterministic) for auditability.
- Default route for private nodes (node1, node2, db) goes through **egress**.
- Subnet and network zone are configurable.

### 6.3 Load balancer (public entrypoint)
- Dedicated public LB attached to the private network.
- **Port forwarding**:
  - 80 -> node1 private IP: **30080**
  - 443 -> node1 private IP: **30443**
- Health checks on node1.
- Firewall rules allow LB private IP to access node1 NodePorts.

### 6.4 DB volume
- Persistent volume attached to db server.
- **Must not be destroyed** during `destroy` or rebuilds.
- **Created only if not exist**:
  - If a volume with the configured name exists, use it.
  - Otherwise, create a new volume.
- Automount disabled; volume is mounted by bootstrap script.

### 6.5 Placement groups
- Placement groups (type `spread`) for bastion, egress, nodes, db.
- Configurable and optional (enabled by default).

### 6.6 Firewalls (default deny)
Rules based on the current repo, adapted to new roles:
- **bastion**
  - Allow WireGuard UDP from `wireguard_allowed_cidrs` (or allow SSH from admin CIDRs if WG is not used).
  - No other public ingress.
- **egress**
  - Allow private network to reach egress for NAT (TCP/UDP/ICMP from private CIDR).
  - Allow SSH only via WireGuard/bastion network.
- **node1**
  - Allow LB private IP -> TCP 30080/30443.
  - Allow SSH only via WireGuard network.
  - Allow k3s API (6443) only from WireGuard + node2.
  - Allow k3s supervisor (9345), flannel (UDP 8472), kubelet (10250) from node2.
- **node2**
  - Allow SSH only via WireGuard network.
  - Allow flannel/kubelet from node1.
- **db**
  - Allow SSH only via WireGuard network.
  - Allow Postgres (5432) only from node1/node2.

## 7) Bootstrap strategy

### 7.1 Bootstrap scripts in repo
`/bootstrap/` will contain role scripts derived from the current `cloud-init/*.tftpl` logic:
- `bootstrap/common.sh` (shared hardening and base setup)
  - SSH hardening, users, auditd, journald persistence, DNS fallback.
  - Network readiness, egress checks, base packages.
- `bootstrap/bastion.sh`
  - WireGuard setup, SSH binding to wg0, strict iptables/iptables rules.
- `bootstrap/egress.sh`
  - NAT/egress iptables setup + systemd service.
  - Optional: placeholders to install Infisical/logging agents.
- `bootstrap/node1.sh`
  - k3s server install, NodePort ingress readiness.
  - Argo CD + GHCR bootstrap (if needed in this template).
- `bootstrap/node2.sh`
  - k3s agent join.
- `bootstrap/db.sh`
  - Mount DB volume, install PostgreSQL, configure pg_hba, backup/restore scripts.

These scripts should be **direct ports** of the long cloud-init files in this repo, split into reusable, testable bash scripts.

### 7.2 Packaging and delivery
In GitHub Actions:
1) Create compressed artifacts per role (e.g., `bootstrap/node1.tar.zst`).
2) Compute `sha256` for each artifact.
3) Upload artifacts to the S3 bucket from the GitHub secret `infra_state_bucket` under `bootstrap/`,
   using `s3_access_key_id` and `s3_secret_access_key` for credentials.
4) Generate **pre-signed URLs** for each artifact.
5) Pass URL + sha256 into OpenTofu as variables, injected into cloud-init templates.

Cloud-init on each server:
- Downloads its role artifact from the pre-signed URL.
- Verifies SHA256 checksum.
- Decompresses.
- Executes the role bootstrap script.
- Logs outcome and exits cleanly on partial failures (best effort).

## 8) Single config file (universal template requirement)
All customization must be in **one file** only (no other edits required).

Proposed file: `config/infra.yaml` (example)

Must include:
- Naming/prefix: `project`, `environment`, `name_prefix`.
- Region/location, network zone, CIDR.
- Server types for bastion/egress/node/db.
- Explicit private IP allocations (or deterministic offsets).
- LB type, LB private IP, forwarding ports (80->30080, 443->30443).
- Placement group toggle/type.
- DB volume name + size.
- S3 backend settings (endpoint, region, state prefix, bucket name from `infra_state_bucket`).
- WireGuard settings (if used).
- K3s settings (join token generation, node roles).
- Any feature toggles.

The repo must include:
- Schema/validation for config (JSON schema or strict validation script).
- A small render step in GitHub Actions that converts the config into OpenTofu variables (`tofu.tfvars.json`).

## 9) GitHub Actions workflows

### 9.1 Required workflows
1) **build.yml** (main build)
   - Upload bootstraps to S3, generate presigned URLs and sha256.
   - `tofu init`
   - `tofu destroy` of all resources **except DB volume**.
   - `tofu apply` to recreate all servers + network + LB.

2) **rebuild-bastion.yml**
   - Replace only bastion server (targeted destroy/apply or `-replace`).

3) **rebuild-egress.yml**
   - Replace only egress server.

4) **rebuild-db.yml**
   - Replace only db server (volume preserved).

5) **rebuild-nodes.yml**
   - Replace node1 and node2 (either together or separate workflows).

Optional:
- `plan.yml`, `apply.yml`, `destroy.yml` if manual ops are desired.

### 9.2 Secrets required (GitHub Actions)
All secrets are stored as GitHub secrets (no Infisical):
- `hcloud_token`
- `s3_access_key_id`
- `s3_secret_access_key`
- `infra_state_bucket` (bucket name)
- `s3_endpoint`
- `s3_region`
- `ops_ssh_keys_json`
- `bastion_server_type`
- `egress_server_type`
- `db_server_type`
- `k3s_node_server_type`
- `k3s_node_count`
- WireGuard keys and peer JSON (if using WG)
- Service FQDNs (`bastion_fqdn`, `grafana_fqdn`, `loki_fqdn`, `infisical_fqdn`, `db_fqdn`) or `internal_services_domains_json`
- `deployed_apps_json`
- `cloudflare_api_token` (DNS + ACME via DNS-01)
- GitHub App + GHCR secrets (if Argo/GitOps is used)

## 10) OpenTofu module structure
Structure mirrors current repo, updated for new roles and OpenTofu:
- `tofu/` (main stack)
- `tofu/stacks/public-lb/` (optional persistent LB stack if we want to preserve LB IPs)
- `bootstrap/` (role scripts)
- `config/infra.yaml`

Core resources:
- Network + subnet.
- Servers (bastion, egress, node1, node2, db).
- Firewalls per role.
- Placement groups.
- LB + services (80->30080, 443->30443).
- DB volume (conditional create + prevent_destroy) + attachment.

## 11) Security requirements
- No public SSH on any node except via bastion/WireGuard.
- Private nodes have **no public IP**.
- Default deny firewalls; explicit allow rules only.
- Secrets are never committed to git.
- Bootstrap scripts scrub user-data or temporary secrets when possible.

## 12) Acceptance criteria
1) A new deployment can be created by:
   - Cloning the repo
   - Editing **only** `config/infra.yaml`
   - Running the GitHub Actions `build.yml`
2) DB volume persists across rebuilds and is reattached automatically.
3) Load balancer forwards 80/443 to node1 30080/30443 and passes health checks.
4) Private nodes have egress through egress NAT.
5) SSH access is only possible via bastion/WireGuard, not public IPs.
6) Bootstrap scripts download, verify, decompress, and execute successfully.

## 13) Open questions
- Do we want a separate persistent public LB stack (as in current repo), or should LB be recreated on each build?
- Should bastion use WireGuard (as current repo) or direct SSH with CIDR allowlist?
- Should Argo CD/GitOps bootstrap remain part of node1 bootstrap, or be optional?

## 14) Epics

### Epic 1: Core infra template + automation (topology build)
**Goal:** Deliver the universal repo template, OpenTofu stack, CI workflows, and bootstrap delivery system.
**Scope:**
- Single config file (`config/infra.yaml`) + validation + render to `tofu.tfvars.json`.
- OpenTofu stacks: network, subnet, firewalls, placement groups, servers, LB, and DB volume.
- CI workflows: build (destroy+apply) and per-role rebuilds.
- Bootstrap artifacts: pack, upload to S3 (`infra_state_bucket`), presigned URL + SHA256 injected into cloud-init.
**Definition of done:** Running `build.yml` creates the full topology (bastion, egress, node1, node2, db, LB, firewalls, volume) from config-only changes.

### Epic 2: Egress bootstrap (logging + NAT + Infisical)
**Goal:** Make egress the first fully-bootstrapped role; it becomes the log/egress/Infisical hub.
**Must include (order-sensitive):**
1) **Hardening baseline** (users, SSH, auditd, journald persistence, DNS fallback).
2) **Grafana + Loki first** (all other bootstraps must forward logs here).
3) **NAT/egress setup** + systemd service for persistence.
4) **Self-hosted Infisical** with **local PostgreSQL** on egress, served over HTTPS on the Infisical service FQDN using Let's Encrypt (Cloudflare DNS-01).
5) **Grafana + Loki** exposed via service FQDNs with valid HTTPS certificates.
6) **Infisical DB backups** to S3; **restore** latest dump at boot only when GitHub secret `infisical_restore_from_s3` is `true`.
7) **Infisical bootstrap** runs on egress after restore checks and writes the admin token manifest to S3.
8) **Port forwarding / access path** to Infisical UI (admin access via bastion/WG or restricted public ingress).
**Notes:**
- Use a **latest-dump manifest** pattern (as in current repo) for Infisical DB restore.
- **Age private keys are short-lived**: store only in tmpfs, delete after successful restore or if no dump found.

### Epic 3: Bastion bootstrap
**Goal:** Secure admin ingress with hardened access and logging to egress.
**Scope:**
- Hardening baseline (same standard as all roles).
- WireGuard (or restricted SSH) setup.
- SSH bound to WG interface; default deny on public SSH.
- Log forwarding to egress Grafana/Loki.

### Epic 4: Node1 bootstrap (k3s server + Argo CD)
**Goal:** Stand up k3s server and Argo CD from config-only repos.
**Scope:**
- Hardening baseline.
- k3s server install and NodePort readiness (30080/30443).
- Argo CD bootstrap using repo URLs and paths from config file.
- Log forwarding to egress Grafana/Loki.

### Epic 5: Node2 bootstrap (k3s agent)
**Goal:** Join node2 to the cluster with hardened baseline and logging.
**Scope:**
- Hardening baseline.
- k3s agent join to node1.
- Log forwarding to egress Grafana/Loki.

### Epic 6: DB bootstrap (PostgreSQL + backups)
**Goal:** Provide a durable, secure DB setup with backup/restore and volume persistence.
**Scope:**
- Hardening baseline.
- Mount persistent volume (do not reformat if existing).
- Install PostgreSQL, apply pg_hba allowlist for node1/node2.
- **DB backups via cron** to S3 using:
  - S3 creds + backup bucket
  - Age public key
  - DB creds
  - Latest-dump manifest for restore.
- **Restore flow** uses latest-dump manifest; Age private key stored only briefly and deleted after restore or if no dump found.
- Secrets stored securely on server (root-only, minimal exposure).
