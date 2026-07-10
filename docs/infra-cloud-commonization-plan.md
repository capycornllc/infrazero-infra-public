# Infrazero infra cloud commonization audit plan

Status: staged implementation in progress. This document records the architecture target and the current migration checkpoint.

Goal: make the infra repository scalable to many cloud providers by moving only truly cloud-independent logic into common scripts, while keeping provider-specific behavior in small provider adapters. The current Hetzner implementation should be treated as the strongest baseline where it has newer reliability fixes, but OVH also contains real improvements that should be merged into the shared model when they are not OpenStack-specific.

## Scope

Repository audited:

- `infrazero-infra-public`

Primary comparison axes:

- `bootstrap/hetzner/*` vs `bootstrap/ovh/*`
- `tofu/hetzner/*` vs `tofu/ovh/*`
- `scripts/hetzner/*` vs `scripts/ovh/*`
- `.github/workflows/*`
- existing common helpers under `scripts/common/*` and `bootstrap/common/*`

Important constraint:

- Do not move provider-specific cloud mechanics into common code.
- Do not break the S3 bootstrap artifact contract. Servers currently download role archives from object storage and expect the extracted role script plus helper files under `/opt/infrazero/bootstrap/`.
- Do not copy all provider code into a user repo when the user selected only one cloud. Future architecture should package only selected provider adapters plus shared common code.

## Initial high-level similarity

The original bootstrap code was heavily duplicated. Similarity below is the pre-extraction audit baseline based on line-level LCS comparison of paired Hetzner/OVH files.

| Area | Hetzner lines | OVH lines | Similarity | Initial conclusion |
| --- | ---: | ---: | ---: | --- |
| `bootstrap/db.sh` | 2759 | 2771 | 0.959 | Almost entirely common DB role with small provider/drift sections |
| `bootstrap/infisical-bootstrap.sh` | 997 | 1009 | 0.992 | Should become one common role script |
| `bootstrap/infisical-admin-secret.sh` | 1252 | 1339 | 0.953 | Should become one common role script plus unified best fixes |
| `bootstrap/egress.sh` | 1668 | 1621 | 0.924 | Common service bootstrap plus provider network adapter |
| `bootstrap/pgbouncer.sh` | 368 | 388 | 0.923 | Should become one common role script |
| `bootstrap/db-replica.sh` | 600 | 567 | 0.908 | Should become one common role script |
| `bootstrap/nodecp.sh` | 387 | 416 | 0.889 | Mostly common K3s control-plane join logic |
| `bootstrap/node2.sh` | 249 | 224 | 0.884 | Mostly common K3s agent join logic |
| `bootstrap/bastion.sh` | 616 | 525 | 0.861 | Common bastion role plus provider route mode |
| `bootstrap/node1.sh` | 847 | 844 | 0.775 | Common K3s primary plus drift in Argo/etcd/apt behavior |
| `bootstrap/common.sh` | 660 | 602 | 0.739 | Must be split into true common baseline plus provider network helpers |
| `bootstrap/beacon.sh` | 132 | 27 | 0.214 | Hetzner has newer common beacon implementation; OVH is stale |
| `tofu/cloud-init.tf` | 215 | 214 | 0.974 | Common rendering pattern with provider env differences |
| `tofu/locals.tf` | 92 | 88 | 0.956 | Mostly common naming/topology locals, provider-specific resource IDs |
| `tofu/templates/cloud-init.tftpl` | 366 | 255 | 0.818 | Common artifact fetch/run path plus provider boot route differences |
| `tofu/main.tf` | 777 | 944 | 0.237 | Mostly provider-specific resources; do not force into one file |

## Target architecture

Recommended final shape:

```text
bootstrap/
  common/
    lib/
      logging.sh
      beacon.sh
      apt.sh
      aws-cli.sh
      env.sh
      network-detect.sh
      systemd.sh
      ssh-hardening.sh
      routes.sh
      iptables.sh
      docker.sh
      nginx-tls.sh
      promtail.sh
      postgres.sh
      db-volume.sh
      db-backup-restore.sh
      patroni.sh
      pgbouncer.sh
      k3s.sh
      etcd-patroni.sh
      infisical.sh
      gitops.sh
    roles/
      common.sh
      bastion.sh
      egress.sh
      db.sh
      db-replica.sh
      pgbouncer.sh
      node1.sh
      nodecp.sh
      node2.sh
      infisical-bootstrap.sh
      infisical-admin-secret.sh
  providers/
    hetzner/
      adapter.sh
      network.sh
      volume.sh
      cloud-init-route.sh
    ovh/
      adapter.sh
      network.sh
      volume.sh
      cloud-init-route.sh
    aws/
      adapter.sh
      network.sh
      volume.sh
      cloud-init-route.sh
```

Rules for this architecture:

- Role scripts should call common library functions and provider adapter functions.
- Provider adapters should not contain service setup such as PostgreSQL, Patroni, K3s, Infisical, Grafana, Loki, ArgoCD, TLS, GitOps, Promtail.
- Common code should not reference `hcloud`, `openstack`, OVH project IDs, Hetzner MAC prefixes, floating IP resource names, or provider-specific Terraform resource addresses.
- Provider adapters may expose normalized variables/functions such as `provider_detect_private_interface`, `provider_find_db_volume_device`, `provider_should_use_bastion_egress_policy`, `provider_configure_private_nic`, `provider_private_route_gateway`.

## Bootstrap packaging model

Current model:

- Workflows choose `BOOTSTRAP_DIR=bootstrap/hetzner` or `bootstrap/ovh`.
- Each role archive is built as:
  - `common.sh`
  - `beacon.sh`
  - `${role}.sh`
  - role extras such as `infisical-bootstrap.sh`, `infisical-admin-secret.sh`, currently `db-patroni.sh` for DB roles.
- Archive is uploaded to `s3://$INFRA_STATE_BUCKET/bootstrap/${role}.tar.zst`.
- Cloud-init downloads the selected role archive from a presigned URL, verifies SHA, extracts it, then runs `common.sh` and `${ROLE}.sh`.

Problem:

- Because provider directories contain entire role scripts, every cloud duplicates almost the whole bootstrap implementation.
- Adding AWS today would likely require copying all roles again, which repeats bugs and causes drift.

Target packaging:

- Keep role archives per role, but include:
  - `common/lib/*.sh`
  - `common/roles/${role}.sh`
  - `providers/${cloud}/adapter.sh`
  - `providers/${cloud}/network.sh`
  - `providers/${cloud}/volume.sh` when needed
- The archive should not include other providers.
- Cloud-init should set `INFRAZERO_CLOUD_PROVIDER=hetzner|ovh|aws` and source only that provider adapter.
- Preserve the existing S3 key shape at first: `bootstrap/${role}.tar.zst`, to avoid breaking server lookup paths.

## Current implementation checkpoint

Implemented in the current staged migration:

- Added `scripts/common/package-bootstrap.sh`.
  - Workflows now call one packaging implementation for Hetzner and OVH.
  - The S3 object key is still unchanged: `bootstrap/${role}.tar.zst`.
  - Role archives include only role-needed common helpers, not every common file.
- Added common bootstrap helpers:
  - `bootstrap/common/common-base.sh`
    - currently owns shared parameterized `infrazero_apt_get`, base package install flow, outbound-connectivity wait helper, network diagnostics, admin user creation, SSH hardening, network baseline sysctls/IPv6 disable, `network.env` writing, systemd timer generation, and base system hardening.
  - `bootstrap/common/common-beacon.sh`
  - `bootstrap/common/common-infisical-bootstrap.sh`
  - `bootstrap/common/common-infisical-admin-secret.sh`
  - `bootstrap/common/common-egress.sh`
  - `bootstrap/common/common-pgbouncer.sh`
  - `bootstrap/common/common-node1.sh`
  - `bootstrap/common/common-nodecp.sh`
  - `bootstrap/common/common-node-agent.sh`
  - `bootstrap/common/common-db-replica.sh`
  - `bootstrap/common/db-patroni.sh`
- Converted provider role files to thin wrappers where the role is now common:
  - `bootstrap/{hetzner,ovh}/beacon.sh`
  - `bootstrap/{hetzner,ovh}/infisical-bootstrap.sh`
  - `bootstrap/{hetzner,ovh}/infisical-admin-secret.sh`
  - `bootstrap/{hetzner,ovh}/pgbouncer.sh`
  - `bootstrap/{hetzner,ovh}/node1.sh`
  - `bootstrap/{hetzner,ovh}/nodecp.sh`
  - `bootstrap/{hetzner,ovh}/node2.sh`
  - `bootstrap/{hetzner,ovh}/db-replica.sh`
- Kept primary `bootstrap/{hetzner,ovh}/db.sh` provider-specific for now.
  - Reason: it still contains provider-sensitive volume discovery and attach timing.
  - Shared `db-patroni.sh` is packaged into both primary and replica DB roles.
  - Hetzner and OVH primary DB scripts now source `common-base.sh` and use shared `infrazero_ensure_aws_cli`.
    - The DB-local `apt_get` wrapper now delegates to `infrazero_apt_get` with 12 attempts, preserving DB's stricter apt behavior.
    - Volume device discovery and attach timing remain provider-specific.
  - OVH primary DB was aligned with Hetzner HA safeguards: no conflicting `setup_replication_primary` when Patroni is enabled, replication password sync before Patroni takeover, `wait-etcd.sh`, basebackup replica method, and Patroni service timeouts.
  - Hetzner primary DB received portable OVH improvements: log redirect, lock-aware `apt_get`, PgBouncer auth role setup, `wal_log_hints`, and Patroni rewind/diverged timeline recovery options.
- Kept `bootstrap/{hetzner,ovh}/egress.sh` provider-specific for now, but aligned safe non-cloud drift:
  - Hetzner received OVH's lock-aware `apt_get` wrapper and standalone `beacon_status` fallback.
  - Hetzner and OVH egress scripts now source `common-base.sh` and use shared `infrazero_ensure_aws_cli`.
    - The local egress `apt_get` wrapper now delegates to `infrazero_apt_get` with 10 attempts, preserving egress' apt behavior.
  - Hetzner and OVH egress scripts now source `common-egress.sh` for cloud-neutral egress service helpers:
    - offloaded bootstrap env download from presigned URL/S3 into `/etc/infrazero/egress.bootstrap.env`
    - early and persistent IP forwarding sysctl setup
    - egress package installation
    - Docker daemon enable/wait
    - DNS fallback configuration
    - Docker Compose command selection
    - egress Docker Promtail config/service
    - generic private-subnet NAT rules after provider-specific interface detection
    - K3s API firewall cleanup for stale local INPUT rules
    - iptables save/restore systemd service
    - Infisical restore from encrypted S3 dump plus bootstrap private-key scrubbing
    - Infisical env/compose generation and startup retry/wait flow
    - HAProxy TCP proxy for Kubernetes API
    - nginx HTTPS server blocks, certbot retry service, broken lineage cleanup, Let's Encrypt issuance, and self-signed fallback
  - OVH received Hetzner's early IP forwarding before Docker, Docker daemon readiness wait, Loki compose retry loop, and Docker-aware `iptables-restore --noflush` service.
  - Hetzner-only private NIC detection by MAC prefix `86:00:00` and `EGRESS_PRIVATE_IP` self-configuration were not moved to OVH.
  - OVH-only Floating IP single-interface behavior was not moved to Hetzner.
  - OVH-only Infisical `ALLOW_INTERNAL_IP_CONNECTIONS=true` and `extra_hosts` for `KUBERNETES_FQDN` remain explicit OVH flags (`INFISICAL_ALLOW_INTERNAL_IP_CONNECTIONS`, `INFISICAL_KUBERNETES_EXTRA_HOSTS`) instead of becoming silent defaults for future clouds.
- `bootstrap/{hetzner,ovh}/common.sh` now calls common helpers for:
  - admin user creation from `ADMIN_USERS_JSON_B64`
  - base package install (`curl`, `ca-certificates`, `zstd`, `jq`, `e2fsprogs`, `auditd`, `unattended-upgrades`)
    - Hetzner keeps `mirror.hetzner.com`, `300 x 5s`, retry beacon cadence, degraded beacon, and network diagnostics on timeout.
    - OVH keeps public IPv4 autodetect through `connectivity-check.ubuntu.com` and `90 x 2s` wait.
  - network baseline: `rp_filter=0`, IPv6 disable, IPv6 default-route cleanup
  - `/etc/infrazero/network.env` writing with `PRIVATE_CIDR`, `WG_CIDR`, and `BASTION_PRIVATE_IP`
  - route repair timer generation through `infrazero_install_systemd_timer`
    - Hetzner keeps the same private-route and WireGuard-route timer cadence as before.
    - OVH now uses the same periodic route repair pattern for private route and WireGuard route repair.
    - OVH route services no longer use `RemainAfterExit=yes`, because a timer cannot reliably re-run an already-active oneshot service.
  - bastion journald Promtail setup through `infrazero_install_journald_promtail`
    - Both Hetzner and OVH bastion scripts now source `common-base.sh` directly because `common.sh` runs as a separate process before the role script.
    - Provider firewall, forwarding, policy routing, WireGuard route mode, and interface detection remain in provider `bastion.sh` files.
  - bastion WireGuard package install and `wg0.conf` generation through `infrazero_install_wireguard_packages` and `infrazero_configure_bastion_wireguard`
    - The helper intentionally sets `WG_SERVER_IP` in the caller shell, because the provider scripts still use it later for SSH `ListenAddress`.
    - Peer parsing, PSK writing, invalid JSON handling, and `wg-quick@wg0` startup remain behaviorally the same.
  - Infisical bootstrap/admin-secret scripts now use `infrazero_ensure_aws_cli` instead of local AWS CLI installers.
    - This is treated as an S3-compatible object-storage client dependency, not as an AWS cloud-provider adapter.
  - Common K3s, PgBouncer, DB replica, DB primary, egress, and Infisical role scripts now use `infrazero_apt_get` through small role-local wrappers.
    - The wrappers preserve each role's previous retry count and avoid deleting apt lists where the old role behavior did not do that.
  - Common role and provider scripts now use `common-base.sh` helpers for env-file loading, required env validation, retry wrappers, and private-interface/private-IP detection where the detection is based only on normalized `PRIVATE_CIDR`.
    - Standalone generated scripts such as `/opt/infrazero/db/restore.sh`, `/opt/infrazero/egress/grafana-bootstrap.sh`, and `/usr/local/sbin/update-pgbouncer.sh` intentionally keep local env-loading helpers because they run independently after bootstrap extraction.
  - base system hardening: security-only unattended-upgrades policy, `auditd`, persistent journald, and systemd-resolved fallback DNS
  - SSH hardening, including debug root password mode, `AllowGroups`, root login/password toggles, and debug config cleanup
  - Provider route repair and public/private gateway assumptions remain in provider `common.sh` files.

Current archive contract after this stage:

| Role | Common files packaged |
| --- | --- |
| `bastion` | `common-base.sh`, `common-beacon.sh` |
| `egress` | `common-base.sh`, `common-beacon.sh`, `common-egress.sh`, `common-infisical-bootstrap.sh` |
| `node1` | `common-base.sh`, `common-beacon.sh`, `common-node1.sh`, `infisical-admin-secret.sh`, `common-infisical-admin-secret.sh` |
| `nodecp` | `common-base.sh`, `common-beacon.sh`, `common-nodecp.sh` |
| `node2` | `common-base.sh`, `common-beacon.sh`, `common-node-agent.sh` |
| `db` | `common-base.sh`, `common-beacon.sh`, `db-patroni.sh` |
| `db-replica` | `common-base.sh`, `common-beacon.sh`, `db-patroni.sh`, `common-db-replica.sh` |
| `pgbouncer` | `common-base.sh`, `common-beacon.sh`, `common-pgbouncer.sh` |

Do not commonize `db.sh`, `common.sh`, `bastion.sh`, or `egress.sh` as a single whole file in the next stage. They need explicit provider adapter boundaries first.

## Provider adapter safety model

The provider adapter approach is safe for working code only if it is treated as a strict boundary, not as a broad shared inheritance layer.

Safe:

- Common role code owns server behavior:
  - security hardening
  - package retry policy
  - PostgreSQL/Patroni/PgBouncer
  - K3s/ArgoCD/Infisical/Grafana/Loki
  - TLS/nginx/Promtail
  - common bootstrap/beacon/error handling
- Provider adapters own cloud mechanics:
  - private interface detection
  - gateway/route mode
  - volume device discovery
  - cloud-init boot route repair
  - Terraform resource addresses and provider credentials
- Packaging includes only:
  - selected common role
  - selected common libraries
  - selected provider adapter
  - selected provider Terraform directory

Unsafe:

- Common role code references `HCLOUD_TOKEN`, `OS_*`, `OVH_*`, `hcloud_*`, `openstack_*`, floating IP resource names, Hetzner MAC assumptions, or OVH project IDs.
- A generated user repo receives `bootstrap/hetzner` and `bootstrap/ovh` together when only one provider was selected.
- GitHub secrets/templates contain both Hetzner and OVH credential fields for a single-provider deployment.
- A provider adapter configures product services such as PostgreSQL, K3s, ArgoCD, Infisical, Grafana, Loki, PgBouncer, or app manifests.

Required guardrails:

- Add a single provider selection script, for example `scripts/common/select-provider.sh`.
  - Input: `CLOUD_PROVIDER`.
  - Output: `CLOUD_PROVIDER_RESOLVED`, `TOFU_DIR`, `SCRIPTS_DIR`, `BOOTSTRAP_PROVIDER_DIR`, `TF_VAR_*` only for the selected provider.
  - It must not export Hetzner fields for OVH or OVH/OpenStack fields for Hetzner.
- Add a provider manifest per cloud, for example `providers/hetzner/provider.json`, `providers/ovh/provider.json`.
  - Lists required repository files.
  - Lists allowed GitHub secrets for that cloud.
  - Lists provider-specific Terraform variables.
  - Lists bootstrap adapter files.
- Add a repository materializer step.
  - For Hetzner it copies common files plus Hetzner adapter/files only.
  - For OVH it copies common files plus OVH adapter/files only.
  - For AWS later it copies common files plus AWS adapter/files only.
- Add CI validation:
  - Hetzner materialized repo must not contain `bootstrap/providers/ovh`, `tofu/ovh`, `scripts/ovh`, `OVH_`, `OPENSTACK_`, or `openstack_` references outside documentation/tests.
  - OVH materialized repo must not contain `bootstrap/providers/hetzner`, `tofu/hetzner`, `scripts/hetzner`, `HCLOUD_TOKEN`, or `hcloud_` references outside documentation/tests.
  - Role archives must contain `common/*` and exactly one provider adapter.
  - Role archives must preserve S3 paths: `bootstrap/${role}.tar.zst`.
- `scripts/common/render-config.py` should stay mostly provider-neutral, but provider defaults must come from the selected provider manifest instead of inline `if cloud_provider == ...` branching whenever possible.

Current risk observed:

- Workflows currently expose both provider credential families in job env, then select provider later.
- This is workable only when non-selected secrets are empty, but it is not the desired architecture.
- The target model should make selected-provider secrets the only available provider credential set for that workflow run.

## Canonical file compilation matrix

This is the file-by-file target map. "Base" means the side that currently looks safer as the starting implementation. "Import" means concrete improvements from the other side that should be merged into the canonical file after verification.

| Current pair | Target canonical file | Base | Import from other provider | Stays provider-specific |
| --- | --- | --- | --- | --- |
| `bootstrap/*/beacon.sh` | `bootstrap/common/lib/beacon.sh` | Hetzner | No OVH logic to preserve except compatibility with `beacon_status` calls | Nothing, beacon is not cloud-specific |
| `bootstrap/*/common.sh` | `bootstrap/common/roles/common.sh` plus `common/lib/{apt,ssh-hardening,network-env,base-system,routes}.sh` | Hetzner for reliability | OVH public IPv4/default-route auto-detection and `resolve_private_gateway` idea | Private route mode, WG route mode, gateway detection details |
| `bootstrap/*/bastion.sh` | `bootstrap/common/roles/bastion.sh` plus `common/lib/{wireguard,promtail,iptables,ssh-listen}.sh` | Hetzner for catch-all egress fix | OVH SNAT/direct-bastion mode and OpenStack route assumptions as adapter options | Private NIC configuration, policy route mode, WG route mode |
| `bootstrap/*/egress.sh` | `bootstrap/common/roles/egress.sh` plus `common/lib/{docker,promtail,nginx-tls,infisical,loki,iptables}.sh` | Hetzner for newer interface race handling | OVH single-interface Floating IP mode and `apt_get` retry wrapper | Public/private interface detection, Floating IP handling, provider route repair |
| `bootstrap/*/db.sh` | `bootstrap/common/roles/db.sh` plus `common/lib/{postgres,patroni,db-volume,db-backup-restore,pg-hba}.sh` | Hetzner after current DB pg_hba fix | OVH longer volume wait, `apt_get`, `setup_pgbouncer_auth_role`, useful Patroni DCS options after verification | Volume device finder and attach timing defaults |
| `bootstrap/*/db-replica.sh` | `bootstrap/common/roles/db-replica.sh` plus same DB libs | Hetzner for primary `/leader` wait | OVH longer package/volume waits and `apt_get` | Volume device finder and provider attach semantics |
| `bootstrap/*/pgbouncer.sh` | `bootstrap/common/roles/pgbouncer.sh` plus `common/lib/pgbouncer.sh` | OVH for health handling | Hetzner structure where simpler/cleaner | Private IP resolver only if provider-specific detection is needed |
| `bootstrap/*/infisical-bootstrap.sh` | `bootstrap/common/roles/infisical-bootstrap.sh` plus `common/lib/infisical.sh` | Hetzner/OVH are almost identical | OVH `apt_get`; keep whichever retry implementation is stricter after shell diff | Nothing provider-specific expected |
| `bootstrap/*/infisical-admin-secret.sh` | `bootstrap/common/roles/infisical-admin-secret.sh` plus `common/lib/{gitops,infisical,kubernetes}.sh` | OVH for newer resilience paths | Hetzner baseline where equivalent; preserve behavior that is already proven | Nothing provider-specific expected, except provider-derived service URLs from env |
| `bootstrap/*/node1.sh` | `bootstrap/common/roles/node1.sh` plus `common/lib/{k3s,argocd,etcd-patroni,infisical-retry,cert-check}.sh` | Hetzner for stricter ArgoCD readiness/error reporting | OVH `apt_get`, earlier/common `setup_etcd_patroni`, configurable Infisical retry attempts | Private interface detection and K3s API endpoint source |
| `bootstrap/*/nodecp.sh` | `bootstrap/common/roles/nodecp.sh` plus `common/lib/{k3s,etcd-patroni}.sh` | Hetzner for primary API wait/beacon retry | OVH `apt_get`; compare join URL naming and keep normalized contract | Private interface detection and join URL variable mapping |
| `bootstrap/*/node2.sh` | `bootstrap/common/roles/node2.sh` plus `common/lib/k3s.sh` | Hetzner for primary API wait/beacon retry | OVH `apt_get` | Private interface detection and join URL variable mapping |
| `tofu/*/cloud-init.tf` | Keep provider files, extract common locals/template inputs where safe | Existing split | Share artifact variable shape and role env contract | Provider env values, network IDs, IPs, route snippets |
| `tofu/*/templates/cloud-init.tftpl` | `tofu/common/templates/cloud-init-runner.tftpl` plus provider boot snippets | Hetzner for richer route repair/failure wrapper | OVH simpler OpenStack path where route repair is unnecessary | Bootcmd/network route snippets and metadata assumptions |
| `tofu/*/locals.tf` | `tofu/common/topology-contract.md` or generated shared locals module only if low-risk | Existing split | Normalize names/output contract | Provider resource references |
| `tofu/*/variables.tf` | Common variable contract docs plus provider-specific variables files | Existing split | Deduplicate neutral vars only after contract tests | Provider credentials, image/flavor/region/resource names |
| `tofu/*/main.tf` | Keep provider-specific | None | Do not merge mechanically | Almost all resource graph |
| `scripts/*/import-volume.sh` | `scripts/common/import-volume.sh` dispatching provider adapter | Existing split | Common state checks/retry/import wrapper | Provider volume lookup and resource address |
| `scripts/*/destroy-without-volume.sh` | `scripts/common/destroy-without-volume.sh` with provider target manifest | Existing split | Common safety prompts, tofu retry, preserve-volume behavior | Provider resource addresses/excludes |
| `scripts/*/import-ssh-keys.py` | Common CLI plus provider SSH-key adapter modules | Existing split | Common key parsing/state import flow | Provider API calls/resource addresses |
| `.github/workflows/*.yml` | Reusable provider selection and role packaging steps | Current workflows | Keep all working behavior, remove duplicated provider/packaging blocks | Provider credential export and provider-specific tofu targets |

Canonical file rules:

- Every canonical role file should read only normalized env names.
- Every provider adapter should translate cloud-specific facts into normalized env/functions before the role runs.
- The canonical role should fail fast if a normalized required field is missing.
- The provider adapter should fail fast if a selected provider credential is missing.
- The packaging script should fail if more than one provider adapter is present in a role archive.
- The materialized user repo should fail CI if it contains files or secret names for non-selected providers.

## Target materialized repository shape

For a Hetzner App deployment, the generated user infra repo should look like:

```text
.github/workflows/
  build.yml
  rebuild-bastion.yml
  rebuild-db.yml
  rebuild-db-replica.yml
  rebuild-egress.yml
  rebuild-nodes.yml
bootstrap/
  common/
    lib/*.sh
    roles/*.sh
  providers/
    hetzner/*.sh
scripts/
  common/*.sh
  common/*.py
  providers/hetzner/*.sh
  providers/hetzner/*.py
tofu/
  hetzner/*.tf
  common/templates/*.tftpl
providers/
  hetzner/provider.json
```

It should not contain:

```text
bootstrap/providers/ovh/
scripts/providers/ovh/
tofu/ovh/
OVH_APPLICATION_KEY
OVH_APPLICATION_SECRET
OVH_CONSUMER_KEY
OPENSTACK_USER_NAME
OPENSTACK_PASSWORD
openstack_*
```

For an OVH App deployment, the generated user infra repo should look symmetrical and should not contain:

```text
bootstrap/providers/hetzner/
scripts/providers/hetzner/
tofu/hetzner/
HCLOUD_TOKEN
TF_VAR_hcloud_token
hcloud_*
```

VPN and Agent deployments should use the same materialization rule:

- common files required by their roles
- selected provider adapter only
- selected provider Terraform only
- selected provider secrets only
- no App-only role files unless VPN/Agent actually use them

## File-by-file findings and extraction plan

### `bootstrap/beacon.sh`

Findings:

- Hetzner has a full beacon implementation:
  - `infrazero_redact`
  - `infrazero_json_escape`
  - `infrazero_state_for_phase`
  - `beacon_write`
  - `beacon_status`
  - `beacon_retrying`
  - `beacon_degraded`
  - `beacon_failed`
  - `infrazero_trap_error`
  - `infrazero_install_error_trap`
- OVH has only a minimal `beacon_status`.
- This is not cloud-specific. OVH is stale.

Plan:

- Move Hetzner beacon implementation to `bootstrap/common/lib/beacon.sh`.
- Keep a tiny compatibility wrapper if needed:
  - `beacon_status phase message progress`
  - `beacon_retrying`
  - `beacon_degraded`
  - `beacon_failed`
- All roles source the same beacon.
- Remove provider copies after proving all role archives include common beacon.

Risk:

- Existing OVH scripts may only export `beacon_status`; after unification cloud-init must export all beacon functions for subprocess role scripts.

### `bootstrap/common.sh`

Findings:

- Both files share admin user creation, SSH hardening, sysctl, IPv6 disable, auditd, journald, DNS fallback.
- Admin user creation and SSH hardening have been moved into `bootstrap/common/common-base.sh`; provider `common.sh` files now call `infrazero_setup_admin_users` and `infrazero_harden_ssh`.
- Base package installation and outbound-connectivity waiting have been moved into parameterized `infrazero_install_base_packages`.
- Shared network baseline, `network.env` writing, and base system configuration have been moved into `infrazero_apply_network_baseline`, `infrazero_write_network_env`, and `infrazero_configure_base_system`.
- Hetzner contains stronger bootstrap status/error behavior and longer outbound NAT wait:
  - waits up to 300 attempts x 5 seconds for private servers without public IPv4
  - emits `beacon_retrying` and `beacon_degraded`
  - captures network diagnostics
- OVH contains useful provider-neutral improvements:
  - `resolve_private_gateway`
  - auto-detect public IPv4/default route
  - stores `BASTION_PRIVATE_IP` in `/etc/infrazero/network.env`
- Route repair differs:
  - Hetzner assumes /32 private NIC behavior and network-level WG route.
  - OVH assumes OpenStack/DHCP style route and may route WG directly via bastion private IP.

Common extraction:

- `logging.sh`: redirect to `/var/log/infrazero-bootstrap.log`.
- `apt.sh`: `apt_get` with timeout, lock timeout, retries, cleanup.
- `admins.sh`: decode `ADMIN_USERS_JSON_B64`, create group/users, authorized keys.
- `ssh-hardening.sh`: debug password behavior, `AllowGroups`, root/password auth toggles, config include.
- `sysctl.sh`: rp_filter, IPv6 disable, forwarding where role requires it.
- `network-env.sh`: write `/etc/infrazero/network.env`.
- `base-system.sh`: auditd, unattended-upgrades, journald, resolved fallback.

Provider adapter:

- `provider_resolve_private_gateway`
- `provider_repair_private_route`
- `provider_repair_wg_route`
- `provider_has_public_ipv4`

Do not blindly move:

- Hetzner-specific `/32` route assumptions unless protected by prefix-length checks.
- OVH-specific `BASTION_PRIVATE_IP` as WG route gateway unless route mode says `bastion-snat` or `direct-bastion`.

Real drift to merge:

- Hetzner beacon/error reporting should become common.
- OVH public IPv4 auto-detect should become common.
- Hetzner long wait + diagnostics should become common but controlled by env.

### `bootstrap/bastion.sh`

Findings:

- `require_env` and WireGuard package install are nearly common.
- Interface detection/routing differs:
  - Hetzner configures a private interface if `BASTION_PRIVATE_IP` is missing from OS config, using public/private interface detection and `/32` route repair.
  - OVH assumes OpenStack private networking and enables `WG_SNAT_ENABLED=true` by default.
- Policy routing diverged:
  - Hetzner removed the pref 200 catch-all route to prevent bastion's own traffic from being forced through egress.
  - OVH still has a pref 200 catch-all `lookup egress` in the older path.
- Promtail installation/config is common.
- SSH listen-address hardening is common.

Common extraction:

- `bastion-wireguard.sh`: render `wg0.conf`, peers, systemd `wg-quick@wg0`.
- `bastion-firewall.sh`: forwarding rules, WAN reject, iptables persistence.
- `bastion-ssh-listen.sh`: bind SSH to WG/private/public depending debug mode.
- `promtail.sh`: install Promtail and render journald shipping config.

Provider adapter:

- `provider_configure_bastion_private_if`
- `provider_bastion_wg_route_mode`: `network-route`, `snat`, `direct-bastion`
- `provider_bastion_egress_policy_mode`: `none`, `selective`, `catch_all`

Bug/drift candidate:

- Hetzner's removal of pref 200 looks like a real reliability fix, not Hetzner-only. Any provider where bastion has its own public IP should not use catch-all egress routing.

Note:

- WG implementation changes should be scheduled separately if the current immediate priority is DB. The audit still records the divergence.

### `bootstrap/db.sh`

Findings:

- This is the strongest commonization candidate. About 96% of the file matches.
- Exact common functions include:
  - `load_env`
  - `cleanup_private_restore_secrets`
  - `require_env`
  - `is_data_dir_empty`
  - `drop_stale_cluster_config`
  - `ensure_bind_mount`
  - `start_cluster`
  - `set_conf`
  - `resolve_listen_addresses`
  - `wait_for_postgres`
  - `setup_db_tls`
  - `psql_as_postgres`
  - `sql_escape`
  - `sql_ident`
  - `ensure_databases`
  - `normalize_db_ownership_and_privileges`
  - all restore detection helpers
  - `restore_databases_from_s3`
  - `apply_infrazero_hba`
  - `apply_postgres_config`
  - `payload_looks_text_sql`
  - `wipe_target_database`
  - `build_pg_restore_candidates`
  - `run_pg_restore_with_candidates`
  - `run_pg_restore_with_auto_install`
- We already introduced `bootstrap/common/db-patroni.sh` for shared Patroni `pg_hba`.

Provider-specific parts:

- DB volume device discovery:
  - Hetzner uses `/dev/disk/by-id/scsi-0HC_Volume_*` and `scsi-SHC_Volume_*`.
  - OVH adds fallback to unmounted plain disk via `lsblk`.
- Volume attach wait:
  - Hetzner default: 45 attempts x 2 seconds.
  - OVH default: 360 attempts x 5 seconds.

Non-cloud-specific drift:

- OVH has a stronger `apt_get` helper. This belongs in common `apt.sh`.
- Hetzner has AWS CLI install retry. This belongs in common `aws-cli.sh`.
- OVH has `setup_pgbouncer_auth_role`; this is not OVH-specific and should be common.
- Hetzner skips `setup_replication_primary` when Patroni is enabled to avoid conflicting DCS settings and pending restart loops. This is not Hetzner-specific and should be common.
- Hetzner syncs both postgres superuser password and replication user password before Patroni takes over. OVH only syncs superuser. Hetzner behavior should be common.
- Hetzner writes `wait-etcd.sh` and uses `ExecStartPre` before Patroni. OVH does not. This should be common.
- OVH Patroni DCS has `wal_log_hints`, `remove_data_directory_on_rewind_failure`, `remove_data_directory_on_diverged_timelines`; these are Patroni behavior choices, not OpenStack-specific. Need deliberate merge.
- Hetzner keeps `basebackup` method config in Patroni YAML; OVH removed it. Need decide one canonical Patroni bootstrap model, then apply everywhere.

Extraction plan:

- `db-volume.sh`
  - common mount/format/fstab/bind mount
  - calls `provider_find_db_volume_device`
  - env-controlled attach wait defaults
- `postgres-install.sh`
  - common PGDG enable
  - common PostgreSQL package install
- `db-users.sh`
  - app DB creation
  - ownership normalization
  - pgbouncer auth role
  - replication role
- `db-backup-restore.sh`
  - S3 restore
  - compression detection
  - `pg_restore` version fallback
  - backup service generation
- `patroni.sh`
  - render Patroni config
  - render `pg_hba`
  - sync users/passwords
  - wait for etcd
  - systemd unit
  - health wait

### `bootstrap/db-replica.sh`

Findings:

- The file is mostly common.
- Provider-specific code is minimal.
- Hetzner has a valuable Patroni-primary wait before `pg_basebackup`:
  - waits for primary Patroni `/leader`
  - avoids racing vanilla pg_hba before Patroni writes config
- OVH has stronger `apt_get` and longer primary wait:
  - `DB_REPLICA_PRIMARY_WAIT_ATTEMPTS`
  - `DB_REPLICA_PRIMARY_WAIT_DELAY`
- Patroni YAML drift matches `db.sh`.

Extraction plan:

- Use the same `postgres-install.sh`, `patroni.sh`, `apt.sh`, `network-detect.sh`.
- Common replica flow:
  1. install packages
  2. create Debian cluster config if missing
  3. wait primary PostgreSQL readiness with env-controlled attempts
  4. if Patroni enabled, wait primary Patroni leader
  5. run `pg_basebackup` with retry
  6. if Patroni enabled, remove `standby.signal` and let Patroni manage replication
  7. start Patroni with common unit

### `bootstrap/pgbouncer.sh`

Findings:

- Mostly common.
- OVH has stronger behavior:
  - `apt_get`
  - `PGPASSWORD` used in health checks
  - health host resolves `0.0.0.0` to `127.0.0.1`
  - no DB hosts exits cleanly with beacon complete
  - read pool uses only replicas with `state=="running"` or `state=="streaming"`
- Hetzner has broader replica host handling but should be merged with OVH health filtering.

Extraction plan:

- Move all PgBouncer logic into `bootstrap/common/lib/pgbouncer.sh` and `common/roles/pgbouncer.sh`.
- Keep provider only for server provisioning/security group/firewall rules.
- Canonical behavior:
  - both pools start on primary until replicas are healthy
  - watcher updates write to leader and read to healthy replicas
  - health check uses auth password and bind-safe host

### `bootstrap/egress.sh`

Findings:

- Service bootstrap is mostly common:
  - AWS CLI install
  - DNS fallback
  - Docker/compose helpers
  - Loki/Grafana config
  - Promtail Docker log shipping
  - Infisical restore
  - Infisical compose
  - Nginx/TLS/certbot
  - HAProxy for K3s API
  - iptables persistence
- Provider-specific:
  - Hetzner private NIC detection by MAC prefix `86:00:00`
  - Hetzner self-configures private NIC using `EGRESS_PRIVATE_IP`
  - OVH supports single-interface mode where Floating IP is outside the guest and public/private interface may be the same
- Non-cloud-specific drift already aligned in the staged implementation:
  - Hetzner enables forwarding before Docker and waits for Docker daemon.
  - Hetzner retries Loki compose up.
  - Hetzner uses `iptables-restore --noflush` after Docker and requires Docker for DOCKER-USER.
  - OVH has `apt_get` helper.
- Remaining unverified service drift:
  - OVH sets `ALLOW_INTERNAL_IP_CONNECTIONS=true` for Infisical.
  - OVH adds `extra_hosts` for `KUBERNETES_FQDN` to private IP.
  - Do not blindly copy these to Hetzner or remove them from OVH. First verify whether Infisical's Kubernetes auth/SecretProviderClass flow needs internal IP access or egress-local FQDN resolution.

Extraction plan:

- `egress-network.sh` provider adapter:
  - `provider_detect_public_if`
  - `provider_detect_private_if`
  - `provider_configure_egress_private_interface`
  - `provider_single_interface_mode`
- `egress-services.sh` common:
  - Docker install/readiness
  - Loki/Grafana compose
  - Infisical compose
  - restore
  - backup
  - Promtail
- `egress-tls.sh` common:
  - certbot retry service
  - self-signed fallback
  - Nginx server blocks
  - Kubernetes/Argo/Grafana/Loki/Infisical proxies
- `egress-firewall.sh` common:
  - NAT and DOCKER-USER/FORWARD rules
  - iptables persistence
  - K3s API cleanup

### `bootstrap/node1.sh`

Findings:

- Common K3s primary install and ArgoCD/Infisical/etcd behavior are duplicated.
- Non-cloud-specific drift:
  - OVH uses `apt_get`.
  - Hetzner has `wait_argocd_rollouts` for all deployments/statefulsets and reports beacon failures.
  - OVH uses fixed deployment names and ignores rollout failures with `|| true`.
  - OVH has more configurable Infisical admin bootstrap attempts.
  - etcd-patroni exists in both but differs in idempotency, `Type=simple` vs `Type=notify`, listener readiness fallback, and existing data handling.
- Provider-specific:
  - private interface/IP detection, if any.
  - K3s API endpoint values from Terraform/cloud-init.

Extraction plan:

- `k3s-primary.sh` common:
  - install k3s
  - wait kubeconfig
  - apply ArgoCD
  - wait rollouts with failure reporting
  - create app
  - cert checks
- `etcd-patroni.sh` common:
  - install etcd binary
  - render systemd
  - existing data -> `initial-cluster-state=existing`
  - health/listener readiness
  - port collision check
- `infisical-admin-bootstrap-runner.sh` common:
  - attempts/delay envs
  - retry timer

### `bootstrap/nodecp.sh`

Findings:

- Mostly common K3s control-plane join and etcd-patroni.
- Non-cloud-specific drift:
  - OVH supports `K3S_CONTROL_PLANE_JOIN_URL`, defaulting to `https://${K3S_SERVER_IP}:6443`.
  - Hetzner has function-based `wait_for_k3s_primary_api` with beacon retry/failure.
  - OVH has `apt_get`.
  - OVH etcd-patroni has idempotency and existing data handling.

Extraction plan:

- Common control-plane role should:
  - resolve join URL with override
  - wait primary API with beacon events
  - install k3s server join
  - optionally install etcd-patroni via common helper

### `bootstrap/node2.sh`

Findings:

- Mostly common K3s agent join.
- Non-cloud-specific drift:
  - OVH has `apt_get`.
  - Hetzner has `wait_for_k3s_primary_api` with beacon reporting.

Extraction plan:

- Common K3s agent role:
  - resolve private node IP
  - wait primary API with env attempts
  - install k3s agent
  - keep provider only for IP discovery defaults.

### `bootstrap/infisical-bootstrap.sh`

Findings:

- 99% common.
- Only meaningful difference is OVH `apt_get`.

Extraction plan:

- Make it one common role/helper.
- Source `apt.sh`.
- No provider adapter expected unless service URL defaults differ.

### `bootstrap/infisical-admin-secret.sh`

Findings:

- Mostly common but several OVH improvements look real and provider-neutral:
  - `apt_get`
  - token validation uses `curl -sk` and handles HTTP `000`
  - Kubernetes host prefers private IP / API LB before public FQDN
  - `git rebase --autostash`
  - patches bootstrap configmap `KUBE_HOST` and curl insecure mode
  - resets failed bootstrap job and result secret
  - generates placeholder manifest when no SecretProviderClass exists
  - makes `git_push_changes` non-fatal in some paths
- These are not OpenStack-specific.

Extraction plan:

- Move to common role.
- Use canonical Kubernetes endpoint resolver:
  1. `K3S_API_LB_PRIVATE_IP`
  2. `K3S_SERVER_IP`
  3. `K3S_SERVER_PRIVATE_IP`
  4. `KUBERNETES_FQDN`
- Make insecure TLS behavior explicit via env, not hidden OVH-only patch.
- Keep GitOps mutation logic common.

## Tofu findings

### `tofu/main.tf`

Findings:

- This file is mostly provider-specific and should not be forced into one common `main.tf`.
- Hetzner uses:
  - `hcloud_network`
  - `hcloud_network_route`
  - `hcloud_firewall`
  - `hcloud_server`
  - `hcloud_load_balancer`
  - `hcloud_volume`
- OVH uses:
  - OpenStack networks/subnets/routers
  - security groups/rules
  - compute instances
  - block storage volumes
  - Octavia load balancers
  - floating IP associations

Commonizable at the model level, not line level:

- topology roles:
  - bastion
  - egress
  - k3s primary/control-plane/agent
  - db
  - db-replica
  - pgbouncer
  - HTTP/HTTPS LB
  - K3s API LB
- normalized outputs:
  - `bastion_public_ipv4`
  - `egress_public_ipv4`
  - `private_ips`
  - `db_volume_id`
  - `db_replica_private_ips`
  - `pgbouncer_private_ip`
  - `bootstrap_artifacts`

Do not move:

- actual resource blocks into shared HCL unless using a higher-level generator or module interface.

Recommended AWS extension model:

- Add `tofu/aws/main.tf` as provider-specific implementation of the same topology contract.
- Keep common config rendering in `scripts/common/render-config.py`.
- Keep common output names across providers.

### `tofu/cloud-init.tf`

Findings:

- Mostly common.
- Drift:
  - OVH intentionally omits `EGRESS_PRIVATE_IP` for bastion/egress env because bastion has direct internet via Floating IP.
  - OVH sets `node_role_env = concat(local.db_env_lines, local.pgbouncer_env_lines)`.

Plan:

- Keep provider-specific env decisions in provider cloud-init mapping.
- Commonize variable assembly patterns:
  - role env lines
  - secrets env lines
  - bootstrap artifact map
  - template invocation

### `tofu/templates/cloud-init.tftpl`

Findings:

- Common artifact download/verify/extract/run model.
- Hetzner has large `bootcmd` default route repair for private servers before packages.
- Hetzner has newer beacon failure wrapping around `common.sh` and role script execution.
- OVH template is shorter and lacks the same error wrapper.

Plan:

- Commonize artifact fetch/sha/extract/run logic.
- Commonize beacon failure wrapper.
- Keep provider bootcmd route repair as adapter snippet:
  - Hetzner needs early default route repair.
  - OVH may not need it.
  - AWS will likely need different metadata/route behavior.

## Scripts findings

### `scripts/common/*`

Already common and should remain common:

- `render-config.py`
- `render-backend.py`
- `validate-config.py`
- `clean-s3-state.sh`
- `tofu-retry.sh`
- `monitor-bootstrap.sh`
- `offload-egress-bootstrap-secrets.sh`
- `sync-cloudflare-dns.py`
- `export-bootstrap-folder-secrets.py`

Plan:

- Expand common scripts with:
  - `package-bootstrap.sh`
  - `select-provider.sh`
  - `destroy-preserve-volume.sh` wrapper
  - `import-ssh-keys.py` with provider adapter classes
  - `import-volume.sh` wrapper with provider adapter classes

### `scripts/hetzner/*` vs `scripts/ovh/*`

Findings:

- `destroy-without-volume.sh` has common lifecycle intent but provider-specific resource names and fallback cleanup APIs.
- `import-volume.sh` has common intent but provider-specific volume lookup.
- `import-ssh-keys.py` has common intent but provider-specific keypair APIs and Terraform resource addresses.
- `scripts/hetzner/gitops-preflight.sh` exists only for Hetzner, but the logic is GitHub/GitOps and should be common if still needed.
- `scripts/ovh/cleanup-openstack.sh` and `scripts/ovh/nuke-all.sh` are OpenStack-specific cleanup tools. They should stay provider-specific.
- `scripts/ovh/cleanup-openstack.sh` contains hardcoded OVH project/user defaults. This should not live as fixed values in a reusable public template.

Plan:

- Keep OpenStack cleanup/nuke provider-specific.
- Move GitOps preflight to `scripts/common/gitops-preflight.sh`.
- Convert import/destroy scripts into common wrapper + provider implementation.
- Remove `__pycache__` from repo if tracked or ensure ignored.
- Parameterize OVH cleanup defaults through env/config only.

## Workflows findings

Findings:

- All workflows repeat provider selection:
  - `TOFU_DIR=tofu/ovh|tofu/hetzner`
  - `SCRIPTS_DIR=scripts/ovh|scripts/hetzner`
  - `BOOTSTRAP_DIR=bootstrap/ovh|bootstrap/hetzner`
- All workflows repeat package/upload bootstrap logic.
- Role archive composition is repeated in build/rebuild workflows.
- Current package logic still assumes one provider directory containing both role scripts and common scripts.

Plan:

- Add `scripts/common/select-provider.sh` or a generated GitHub env step that exports:
  - `TOFU_DIR`
  - `PROVIDER_DIR`
  - `PROVIDER_BOOTSTRAP_DIR`
  - `PROVIDER_SCRIPTS_DIR`
- Add `scripts/common/package-bootstrap.sh`:
  - inputs: provider, role, output dir
  - includes common libs, common role script, provider adapter, role extras
  - writes tar.zst + sha
- Workflows should call the same packaging script.
- Rebuild workflows should only change target role artifact and preserve artifact manifest for other roles.
- Add package verification:
  - list tar contents
  - ensure selected provider only
  - ensure no other provider files included
  - ensure all sourced common libs are present

## Priority migration plan

### Phase 0: freeze and test current behavior

No refactor yet.

Tasks:

- Save current file similarity matrix.
- Add package content tests for all roles.
- Add `bash -n` validation for all bootstrap scripts in both providers.
- Add tar extraction smoke test for each role.
- Add source-resolution test: every `source ./x.sh` or `source "$SCRIPT_DIR/..."` file exists in archive.

### Phase 1: common libraries without changing role flow

Lowest risk.

Move:

- `beacon.sh`
- `apt_get`
- logging redirect
- env load/require helpers
- AWS CLI installer
- private IP from CIDR helper
- common systemd writer helpers

Provider scripts can still exist, but they source common libs.

### Phase 2: DB commonization

Highest value, controlled scope.

Move:

- volume mount flow with provider volume adapter
- PostgreSQL package install
- DB/user/ownership normalization
- backup/restore logic
- Patroni rendering and systemd unit
- replica basebackup flow
- PgBouncer auth role

Merge canonical DB behavior:

- OVH `apt_get`
- OVH long volume wait as configurable env default where needed
- OVH PgBouncer auth role
- Hetzner skip replication-primary config when Patroni enabled
- Hetzner replication password sync before Patroni
- Hetzner wait-etcd `ExecStartPre`
- common Patroni `pg_hba` already started via `bootstrap/common/db-patroni.sh`

### Phase 3: PgBouncer and Infisical commonization

Move:

- PgBouncer role
- Infisical bootstrap role
- Infisical admin secret role

Merge canonical behavior:

- OVH PGPASSWORD health check
- OVH healthy replica filtering
- OVH token validation resilience
- OVH GitOps `--autostash`
- OVH failed-job reset
- Hetzner if it has stronger beacon/failure reporting around these paths.

### Phase 4: K3s/common node roles

Move:

- K3s install/join logic
- wait primary API
- ArgoCD install/wait/app generation
- cert checks
- etcd-patroni

Merge canonical behavior:

- Hetzner ArgoCD rollout wait and beacon failures.
- OVH configurable join URL.
- OVH etcd idempotency/existing data handling.
- Hetzner primary API wait beacon reporting.

### Phase 5: Egress and bastion commonization

Higher risk because it touches networking.

Move common service logic:

- Docker readiness
- Loki/Grafana/Promtail
- Infisical compose/restore/backup
- TLS/certbot/nginx
- HAProxy
- iptables persistence

Keep provider adapters:

- Hetzner private NIC MAC detection and self-config.
- OVH single-interface Floating IP mode.
- Future AWS ENI/source-dest-check/NAT/security-group behavior.

### Phase 6: workflow packaging and selected-provider repo output

Goal:

- The user repo should receive only:
  - common infra code
  - selected provider adapter
  - selected provider tofu
  - selected provider scripts
- No Hetzner code in an OVH-only repo and no OVH code in a Hetzner-only repo.

Implementation plan:

- Introduce source layout with `common` plus `providers/<cloud>`.
- Packaging script copies only chosen provider.
- `render-config.py` validates `cloud_provider`.
- Workflows never reference provider-specific paths directly except through selection output.

## What not to commonize

Do not commonize these as shell role code:

- Hetzner `hcloud_*` resources.
- OVH `openstack_*` resources.
- Provider-specific load balancer resource blocks.
- Provider-specific security group/firewall resource syntax.
- Provider-specific volume IDs/resource addresses.
- Provider-specific destroy order resource prefixes.
- Hetzner MAC prefix private NIC detection.
- OVH direct OpenStack cleanup/nuke behavior.

Instead, commonize only the interface contract:

- role names
- env vars
- outputs
- artifact names
- lifecycle hooks
- provider adapter function names

## Current likely bugs / logical drift

These need deeper verification before implementation, but they are strong candidates:

1. OVH stale beacon implementation.
   - Risk: worse monitoring/status and missing failure cause in OVH bootstrap.

2. OVH `common.sh` still has shorter outbound wait and less diagnostics.
   - Risk: transient egress/NAT readiness bugs appear as random bootstrap failures.

3. Hetzner lacks OVH-style `apt_get` helper in many role scripts.
   - Risk: apt lock/network flakiness differs by role/cloud.

4. OVH DB primary runs `setup_replication_primary` even when Patroni is enabled.
   - Risk: conflicting PostgreSQL config and Patroni pending_restart loops.

5. OVH DB primary does not sync replication user password in Patroni path.
   - Risk: replica auth failures on redeploy or stale etcd cluster.

6. OVH DB/replica Patroni lacks wait-etcd `ExecStartPre`.
   - Risk: Patroni starts too early and enters unhealthy/retry states.

7. Hetzner DB lacks OVH `setup_pgbouncer_auth_role`.
   - Risk: PgBouncer auth role may be absent depending on flow.

8. PgBouncer health checks differ.
   - Risk: health probe can fail without `PGPASSWORD` or when `LISTEN_ADDR=0.0.0.0`.

9. Node/Argo behavior differs.
   - Risk: one cloud may ignore failed Argo rollout while the other fails with beacon context.

10. `scripts/ovh/cleanup-openstack.sh` has hardcoded project/user defaults.
    - Risk: public template leaks environment-specific assumptions and is unsafe for reuse.

11. Workflows duplicate bootstrap packaging.
    - Risk: every new helper must be added to many workflow files, as already happened with `db-patroni.sh`.

12. Provider bootstrap dirs force copying all role logic per provider.
    - Risk: AWS will start as a third full copy and drift immediately.

## Validation plan for future implementation

Every refactor phase should include:

- `git diff --check`
- `bash -n` on all packaged shell files
- tar content check for every role
- source-reference check inside every tar
- no-other-provider-files check
- render-config check for Hetzner and OVH
- OpenTofu `fmt` and `validate` where CLI is available
- dry package test for `cloud_provider=hetzner`
- dry package test for `cloud_provider=ovh`
- future dry package test for `cloud_provider=aws`

For DB-specific phases:

- verify generated Patroni YAML for primary and replica
- verify `pg_hba` contains localhost and private CIDR only
- verify pgbouncer auth role SQL path
- verify replica waits Patroni leader when Patroni enabled
- verify provider volume adapter returns the expected device on each cloud

For bootstrap/S3:

- artifact keys must remain `s3://$INFRA_STATE_BUCKET/bootstrap/${role}.tar.zst`
- manifest shape must remain compatible with `bootstrap_artifacts`
- cloud-init must continue to verify SHA before extraction
- extracted path must continue to be `/opt/infrazero/bootstrap`

## Recommended immediate next implementation step

Start with DB because it has the highest duplicate ratio and current known bugs.

Do not rewrite all DB scripts at once. Do this order:

1. Add common `apt.sh`, `aws-cli.sh`, `postgres.sh`, `db-volume.sh`, `patroni.sh`.
2. Keep current provider `db.sh` wrappers.
3. Move one function group at a time from both provider files into common.
4. After each group, package-test DB and DB replica archives.
5. Only after DB is stable, proceed to PgBouncer and Infisical.

Expected first DB common modules:

- `bootstrap/common/lib/apt.sh`
- `bootstrap/common/lib/aws-cli.sh`
- `bootstrap/common/lib/network.sh`
- `bootstrap/common/lib/db-volume.sh`
- `bootstrap/common/lib/postgres.sh`
- `bootstrap/common/lib/patroni.sh`
- `bootstrap/providers/hetzner/volume.sh`
- `bootstrap/providers/ovh/volume.sh`

The current `bootstrap/common/db-patroni.sh` should be folded into `bootstrap/common/lib/patroni.sh` when the larger DB extraction starts.
