# EPIC-3 Appendix: NAT + Egress Plan (Split Bastion/Egress)

## Goal
Restore outbound Internet access for private-only nodes (to fetch bootstrap artifacts, OS packages, and S3) while keeping WireGuard on bastion working in the split bastion/egress topology.

## Current repo reality (findings)
- No provider network routes exist for default egress or WireGuard return traffic; `tofu/main.tf` only defines the network/subnet, servers, and firewalls.
- Private-only nodes do not set a default route to the network gateway anywhere in cloud-init or bootstrap; `tofu/templates/cloud-init.tftpl` jumps straight to the bootstrap download.
- Egress does NAT and enables `ip_forward` in `bootstrap/egress.sh`, but routing never reaches it without provider routes + per-node default route.
- Bastion currently SNATs WireGuard traffic to the bastion private IP in `bootstrap/bastion.sh`, and `bootstrap/common.sh` explicitly assumes SNAT.

## Decision points
We need to decide how to keep WireGuard working once the default route for private nodes points at egress:
- **Preferred (route-based)**: Add a provider network route for the WireGuard subnet to the bastion. Disable SNAT on bastion and allow L3 routing so private nodes see real WG client IPs.
- **Fallback (SNAT-based)**: Keep bastion SNAT as-is. This avoids needing WG routes but hides client IPs.

We also need a decision on bastion outbound behavior:
- **Chosen:** Keep bastion public IP, but steer its outbound traffic through egress NAT using policy routing, while preserving WireGuard client <-> bastion connectivity on the public interface.

This plan defaults to **SNAT-enabled WG** for maximum robustness (no dependency on WG subnet routes), while still adding the WG route for route-based correctness and observability.

## Plan (implementation steps)
### 1) Provider network routes (OpenTofu)
- Add `hcloud_network_route` resources in `tofu/main.tf`:
  - `0.0.0.0/0 -> egress_private_ip` so the network router sends all default traffic to the egress host.
  - `wireguard_subnet -> bastion_private_ip` so replies to WG clients return to bastion (required if SNAT is disabled).
- Derive `wireguard_subnet` from `wg_server_address` (e.g., `10.50.0.1/24` -> `10.50.0.0/24`) in OpenTofu locals, or introduce a new config field if derivation is too fragile.
- Ensure routes depend on the network and use `var.servers.egress.private_ip` / `var.servers.bastion.private_ip` as gateways.

### 2) Bastion outbound via egress (policy routing, keep WG working)
- Keep bastion public IP enabled; do **not** delete the public default route from `main`.
- Add policy routing in `bootstrap/bastion.sh` (after WG is up) to send most outbound traffic through egress while keeping WG on public:
  - Compute `PRIVATE_GW` from `PRIVATE_CIDR` and ensure an onlink host route to it.
  - Create a routing table (e.g., `egress` table 100) with `default via $PRIVATE_GW dev $PRIVATE_IF onlink`.
  - Add `ip rule` entries (low preference numbers first) to preserve WG and public replies:
    - `from <WG_CIDR> lookup main` (so wg0 routes stay intact).
    - `to <WG_CIDR> lookup main` (so traffic destined to WG clients doesn’t get pulled into egress).
    - `from <BASTION_PUBLIC_IP>/32 lookup main` (so WG UDP and other public replies egress on the public NIC).
  - Add a catch‑all rule `lookup egress` for everything else.
  - Persist rules with a oneshot systemd unit (similar to iptables restore).

### 3) Default route on private-only nodes (cloud-init)
- Update `tofu/templates/cloud-init.tftpl` `run.sh` to ensure a default route exists **before** `wait_for_bootstrap_url`:
  - If no default route is present, compute the private gateway (`cidrhost(private_cidr, 1)` or Python `ipaddress` fallback) and apply:
    - `ip route replace $PRIVATE_GW/32 dev $PRIV_IF scope link`
    - `ip route replace default via $PRIVATE_GW dev $PRIV_IF onlink metric 50`
  - Only apply when there is no default route, to avoid overriding public routes on bastion/egress.

### 4) Bastion WireGuard forwarding mode
- Make SNAT optional in `bootstrap/bastion.sh`:
  - Default to **route-based** when `WG_SNAT_ENABLED=false` (or similar env flag), skip NAT but keep FORWARD rules for WG <-> private.
  - Keep the current SNAT rules as a fallback when `WG_SNAT_ENABLED=true` (backwards-compatible).
- Add an explicit `REJECT` rule for `WG -> WAN` if full-tunnel is not desired.
- Update `bootstrap/common.sh` comment to reflect the chosen routing mode instead of always assuming SNAT.

### 5) Egress NAT hardening
- Make NAT iptables rules in `bootstrap/egress.sh` idempotent (use `iptables -C ... || iptables -A ...`) to avoid duplicates on rerun.
- Keep `net.ipv4.ip_forward=1` and ensure `infrazero-iptables.service` restores the NAT rules at boot.

### 6) Optional bootstrap resiliency
- (Optional) Add a short egress-wait loop before fetching the bootstrap artifact if the private default route is newly created, to avoid transient failures.

## Files expected to change
- `tofu/main.tf` (add `hcloud_network_route` resources)
- `tofu/locals.tf` (compute `wireguard_subnet` if derived here)
- `tofu/variables.tf` and `config/schema.json` (only if a new `wireguard_subnet` config value is introduced)
- `tofu/templates/cloud-init.tftpl` (default route before download)
- `bootstrap/bastion.sh` (policy routing + optional SNAT toggle + WG forwarding)
- `bootstrap/common.sh` (update routing comment)
- `bootstrap/egress.sh` (idempotent NAT rules)

## Validation plan
- `tofu validate` (or `tofu plan`) to confirm route resources wire up correctly.
- On a private node:
  - `ip route` shows default via private gateway.
  - `curl -I <bootstrap_url>` succeeds.
- On egress:
  - `iptables -t nat -S | grep MASQUERADE` shows NAT rules.
  - `sysctl net.ipv4.ip_forward` returns 1.
- On bastion:
  - `ip rule` shows WG/public rules before the catch‑all egress rule.
  - `ip route show table egress` shows default via private gateway.
  - `wg show` confirms peers.
  - Test SSH or HTTP to a private node from a WG client; verify source IP if route-based.

## Rollout notes
- Apply routes + cloud-init changes before next rebuild to ensure bootstraps download successfully.
- If switching from SNAT to route-based, update firewalls (if any) that rely on the bastion private IP rather than WG subnet.

## Risks / mitigations
- **WG breakage** if SNAT is disabled without WG route -> bastion: mitigated by adding the network route and making SNAT configurable.
- **WG breakage** if bastion policy routing prefers egress for WG/public replies: mitigated by explicit WG/public `ip rule` ordering.
- **No egress** if default route script miscomputes the gateway: mitigated by using `cidrhost` or Python ipaddress and only acting when no default route exists.
- **Bootstrap failure before route**: mitigated by running the route setup at the top of `run.sh`.
