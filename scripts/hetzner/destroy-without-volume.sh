#!/usr/bin/env bash
# Hetzner: ordered destroy of everything except the data volume.
# Shared logic lives in scripts/common/destroy-without-volume-driver.sh.
set -euo pipefail

_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DESTROY_PREFIXES_PRE_S3=(
  hcloud_load_balancer_service
  hcloud_load_balancer_target
  # Subnet/network destroy can hang/fail if any LB is still attached to the network.
  hcloud_load_balancer_network
  hcloud_load_balancer.
  hcloud_volume_attachment
  # ALL servers (prefix catches indexed resources like server.k3s[0])
  hcloud_server.bastion
  hcloud_server.egress
  hcloud_server.db
  hcloud_server.k3s
  hcloud_server.db_replica
  hcloud_server.pgbouncer
  # ALL firewalls
  hcloud_firewall.bastion
  hcloud_firewall.egress
  hcloud_firewall.k3s
  hcloud_firewall.db
  hcloud_firewall.db_replica
  hcloud_firewall.pgbouncer
  hcloud_placement_group.
  # Only ops SSH keys (project-specific, not user keys)
  hcloud_ssh_key.ops
  hcloud_network_route
)

# Network subnet and network - only destroy AFTER all servers, firewalls, LBs
# are gone. This prevents the hang where Hetzner waits for attachments.
DESTROY_PREFIXES_POST_S3=(
  hcloud_network_subnet
  hcloud_network.
)

# shellcheck disable=SC1091
source "${_script_dir}/../common/destroy-without-volume-driver.sh"
