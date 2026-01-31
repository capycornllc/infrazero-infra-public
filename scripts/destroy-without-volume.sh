#!/usr/bin/env bash
set -euo pipefail

existing=$(tofu state list 2>/dev/null || true)

if [ -z "$existing" ]; then
  echo "No state found; skipping destroy"
  exit 0
fi

destroy_targets() {
  local targets=()
  for res in "$@"; do
    if echo "$existing" | grep -qx "$res"; then
      targets+=("-target=${res}")
    fi
  done

  if [ ${#targets[@]} -eq 0 ]; then
    return 0
  fi

  local var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi

  tofu destroy -auto-approve "${var_args[@]}" "${targets[@]}"
}

destroy_targets_prefix() {
  local prefix="$1"
  local targets=()
  while IFS= read -r res; do
    if [[ "$res" == ${prefix}* ]]; then
      targets+=("-target=${res}")
    fi
  done <<< "$existing"

  if [ ${#targets[@]} -eq 0 ]; then
    return 0
  fi

  local var_args=()
  if [ -n "${TOFU_VAR_FILE:-}" ]; then
    var_args+=("-var-file=${TOFU_VAR_FILE}")
  elif [ -f "tofu.tfvars.json" ]; then
    var_args+=("-var-file=tofu.tfvars.json")
  fi

  tofu destroy -auto-approve "${var_args[@]}" "${targets[@]}"
}

destroy_targets \
  hcloud_load_balancer_service.http \
  hcloud_load_balancer_service.https \
  hcloud_load_balancer_target.k3s_server

destroy_targets hcloud_load_balancer_network.main
destroy_targets hcloud_load_balancer.main
destroy_targets \
  hcloud_server.bastion \
  hcloud_server.egress \
  hcloud_server.db
destroy_targets_prefix hcloud_server.k3s

destroy_targets \
  hcloud_firewall.bastion \
  hcloud_firewall.egress \
  hcloud_firewall.k3s_server \
  hcloud_firewall.k3s_agent \
  hcloud_firewall.db

destroy_targets \
  hcloud_placement_group.bastion \
  hcloud_placement_group.egress \
  hcloud_placement_group.k3s \
  hcloud_placement_group.db

destroy_targets hcloud_network_subnet.main
destroy_targets hcloud_network.main
