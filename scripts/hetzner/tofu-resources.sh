#!/usr/bin/env bash
# Provider tofu resource addresses used by the CI build/rebuild workflows.
# Keeps provider-specific resource names out of the workflow YAML, so the
# workflows are identical for every cloud. Adding a cloud = add
# scripts/<cloud>/tofu-resources.sh; the workflows do not change.
#
# Contract (consumed by .github/workflows/*):
#   tofu_server_resource <role>        -> server resource address for a role
#   tofu_replace_extra_targets <role>  -> extra -target resources that must be
#                                         reconciled alongside a server replace
#                                         (space-separated; may be empty)
#   tofu_build_retry_excludes          -> -exclude resources for the build
#                                         LB-ordering retry (space-separated)
# Roles: bastion | egress | db | db_replica | k3s

tofu_server_resource() {
  case "${1:-}" in
    bastion)    echo "hcloud_server.bastion" ;;
    egress)     echo "hcloud_server.egress" ;;
    db)         echo "hcloud_server.db" ;;
    db_replica) echo "hcloud_server.db_replica" ;;
    k3s)        echo "hcloud_server.k3s" ;;
    *) echo "[tofu-resources] unknown role: ${1:-}" >&2; return 1 ;;
  esac
}

tofu_replace_extra_targets() {
  case "${1:-}" in
    db)  echo "hcloud_volume_attachment.db" ;;
    k3s) echo "hcloud_load_balancer_target.k3s hcloud_load_balancer_target.k3s_api" ;;
    *)   echo "" ;;
  esac
}

tofu_build_retry_excludes() {
  echo "hcloud_load_balancer_target.k3s hcloud_load_balancer_target.k3s_api"
}
