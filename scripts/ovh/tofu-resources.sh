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
    bastion)    echo "openstack_compute_instance_v2.bastion" ;;
    egress)     echo "openstack_compute_instance_v2.egress" ;;
    db)         echo "openstack_compute_instance_v2.db" ;;
    db_replica) echo "openstack_compute_instance_v2.db_replica" ;;
    k3s)        echo "openstack_compute_instance_v2.k3s" ;;
    *) echo "[tofu-resources] unknown role: ${1:-}" >&2; return 1 ;;
  esac
}

tofu_replace_extra_targets() {
  case "${1:-}" in
    # OVH floating IPs live in a SEPARATE resource bound to the instance id.
    # Replacing only the instance detaches the IP forever (the associate
    # resource is outside the target set and never reconciled), so it must be
    # co-targeted with the server replace.
    bastion) echo "openstack_compute_floatingip_associate_v2.bastion" ;;
    egress)  echo "openstack_compute_floatingip_associate_v2.egress" ;;
    db)      echo "openstack_compute_volume_attach_v2.db" ;;
    *)       echo "" ;;
  esac
}

tofu_build_retry_excludes() {
  echo "openstack_lb_member_v2.http openstack_lb_member_v2.https"
}
