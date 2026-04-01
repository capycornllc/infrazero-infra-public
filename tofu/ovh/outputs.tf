output "bastion_public_ipv4" {
  value = openstack_networking_floatingip_v2.bastion.address
}

output "egress_public_ipv4" {
  value = openstack_networking_floatingip_v2.egress.address
}

output "load_balancer_public_ipv4" {
  value = openstack_networking_floatingip_v2.lb.address
}

output "k3s_api_load_balancer_private_ipv4" {
  value = local.k3s_ha_enabled ? local.k3s_api_lb_private_ip : ""
}

output "private_ips" {
  value = {
    bastion   = var.servers.bastion.private_ip
    egress    = var.servers.egress.private_ip
    k3s_nodes = [for node in var.k3s_nodes : node.private_ip]
    db        = var.servers.db.private_ip
  }
}

output "db_volume_id" {
  value = openstack_blockstorage_volume_v3.db.id
}

output "db_replica_private_ips" {
  value = [for key, replica in local.db_replicas_map : replica.private_ip]
}

output "pgbouncer_private_ip" {
  value = local.pgbouncer_enabled ? try(var.servers.pgbouncer.private_ip, "") : ""
}
