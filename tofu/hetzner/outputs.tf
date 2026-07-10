output "bastion_public_ipv4" {
  value = hcloud_server.bastion.ipv4_address
}

output "egress_public_ipv4" {
  value = hcloud_server.egress.ipv4_address
}

output "egress_private_ipv4" {
  value = var.servers.egress.private_ip
}

output "node1_private_ipv4" {
  value = length(var.k3s_nodes) > 0 ? var.k3s_nodes[0].private_ip : ""
}

output "db_private_ipv4" {
  value = var.servers.db.private_ip
}

output "load_balancer_public_ipv4" {
  value = hcloud_load_balancer.main.ipv4
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
  value = hcloud_volume.db.id
}

output "db_replica_private_ips" {
  value = [for key, replica in local.db_replicas_map : replica.private_ip]
}

output "pgbouncer_private_ip" {
  value = local.pgbouncer_enabled ? try(var.servers.pgbouncer.private_ip, "") : ""
}
