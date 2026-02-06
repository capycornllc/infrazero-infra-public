output "bastion_public_ipv4" {
  value = hcloud_server.bastion.ipv4_address
}

output "egress_public_ipv4" {
  value = hcloud_server.egress.ipv4_address
}

output "load_balancer_public_ipv4" {
  value = hcloud_load_balancer.main.ipv4
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
