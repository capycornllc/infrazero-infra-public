locals {
  lb_services = { for svc in var.load_balancer.services : svc.name => svc }

  lb_private_cidr = can(regex("/", var.load_balancer.private_ip)) ? var.load_balancer.private_ip : "${var.load_balancer.private_ip}/32"
  bastion_cidr    = "${var.servers.bastion.private_ip}/32"
  node1_cidr      = "${var.servers.node1.private_ip}/32"
  node2_cidr      = "${var.servers.node2.private_ip}/32"
  db_cidr         = "${var.servers.db.private_ip}/32"

  ssh_keys_map = { for idx, key in var.ssh_public_keys : idx => key }
  ssh_key_ids  = [for key in values(hcloud_ssh_key.ops) : key.id]

  egress_env_lines = [
    for key, value in var.egress_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]
}
