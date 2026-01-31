locals {
  lb_services = { for svc in var.load_balancer.services : svc.name => svc }

  lb_private_cidr = can(regex("/", var.load_balancer.private_ip)) ? var.load_balancer.private_ip : "${var.load_balancer.private_ip}/32"
  bastion_cidr    = "${var.servers.bastion.private_ip}/32"
  db_cidr         = "${var.servers.db.private_ip}/32"

  ssh_keys_map = { for idx, key in var.ssh_public_keys : idx => key }
  ssh_key_ids  = [for key in values(hcloud_ssh_key.ops) : key.id]

  k3s_nodes_map         = { for idx, node in var.k3s_nodes : tostring(idx) => node }
  k3s_node_cidrs        = [for node in var.k3s_nodes : "${node.private_ip}/32"]
  k3s_server_key        = "0"
  k3s_server_private_ip = var.k3s_nodes[0].private_ip
  k3s_server_cidr       = "${var.k3s_nodes[0].private_ip}/32"
  k3s_agent_cidrs       = length(var.k3s_nodes) > 1 ? [for node in slice(var.k3s_nodes, 1, length(var.k3s_nodes)) : "${node.private_ip}/32"] : []

  egress_env_lines = [
    for key, value in var.egress_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]

  bastion_env_lines = [
    for key, value in var.bastion_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]
}
