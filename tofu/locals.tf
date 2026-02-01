locals {
  lb_services = { for svc in var.load_balancer.services : svc.name => svc }

  lb_private_cidr = can(regex("/", var.load_balancer.private_ip)) ? var.load_balancer.private_ip : "${var.load_balancer.private_ip}/32"
  bastion_cidr    = "${var.servers.bastion.private_ip}/32"
  db_cidr         = "${var.servers.db.private_ip}/32"
  bastion_ssh_cidrs = length(var.debug_root_password) > 0 ? concat(var.wireguard.allowed_cidrs, ["0.0.0.0/0"]) : var.wireguard.allowed_cidrs

  ssh_keys_map = { for idx, key in var.ssh_public_keys : idx => key }
  ssh_key_ids  = [for key in values(hcloud_ssh_key.ops) : key.id]

  k3s_nodes_map         = { for idx, node in var.k3s_nodes : tostring(idx) => node }
  k3s_node_cidrs        = [for node in var.k3s_nodes : "${node.private_ip}/32"]
  k3s_server_key        = "0"
  k3s_server_private_ip = var.k3s_nodes[0].private_ip
  k3s_server_cidr       = "${var.k3s_nodes[0].private_ip}/32"
  k3s_agent_cidrs       = length(var.k3s_nodes) > 1 ? [for node in slice(var.k3s_nodes, 1, length(var.k3s_nodes)) : "${node.private_ip}/32"] : []

  wg_prefix_length = tonumber(split("/", var.wg_server_address)[1])
  wg_network_ip    = cidrhost(var.wg_server_address, 0)
  wg_cidr          = "${local.wg_network_ip}/${local.wg_prefix_length}"
  debug_root_password_escaped = replace(var.debug_root_password, "'", "'\"'\"'")

  egress_env_lines = [
    for key, value in var.egress_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]

  bastion_env_lines = [
    for key, value in var.bastion_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]

  k3s_env_lines = [
    for key, value in var.k3s_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]

  k3s_server_env_lines = [
    for key, value in var.k3s_server_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]

  k3s_agent_env_lines = [
    for key, value in var.k3s_agent_secrets :
    format("%s='%s'", key, replace(value, "'", "'\"'\"'"))
  ]
}
