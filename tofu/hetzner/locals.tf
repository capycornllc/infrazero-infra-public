locals {
  lb_services = { for svc in var.load_balancer.services : svc.name => svc }
  lb_extra_services = {
    for svc in var.load_balancer.services : svc.name => svc
    if svc.name != "http" && svc.name != "https"
  }

  # Ports that the LB should be able to reach on k3s nodes (NodePort destinations + health checks).
  k3s_lb_ports = toset(
    concat(
      [for svc in var.load_balancer.services : tostring(svc.destination_port)],
      [tostring(var.load_balancer.health_check.port)]
    )
  )

  # Accept either an IP (10.0.0.1) or CIDR (10.0.0.1/32) in vars; strip CIDR
  # where an IP is required by the Hetzner API.
  lb_private_ip        = split("/", var.load_balancer.private_ip)[0]
  lb_private_cidr      = can(regex("/", var.load_balancer.private_ip)) ? var.load_balancer.private_ip : "${var.load_balancer.private_ip}/32"
  bastion_cidr         = "${var.servers.bastion.private_ip}/32"
  egress_cidr          = "${var.servers.egress.private_ip}/32"
  db_cidr              = "${var.servers.db.private_ip}/32"
  pgbouncer_enabled    = var.servers.pgbouncer != null
  pgbouncer_cidr       = var.servers.pgbouncer != null ? "${try(var.servers.pgbouncer.private_ip, "")}/32" : ""
  egress_service_cidrs = concat([var.private_cidr], var.wireguard.allowed_cidrs)
  bastion_ssh_cidrs    = length(var.debug_root_password) > 0 ? concat(var.wireguard.allowed_cidrs, ["0.0.0.0/0"]) : var.wireguard.allowed_cidrs

  ssh_keys_map = { for idx, key in var.ssh_public_keys : idx => key }
  ssh_key_ids  = [for key in values(hcloud_ssh_key.ops) : key.id]

  k3s_nodes_map            = { for idx, node in var.k3s_nodes : tostring(idx) => node }
  k3s_node_cidrs           = [for node in var.k3s_nodes : "${node.private_ip}/32"]
  k3s_control_planes_count = var.k3s_control_planes_count
  k3s_ha_enabled           = local.k3s_control_planes_count > 1
  k3s_control_plane_nodes  = slice(var.k3s_nodes, 0, local.k3s_control_planes_count)
  k3s_worker_nodes         = slice(var.k3s_nodes, local.k3s_control_planes_count, length(var.k3s_nodes))
  k3s_control_plane_cidrs  = [for node in local.k3s_control_plane_nodes : "${node.private_ip}/32"]
  k3s_worker_cidrs         = [for node in local.k3s_worker_nodes : "${node.private_ip}/32"]
  k3s_api_lb_private_ip    = split("/", var.k3s_api_load_balancer.private_ip)[0]
  k3s_api_lb_cidr          = can(regex("/", var.k3s_api_load_balancer.private_ip)) ? var.k3s_api_load_balancer.private_ip : "${var.k3s_api_load_balancer.private_ip}/32"
  k3s_server_key           = "0"
  k3s_server_private_ip    = local.k3s_control_plane_nodes[0].private_ip
  k3s_server_cidr          = "${local.k3s_control_plane_nodes[0].private_ip}/32"


  db_replicas_map  = { for idx, replica in var.db_replicas : tostring(idx) => replica }
  db_replica_cidrs = [for replica in var.db_replicas : "${replica.private_ip}/32"]

}
