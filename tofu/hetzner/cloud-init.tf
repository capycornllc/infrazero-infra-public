# Cloud-init rendering is shared across providers - see tofu/modules/cloud-init.
# This file only passes provider deltas and re-exports the rendered results
# under the local names used by main.tf.

module "cloud_init" {
  source = "../modules/cloud-init"

  route_mode = "hetzner-32"

  bootstrap_artifacts                 = var.bootstrap_artifacts
  db_volume                           = var.db_volume
  private_cidr                        = var.private_cidr
  servers                             = var.servers
  wg_server_address                   = var.wg_server_address
  wireguard                           = var.wireguard
  admin_users_json_b64                = var.admin_users_json_b64
  debug_root_password                 = var.debug_root_password
  bastion_cloud_init                  = var.bastion_cloud_init
  egress_cloud_init                   = var.egress_cloud_init
  db_cloud_init                       = var.db_cloud_init
  node_primary_cloud_init             = var.node_primary_cloud_init
  nodes_secondary_cloud_init          = var.nodes_secondary_cloud_init
  pgbouncer_cloud_init                = var.pgbouncer_cloud_init
  infisical_db_backup_age_private_key = var.infisical_db_backup_age_private_key
  databases_json_private_b64          = var.databases_json_private_b64
  db_replicas                         = var.db_replicas
  k3s_nodes                           = var.k3s_nodes
  k3s_control_planes_count            = var.k3s_control_planes_count
  egress_secrets                      = var.egress_secrets
  bastion_secrets                     = var.bastion_secrets
  db_secrets                          = var.db_secrets
  k3s_secrets                         = var.k3s_secrets
  k3s_server_secrets                  = var.k3s_server_secrets
  k3s_agent_secrets                   = var.k3s_agent_secrets
  db_replica_secrets                  = var.db_replica_secrets
  pgbouncer_secrets                   = var.pgbouncer_secrets

  # Hetzner: bastion and egress need the egress private IP for policy routing.
  extra_bastion_env = [
    format("EGRESS_PRIVATE_IP='%s'", var.servers.egress.private_ip),
  ]
  extra_egress_env = [
    format("EGRESS_PRIVATE_IP='%s'", var.servers.egress.private_ip),
  ]
  include_pgbouncer_env_in_db_role = false
}

locals {
  cloud_init_rendered_bastion    = module.cloud_init.rendered_bastion
  cloud_init_rendered_egress     = module.cloud_init.rendered_egress
  cloud_init_rendered_db         = module.cloud_init.rendered_db
  cloud_init_rendered_db_replica = module.cloud_init.rendered_db_replica
  cloud_init_rendered_k3s        = module.cloud_init.rendered_k3s
  cloud_init_rendered_pgbouncer  = module.cloud_init.rendered_pgbouncer
}
