locals {
  cloud_init_template_path = "${path.module}/templates/cloud-init.tftpl"

  # Extra cloud-init YAML snippets per role (optional).
  # We parse these as YAML maps and then merge into the base config while
  # concatenating list keys we care about so we don't accidentally replace them.
  cloud_init_extra_bastion = length(trimspace(var.bastion_cloud_init)) > 0 ? yamldecode(var.bastion_cloud_init) : {}
  cloud_init_extra_egress  = length(trimspace(var.egress_cloud_init)) > 0 ? yamldecode(var.egress_cloud_init) : {}
  cloud_init_extra_db      = length(trimspace(var.db_cloud_init)) > 0 ? yamldecode(var.db_cloud_init) : {}

  cloud_init_extra_node_primary    = length(trimspace(var.node_primary_cloud_init)) > 0 ? yamldecode(var.node_primary_cloud_init) : {}
  cloud_init_extra_nodes_secondary = length(trimspace(var.nodes_secondary_cloud_init)) > 0 ? yamldecode(var.nodes_secondary_cloud_init) : {}

  cloud_init_base_bastion = yamldecode(
    templatefile(local.cloud_init_template_path, {
      bootstrap_role            = "bastion"
      bootstrap_url             = var.bootstrap_artifacts["bastion"].url
      bootstrap_sha256          = var.bootstrap_artifacts["bastion"].sha256
      db_volume_name            = var.db_volume.name
      db_volume_format          = var.db_volume.format
      private_cidr              = var.private_cidr
      bastion_private_ip        = var.servers.bastion.private_ip
      wg_server_address         = var.wg_server_address
      wg_cidr                   = var.wireguard.allowed_cidrs[0]
      admin_users_json_b64      = var.admin_users_json_b64
      debug_root_password       = local.debug_root_password_escaped
      egress_env                = []
      infisical_db_backup_age_private_key = ""
      databases_json_private_b64          = ""
      bastion_env = concat(local.bastion_env_lines, [
        format("EGRESS_PRIVATE_IP='%s'", var.servers.egress.private_ip),
        format("EGRESS_LOKI_URL='http://%s:3100/loki/api/v1/push'", var.servers.egress.private_ip),
      ])
      node_env      = []
      node_role_env = []
    })
  )

  cloud_init_base_egress = yamldecode(
    templatefile(local.cloud_init_template_path, {
      bootstrap_role            = "egress"
      bootstrap_url             = var.bootstrap_artifacts["egress"].url
      bootstrap_sha256          = var.bootstrap_artifacts["egress"].sha256
      db_volume_name            = var.db_volume.name
      db_volume_format          = var.db_volume.format
      private_cidr              = var.private_cidr
      bastion_private_ip        = var.servers.bastion.private_ip
      wg_server_address         = var.wg_server_address
      wg_cidr                   = var.wireguard.allowed_cidrs[0]
      admin_users_json_b64      = var.admin_users_json_b64
      debug_root_password       = local.debug_root_password_escaped
      egress_env                = local.egress_env_lines
      infisical_db_backup_age_private_key = var.infisical_db_backup_age_private_key
      databases_json_private_b64          = ""
      bastion_env               = []
      node_env                  = []
      node_role_env             = []
    })
  )

  cloud_init_base_db = yamldecode(
    templatefile(local.cloud_init_template_path, {
      bootstrap_role            = "db"
      bootstrap_url             = var.bootstrap_artifacts["db"].url
      bootstrap_sha256          = var.bootstrap_artifacts["db"].sha256
      db_volume_name            = var.db_volume.name
      db_volume_format          = var.db_volume.format
      private_cidr              = var.private_cidr
      bastion_private_ip        = var.servers.bastion.private_ip
      wg_server_address         = var.wg_server_address
      wg_cidr                   = var.wireguard.allowed_cidrs[0]
      admin_users_json_b64      = var.admin_users_json_b64
      debug_root_password       = local.debug_root_password_escaped
      egress_env                = []
      infisical_db_backup_age_private_key = ""
      databases_json_private_b64          = var.databases_json_private_b64
      bastion_env               = []
      node_env                  = []
      node_role_env             = local.db_env_lines
    })
  )

  cloud_init_merged_bastion = merge(local.cloud_init_base_bastion, local.cloud_init_extra_bastion, {
    packages    = distinct(concat(try(local.cloud_init_base_bastion.packages, []), try(local.cloud_init_extra_bastion.packages, [])))
    write_files = concat(try(local.cloud_init_base_bastion.write_files, []), try(local.cloud_init_extra_bastion.write_files, []))
    runcmd      = concat(try(local.cloud_init_base_bastion.runcmd, []), try(local.cloud_init_extra_bastion.runcmd, []))
  })

  cloud_init_merged_egress = merge(local.cloud_init_base_egress, local.cloud_init_extra_egress, {
    packages    = distinct(concat(try(local.cloud_init_base_egress.packages, []), try(local.cloud_init_extra_egress.packages, [])))
    write_files = concat(try(local.cloud_init_base_egress.write_files, []), try(local.cloud_init_extra_egress.write_files, []))
    runcmd      = concat(try(local.cloud_init_base_egress.runcmd, []), try(local.cloud_init_extra_egress.runcmd, []))
  })

  cloud_init_merged_db = merge(local.cloud_init_base_db, local.cloud_init_extra_db, {
    packages    = distinct(concat(try(local.cloud_init_base_db.packages, []), try(local.cloud_init_extra_db.packages, [])))
    write_files = concat(try(local.cloud_init_base_db.write_files, []), try(local.cloud_init_extra_db.write_files, []))
    runcmd      = concat(try(local.cloud_init_base_db.runcmd, []), try(local.cloud_init_extra_db.runcmd, []))
  })

  cloud_init_rendered_bastion = "#cloud-config\n${yamlencode(local.cloud_init_merged_bastion)}"
  cloud_init_rendered_egress  = "#cloud-config\n${yamlencode(local.cloud_init_merged_egress)}"
  cloud_init_rendered_db      = "#cloud-config\n${yamlencode(local.cloud_init_merged_db)}"

  cloud_init_base_k3s = {
    for key, node in local.k3s_nodes_map : key => yamldecode(
      templatefile(local.cloud_init_template_path, {
        bootstrap_role            = key == local.k3s_server_key ? "node1" : "node2"
        bootstrap_url             = var.bootstrap_artifacts[key == local.k3s_server_key ? "node1" : "node2"].url
        bootstrap_sha256          = var.bootstrap_artifacts[key == local.k3s_server_key ? "node1" : "node2"].sha256
        db_volume_name            = var.db_volume.name
        db_volume_format          = var.db_volume.format
        private_cidr              = var.private_cidr
        bastion_private_ip        = var.servers.bastion.private_ip
        wg_server_address         = var.wg_server_address
        wg_cidr                   = var.wireguard.allowed_cidrs[0]
        admin_users_json_b64      = var.admin_users_json_b64
        debug_root_password       = local.debug_root_password_escaped
        egress_env                = []
        infisical_db_backup_age_private_key = ""
        databases_json_private_b64          = ""
        bastion_env               = []
        node_env                  = local.k3s_env_lines
        node_role_env             = key == local.k3s_server_key ? local.k3s_server_env_lines : local.k3s_agent_env_lines
      })
    )
  }

  cloud_init_extra_k3s = {
    for key, _node in local.k3s_nodes_map :
    key => (key == local.k3s_server_key ? local.cloud_init_extra_node_primary : local.cloud_init_extra_nodes_secondary)
  }

  cloud_init_merged_k3s = {
    for key, base in local.cloud_init_base_k3s :
    key => merge(base, local.cloud_init_extra_k3s[key], {
      packages    = distinct(concat(try(base.packages, []), try(local.cloud_init_extra_k3s[key].packages, [])))
      write_files = concat(try(base.write_files, []), try(local.cloud_init_extra_k3s[key].write_files, []))
      runcmd      = concat(try(base.runcmd, []), try(local.cloud_init_extra_k3s[key].runcmd, []))
    })
  }

  cloud_init_rendered_k3s = {
    for key, cfg in local.cloud_init_merged_k3s :
    key => "#cloud-config\n${yamlencode(cfg)}"
  }
}
