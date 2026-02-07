variable "project" {
  type = string
}

variable "environment" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "location" {
  type = string
}

variable "network_zone" {
  type = string
}

variable "private_cidr" {
  type = string
}

variable "server_image" {
  type = string
}

variable "servers" {
  type = object({
    bastion = object({
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
    egress = object({
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
    db = object({
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
  })
}

variable "k3s_nodes" {
  type = list(object({
    private_ip  = string
    public_ipv4 = bool
    public_ipv6 = bool
  }))

  validation {
    condition     = length(var.k3s_nodes) >= 1
    error_message = "k3s_nodes must include at least one node."
  }
}

variable "k3s_control_planes_count" {
  type = number

  validation {
    condition     = contains([1, 3, 5], var.k3s_control_planes_count)
    error_message = "k3s_control_planes_count must be one of: 1, 3, 5."
  }

  validation {
    condition     = var.k3s_control_planes_count >= 1 && var.k3s_control_planes_count <= length(var.k3s_nodes)
    error_message = "k3s_control_planes_count must be between 1 and the number of k3s_nodes."
  }
}

variable "k3s_api_load_balancer" {
  type = object({
    type       = string
    private_ip = string
  })
}

variable "load_balancer" {
  type = object({
    type       = string
    private_ip = string
    services = list(object({
      name             = string
      protocol         = string
      listen_port      = number
      destination_port = number
    }))
    health_check = object({
      protocol = string
      port     = number
      interval = number
      timeout  = number
      retries  = number
    })
  })
}

variable "db_volume" {
  type = object({
    name   = string
    size   = number
    format = string
  })
}

variable "placement_groups" {
  type = object({
    enabled = bool
    type    = string
  })
}

variable "wireguard" {
  type = object({
    enabled       = bool
    listen_port   = number
    allowed_cidrs = list(string)
  })
}

variable "k3s" {
  type = object({
    token_name   = string
    server_taint = bool
  })
}

variable "s3_backend" {
  type = object({
    state_prefix = string
  })
}

variable "bootstrap" {
  type = object({
    presign_expiry_seconds = number
  })
}

variable "bastion_server_type" {
  type = string
}

variable "egress_server_type" {
  type = string
}

variable "db_server_type" {
  type = string
}

variable "k3s_node_server_type" {
  type = string
}

variable "bootstrap_artifacts" {
  type = map(object({
    url    = string
    sha256 = string
  }))
}

variable "ssh_public_keys" {
  type = list(string)
}

variable "admin_users_json_b64" {
  type = string
}

variable "debug_root_password" {
  type      = string
  default   = ""
  sensitive = true
}

variable "bastion_cloud_init" {
  type      = string
  default   = ""
  sensitive = true

  validation {
    condition     = trimspace(var.bastion_cloud_init) == "" || can(merge(yamldecode(var.bastion_cloud_init), {}))
    error_message = "bastion_cloud_init must be empty or a YAML mapping (cloud-init snippet)."
  }
}

variable "egress_cloud_init" {
  type      = string
  default   = ""
  sensitive = true

  validation {
    condition     = trimspace(var.egress_cloud_init) == "" || can(merge(yamldecode(var.egress_cloud_init), {}))
    error_message = "egress_cloud_init must be empty or a YAML mapping (cloud-init snippet)."
  }
}

variable "db_cloud_init" {
  type      = string
  default   = ""
  sensitive = true

  validation {
    condition     = trimspace(var.db_cloud_init) == "" || can(merge(yamldecode(var.db_cloud_init), {}))
    error_message = "db_cloud_init must be empty or a YAML mapping (cloud-init snippet)."
  }
}

variable "node_primary_cloud_init" {
  type      = string
  default   = ""
  sensitive = true

  validation {
    condition     = trimspace(var.node_primary_cloud_init) == "" || can(merge(yamldecode(var.node_primary_cloud_init), {}))
    error_message = "node_primary_cloud_init must be empty or a YAML mapping (cloud-init snippet)."
  }
}

variable "nodes_secondary_cloud_init" {
  type      = string
  default   = ""
  sensitive = true

  validation {
    condition     = trimspace(var.nodes_secondary_cloud_init) == "" || can(merge(yamldecode(var.nodes_secondary_cloud_init), {}))
    error_message = "nodes_secondary_cloud_init must be empty or a YAML mapping (cloud-init snippet)."
  }
}

variable "wg_server_address" {
  type = string
}

variable "egress_secrets" {
  type      = map(string)
  sensitive = true
}

variable "bastion_secrets" {
  type      = map(string)
  sensitive = true
}

variable "db_secrets" {
  type      = map(string)
  sensitive = true
}

variable "k3s_secrets" {
  type      = map(string)
  sensitive = true
}

variable "k3s_server_secrets" {
  type      = map(string)
  sensitive = true
}

variable "k3s_agent_secrets" {
  type      = map(string)
  sensitive = true
}

variable "internal_services_domains" {
  type    = map(object({ fqdn = string }))
  default = {}
}

variable "deployed_apps" {
  type    = any
  default = []
}

variable "infisical_db_backup_age_private_key" {
  type      = string
  sensitive = true
}

variable "databases_json_private_b64" {
  type      = string
  sensitive = true
}

variable "hcloud_token" {
  type      = string
  sensitive = true
}
