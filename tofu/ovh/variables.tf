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
  type        = string
  description = "OVHcloud region (e.g. GRA, SBG, BHS, WAW)"
}

variable "private_cidr" {
  type = string
}

variable "server_image" {
  type    = string
  default = "Ubuntu 24.04"
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
  type        = string
  description = "OVHcloud flavor (e.g. b2-7, b2-15)"
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
}

variable "egress_cloud_init" {
  type      = string
  default   = ""
  sensitive = true
}

variable "db_cloud_init" {
  type      = string
  default   = ""
  sensitive = true
}

variable "node_primary_cloud_init" {
  type      = string
  default   = ""
  sensitive = true
}

variable "nodes_secondary_cloud_init" {
  type      = string
  default   = ""
  sensitive = true
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

variable "db_replicas" {
  type = list(object({
    private_ip  = string
    public_ipv4 = bool
    public_ipv6 = bool
  }))
  default = []
}

variable "db_replica_secrets" {
  type      = map(string)
  default   = {}
  sensitive = true
}

# --- OVH-specific credentials ---

variable "ovh_application_key" {
  type      = string
  sensitive = true
}

variable "ovh_application_secret" {
  type      = string
  sensitive = true
}

variable "ovh_consumer_key" {
  type      = string
  sensitive = true
}

variable "ovh_cloud_project_id" {
  type        = string
  description = "OVHcloud Public Cloud project service name (UUID)"
}

variable "openstack_auth_url" {
  type    = string
  default = "https://auth.cloud.ovh.net/v3"
}

variable "openstack_user_name" {
  type = string
}

variable "openstack_password" {
  type      = string
  sensitive = true
}

variable "openstack_tenant_id" {
  type        = string
  description = "Same as ovh_cloud_project_id for most setups"
}
