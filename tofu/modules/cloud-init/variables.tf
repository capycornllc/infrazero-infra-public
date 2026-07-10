# Inputs of the shared cloud-init rendering module. Mirrors the root
# variable declarations (see tofu/common/variables-common.tf); provider roots
# pass these through unchanged.

variable "bootstrap_artifacts" {
  type = map(object({
    url    = string
    sha256 = string
  }))
}

variable "db_volume" {
  type = object({
    name   = string
    size   = number
    format = string
  })
}

variable "private_cidr" {
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
    pgbouncer = optional(object({
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    }))
  })
}

variable "wg_server_address" {
  type = string
}

variable "wireguard" {
  type = object({
    enabled       = bool
    listen_port   = number
    allowed_cidrs = list(string)
  })
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

variable "pgbouncer_cloud_init" {
  type      = string
  default   = ""
  sensitive = true

  validation {
    condition     = trimspace(var.pgbouncer_cloud_init) == "" || can(merge(yamldecode(var.pgbouncer_cloud_init), {}))
    error_message = "pgbouncer_cloud_init must be empty or a YAML mapping (cloud-init snippet)."
  }
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

variable "db_replica_secrets" {
  type      = map(string)
  default   = {}
  sensitive = true
}

variable "pgbouncer_secrets" {
  type      = map(string)
  default   = {}
  sensitive = true
}

# --- Provider-specific knobs (set by each provider root) ---------------------

variable "route_mode" {
  type        = string
  description = "Provider route mode (see docs/provider-adapter-contract.md): hetzner-32, ovh-dhcp or none. Gates the /32 default-route-repair bootcmd."

  validation {
    condition     = contains(["hetzner-32", "ovh-dhcp", "none"], var.route_mode)
    error_message = "route_mode must be one of: hetzner-32, ovh-dhcp, none."
  }
}

variable "extra_bastion_env" {
  type        = list(string)
  default     = []
  sensitive   = true
  description = "Provider-specific extra lines for bastion.env (e.g. EGRESS_PRIVATE_IP on Hetzner)."
}

variable "extra_egress_env" {
  type        = list(string)
  default     = []
  sensitive   = true
  description = "Provider-specific extra lines for egress.env (e.g. EGRESS_PRIVATE_IP on Hetzner)."
}

variable "include_pgbouncer_env_in_db_role" {
  type        = bool
  default     = false
  description = "Append pgbouncer env lines to the db role env (OVH behavior)."
}
