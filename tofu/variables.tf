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
      type        = string
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
    egress = object({
      type        = string
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
    node1 = object({
      type        = string
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
    node2 = object({
      type        = string
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
    db = object({
      type        = string
      private_ip  = string
      public_ipv4 = bool
      public_ipv6 = bool
    })
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
    enabled      = bool
    listen_port  = number
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

variable "db_backup_age_private_key" {
  type      = string
  sensitive = true
}

variable "hcloud_token" {
  type      = string
  sensitive = true
}
