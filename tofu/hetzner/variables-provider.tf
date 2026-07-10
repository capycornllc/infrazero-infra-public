# Hetzner-specific variable declarations.
# Common variables live in variables-common.tf (synced from tofu/common/).

variable "network_zone" {
  type = string
}

variable "server_image" {
  type = string
}

variable "pgbouncer_server_type" {
  type    = string
  default = "cx23"
}

variable "hcloud_token" {
  type      = string
  sensitive = true
}
