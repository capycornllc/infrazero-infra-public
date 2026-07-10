# OVHcloud (OpenStack)-specific variable declarations.
# Common variables live in variables-common.tf (synced from tofu/common/).

variable "server_image" {
  type    = string
  default = "Ubuntu 24.04"
}

variable "server_image_regex" {
  type        = string
  default     = "^Ubuntu 24\\.04"
  description = "Regex to match the OS image name. OVH image names vary by region."
}

variable "pgbouncer_server_type" {
  type    = string
  default = "b2-7"
}

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

variable "ovh_endpoint" {
  type        = string
  default     = "ovh-eu"
  description = "OVH API endpoint: ovh-eu for Europe, ovh-us for US"
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

variable "ovh_ext_net_name" {
  type        = string
  default     = "Ext-Net"
  description = "OVH Public Cloud external network name (Ext-Net in most regions)"
}
