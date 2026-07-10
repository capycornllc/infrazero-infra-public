output "rendered_bastion" {
  value     = local.cloud_init_rendered_bastion
  sensitive = true
}

output "rendered_egress" {
  value     = local.cloud_init_rendered_egress
  sensitive = true
}

output "rendered_db" {
  value     = local.cloud_init_rendered_db
  sensitive = true
}

output "rendered_db_replica" {
  value     = local.cloud_init_rendered_db_replica
  sensitive = true
}

output "rendered_k3s" {
  description = "Map of k3s node key -> rendered cloud-init."
  value       = local.cloud_init_rendered_k3s
  sensitive   = true
}

output "rendered_pgbouncer" {
  value     = local.cloud_init_rendered_pgbouncer
  sensitive = true
}

output "k3s_bootstrap_roles" {
  description = "Map of k3s node key -> bootstrap role (node1/nodecp/node2)."
  value       = local.k3s_bootstrap_roles
}
