resource "terraform_data" "bootstrap_artifacts" {
  # Persist the currently-applied bootstrap manifest in state so rebuild workflows
  # can reuse non-target roles without changing their user_data (which forces
  # server replacement in the Hetzner provider).
  input = var.bootstrap_artifacts
}

output "bootstrap_artifacts" {
  value     = terraform_data.bootstrap_artifacts.output
  sensitive = true
}

