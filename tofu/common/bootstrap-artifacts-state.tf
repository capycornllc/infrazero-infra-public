# Shared across ALL provider roots. CANONICAL SOURCE: tofu/common/bootstrap-artifacts-state.tf
# Copies in tofu/<provider>/ are generated - do not edit them directly;
# run scripts/common/sync-tofu-common.sh after changing the canonical file.

resource "terraform_data" "bootstrap_artifacts" {
  # Persist the currently-applied bootstrap manifest in state so rebuild workflows
  # can reuse non-target roles without changing their user_data (changing it forces
  # server replacement on the cloud providers).
  input = var.bootstrap_artifacts
}

output "bootstrap_artifacts" {
  value     = terraform_data.bootstrap_artifacts.output
  sensitive = true
}
