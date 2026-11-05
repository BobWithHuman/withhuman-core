output "secret_store_name" {
  description = "ClusterSecretStore for the engine chart's externalSecret.storeName."
  value       = var.secret_store_name
}

output "external_secrets_service_account" {
  description = "Namespace and name of the External Secrets controller's service account, for the cloud's workload identity."
  value       = { namespace = helm_release.external_secrets.namespace, name = "external-secrets" }
}
