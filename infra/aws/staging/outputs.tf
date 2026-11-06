output "cluster_name" {
  value = module.eks.cluster_name
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "database_url_secret_arn" {
  description = "Set the PostgreSQL DSN by hand and map this secret to database-url in the engine chart."
  value       = aws_secretsmanager_secret.postgres.arn
}

output "engine_secret_arn" {
  description = "Holds redis-url."
  value       = aws_secretsmanager_secret.engine.arn
}

output "gitops_deploy_key_secret_arn" {
  description = "Set the read-only deploy key of withhuman-gitops: aws secretsmanager put-secret-value --secret-id <arn> --secret-string file://argocd-gitops"
  value       = aws_secretsmanager_secret.gitops_deploy_key.arn
}

output "jev_secret_arn" {
  description = "Set its value with: aws secretsmanager put-secret-value --secret-id <arn> --secret-string <key>"
  value       = aws_secretsmanager_secret.jev.arn
}
