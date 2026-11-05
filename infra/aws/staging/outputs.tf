output "cluster_name" {
  value = module.eks.cluster_name
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "neo4j_http_url" {
  description = "neo4j.httpUrl in withhuman-gitops envs/staging/values.yaml."
  value       = module.neo4j.http_url
}

output "neo4j_bolt_url" {
  description = "neo4j.boltUrl in withhuman-gitops envs/staging/values.yaml."
  value       = module.neo4j.bolt_url
}

output "neo4j_instance_id" {
  value = module.neo4j.instance_id
}

output "engine_secret_arn" {
  description = "Holds neo4j-password and redis-url."
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
