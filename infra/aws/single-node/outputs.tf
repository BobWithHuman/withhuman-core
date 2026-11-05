output "url" {
  value = "https://${var.domain_name}"
}

output "instance_id" {
  description = "Use with aws ssm start-session --target <id>."
  value       = module.engine.instance_id
}

output "jev_secret_arn" {
  description = "Set this secret's value to the Jev API key before starting the service."
  value       = aws_secretsmanager_secret.jev.arn
}

output "engine_secret_arn" {
  value = aws_secretsmanager_secret.engine.arn
}
