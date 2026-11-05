output "instance_id" {
  description = "For Session Manager: aws ssm start-session --target <id>."
  value       = aws_instance.engine.id
}

output "private_ip" {
  description = "Target address for the load balancer in front of the gateway."
  value       = aws_instance.engine.private_ip
}

output "gateway_port" {
  value = var.gateway_port
}

output "security_group_id" {
  description = "Allow this group on Neo4j or Redis if anything outside the host must reach them."
  value       = aws_security_group.engine.id
}
