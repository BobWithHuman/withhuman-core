output "private_ip" {
  value = aws_instance.neo4j.private_ip
}

output "http_url" {
  description = "Value for the chart's neo4j.httpUrl."
  value       = "http://${aws_instance.neo4j.private_ip}:7474"
}

output "bolt_url" {
  description = "Value for the chart's neo4j.boltUrl."
  value       = "bolt://${aws_instance.neo4j.private_ip}:7687"
}

output "instance_id" {
  description = "For Session Manager: aws ssm start-session --target <id>."
  value       = aws_instance.neo4j.id
}
