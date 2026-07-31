output "server_id" {
  description = "Transfer Family server ID."
  value       = aws_transfer_server.this.id
}

output "server_endpoint" {
  description = "Transfer Family SFTP endpoint hostname."
  value       = aws_transfer_server.this.endpoint
}

output "hostname" {
  description = "Custom SFTP hostname when configured, otherwise the AWS endpoint hostname."
  value       = coalesce(var.custom_hostname, aws_transfer_server.this.endpoint)
}

output "user_arns" {
  description = "Map of SFTP username to Transfer Family user ARN."
  value       = { for username, user in aws_transfer_user.this : username => user.arn }
}
