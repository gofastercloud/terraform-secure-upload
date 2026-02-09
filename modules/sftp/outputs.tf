output "server_id" {
  description = "The ID of the Transfer Family server"
  value       = local.server_id
}

output "server_endpoint" {
  description = "The endpoint of the Transfer Family server"
  value       = var.create_sftp_server ? aws_transfer_server.this[0].endpoint : null
}

output "user_arns" {
  description = "Map of SFTP username to Transfer user ARN"
  value       = { for k, v in aws_transfer_user.this : k => v.arn }
}
