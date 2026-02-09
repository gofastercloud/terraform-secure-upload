variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "sftp_server_id" {
  description = "ID of the existing Transfer Family server."
  type        = string
}

variable "sftp_users" {
  description = "SFTP users to provision on the existing server."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = optional(string, "/")
  }))
  default = []
}
