variable "name_prefix" {
  description = "Prefix for all resource names."
  type        = string
}

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "sftp_ingress_server_id" {
  description = "ID of the existing Transfer Family server for ingress."
  type        = string
}

variable "sftp_ingress_users" {
  description = "Ingress SFTP users. home_directory_prefix must start/end with / and contain at least one path component (e.g. /uploads/partner-a/)."
  type = list(object({
    username              = string
    ssh_public_key        = string
    home_directory_prefix = string
  }))
  default = []
}
