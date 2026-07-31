variable "aws_region" {
  type = string
}

variable "test_id" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "sftp_vpc_id" {
  type = string
}

variable "sftp_subnet_ids" {
  type = list(string)
}

variable "sftp_address_allocation_ids" {
  type = list(string)
}

variable "sftp_allowed_cidrs" {
  type = list(string)
}

variable "sftp_users_json" {
  type = string
}

variable "sftp_custom_hostname" {
  type    = string
  default = null
}

variable "sftp_route53_hosted_zone_id" {
  type    = string
  default = null
}
