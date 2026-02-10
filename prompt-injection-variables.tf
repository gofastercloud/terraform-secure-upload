################################################################################
# Prompt Injection Scanning
################################################################################

variable "enable_prompt_injection_scanning" {
  description = "Enable prompt injection scanning of uploaded documents. When true, files that pass GuardDuty malware scanning are additionally scanned for prompt injection attacks before being routed to the egress bucket."
  type        = bool
  default     = false
}

variable "prompt_injection_threshold" {
  description = "Score threshold (0–100) above which a file is quarantined for prompt injection. The scanner model outputs a probability score; files scoring above this threshold are treated as prompt injection attempts."
  type        = number
  default     = 80

  validation {
    condition     = var.prompt_injection_threshold >= 0 && var.prompt_injection_threshold <= 100
    error_message = "prompt_injection_threshold must be between 0 and 100."
  }
}

variable "prompt_injection_memory_size" {
  description = "Memory (MB) allocated to the prompt injection scanner Lambda function. Higher memory also allocates more CPU, which speeds up ONNX model loading on cold start. 3008 MB is recommended (default Lambda account limit)."
  type        = number
  default     = 3008

  validation {
    condition     = var.prompt_injection_memory_size >= 512 && var.prompt_injection_memory_size <= 10240
    error_message = "prompt_injection_memory_size must be between 512 and 10240 MB."
  }
}

variable "prompt_injection_timeout" {
  description = "Timeout (seconds) for the prompt injection scanner Lambda function."
  type        = number
  default     = 120

  validation {
    condition     = var.prompt_injection_timeout >= 1 && var.prompt_injection_timeout <= 900
    error_message = "prompt_injection_timeout must be between 1 and 900 seconds."
  }
}

variable "prompt_injection_reserved_concurrency" {
  description = "Reserved concurrent executions for the prompt injection scanner Lambda function. Set to -1 to use unreserved account concurrency."
  type        = number
  default     = 5

  validation {
    condition     = var.prompt_injection_reserved_concurrency == -1 || var.prompt_injection_reserved_concurrency >= 1
    error_message = "prompt_injection_reserved_concurrency must be -1 (unreserved) or at least 1."
  }
}

variable "prompt_injection_image_uri" {
  description = "URI of a pre-built container image for the prompt injection scanner Lambda. When set, the module skips creating an ECR repository and building the image."
  type        = string
  default     = null

  validation {
    condition     = var.prompt_injection_image_uri == null || can(regex("^[0-9]+\\.dkr\\.ecr\\.", var.prompt_injection_image_uri))
    error_message = "prompt_injection_image_uri must be a valid ECR image URI (e.g. 123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag)."
  }
}
