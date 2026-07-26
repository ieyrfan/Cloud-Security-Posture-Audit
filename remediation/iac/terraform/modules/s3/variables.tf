# ----------------------------------------------------------------------------------------------------------------------
# S3 Module Variables
# ----------------------------------------------------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
}

variable "bucket_name" {
  description = "Name of the S3 bucket (null auto-generates)"
  type        = string
  default     = null
}

variable "bucket_suffix" {
  description = "Suffix for auto-generating bucket name"
  type        = string
  default     = "artifacts"
}

variable "log_bucket_name" {
  description = "Name of the access logging bucket (null auto-generates)"
  type        = string
  default     = null
}

variable "create_kms_key" {
  description = "Create a KMS key for S3 encryption (false to use existing kms_key_arn)"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN of existing KMS key for S3 encryption (used when create_kms_key = false)"
  type        = string
  default     = null
}

variable "enable_mfa_delete" {
  description = "Enable MFA delete on versioning (requires MFA token to delete versions)"
  type        = bool
  default     = false
}

variable "enable_access_logging" {
  description = "Enable S3 access logging to a separate log bucket"
  type        = bool
  default     = true
}

variable "access_log_expiration_days" {
  description = "Number of days to retain access logs"
  type        = number
  default     = 365
}

variable "attach_bucket_policy" {
  description = "Attach a bucket policy enforcing HTTPS-only access"
  type        = bool
  default     = true
}

variable "enable_cors" {
  description = "Enable CORS configuration on the bucket"
  type        = bool
  default     = false
}

variable "cors_rules" {
  description = "List of CORS rules (used when enable_cors = true)"
  type = list(object({
    allowed_headers = list(string)
    allowed_methods = list(string)
    allowed_origins = list(string)
    expose_headers  = list(string)
    max_age_seconds = number
  }))
  default = []
}

variable "lifecycle_rules" {
  description = "List of lifecycle configuration rules"
  type = list(object({
    id      = string
    enabled = bool
    prefix  = optional(string)
    tags    = optional(map(string))
    expiration = optional(object({
      days = number
    }))
    transitions = optional(list(object({
      days          = number
      storage_class = string
    })))
    noncurrent_version_transitions = optional(list(object({
      days          = number
      storage_class = string
    })))
    noncurrent_version_expiration = optional(object({
      days = number
    }))
  }))
  default = [
    {
      id      = "standard-ia-transition"
      enabled = true
      prefix  = ""
      transitions = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]
      expiration = null
      noncurrent_version_transitions = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        }
      ]
      noncurrent_version_expiration = {
        days = 365
      }
    }
  ]
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
