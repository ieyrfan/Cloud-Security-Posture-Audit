# ----------------------------------------------------------------------------------------------------------------------
# Remote State Backend Configuration
# ----------------------------------------------------------------------------------------------------------------------
# Stores Terraform state in S3 with DynamoDB locking for team collaboration.
# ----------------------------------------------------------------------------------------------------------------------

terraform {
  backend "s3" {
    bucket         = "company-terraform-state-123456789012"
    key            = "cloud-security-posture-audit/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    kms_key_id     = "alias/terraform-state-key"
  }

  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Provider Configuration
# ----------------------------------------------------------------------------------------------------------------------
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Project     = "cloud-security-posture-audit"
    }
  }
}

provider "random" {
  # No configuration needed
}
