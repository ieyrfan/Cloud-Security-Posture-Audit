# ----------------------------------------------------------------------------------------------------------------------
# RDS Module Outputs
# ----------------------------------------------------------------------------------------------------------------------

output "db_instance_id" {
  description = "The RDS instance identifier"
  value       = aws_db_instance.this.id
}

output "db_instance_arn" {
  description = "The ARN of the RDS instance"
  value       = aws_db_instance.this.arn
}

output "db_instance_address" {
  description = "The DNS address of the RDS instance"
  value       = aws_db_instance.this.address
}

output "db_instance_port" {
  description = "The port the RDS instance is listening on"
  value       = aws_db_instance.this.port
}

output "db_instance_endpoint" {
  description = "The connection endpoint"
  value       = aws_db_instance.this.endpoint
}

output "db_name" {
  description = "The database name"
  value       = aws_db_instance.this.db_name
}

output "db_master_username" {
  description = "The master username"
  value       = aws_db_instance.this.username
}

output "db_master_password" {
  description = "The master password (sensitive)"
  value       = aws_db_instance.this.password
  sensitive   = true
}

output "db_subnet_group_name" {
  description = "The DB subnet group name"
  value       = var.create_subnet_group ? aws_db_subnet_group.this[0].name : var.db_subnet_group_name
}

output "db_parameter_group_name" {
  description = "The DB parameter group name"
  value       = var.create_parameter_group ? aws_db_parameter_group.this[0].name : var.parameter_group_name
}

output "security_group_id" {
  description = "The security group ID for the RDS instance"
  value       = var.create_security_group ? aws_security_group.this[0].id : null
}

output "kms_key_arn" {
  description = "The KMS key ARN used for RDS encryption"
  value       = var.create_kms_key ? aws_kms_key.rds[0].arn : var.kms_key_arn
}

output "multi_az" {
  description = "Whether Multi-AZ is enabled"
  value       = aws_db_instance.this.multi_az
}

output "deletion_protection" {
  description = "Whether deletion protection is enabled"
  value       = aws_db_instance.this.deletion_protection
}

output "storage_encrypted" {
  description = "Whether storage encryption is enabled"
  value       = aws_db_instance.this.storage_encrypted
}
