# ----------------------------------------------------------------------------------------------------------------------
# VPC Module - Production-grade VPC with security best practices
# ----------------------------------------------------------------------------------------------------------------------
# Creates a VPC with public/private subnets across 2 AZs, NAT Gateway, VPC Flow Logs,
# and a default security group that denies all ingress/egress.
# ----------------------------------------------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# Local variables
# ----------------------------------------------------------------------------------------------------------------------
locals {
  vpc_name = format("%s-vpc", var.environment)

  # Derive subnet names: public/private per AZ
  public_subnet_names  = [for i, az in var.availability_zones : format("%s-public-%s", var.environment, az)]
  private_subnet_names = [for i, az in var.availability_zones : format("%s-private-%s", var.environment, az)]

  # Common tags applied to all resources
  common_tags = merge(
    var.tags,
    {
      Environment = var.environment
      ManagedBy   = "terraform"
      Module      = "vpc"
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# VPC
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"

  tags = merge(
    local.common_tags,
    {
      Name = local.vpc_name
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Public subnets
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    local.common_tags,
    {
      Name                                          = local.public_subnet_names[count.index]
      Tier                                          = "public"
      "kubernetes.io/role/elb"                      = "1"
      "kubernetes.io/cluster/\"    = "shared"
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Private subnets
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + length(var.availability_zones))
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = merge(
    local.common_tags,
    {
      Name                                          = local.private_subnet_names[count.index]
      Tier                                          = "private"
      "kubernetes.io/role/internal-elb"             = "1"
      "kubernetes.io/cluster/\"    = "shared"
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Internet Gateway
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-igw", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Elastic IP for NAT Gateway(s)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_eip" "nat" {
  count = var.single_nat_gateway ? 1 : length(var.availability_zones)

  domain = "vpc"

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-nat-eip-%d", var.environment, count.index + 1)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# NAT Gateway(s) - one per AZ, or single for cost savings
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_nat_gateway" "this" {
  count = var.single_nat_gateway ? 1 : length(var.availability_zones)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(
    local.common_tags,
    {
      Name = var.single_nat_gateway
        ? format("%s-nat", var.environment)
        : format("%s-nat-%s", var.environment, var.availability_zones[count.index])
    }
  )

  depends_on = [aws_internet_gateway.this]
}

# ----------------------------------------------------------------------------------------------------------------------
# Public route table (routes traffic to IGW)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-public-rt", var.environment)
    }
  )
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ----------------------------------------------------------------------------------------------------------------------
# Private route tables (routes traffic to NAT Gateway)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_route_table" "private" {
  count = var.single_nat_gateway ? 1 : length(var.availability_zones)

  vpc_id = aws_vpc.this.id

  tags = merge(
    local.common_tags,
    {
      Name = var.single_nat_gateway
        ? format("%s-private-rt", var.environment)
        : format("%s-private-rt-%s", var.environment, var.availability_zones[count.index])
    }
  )
}

resource "aws_route" "private_nat_gateway" {
  count = var.single_nat_gateway ? 1 : length(var.availability_zones)

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[count.index].id
}

resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)

  subnet_id = aws_subnet.private[count.index].id

  route_table_id = var.single_nat_gateway
    ? aws_route_table.private[0].id
    : aws_route_table.private[count.index].id
}

# ----------------------------------------------------------------------------------------------------------------------
# VPC Flow Logs - IAM Role
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_iam_role" "flow_logs" {
  name = format("%s-vpc-flow-logs-role", var.environment)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = format("%s-vpc-flow-logs-policy", var.environment)
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# ----------------------------------------------------------------------------------------------------------------------
# VPC Flow Logs - CloudWatch Log Group
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = format("/aws/vpc/flow-logs/%s", var.environment)
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = var.flow_logs_kms_key_id != null ? var.flow_logs_kms_key_id : null

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-vpc-flow-logs", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# VPC Flow Logs
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_flow_log" "this" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = var.flow_logs_traffic_type
  vpc_id          = aws_vpc.this.id

  max_aggregation_interval = 60

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-vpc-flow-log", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# Default Security Group - Deny All Ingress/Egress
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  # Deny all ingress
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
    self        = false
  }

  # Deny all egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
    self        = false
  }

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-default-sg", var.environment)
    }
  )
}

# ----------------------------------------------------------------------------------------------------------------------
# VPC Endpoints for S3 and DynamoDB (Gateway endpoints)
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_s3_endpoint ? 1 : 0

  vpc_id            = aws_vpc.this.id
  service_name      = format("com.amazonaws.%s.s3", var.aws_region)
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    [aws_route_table.public.id],
    [for rt in aws_route_table.private : rt.id]
  )

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-s3-vpce", var.environment)
    }
  )
}

resource "aws_vpc_endpoint" "dynamodb" {
  count = var.enable_dynamodb_endpoint ? 1 : 0

  vpc_id            = aws_vpc.this.id
  service_name      = format("com.amazonaws.%s.dynamodb", var.aws_region)
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    [aws_route_table.public.id],
    [for rt in aws_route_table.private : rt.id]
  )

  tags = merge(
    local.common_tags,
    {
      Name = format("%s-dynamodb-vpce", var.environment)
    }
  )
}
