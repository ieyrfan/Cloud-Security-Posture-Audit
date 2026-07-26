# Cloud Security Posture Audit - Remediation Runbook

## Overview

This runbook provides step-by-step procedures for remediating common AWS security misconfigurations identified during the security posture audit. Each procedure includes pre-checks, remediation steps, validation, and rollback instructions.

---

## Table of Contents

1. [S3 Public Access Block](#1-s3-public-access-block)
2. [RDS Encryption at Rest](#2-rds-encryption-at-rest)
3. [IAM Excessive Permissions](#3-iam-excessive-permissions)
4. [Security Group Hardening](#4-security-group-hardening)
5. [CloudTrail Enablement](#5-cloudtrail-enablement)
6. [VPC Flow Logs](#6-vpc-flow-logs)
7. [EBS Volume Encryption](#7-ebs-volume-encryption)
8. [CloudWatch Alarms](#8-cloudwatch-alarms)
9. [GuardDuty Enablement](#9-guardduty-enablement)
10. [IMDSv2 Enforcement](#10-imdsv2-enforcement)

---

## 1. S3 Public Access Block

### Control: CIS 5.1, 5.2

### Pre-Checks
```bash
# List all S3 buckets
aws s3 ls

# Check current public access block settings
for bucket in $(aws s3 ls --query 'Buckets[*].Name' --output text); do
  echo "Bucket: $bucket"
  aws s3api get-public-access-block --bucket $bucket
  echo "---"
done

# Check bucket ACL
aws s3api get-bucket-acl --bucket <bucket-name>
```

### Remediation Steps

```bash
BUCKET_NAME="your-bucket-name"

# Step 1: Block all public access
aws s3api put-public-access-block \
  --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Step 2: Remove public ACL
aws s3api put-bucket-acl \
  --bucket $BUCKET_NAME \
  --acl private

# Step 3: Enable encryption
aws s3api put-bucket-encryption \
  --bucket $BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Step 4: Enable versioning
aws s3api put-bucket-versioning \
  --bucket $BUCKET_NAME \
  --versioning-configuration Status=Enabled

# Step 5: Enable logging
LOG_BUCKET="audit-logs-$(aws sts get-caller-identity --query Account --output text)"
aws s3api put-bucket-logging \
  --bucket $BUCKET_NAME \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "'$LOG_BUCKET'",
      "TargetPrefix": "s3-access-logs/audit/"
    }
  }'

# Step 6: Add bucket policy to enforce encryption
aws s3api put-bucket-policy \
  --bucket $BUCKET_NAME \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::'$BUCKET_NAME'/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }]
  }'
```

### Validation
```bash
# Verify public access block
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Verify encryptio
aws s3api get-bucket-encryption --bucket $BUCKET_NAME

# Verify versioning
aws s3api get-bucket-versioning --bucket $BUCKET_NAME

# Expected output: All settings show encryption enabled, public access blocked
```

### Rollback
```bash
# To rollback (NOT recommended for production)
aws s3api delete-public-access-block --bucket $BUCKET_NAME
aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl public-read
```

---

## 2. RDS Encryption at Rest

### Control: CIS 5.4

### Pre-Checks
```bash
# Check current RDS instances and encryption status
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,PubliclyAccessible]' \
  --output table
```

### Remediation Steps

```bash
# IMPORTANT: Cannot enable encryption on existing RDS instance!
# Must create new encrypted instance and migrate data

INSTANCE_ID="audit-mysql-db"
TIMESTAMP=$(date +%Y%m%d)

# Step 1: Create snapshot of unencrypted database
echo "[1/6] Creating snapshot..."
aws rds create-db-snapshot \
  --db-instance-identifier $INSTANCE_ID \
  --db-snapshot-identifier ${INSTANCE_ID}-backup-${TIMESTAMP}

# Wait for snapshot
aws rds wait db-snapshot-available \
  --db-snapshot-identifier ${INSTANCE_ID}-backup-${TIMESTAMP}

# Step 2: Restore with encryption enabled
echo "[2/6] Restoring encrypted instance..."
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier ${INSTANCE_ID}-encrypted \
  --db-snapshot-identifier ${INSTANCE_ID}-backup-${TIMESTAMP} \
  --storage-encrypted \
  --kms-key-id alias/aws/rds \
  --db-instance-class db.t3.micro

# Wait for restore
aws rds wait db-instance-available \
  --db-instance-identifier ${INSTANCE_ID}-encrypted

# Step 3: Disable public access
echo "[3/6] Removing public access..."
aws rds modify-db-instance \
  --db-instance-identifier ${INSTANCE_ID}-encrypted \
  --no-publicly-accessible \
  --apply-immediately

# Step 4: Enable automatic backups
echo "[4/6] Enabling automated backups..."
aws rds modify-db-instance \
  --db-instance-identifier ${INSTANCE_ID}-encrypted \
  --backup-retention-period 7 \
  --preferred-backup-window "03:00-04:00" \
  --apply-immediately

# Step 5: Update security groups
echo "[5/6] Updating security groups..."
# Get new instance endpoint
ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier ${INSTANCE_ID}-encrypted \
  --query 'DBInstances[0].Endpoint.Address' --output text)

# Update application to use new endpoint
echo "Update application connection string to: $ENDPOINT"

# Step 6: Delete old instance (after validation!)
echo "[6/6] Schedule deletion of old instance..."
aws rds delete-db-instance \
  --db-instance-identifier $INSTANCE_ID \
  --skip-final-snapshot \
  --no-delete-automated-backups
```

### Validation
```bash
# Verify encryption
aws rds describe-db-instances \
  --db-instance-identifier ${INSTANCE_ID}-encrypted \
  --query 'DBInstances[0].StorageEncrypted'

# Expected: true
```

---

## 3. IAM Excessive Permissions

### Control: CIS 1.16

### Pre-Checks
```bash
# Identify IAM users, roles, and policies
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local

# Check for overly permissive policies
aws iam list-attached-role-policies --role-name <role-name>
aws iam get-role-policy --role-name <role-name> --policy-name <policy-name>
```

### Remediation Steps

```bash
ROLE_NAME="audit-ec2-role"

# Step 1: Create least privilege policy
cat > /tmp/least-privilege.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::audit-data",
        "arn:aws:s3:::audit-data/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
EOF

# Step 2: Apply new policy
aws iam put-role-policy \
  --role-name $ROLE_NAME \
  --policy-name LeastPrivilegeAccess \
  --policy-document file:///tmp/least-privilege.json

# Step 3: Remove excessive policies
aws iam delete-role-policy \
  --role-name $ROLE_NAME \
  --policy-name s3-full-access

aws iam delete-role-policy \
  --role-name $ROLE_NAME \
  --policy-name ec2-full-access

# Step 4: Verify policy
aws iam get-role-policy --role-name $ROLE_NAME --policy-name LeastPrivilegeAccess
```

### Validation
```bash
# Test role permissions (if possible in non-production)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account>:role/$ROLE_NAME \
  --action-names s3:DeleteBucket \
  --output json

# Expected: explicit Deny or not authorized
```

---

## 4. Security Group Hardening

### Control: CIS 4.1, 4.2

### Pre-Checks
```bash
# List all security groups
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' \
  --output table

# Find overly permissive rules
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName,IpPermissions]' \
  --output table
```

### Remediation Steps

```bash
SG_ID="sg-xxxxxxxxx"

# Step 1: Remove SSH from 0.0.0.0/0
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Step 2: Add SSH from management CIDR only
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.0/24  # Replace with your IP

# Step 3: Remove unrestricted outbound
aws ec2 revoke-security-group-egress \
  --group-id $SG_ID \
  --protocol -1 \
  --cidr 0.0.0.0/0

# Step 4: Add specific outbound rules
aws ec2 authorize-security-group-egress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-egress \
  --group-id $SG_ID \
  --protocol udp \
  --port 53 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-egress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 123 \
  --cidr 0.0.0.0/0
```

### Validation
```bash
# Verify security group rules
aws ec2 describe-security-groups --group-ids $SG_ID
```

---

## 5. CloudTrail Enablement

### Control: CIS 2.1

### Remediation Steps

```bash
TRAIL_NAME="audit-trail"
BUCKET_NAME="audit-logs-$(aws sts get-caller-identity --query Account --output text)"

# Step 1: Create S3 bucket for logs
aws s3 mb s3://$BUCKET_NAME --region us-east-1

# Step 2: Enable versioning
aws s3api put-bucket-versioning \
  --bucket $BUCKET_NAME \
  --versioning-configuration Status=Enabled

# Step 3: Block public access
aws s3api put-public-access-block \
  --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Step 4: Create trail
aws cloudtrail create-trail \
  --name $TRAIL_NAME \
  --s3-bucket-name $BUCKET_NAME \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --is-organization-trail \
  --kms-key-id alias/aws/cloudtrail

# Step 5: Start logging
aws cloudtrail start-logging --trail-name $TRAIL_NAME

# Step 6: Configure event selectors
aws cloudtrail put-event-selectors \
  --trail-name $TRAIL_NAME \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::*/"]},
        {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda:*:*:function:*"]}
      ]
    }
  ]'
```

---

## 6. VPC Flow Logs

### Control: CIS 4.1

### Remediation Steps

```bash
VPC_ID="vpc-xxxxxxxxx"
LOG_GROUP="/aws/vpc/flow-logs"
ROLE_ARN="arn:aws:iam::<account-id>:role/flow-logs-role"

# Create CloudWatch Logs log group
aws logs create-log-group --log-group-name $LOG_GROUP

# Set retention to 365 days
aws logs put-retention-policy \
  --log-group-name $LOG_GROUP \
  --retention-in-days 365

# Create flow logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name $LOG_GROUP \
  --deliver-logs-permission-arn $ROLE_ARN
```

---

## 7. EBS Volume Encryption

### Control: CIS 5.2

### Remediation Steps

```bash
# List unencrypted volumes
aws ec2 describe-volumes \
  --filters "Name=encrypted,Values=false" \
  --query 'Volumes[*].[VolumeId,Attachments[0].InstanceId]' \
  --output table

INSTANCE_ID="i-xxxxxxxxx"
VOLUME_ID="vol-xxxxxxxxx"
AZ="us-east-1a"

# Step 1: Stop instance
aws ec2 stop-instances --instance-ids $INSTANCE_ID
aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID

# Step 2: Detach old volume
aws ec2 detach-volume --volume-id $VOLUME_ID
aws ec2 wait volume-available --volume-ids $VOLUME_ID

# Step 3: Create encrypted volume from snapshot
SNAPSHOT_ID=$(aws ec2 create-snapshot \
  --volume-id $VOLUME_ID \
  --description "Pre-encryption snapshot" \
  --query 'SnapshotId' --output text)

aws ec2 wait snapshot-completed --snapshot-ids $SNAPSHOT_ID

# Step 4: Create encrypted volume
NEW_VOLUME_ID=$(aws ec2 create-volume \
  --snapshot-id $SNAPSHOT_ID \
  --availability-zone $AZ \
  --encrypted \
  --query 'VolumeId' --output text)

aws ec2 wait volume-available --volume-ids $NEW_VOLUME_ID

# Step 5: Attach new volume
aws ec2 attach-volume \
  --volume-id $NEW_VOLUME_ID \
  --instance-id $INSTANCE_ID \
  --device /dev/xvda

# Step 6: Start instance
aws ec2 start-instances --instance-ids $INSTANCE_ID

# Step 7: Delete old volume (after validation)
# aws ec2 delete-volume --volume-id $VOLUME_ID
```

---

## 8. CloudWatch Alarms

### Control: CIS 3.1

### Remediation Steps

```bash
# Create alarm for unauthorized API calls
aws cloudwatch put-metric-alarm \
  --alarm-name "UnauthorizedAPICalls" \
  --metric-name "UnauthorizedAPICalls" \
  --namespace "CloudTrailMetrics" \
  --statistic "Sum" \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --alarm-actions "arn:aws:sns:us-east-1:<account>:security-alerts" \
  --dimensions Name=period,Value=300 \
  --treat-missing-data "notBreaching"

# Create alarm for root account usage
aws cloudwatch put-metric-alarm \
  --alarm-name "RootAccountUsage" \
  --metric-name "RootAccountUsage" \
  --namespace "CloudTrailMetrics" \
  --statistic "Sum" \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator "GreaterThanThreshold"

# Create alarm for sign-in failures
aws cloudwatch put-metric-alarm \
  --alarm-name "SignInFailures" \
  --metric-name "ConsoleSignInFailures" \
  --namespace "CloudTrailMetrics" \
  --statistic "Sum" \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator "GreaterThanThreshold"
```

---

## 9. GuardDuty Enablement

### Control: CIS 3.2

### Remediation Steps

```bash
# Enable GuardDuty
aws guardduty enable-guardduty \
  --region us-east-1

# Enable in all regions
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  echo "Enabling GuardDuty in $region"
  aws guardduty enable-guardduty --region $region
done

# Create S3 bucket for findings export
FINDINGS_BUCKET="guardduty-findings-$(aws sts get-caller-identity --query Account --output text)"
aws s3 mb s3://$FINDINGS_BUCKET --region us-east-1

# Configure findings export
aws guardduty create-publishing-destination \
  --region us-east-1 \
  --detector-id $(aws guardduty list-detectors --region us-east-1 --query 'DetectorIds[0]' --output text) \
  --destination-type S3 \
  --destination-properties DestinationArn=arn:aws:s3:::$FINDINGS_BUCKET
```

---

## 10. IMDSv2 Enforcement

### Control: CIS 4.2

### Remediation Steps

```bash
# Get instances with IMDSv1 enabled
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' \
  --output table

INSTANCE_ID="i-xxxxxxxxx"

# Enforce IMDSv2
aws ec2 modify-instance-metadata-options \
  --instance-id $INSTANCE_ID \
  --http-tokens required \
  --http-endpoint enabled \
  --hop-limit 1
```

---

## General Verification Steps

After completing all remediations:

```bash
# Re-run Prowler scan
./prowler aws -f json -o ../audit-reports/prowler-remediated.json

# Verify Security Hub
aws securityhub get-findings \
  --query 'Findings[*].[Title,Severity.Label,ComplianceStatus]' \
  --output table

# Generate compliance report
python scripts/compliance-check.py --environment prod --benchmark cis

# Expected: Compliance score > 85%
```

---

*Version: 1.0.0 | Last Updated: 2024-01-15*
