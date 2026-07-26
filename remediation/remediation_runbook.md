# Remediation Runbook — Cloud Security Incident Response

**Document ID:** CSPA-RUNBOOK-001  
**Version:** 1.0  
**Classification:** Confidential — Incident Response  
**Last Updated:** 2025-01-22  
**SLA for Critical Findings:** 7 days (168 hours)  
**SLA for High Findings:** 30 days (720 hours)

---

## Table of Contents

1. [Purpose & Scope](#purpose--scope)
2. [Incident Severity Classification](#incident-severity-classification)
3. [Communication Templates](#communication-templates)
4. [Emergency Remediation Procedures](#emergency-remediation-procedures)
5. [Verification Steps](#verification-steps)
6. [Rollback Plans](#rollback-plans)
7. [Post-Remediation Activities](#post-remediation-activities)

---

## Purpose & Scope

This runbook provides **incident-response-style** step-by-step procedures for emergency remediation of critical cloud security findings. It is designed for on-call security engineers, cloud engineers, and incident responders who need to rapidly address active security threats.

**Scope:** AWS Accounts 123456789012 (prod), 210987654321 (staging), 345678901234 (dev), 456789012345 (shared-services)

**Assumptions:**
- Responder has `AdministratorAccess` or equivalent break-glass permissions
- Responder has access to the AWS Organization management account
- AWS CLI v2 is installed and configured
- All commands are run from a secure, audited bastion host

---

## Incident Severity Classification

| Severity | Response Time | Escalation | Example |
|----------|--------------|------------|---------|
| **SEV-1** (Critical) | < 1 hour | VP Engineering + CISO | Active S3 data leak, root user compromise |
| **SEV-2** (High) | < 4 hours | Security Team Lead | Unencrypted RDS, permissive SGs |
| **SEV-3** (Medium) | < 24 hours | Security Engineer | Disabled CloudTrail validation, old keys |
| **SEV-4** (Low) | < 72 hours | Ticket tracking | Missing tags, no dashboards |

---

## Communication Templates

### Initial Notification (Slack / Email)

```text
🚨 [SEV-{1|2|3|4}] Cloud Security Incident — {FINDING-ID}

Description: {Brief description of finding and impact}
Affected Resources: {ARNs or resource IDs}
Detected: {timestamp}
Detected By: {Prowler / Security Hub / Manual Review}
Severity: {Critical / High / Medium / Low}
CVSS Score: {score}

Actions Taken: {immediate containment steps}
Next Steps: {planned remediation}
Responder: {name}
```

### Status Update Template (Every 2 hours for SEV-1)

```text
⏰ Status Update — {FINDING-ID}

Current Status: {In Progress / Contained / Resolved}
Time Elapsed: {elapsed hours}
Remaining Steps:
1. {step}
2. {step}
3. {step}

Blocks / Risks: {any blockers}
ETA to Resolution: {estimated time}
```

### Resolution Notification

```text
✅ Resolved — {FINDING-ID}

Finding: {name}
Resolution Time: {timestamp}
Total Time to Resolve: {elapsed hours}

Remediation Summary:
- {action taken}
- {action taken}

Verification Status: {Passed / Failed}
Post-Incident Actions: {root cause analysis, policy changes}
```

---

## Emergency Remediation Procedures

---

### Procedure CR-001: Active S3 Data Leak — Block Public Access

**Severity:** SEV-1  |  **SLA:** 15 minutes to containment  |  **FINDING-ID:** FINDING-001

#### Step 1: Assess the Exposure (2 minutes)

```bash
# Check bucket ACLs and policies
echo "=== Checking S3 bucket public access ==="
aws s3api get-public-access-block --bucket prod-customer-data-2024 2>&1 || echo "No public access block configured"

aws s3api get-bucket-acl --bucket prod-customer-data-2024

aws s3api get-bucket-policy --bucket prod-customer-data-2024 --query Policy --output json | jq .

# Check if bucket is listable
aws s3 ls s3://prod-customer-data-2024 --no-sign-request 2>&1 && echo "⚠️ BUCKET IS PUBLICLY LISTABLE"
```

#### Step 2: IMMEDIATE CONTAINMENT — Block All Public Access (5 minutes)

```bash
# ACCOUNT-LEVEL block (stops all S3 public access in the account)
echo "[ACTION] Applying account-level Block Public Access..."
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

# BUCKET-LEVEL block (redundant defense)
echo "[ACTION] Applying bucket-level Block Public Access..."
aws s3api put-public-access-block \
  --bucket prod-customer-data-2024 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

echo "[VERIFY] Checking public access is blocked..."
aws s3 ls s3://prod-customer-data-2024 --no-sign-request 2>&1 && echo "❌ STILL ACCESSIBLE" || echo "✅ Blocked"
```

#### Step 3: Revoke Bucket Policy (5 minutes)

```bash
# Replace bucket policy with a deny-all public policy
echo "[ACTION] Replacing bucket policy with restricted policy..."
cat > /tmp/emergency-restrict-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EmergencyDenyPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::prod-customer-data-2024",
        "arn:aws:s3:::prod-customer-data-2024/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:SourceAccount": "123456789012"
        }
      }
    }
  ]
}
POLICY

aws s3api put-bucket-policy --bucket prod-customer-data-2024 --policy file:///tmp/emergency-restrict-policy.json
```

#### Step 4: Enable Encryption & Versioning (5 minutes)

```bash
echo "[ACTION] Enabling default encryption..."
aws s3api put-bucket-encryption \
  --bucket prod-customer-data-2024 \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

echo "[ACTION] Enabling versioning..."
aws s3api put-bucket-versioning \
  --bucket prod-customer-data-2024 \
  --versioning-configuration Status=Enabled
```

#### Step 5: Notify Stakeholders (5 minutes)

Send notification using the template above. Include:
- Time of detection
- What data was exposed
- Number of exposed objects (est.)
- Containment actions taken
- Legal/DPO notification required

#### Verification

```bash
echo "=== VERIFICATION ==="
aws s3api get-public-access-block --bucket prod-customer-data-2024
aws s3api get-bucket-policy --bucket prod-customer-data-2024 --query Policy --output json | jq '.Statement[0].Effect'
echo "Expected: Deny"
aws s3 ls s3://prod-customer-data-2024 --no-sign-request 2>&1 && echo "❌ FAIL" || echo "✅ PASS"
```

---

### Procedure CR-002: CloudTrail Disabled — Enable Immediately

**Severity:** SEV-1  |  **SLA:** 1 hour  |  **FINDING-ID:** FINDING-004

#### Step 1: Create S3 Bucket for CloudTrail (10 minutes)

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="cloudtrail-logs-${ACCOUNT_ID}"
REGION="us-east-1"

echo "[ACTION] Creating S3 bucket: ${BUCKET}"
aws s3api create-bucket --bucket ${BUCKET} --region ${REGION}

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket ${BUCKET} \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Block public access
aws s3api put-public-access-block \
  --bucket ${BUCKET} \
  --public-access-block-configuration '{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}'
```

#### Step 2: Attach Bucket Policy (5 minutes)

```bash
cat > /tmp/ct-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${BUCKET}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET}/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket ${BUCKET} --policy file:///tmp/ct-bucket-policy.json
```

#### Step 3: Create CloudTrail (10 minutes)

```bash
echo "[ACTION] Creating multi-region CloudTrail trail..."
aws cloudtrail create-trail \
  --name prod-multi-region-trail \
  --s3-bucket-name ${BUCKET} \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events

aws cloudtrail start-logging --name prod-multi-region-trail

echo "[ACTION] Bullet Time (IAM) — protect trail from deletion..."
# Create a trail-specific SCP or IAM policy to prevent disabling
```

#### Verification

```bash
echo "=== VERIFICATION ==="
TRAIL_STATUS=$(aws cloudtrail get-trail-status --name prod-multi-region-trail --query 'IsLogging' --output text)
echo "Trail logging: $TRAIL_STATUS"
[[ "$TRAIL_STATUS" == "True" ]] && echo "✅ PASS" || echo "❌ FAIL"

MULTI_REGION=$(aws cloudtrail describe-trails --trail-name-list prod-multi-region-trail --query 'trailList[0].IsMultiRegionTrail' --output text)
echo "Multi-region: $MULTI_REGION"
```

---

### Procedure CR-003: Root User Access Keys Active — Delete Immediately

**Severity:** SEV-1  |  **SLA:** 15 minutes  |  **FINDING-ID:** FINDING-005

#### WARNING
> Deleting root access keys will break any automation using them. Ensure alternative credentials are available.

#### Step 1: List Root User Keys

```bash
# Requires root user credentials
echo "[ACTION] Listing root user access keys..."
aws iam list-access-keys --user-name root
```

#### Step 2: Deactivate Keys

```bash
for key in $(aws iam list-access-keys --user-name root --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  echo "[ACTION] Deactivating key: $key"
  aws iam update-access-key --user-name root --access-key-id $key --status Inactive
  echo "  Key $key deactivated"
done
```

#### Step 3: Validate Impact

```bash
# Wait 5 minutes, check if any systems report authentication failures
# Communicate with engineering teams
```

#### Step 4: Delete Keys

```bash
echo "[ACTION] Deleting root user access keys..."
for key in $(aws iam list-access-keys --user-name root --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
  aws iam delete-access-key --user-name root --access-key-id $key
  echo "  Key $key deleted"
done
```

#### Step 5: Enable MFA on Root

```bash
echo "[ACTION] Enabling MFA on root account..."
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name "root-account-mfa" \
  --outfile /tmp/root-mfa-qrcode.png \
  --bootstrap-method QRCodePNG

echo "[MANUAL] Scan QR code at /tmp/root-mfa-qrcode.png with authenticator app"
```

---

### Procedure CR-004: Unrestricted SSH Access — Restrict Immediately

**Severity:** SEV-1  |  **SLA:** 1 hour  |  **FINDING-ID:** FINDING-003

#### Step 1: Find All Affected Security Groups

```bash
echo "[SCAN] Finding SGs with unrestricted SSH..."
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' \
  --output table
```

#### Step 2: For Each SG, Remove the 0.0.0.0/0 SSH Rule

```bash
for sg in $(aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[*].GroupId' --output text); do
  echo "[ACTION] Processing security group: $sg"
  
  # Remove 0.0.0.0/0 SSH rule
  aws ec2 revoke-security-group-ingress \
    --group-id $sg \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0
  
  # Add corporate VPN CIDR
  aws ec2 authorize-security-group-ingress \
    --group-id $sg \
    --protocol tcp \
    --port 22 \
    --cidr 10.0.0.0/8
  
  echo "  ✅ Updated $sg"
done
```

#### Step 3: Verify Access Still Works (Via VPN)

```bash
# Test SSH from corporate network
# ssh -i key.pem ec2-user@instance-ip
# If VPN is down, use AWS SSM Session Manager as backup:
# aws ssm start-session --target instance-id
```

---

### Procedure CR-005: Unencrypted RDS with PII — Encrypt Immediately

**Severity:** SEV-1  |  **SLA:** 4 hours (with maintenance window)  |  **FINDING-ID:** FINDING-002

#### Step 1: Create Snapshot & Verify

```bash
DB_ID="prod-user-db"
export SNAPSHOT_NAME="${DB_ID}-pre-encryption-$(date +%Y%m%d-%H%M%S)"

echo "[ACTION] Creating unencrypted snapshot: ${SNAPSHOT_NAME}"
aws rds create-db-snapshot \
  --db-instance-identifier ${DB_ID} \
  --db-snapshot-identifier "${SNAPSHOT_NAME}"

echo "[WAIT] Waiting for snapshot to complete..."
aws rds wait db-snapshot-completed --db-snapshot-identifier "${SNAPSHOT_NAME}"
echo "  ✅ Snapshot complete"
```

#### Step 2: Copy with Encryption & Restore

```bash
KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id"
ENCRYPTED_SNAPSHOT="${DB_ID}-encrypted-$(date +%Y%m%d)"
NEW_DB_ID="${DB_ID}-v2"

echo "[ACTION] Creating encrypted copy: ${ENCRYPTED_SNAPSHOT}"
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier "arn:aws:rds:us-east-1:123456789012:snapshot:${SNAPSHOT_NAME}" \
  --target-db-snapshot-identifier "${ENCRYPTED_SNAPSHOT}" \
  --kms-key-id "${KMS_KEY_ID}" \
  --copy-tags

echo "[WAIT] Waiting for encrypted snapshot..."
aws rds wait db-snapshot-completed --db-snapshot-identifier "${ENCRYPTED_SNAPSHOT}"

echo "[ACTION] Restoring encrypted instance: ${NEW_DB_ID}"
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "${NEW_DB_ID}" \
  --db-snapshot-identifier "${ENCRYPTED_SNAPSHOT}" \
  --db-instance-class db.r5.large \
  --multi-az \
  --no-publicly-accessible \
  --vpc-security-group-ids sg-restricted \
  --db-subnet-group-name prod-private

echo "[WAIT] Waiting for new instance..."
aws rds wait db-instance-available --db-instance-identifier "${NEW_DB_ID}"

echo "[ACTION] Enabling deletion protection..."
aws rds modify-db-instance \
  --db-instance-identifier "${NEW_DB_ID}" \
  --deletion-protection \
  --backup-retention-period 35 \
  --apply-immediately
```

#### Step 3: Update Connection Strings (Manual, Critical)

```bash
NEW_ENDPOINT=$(aws rds describe-db-instances --db-instance-identifier "${NEW_DB_ID}" --query 'DBInstances[0].Endpoint.Address' --output text)
echo "New RDS endpoint: ${NEW_ENDPOINT}"

# Update in Secrets Manager
aws secretsmanager put-secret-value \
  --secret-id prod/db/connection-string \
  --secret-string "{\"host\":\"${NEW_ENDPOINT}\",\"port\":5432}"

echo "[MANUAL] Restart application services to pick up new connection string"
```

---

## Rollback Plans

### Rollback: S3 Public Access

| Step | Command | Time |
|------|---------|------|
| 1 | Disable account-level block public access | `aws s3control put-public-access-block --account-id 123456789012 --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false` |
| 2 | Restore original bucket policy | `aws s3api put-bucket-policy --bucket prod-customer-data-2024 --policy file://backup-policy.json` |
| 3 | Verify rollback | `aws s3 ls s3://prod-customer-data-2024 --no-sign-request` |

### Rollback: CloudTrail

| Step | Command | Time |
|------|---------|------|
| 1 | Stop logging | `aws cloudtrail stop-logging --name prod-multi-region-trail` |
| 2 | Delete trail | `aws cloudtrail delete-trail --name prod-multi-region-trail` |
| 3 | Delete log bucket | `aws s3 rb s3://cloudtrail-logs-123456789012 --force` |

### Rollback: RDS Encryption

| Step | Command | Time |
|------|---------|------|
| 1 | Point apps back to old endpoint | Update Secrets Manager with old RDS endpoint |
| 2 | Delete encrypted instance | `aws rds delete-db-instance --db-instance-identifier prod-user-db-v2 --skip-final-snapshot` |
| 3 | Restore from pre-encryption snapshot | `aws rds restore-db-instance-from-db-snapshot --db-instance-identifier prod-user-db --db-snapshot-identifier prod-user-db-pre-encryption` |

### Rollback: Security Group Changes

```bash
# Re-add 0.0.0.0/0 SSH rule (emergency only)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f6g7h8 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```

---

## Post-Remediation Activities

### 1. Root Cause Analysis (RCA)

For each finding, complete within 5 business days:
- How was the finding introduced?
- Why wasn't it detected earlier?
- What preventive controls should be added?
- What detective controls should be added?

### 2. Preventive Controls

| Control | Implementation |
|---------|---------------|
| SCP to block public S3 buckets | `aws organizations create-policy --content file://scp.json --name DenyPublicS3 --type SERVICE_CONTROL_POLICY` |
| AWS Config auto-remediation | `aws config put-remediation-configuration --config-rule-name s3-bucket-public-read-prohibited --target-type SSM_DOCUMENT` |
| Terraform/CloudFormation guardrails | Add `prevent_public_access = true` to all S3 module calls |
| CI/CD pipeline scanning | Integrate `checkov` or `tfsec` into CI/CD pipelines |

### 3. Detective Controls

| Control | Implementation |
|---------|---------------|
| CloudWatch alarm for S3 public access | Alarm on `PutBucketPolicy` with `aws:SourceIp` condition |
| Security Hub auto-enable | Enable all standards via `aws securityhub enable-security-hub` |
| GuardDuty enable | `aws guardduty create-detector --enable` |
| Prowler scheduled scan | `0 6 * * 1 prowler aws --compliance cis_1.4 -o html` |

### 4. Lessons Learned Template

```markdown
## Lessons Learned — {FINDING-ID}

**Date:** YYYY-MM-DD
**Severity:** {severity}
**Duration:** {hours} hours to resolve

### What went well
- 
- 

### What could be improved
- 
- 

### Action Items
| Action | Owner | Due Date |
|--------|-------|----------|
| | | |
| | | |

### Changes to runbook
- 
```

---

## Escalation Contacts

| Role | Name | Phone | Email |
|------|------|-------|-------|
| CISO | Sarah Chen | +1-555-0101 | s.chen@company.com |
| VP Engineering | Mike Rodriguez | +1-555-0102 | m.rodriguez@company.com |
| Security Lead | Alex Kim | +1-555-0103 | a.kim@company.com |
| Cloud Ops Lead | Jamie Patel | +1-555-0104 | j.patel@company.com |
| Legal/DPO | Lisa Thompson | +1-555-0105 | l.thompson@company.com |
| On-Call Engineer | PagerDuty | N/A | pagerduty@company.com |

---

## Appendix: Quick Reference Card

### Critical Commands

```bash
# Emergency S3 block
aws s3control put-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) --public-access-block-configuration '{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}'

# Emergency CloudTrail create
aws cloudtrail create-trail --name emergency-trail --s3-bucket-name "ct-logs-$(aws sts get-caller-identity --query Account --output text)" --is-multi-region-trail --enable-log-file-validation --include-global-service-events && aws cloudtrail start-logging --name emergency-trail

# List all SGs with SSH from anywhere
aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[*].[GroupId,GroupName]' --output table

# Remove SSH anywhere
aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 0.0.0.0/0
```

---

*Document approved by: Head of Security Engineering*  
*Next review date: 2025-04-22*
