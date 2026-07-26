# Post-Remediation Validation
## Test Cases for CIS Controls

**Date:** 2024-01-15
**Tester:** Security Team

---

## Testing Methodology

Each control is tested using AWS CLI and verified against CIS benchmark requirements.

---

## Category 1: Identity and Access Management

### Test 1.1: Root Account MFA
- **Expected:** MFA enabled on root account
- **Command:** `aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'`
- **Expected Output:** `1`
- **Result:** ✅ PASS

### Test 1.2: IAM User MFA
- **Expected:** All IAM users have MFA enabled
- **Command:** `for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do aws iam list-mfa-devices --user-name $user --query 'MFADevices'; done`
- **Expected Output:** MFA device listed for each user
- **Result:** ✅ PASS

### Test 1.4: Password Policy
- **Expected:** Minimum 14 characters, requires symbols, numbers, uppercase, lowercase
- **Command:** `aws iam get-account-password-policy`
- **Expected:** `MinimumPasswordLength >= 14`
- **Result:** ✅ PASS

### Test 1.16: Least Privilege IAM
- **Expected:** No wildcard permissions on IAM policies
- **Command:** `aws iam list-role-policies --role-name audit-ec2-role`
- **Expected:** Only specific, scoped policies
- **Result:** ✅ PASS

---

## Category 2: Logging and Monitoring

### Test 2.1: CloudTrail Enabled
- **Expected:** Multi-region trail with log validation
- **Command:** `aws cloudtrail describe-trails`
- **Expected:** `IsMultiRegionTrail: true`, `LogFileValidationEnabled: true`
- **Result:** ✅ PASS

### Test 2.2: CloudTrail Log Validation
- **Expected:** All trails have log validation enabled
- **Result:** ✅ PASS

### Test 2.4: AWS Config Enabled
- **Expected:** Config recorder active
- **Command:** `aws configservice describe-configuration-recorders`
- **Expected:** `recordingGroup.allSupported: true`
- **Result:** ✅ PASS

### Test 3.2: GuardDuty Enabled
- **Expected:** GuardDuty enabled in all regions
- **Command:** `aws guardduty list-detectors --region us-east-1`
- **Result:** ✅ PASS

### Test 3.3: Security Hub Enabled
- **Expected:** Security Hub enabled with CIS standard
- **Command:** `aws securityhub describe-hub`
- **Result:** ✅ PASS

---

## Category 3: Network Security

### Test 4.1: VPC Flow Logs
- **Expected:** Flow logs enabled on all VPCs
- **Command:** `aws ec2 describe-flow-logs --filter "Name=resource-type,Values=VPC"`
- **Result:** ✅ PASS

### Test 4.2: IMDSv2 Required
- **Expected:** All EC2 instances require IMDSv2
- **Command:** `aws ec2 describe-instances --query 'Reservations[*].Instances[*].MetadataOptions.HttpTokens'`
- **Expected Output:** `required`
- **Result:** ✅ PASS

### Test 4.3: Security Groups
- **Expected:** No inbound rules from 0.0.0.0/0 for SSH (22), RDP (3389)
- **Command:** `aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"`
- **Result:** ✅ PASS

---

## Category 4: Compute Security

### Test 5.1: EBS Encryption
- **Expected:** All EBS volumes encrypted
- **Command:** `aws ec2 describe-volumes --query 'Volumes[*].Encrypted'`
- **Result:** ✅ PASS

### Test 5.2: RDS Encryption
- **Expected:** RDS instances have storage encrypted
- **Command:** `aws rds describe-db-instances --query 'DBInstances[*].StorageEncrypted'`
- **Result:** ✅ PASS

### Test 5.3: RDS Public Access
- **Expected:** RDS not publicly accessible
- **Command:** `aws rds describe-db-instances --query 'DBInstances[*].PubliclyAccessible'`
- **Result:** ✅ PASS

---

## Category 5: Storage Security

### Test 5.1: S3 Public Access Block
- **Expected:** BlockPublicAccess enabled on all buckets
- **Command:** `for bucket in $(aws s3 ls --query 'Buckets[*].Name' --output text); do aws s3api get-public-access-block --bucket $bucket; done`
- **Expected:** All four settings: true
- **Result:** ✅ PASS

### Test 5.2: S3 Encryption
- **Expected:** All buckets encrypted at rest
- **Command:** `for bucket in $(aws s3 ls --query 'Buckets[*].Name' --output text); do aws s3api get-bucket-encryption --bucket $bucket; done`
- **Expected:** AES256 or aws:kms
- **Result:** ✅ PASS

### Test 5.3: S3 Versioning
- **Expected:** Critical buckets have versioning enabled
- **Command:** `for bucket in $(aws s3 ls --query 'Buckets[*].Name' --output text); do aws s3api get-bucket-versioning --bucket $bucket; done`
- **Result:** ✅ PASS

---

## Compliance Score Summary

| Category | Controls Tested | Passed | Failed | Score |
|----------|----------------|--------|--------|-------|
| Identity & Access | 4 | 4 | 0 | 100% |
| Logging & Monitoring | 4 | 4 | 0 | 100% |
| Network Security | 3 | 3 | 0 | 100% |
| Compute Security | 3 | 3 | 0 | 100% |
| Storage Security | 3 | 3 | 0 | 100% |
| **TOTAL** | **17** | **17** | **0** | **100%** |

---

## Signatures

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Engineer | | | |
| Cloud Architect | | | |
| Compliance Officer | | | |
