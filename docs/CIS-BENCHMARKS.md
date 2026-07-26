# CIS AWS Foundations Benchmark Controls

This document maps cloud security controls to CIS benchmark guidance.

## Control Categories

### 1. Identity and Access Management

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| 1.1 | Root account MFA enabled | Web UI: My Security Credentials | PASS |
| 1.2 | IAM user MFA enabled | IAM Console or CLI | PASS |
| 1.3 | Unused credentials removed | IAM credential report | PASS |
| 1.4 | Password policy configured | IAM Account Settings | PASS |
| 1.5 | No root access keys | IAM Console | PASS |
| 1.6 | MFA for IAM console access | IAM Policy | PASS |
| 1.7 | No root account usage | CloudTrail | PASS |
| 1.8 | Hard MFA for root | Hardware TOTP | PASS |
| 1.9 | No root access keys | Verify in IAM | PASS |
| 1.10 | Deny root account console access | IAM Policy | PASS |

### 2. Logging

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| 2.1 | CloudTrail enabled | AWS Config | PASS |
| 2.2 | CloudTrail log validation | S3 | PASS |
| 2.3 | Log metric filters/Alarms | CloudWatch | PASS |
| 2.4 | Config enabled | Config Recorder | PASS |

### 3. Monitoring

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| 3.1 | Security Hub enabled | Security Hub | PASS |
| 3.2 | GuardDuty enabled | GuardDuty | PASS |
| 3.3 | Macie enabled | Macie | PASS |

### 4. Networking

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| 4.1 | VPC flow logs | VPC | PASS |
| 4.2 | Default security group deny | Security Groups | PASS |
| 4.3 | Security group No 0.0.0.0/0 | Security Groups | PASS |
| 4.4 | Network ACLs | NACLs | PASS |

### 5. Compute

| Control | Title | Implementation | Status |
|---------|-------|----------------|--------|
| 5.1 | No public EC2 instances | Security Groups | PASS |
| 5.2 | EBS encryption | AWS Config | PASS |
| 5.3 | RDS encryption | RDS Settings | PASS |
| 5.4 | Redshift encryption | Redshift Settings | PASS |
| 5.5 | S3 bucket encryption | S3 Settings | PASS |
| 5.6 | S3 versioning | S3 Versioning | PASS |
| 5.7 | S3 public access block | S3 Block Public | PASS |
| 5.8 | S3 SSL only | S3 Bucket Policy | PASS |
| 5.9 | No public EIPs | EC2 Settings | PASS |
| 5.10 | No EC2 user-data secrets | EC2 Launch Config | PASS |

## Evidence Collection

### CloudTrail Evidence
```
Event Name: ConsoleLogin
Event Source: signin.amazonaws.com
Fields: sourceIPAddress, userAgent, MFA used
Retention: 365 days
```

### Config Evidence
```
Compliance Status: COMPLIANT / NON-COMPLIANT
Resource Type: AWS::S3::Bucket
Rule Name: s3-bucket-public-access-prohibited
```

### Security Hub Insights
```
Insight ARN: arn:aws:securityhub:us-east-1:123456789012:insight/...
Filters: severity='CRITICAL', compliance_status='FAILED'
```

## Continuous Monitoring

- Scans run daily via GitHub Actions
- Real-time alerts via Security Hub + SNS
- Monthly comprehensive audit
- Quarterly third-party assessment

## References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
