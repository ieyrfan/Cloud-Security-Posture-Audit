# AWS Security Posture Audit - Architecture

## 🏗️ Infrastructure Overview

### High-Level Architecture

```
Internet
    |
    v
[WAF] --> [ALB] --> [Public Subnet]
                           |
                    [Private Subnet]
                    +-------+-------+
                    |       |       |
                  [EC2]   [RDS]   [Lambda]
                    |       |       |
            [Security Groups] [KMS Encryption]
                    |       |       |
            [VPC Flow Logs] [CloudTrail] [CloudWatch]
```

### Security Services Integration

| Service | Purpose | CIS Control |
|---------|---------|-------------|
| AWS Security Hub | Centralized findings | All |
| AWS CloudTrail | API activity logging | 2.1-2.4 |
| AWS Config | Resource compliance | All |
| GuardDuty | Threat detection | - |
| Macie | Data discovery | - |
| VPC Flow Logs | Network logging | 3.9 |
| AWS KMS | Encryption keys | 4.x, 5.x |

## 🔐 Security Controls by Layer

### Layer 1: Identity & Access Management
- MFA enforcement for all users
- Password policy (14+ chars, 90-day rotation)
- Access key rotation (90 days)
- Least privilege IAM policies
- Root account monitoring

### Layer 2: Network Security
- VPC with private/public subnets
- Security groups (default deny)
- Network ACLs (defense in depth)
- VPC Flow Logs enabled
- No public IPs on EC2

### Layer 3: Data Protection
- Encryption at rest (KMS)
- Encryption in transit (TLS)
- S3 Block Public Access
- RDS encryption enabled

### Layer 4: Logging & Monitoring
- CloudTrail multi-region
- CloudTrail log validation
- CloudWatch alarms
- AWS Config rules (50+)
- Security Hub monitoring

## 📊 Deployment Topology

### Dev Environment
```
Single-AZ, t3.micro, limited resources
```

### Production Environment
```
Multi-AZ, Auto Scaling, WAF, HA
```

## 🚀 Deployment Pipeline

```
Git Push --> GitHub Actions --> Terraform Plan --> Security Scan
    --> Pass? --> Terraform Apply --> Post-Deployment Scan
    --> Fail? --> Report Issue
```

## 📈 Compliance Metrics Collection

```
AWS Config --> Lambda --> S3 Reports
    |                       |
    v                       v
Security Hub --> Compliance Dashboard
```

---
*Architecture Version: 2.0.0 | July 2026*
