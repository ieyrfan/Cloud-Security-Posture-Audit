# Architecture Documentation

## Overview

This repository implements a production-grade cloud security posture management (CSPM) pipeline using Infrastructure as Code (IaC), continuous compliance validation, and automated remediation.

## System Components

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. Infrastructure Layer (Terraform)                                  │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐         │
│  │    AWS       │    │   Azure      │    │   United     │         │
│  │  Provider    │    │  Provider    │    │  Providers   │         │
│  └──────────────┘    └──────────────┘    └──────────────┘         │
│         │                    │                    │                 │
│  ┌──────┴────────────────────┴────────────────────┴───────┐        │
│  │                   Shared State Management                │        │
│  │                    (Terraform Cloud / S3)                │        │
│  └────────────────────────────────────────────────────────┘        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ 2. Security Hardening Layer                                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────┐            │
│  │              Identity & Access Security               │            │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │            │
│  │  │ IAM Password│  │   MFA       │  │ Root Acc.  │ │            │
│  │  │  Policy     │  │ Enforcement │  │ Protection  │ │            │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │            │
│  └─────────────────────────────────────────────────────┘            │
│                                                                      │
│  ┌─────────────────────────────────────────────────────┐            │
│  │                 Data Protection Security              │            │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │            │
│  │  │ S3 Encrp.   │  │  EBS Encrp. │  │  KMS Key   │ │            │
│  │  │  & Access   │  │  & Version  │  │  Mgmt      │ │            │
│  │  │  Blocking   │  │  Logging    │  │            │ │            │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │            │
│  └─────────────────────────────────────────────────────┘            │
│                                                                      │
│  ┌─────────────────────────────────────────────────────┐            │
│  │                 Monitoring & Detection                │            │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │            │
│  │  │ CloudTrail  │  │ GuardDuty   │  │  Config     │ │            │
│  │  │ Logging     │  │ Threat Det. │  │  Rules      │ │            │
│  │  └─────────────┘  └─────────────┘  └─────────────┘ │            │
│  │  ┌─────────────┐  ┌─────────────┐                   │            │
│  │  │ SecurityHub │  │  CloudWatch │                   │            │
│  │  │ Findings Mgmt│ │  Alarms     │                   │            │
│  │  └─────────────┘  └─────────────┘                   │            │
│  └─────────────────────────────────────────────────────┘            │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ 3. Validation Layer (Docker & CI/CD)                                 │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────┐                    │
│  │            Security Scanner Container        │                    │
│  │  ┌─────────────┐    ┌─────────────────┐     │                    │
│  │  │   Prowler   │    │   Checkov       │     │                    │
│  │  │   Scanner   │    │   IaC Scanner   │     │                    │
│  │  └─────────────┘    └─────────────────┘     │                    │
│  │         │                     │              │                    │
│  │  ┌──────┴────────┬────────────┴─────────────┐│                    │
│  │  │ CIS Benchmark │   Compliance Engine      ││                    │
│  │  │   Engine      │   (50+ checks)           ││                    │
│  │  └───────────────┴──────────────────────────┘│                    │
│  └─────────────────────────────────────────────┘                    │
│                         │                                           │
│  ┌────────────────────┴────────────────────┐                       │
│  │      GitHub Actions Workflow              │                       │
│  │                                          │                       │
│  │  1. Terraform Validate          ───────►─┼─► SUCCESS/FAIL        │
│  │  2. Security Scan               ───────►─┼─► SUCCESS/FAIL        │
│  │  3. Compliance Check             ───────►─┼─► SUCCESS/FAIL        │
│  │  4. Remediation                 ───────►─┼─► Approval            │
│  │  5. Re-scan                     ───────►─┼─► VALIDATION          │
│  │  6. Report Generation           ───────►─┼─► PUBLISH             │
│  └───────────────────────────────────────────┘                       │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ 4. Reporting Layer                                                   │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────┐             │
│  │              Report Generation                        │             │
│  │                                                       │             │
│  │  • JSON Report    (Machine-readable findings)         │             │
│  │  • Markdown       (Human-readable summary)            │             │
│  │  • HTML           (Visual dashboard)                  │             │
│  │  • Compliance Doc (Audit-ready documentation)         │             │
│  │  • Executive      (Management summary)                │             │
│  └─────────────────────────────────────────────────────┘             │
│                         │                                           │
│          ┌───────────────┼─────────────────┐                        │
│          ▼               ▼                 ▼                        │
│  S3 Bucket     Azure Blob    Slack/Teams   Email                     │
│  (Long-term)   Storage       Webhook       Alert                     │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Shift-Left Security
Security checks run early in the development lifecycle, preventing misconfigurations from reaching production.

### 2. Defense in Depth
Multiple layers of security controls:
- Network: Security groups, NACLs, WAF
- Identity: IAM, MFA, least privilege
- Data: Encryption at rest and in transit
- Monitoring: Continuous logging and alerting

### 3. Least Privilege
Every component has only the permissions necessary:
- Terraform roles for specific operations
- IAM policies scoped to required actions
- Service roles with minimal permissions

### 4. Continuous Compliance
- Automated scans run on every PR and daily
- Drift detection alerts for configuration changes
- Automated remediation where possible
- Audit trail for all changes

### 5. Immutable Infrastructure
Resources are never modified individually:
- Infrastructure is defined in code
- Changes require a new deployment
- Rollbacks are automated
- No manual configuration

## Data Flow

```
Commit → Terraform Plan → Security Scan → Deployment →
Config Recording → Compliance Check → Alert/Report
```

## Security Boundaries

| Layer | Boundary | Controls |
|-------|----------|----------|
| Network | VPC with private subnets, NACLs, SGs | Firewall, WAF, DDoS protection |
| Identity | IAM users, roles, policies | MFA, least privilege, SSO |
| Data | S3 buckets, EBS volumes, RDS | Encryption, access control, versioning |
| Monitoring | CloudWatch, Config, SecurityHub | Alerting, anomaly detection, auditing |

## Scalability Considerations

- Modular Terraform for reuse across environments
- Containerized security tools for consistent scanning
- Cloud-native services for auto-scaling
- Regional deployment for low latency

## Disaster Recovery

- Cross-region replication for critical data
- Encrypted backups with versioning
- Infrastructure recovery via Terraform
- State file backup and locking

---

For deployment instructions, see [DEPLOYMENT.md](./DEPLOYMENT.md).
