# Cloud Security Posture Audit

A production-ready infrastructure-as-code framework for continuous cloud security posture management, compliance validation, and automated remediation across multi-cloud environments.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cloud Security Pipeline                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Terraform │───▶│   Security  │───▶│    Prowler  │        │
│  │    IaC      │    │   Scanner   │    │   Scanner   │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                 │                  │                 │
│         ▼                 ▼                  ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │  CIS Check  │    │ Compliance  │    │ Remediation │        │
│  │   Engine    │    │   Reports   │    │   Engine    │        │
│  └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                 │                  │                 │
│         └─────────────────┴──────────────────┘                 │
│                           ▼                                     │
│                   ┌─────────────┐                              │
│                   │    Audit    │                              │
│                   │   Report    │                              │
│                   └─────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Infrastructure as Code**: Terraform modules for deployable, reproducible cloud infrastructure
- **CIS Benchmark Validation**: Automated checks against Center for Internet Security benchmarks
- **Multi-Cloud Support**: Compatible with AWS, Azure, and GCP environments
- **Continuous Compliance**: GitHub Actions workflow for posture scanning on every PR
- **Automated Remediation**: Python-based remediation engines for common misconfigurations
- **Audit-Ready Reports**: JSON and Markdown reports for compliance documentation

## CIS Controls Coverage

| Control Category | Implementation |
|------------------|----------------|
| Identity and Access Management | IAM policies, MFA enforcement, least privilege |
| Logging and Monitoring | CloudTrail, Azure Monitor, audit logging |
| Data Protection | Encryption at rest/transit, storage security |
| Network Security | Security groups, NSGs, VPC endpoints |
| Asset Management | Resource tagging, inventory tracking |

## Quick Start

### Prerequisites

- Terraform >= 1.5.0
- Python >= 3.10
- Docker >= 24.0
- Cloud provider credentials (AWS/Azure)

### Deployment

```bash
git clone https://github.com/<your-username>/cloud-security-posture-audit.git
cd cloud-security-posture-audit

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var="environment=prod"

# Deploy infrastructure
terraform apply
```

### Security Scanning

```bash
# Build security scanner
docker build -t security-scanner ./docker

# Run posture assessment
docker run --rm security-scanner --environment prod --benchmark cis

# Generate compliance report
python scripts/generate-report.py --format json,md
```

### Remediation

```bash
# Auto-remediate high-risk findings
python scripts/remediate.py --risk-level high --dry-run=false

# Validate remediation
python scripts/security-scan.py --mode post-remediation
```

## Project Structure

```
├── terraform/
│   ├── modules/
│   │   ├── security/
│   │   ├── compliance/
│   │   └── monitoring/
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── docker/
│   ├── Dockerfile
│   ├── Dockerfile.dev
│   └── docker-compose.yml
├── scripts/
│   ├── security-scan.py
│   ├── compliance-check.py
│   ├── remediate.py
│   └── generate-report.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   └── CIS-BENCHMARKS.md
├── reports/
│   ├── findings-template.md
│   └── compliance-score.json
└── .github/
    └── workflows/
        └── posture-scan.yml
```

## Compliance Frameworks

- CIS AWS/Azure/GCP Foundations Benchmark
- NIST SP 800-53
- ISO 27001
- SOC 2 Type II
- PCI DSS

## Key Learning Outcomes

This project demonstrates:
- Cloud security architecture design
- Infrastructure as Code with security controls baked in
- Automated compliance validation
- Risk-based remediation prioritization
- Security documentation for audits

## Resume Keywords

`Cloud Security`, `CIS Benchmarks`, `Infrastructure as Code`, `Security Posture Management`, `Compliance Automation`, `Terraform`, `DevSecOps`, `Risk Assessment`, `AWS/Azure Security`, `Audit Documentation`

## License

MIT
