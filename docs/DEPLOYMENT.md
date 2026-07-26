# Deployment Guide

## Prerequisites

- AWS Account with programmatic access
- Terraform >= 1.5.0
- Python >= 3.10
- Docker >= 24.0
- GitHub CLI (for CI/CD)

## Step 1: Clone Repository

```bash
git clone https://github.com/<your-username>/cloud-security-posture-audit.git
cd cloud-security-posture-audit
```

## Step 2: Configure AWS Credentials

```bash
aws configure
# Enter AWS Access Key ID
# Enter AWS Secret Access Key
# Enter default region (e.g., us-east-1)
# Enter default output format (json)
```

## Step 3: Initialize Terraform

```bash
cd terraform
terraform init
terraform plan -var="environment=prod"
terraform apply
```

## Step 4: Deploy Security Scanner

```bash
cd ../docker
docker build -t security-scanner .
docker-compose up -d
```

## Step 5: Run Initial Scan

```bash
cd scripts
python security-scan.py --environment prod
python compliance-check.py --benchmark cis
python generate-report.py
```

## Step 6: Configure CI/CD

1. Fork repository to your GitHub account
2. Add secrets to repository:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN`
3. Enable GitHub Pages for report publishing
4. Update workflow file with your Docker Hub username

## Step 7: Validate

- Review Security Hub findings in AWS Console
- Check compliance score from generated reports
- Verify GitHub Actions workflow passes

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Terraform state lock | `terraform force-unlock <lock-id>` |
| Permission errors | Verify IAM permissions for AWS account |
| Scan timeout | Increase timeout in Python script |
| Docker build fails | Verify Docker daemon is running |
