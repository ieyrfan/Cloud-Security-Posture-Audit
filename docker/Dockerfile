FROM python:3.11-slim

LABEL maintainer="security-audit"
LABEL description="Cloud Security Posture Audit Container"

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN pip install --no-cache-dir \
    boto3 \
    azure-identity \
    azure-mgmt-resource \
    azure-mgmt-security \
    python-terraform \
    requests \
    pyyaml \
    jinja2 \
    reportlab \
    matplotlib \
    numpy

# Install prowler CLI
RUN pip install --no-cache-dir prowler

# Install Checkov for IaC scanning
RUN pip install --no-cache-dir checkov

# Create app directory
WORKDIR /app

# Copy application files
COPY scripts/ ./scripts/
COPY reports/ ./reports/
COPY docs/ ./docs/

# Set executable permissions
RUN chmod +x ./scripts/*.py

# Environment variables
ENV AWS_REGION=us-east-1
ENV SCAN_OUTPUT_DIR=/app/reports
ENV BENCHMARK_VERSION=v1.5.0

# Default command
CMD ["./scripts/security-scan.py", "--mode", "full"]
