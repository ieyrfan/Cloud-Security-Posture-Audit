#!/bin/bash
#===============================================================================
# fix_s3_buckets.sh
#
# Description: Remediate S3 bucket security findings — Block Public Access,
#              enable default encryption (AES-256), and enable versioning
#              across all S3 buckets in the account.
#
# Usage:
#   ./fix_s3_buckets.sh                    # Normal mode — apply fixes
#   ./fix_s3_buckets.sh --dry-run           # Dry-run — preview changes only
#   ./fix_s3_buckets.sh --bucket BUCKET     # Target a specific bucket
#   ./fix_s3_buckets.sh --exclude BUCKET    # Exclude a specific bucket
#   ./fix_s3_buckets.sh --profile PROFILE   # Use specific AWS profile
#   ./fix_s3_buckets.sh --region REGION     # Use specific AWS region
#
# Requirements:
#   - AWS CLI v2.x installed and configured
#   - IAM permissions: s3:ListAllMyBuckets, s3:GetBucket*, s3:PutBucket*
#   - jq (optional, for pretty JSON output)
#
# Author: Security Engineering Team
# Version: 1.0.0
# License: Internal Use Only
#===============================================================================

set -euo pipefail

#===============================================================================
# Configuration & Constants
#===============================================================================

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOG_FILE="${SCRIPT_DIR}/logs/s3-remediation-$(date +%Y%m%d-%H%M%S).log"
TIMESTAMP_FORMAT="+%Y-%m-%d %H:%M:%S"

# Colors for output
RED=\'\033[0;31m\'
GREEN=\'\033[0;32m\'
YELLOW=\'\033[1;33m\'
BLUE=\'\033[0;34m\'
NC=\'\033[0m\' # No Color

# Default configuration
DRY_RUN=false
TARGET_BUCKET=""
EXCLUDE_BUCKETS=()
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Stats counters
TOTAL_BUCKETS=0
FIXED_PUBLIC_ACCESS=0
FIXED_ENCRYPTION=0
FIXED_VERSIONING=0
ERRORS=0

#===============================================================================
# Utility Functions
#===============================================================================

log() {
    local level="$1"
    local message="$2"
    echo -e "$(date "${TIMESTAMP_FORMAT}") [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info()  { log "INFO"    "${BLUE}${1}${NC}"; }
log_success() { log "SUCCESS" "${GREEN}${1}${NC}"; }
log_warn()  { log "WARN"    "${YELLOW}${1}${NC}"; }
log_error() { log "ERROR"   "${RED}${1}${NC}"; ERRORS=$((ERRORS + 1)); }

print_banner() {
    echo "==========================================="
    echo "  S3 Bucket Security Remediation Script"
    echo "  Version 1.0.0"
    echo "==========================================="
    echo ""
}

print_summary() {
    echo ""
    echo "==========================================="
    echo "  Remediation Summary"
    echo "==========================================="
    echo "  Total buckets scanned:  ${TOTAL_BUCKETS}"
    echo "  Public access blocked:   ${FIXED_PUBLIC_ACCESS}"
    echo "  Encryption enabled:      ${FIXED_ENCRYPTION}"
    echo "  Versioning enabled:      ${FIXED_VERSIONING}"
    echo "  Errors encountered:      ${ERRORS}"
    echo "==========================================="
    echo "  Log file: ${LOG_FILE}"
    echo "==========================================="
}

check_prerequisites() {
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi

    # Check AWS CLI version
    AWS_CLI_VERSION=$(aws --version 2>&1 | cut -d/ -f2 | cut -d. -f1)
    if [[ "${AWS_CLI_VERSION}" -lt 2 ]]; then
        log_warn "AWS CLI v1 detected. Consider upgrading to v2 for better features."
    fi

    # Check AWS credentials
    if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" --region "${AWS_REGION}" &> /dev/null; then
        log_error "Unable to authenticate with AWS. Check your credentials and profile."
        exit 1
    fi

    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    log_info "Authenticated as account: ${ACCOUNT_ID}"

    # Create logs directory
    mkdir -p "${SCRIPT_DIR}/logs"
    log_info "Log file: ${LOG_FILE}"
}

#===============================================================================
# Remediation Functions
#===============================================================================

fix_block_public_access() {
    local bucket="$1"
    
    log_info "Checking public access settings for: ${bucket}"
    
    # Get current public access block configuration
    local current_config
    current_config=$(aws s3api get-public-access-block --bucket "${bucket}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1 || echo "NOT_CONFIGURED")
    
    if [[ "${current_config}" == "NOT_CONFIGURED" ]]; then
        log_warn "  No public access block configured for: ${bucket}"
    else
        # Check if already fully blocked
        local block_public_acls
        block_public_acls=$(echo "${current_config}" | aws s3api get-public-access-block --bucket "${bucket}" --query 'PublicAccessBlockConfiguration.BlockPublicAcls' --output text 2>/dev/null || echo "false")
        
        if [[ "${block_public_acls}" == "true" ]]; then
            log_info "  ✓ Public access already blocked for: ${bucket}"
            return 0
        fi
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would enable Block Public Access for: ${bucket}"
        return 0
    fi
    
    # Apply Block Public Access configuration
    log_info "  Applying Block Public Access for: ${bucket}"
    if aws s3api put-public-access-block \
        --bucket "${bucket}" \
        --public-access-block-configuration '{
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        }' \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}" 2>&1; then
        log_success "  ✓ Block Public Access enabled for: ${bucket}"
        FIXED_PUBLIC_ACCESS=$((FIXED_PUBLIC_ACCESS + 1))
    else
        log_error "  ✗ Failed to enable Block Public Access for: ${bucket}"
        return 1
    fi
}

fix_default_encryption() {
    local bucket="$1"
    
    log_info "Checking encryption settings for: ${bucket}"
    
    # Get current encryption configuration
    local current_encryption
    current_encryption=$(aws s3api get-bucket-encryption --bucket "${bucket}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1 || echo "NOT_CONFIGURED")
    
    if [[ "${current_encryption}" != "NOT_CONFIGURED" ]]; then
        local sse_algorithm
        sse_algorithm=$(echo "${current_encryption}" | aws s3api get-bucket-encryption --bucket "${bucket}" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "")
        
        if [[ "${sse_algorithm}" == "AES256" ]] || [[ "${sse_algorithm}" == "aws:kms" ]]; then
            log_info "  ✓ Encryption already enabled (${sse_algorithm}) for: ${bucket}"
            return 0
        fi
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would enable default encryption (AES-256) for: ${bucket}"
        return 0
    fi
    
    # Enable default encryption with SSE-S3 (AES-256)
    log_info "  Enabling default encryption (AES-256) for: ${bucket}"
    if aws s3api put-bucket-encryption \
        --bucket "${bucket}" \
        --server-side-encryption-configuration '{
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        }' \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}" 2>&1; then
        log_success "  ✓ Default encryption enabled for: ${bucket}"
        FIXED_ENCRYPTION=$((FIXED_ENCRYPTION + 1))
    else
        log_error "  ✗ Failed to enable encryption for: ${bucket}"
        return 1
    fi
}

fix_versioning() {
    local bucket="$1"
    
    log_info "Checking versioning settings for: ${bucket}"
    
    # Get current versioning status
    local versioning_status
    versioning_status=$(aws s3api get-bucket-versioning --bucket "${bucket}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}" --query 'Status' --output text 2>&1 || echo "NotSet")
    
    if [[ "${versioning_status}" == "Enabled" ]]; then
        log_info "  ✓ Versioning already enabled for: ${bucket}"
        return 0
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would enable versioning for: ${bucket}"
        return 0
    fi
    
    # Enable versioning
    log_info "  Enabling versioning for: ${bucket}"
    if aws s3api put-bucket-versioning \
        --bucket "${bucket}" \
        --versioning-configuration '{
            "Status": "Enabled"
        }' \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}" 2>&1; then
        log_success "  ✓ Versioning enabled for: ${bucket}"
        FIXED_VERSIONING=$((FIXED_VERSIONING + 1))
    else
        log_error "  ✗ Failed to enable versioning for: ${bucket}"
        return 1
    fi
}

process_bucket() {
    local bucket="$1"
    
    echo ""
    echo "───────────────────────────────────────────"
    echo "  Processing bucket: ${bucket}"
    echo "───────────────────────────────────────────"
    
    TOTAL_BUCKETS=$((TOTAL_BUCKETS + 1))
    
    # Check if bucket is excluded
    for excluded in "${EXCLUDE_BUCKETS[@]}"; do
        if [[ "${bucket}" == "${excluded}" ]]; then
            log_info "  Skipping excluded bucket: ${bucket}"
            return 0
        fi
    done
    
    # Apply all three fixes
    fix_block_public_access "${bucket}"
    fix_default_encryption "${bucket}"
    fix_versioning "${bucket}"
    
    echo "  ─────────────────────────────────────────"
    echo "  Completed: ${bucket}"
    echo ""
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    print_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --bucket)
                TARGET_BUCKET="$2"
                shift 2
                ;;
            --exclude)
                EXCLUDE_BUCKETS+=("$2")
                shift 2
                ;;
            --profile)
                AWS_PROFILE="$2"
                shift 2
                ;;
            --region)
                AWS_REGION="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --dry-run           Preview changes without applying"
                echo "  --bucket BUCKET     Target specific bucket only"
                echo "  --exclude BUCKET    Exclude a bucket from processing"
                echo "  --profile PROFILE   AWS CLI profile to use"
                echo "  --region REGION     AWS region to use"
                echo "  --help, -h          Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information."
                exit 1
                ;;
        esac
    done
    
    log_info "Starting S3 bucket security remediation"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "*** DRY-RUN MODE — No changes will be applied ***"
    fi
    log_info "AWS Profile: ${AWS_PROFILE}"
    log_info "AWS Region:  ${AWS_REGION}"
    echo ""
    
    check_prerequisites
    
    # Get list of buckets
    if [[ -n "${TARGET_BUCKET}" ]]; then
        log_info "Targeting specific bucket: ${TARGET_BUCKET}"
        BUCKETS=("${TARGET_BUCKET}")
    else
        log_info "Listing all S3 buckets..."
        mapfile -t BUCKETS < <(aws s3api list-buckets --profile "${AWS_PROFILE}" --region "${AWS_REGION}" --query 'Buckets[*].Name' --output text | tr "\t" "\n")
        log_info "Found ${#BUCKETS[@]} bucket(s)"
    fi
    
    # Process each bucket
    for bucket in "${BUCKETS[@]}"; do
        process_bucket "${bucket}"
    done
    
    print_summary
    
    if [[ "${ERRORS}" -gt 0 ]]; then
        log_warn "Remediation completed with ${ERRORS} error(s). Check log file for details."
        return 1
    fi
    
    log_success "Remediation completed successfully."
    return 0
}

# Execute main function
main "$@"
