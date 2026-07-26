#!/bin/bash
#===============================================================================
# enable_cloudtrail.sh
#
# Description: Enable comprehensive multi-region CloudTrail with S3 bucket,
#              log file validation, and CloudWatch Logs integration.
#
# Usage:
#   ./enable_cloudtrail.sh                          # Normal mode
#   ./enable_cloudtrail.sh --dry-run                # Preview only
#   ./enable_cloudtrail.sh --trail-name NAME        # Custom trail name
#   ./enable_cloudtrail.sh --bucket BUCKET-NAME     # Custom bucket name
#   ./enable_cloudtrail.sh --no-cloudwatch          # Skip CloudWatch Logs
#   ./enable_cloudtrail.sh --profile PROFILE        # AWS profile
#   ./enable_cloudtrail.sh --region REGION          # Home region for trail
#
# Author: Security Engineering Team
# Version: 1.0.0
#===============================================================================

set -euo pipefail

#===============================================================================
# Configuration
#===============================================================================

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOG_FILE="${SCRIPT_DIR}/logs/cloudtrail-enable-$(date +%Y%m%d-%H%M%S).log"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

# Defaults
DRY_RUN=false
TRAIL_NAME=""
CUSTOM_BUCKET=""
ENABLE_CLOUDWATCH=true
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Stats
ERRORS=0

#===============================================================================
# Functions
#===============================================================================

log() { local l="$1"; local m="$2"; echo -e "$(date "+%Y-%m-%d %H:%M:%S") [${l}] ${m}" | tee -a "${LOG_FILE}"; }
log_info()    { log "INFO"    "${BLUE}${1}${NC}"; }
log_success() { log "SUCCESS" "${GREEN}${1}${NC}"; }
log_warn()    { log "WARN"    "${YELLOW}${1}${NC}"; }
log_error()   { log "ERROR"   "${RED}${1}${NC}"; ERRORS=$((ERRORS + 1)); }

check_prerequisites() {
    if ! command -v aws &> /dev/null; then log_error "AWS CLI not installed."; exit 1; fi
    if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" &> /dev/null 2>&1; then log_error "AWS auth failed."; exit 1; fi
    mkdir -p "${SCRIPT_DIR}/logs"
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile "${AWS_PROFILE}")
    log_info "Account: ${ACCOUNT_ID}, Region: ${AWS_REGION}"
}

# Generate trail name and bucket name if not provided
initialize_names() {
    if [[ -z "${TRAIL_NAME}" ]]; then
        TRAIL_NAME="multi-region-cloudtrail-${ACCOUNT_ID}"
    fi
    if [[ -z "${CUSTOM_BUCKET}" ]]; then
        CUSTOM_BUCKET="cloudtrail-logs-${ACCOUNT_ID}-$(date +%Y%m%d)"
    fi
    log_info "Trail Name: ${TRAIL_NAME}"
    log_info "Log Bucket: ${CUSTOM_BUCKET}"
}

# Step 1: Create S3 bucket for CloudTrail logs
create_s3_bucket() {
    log_info "[1/5] Creating S3 bucket for CloudTrail logs..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would create bucket: ${CUSTOM_BUCKET}"
        return 0
    fi
    
    # Check if bucket exists
    if aws s3api head-bucket --bucket "${CUSTOM_BUCKET}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>/dev/null; then
        log_info "  Bucket already exists: ${CUSTOM_BUCKET}"
    else
        if [[ "${AWS_REGION}" == "us-east-1" ]]; then
            aws s3api create-bucket \
                --bucket "${CUSTOM_BUCKET}" \
                --region "${AWS_REGION}" \
                --profile "${AWS_PROFILE}" 2>&1
        else
            aws s3api create-bucket \
                --bucket "${CUSTOM_BUCKET}" \
                --region "${AWS_REGION}" \
                --create-bucket-configuration "LocationConstraint=${AWS_REGION}" \
                --profile "${AWS_PROFILE}" 2>&1
        fi
        log_success "  Bucket created: ${CUSTOM_BUCKET}"
    fi
    
    # Enable default encryption
    log_info "  Enabling default encryption on bucket..."
    aws s3api put-bucket-encryption \
        --bucket "${CUSTOM_BUCKET}" \
        --server-side-encryption-configuration '{
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
            }]
        }' \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
    log_success "  Encryption enabled"
    
    # Block public access
    aws s3api put-public-access-block \
        --bucket "${CUSTOM_BUCKET}" \
        --public-access-block-configuration '{
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        }' \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
    log_success "  Public access blocked"
    
    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "${CUSTOM_BUCKET}" \
        --versioning-configuration "Status=Enabled" \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
    log_success "  Versioning enabled"
}

# Step 2: Attach bucket policy for CloudTrail
attach_bucket_policy() {
    log_info "[2/5] Attaching S3 bucket policy for CloudTrail..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would attach bucket policy allowing CloudTrail writes"
        return 0
    fi
    
    local bucket_policy
    bucket_policy=$(cat << POLICYEOT
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${CUSTOM_BUCKET}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${CUSTOM_BUCKET}/AWSLogs/${ACCOUNT_ID}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICYEOT
)
    
    echo "${bucket_policy}" > /tmp/cloudtrail-bucket-policy-${ACCOUNT_ID}.json
    
    aws s3api put-bucket-policy \
        --bucket "${CUSTOM_BUCKET}" \
        --policy "file:///tmp/cloudtrail-bucket-policy-${ACCOUNT_ID}.json" \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
    
    log_success "  Bucket policy attached"
    rm -f "/tmp/cloudtrail-bucket-policy-${ACCOUNT_ID}.json"
}

# Step 3: Create IAM role for CloudWatch Logs delivery (if needed)
create_cloudwatch_role() {
    log_info "[3/5] Setting up CloudWatch Logs integration..."
    
    if [[ "${ENABLE_CLOUDWATCH}" == "false" ]]; then
        log_info "  CloudWatch integration skipped (--no-cloudwatch)"
        return 0
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would create CloudWatch Logs role and log group"
        return 0
    fi
    
    CW_LOG_GROUP="aws-cloudtrail-logs-${ACCOUNT_ID}"
    CW_ROLE_NAME="CloudTrail_CloudWatchLogs_Role_${ACCOUNT_ID}"
    
    # Create log group
    aws logs create-log-group --log-group-name "${CW_LOG_GROUP}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>/dev/null || log_info "  Log group exists: ${CW_LOG_GROUP}"
    log_success "  Log group: ${CW_LOG_GROUP}"
    
    # Create IAM role for CloudTrail to write to CloudWatch
    local trust_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }'
    
    if ! aws iam get-role --role-name "${CW_ROLE_NAME}" --profile "${AWS_PROFILE}" &> /dev/null; then
        aws iam create-role \
            --role-name "${CW_ROLE_NAME}" \
            --assume-role-policy-document "${trust_policy}" \
            --profile "${AWS_PROFILE}" 2>&1
        
        aws iam put-role-policy \
            --role-name "${CW_ROLE_NAME}" \
            --policy-name "CloudTrailCloudWatchLogs" \
            --policy-document '{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams"
                        ],
                        "Resource": "*"
                    }
                ]
            }' \
            --profile "${AWS_PROFILE}"
    fi
    log_success "  IAM role: ${CW_ROLE_NAME}"
    
    CW_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${CW_ROLE_NAME}"
}

# Step 4: Create multi-region CloudTrail trail
create_trail() {
    log_info "[4/5] Creating multi-region CloudTrail trail..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would create trail: ${TRAIL_NAME}"
        log_info "  [DRY-RUN]   Multi-region: true"
        log_info "  [DRY-RUN]   Log validation: true"
        log_info "  [DRY-RUN]   Global events: true"
        return 0
    fi
    
    # Check if trail already exists
    if aws cloudtrail describe-trails --trail-name-list "${TRAIL_NAME}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>/dev/null | grep -q "${TRAIL_NAME}"; then
        log_warn "  Trail ${TRAIL_NAME} already exists. Updating..."
        
        # Update trail configuration
        aws cloudtrail update-trail \
            --name "${TRAIL_NAME}" \
            --s3-bucket-name "${CUSTOM_BUCKET}" \
            --is-multi-region-trail \
            --enable-log-file-validation \
            --include-global-service-events \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1
        
        log_success "  Trail updated"
    else
        aws cloudtrail create-trail \
            --name "${TRAIL_NAME}" \
            --s3-bucket-name "${CUSTOM_BUCKET}" \
            --is-multi-region-trail \
            --enable-log-file-validation \
            --include-global-service-events \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1
        
        log_success "  Trail created"
    fi
    
    # If CloudWatch is enabled, attach it to trail
    if [[ "${ENABLE_CLOUDWATCH}" == "true" ]]; then
        log_info "  Attaching CloudWatch Logs to trail..."
        aws cloudtrail update-trail \
            --name "${TRAIL_NAME}" \
            --cloud-watch-logs-log-group-arn "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:${CW_LOG_GROUP}:*" \
            --cloud-watch-logs-role-arn "${CW_ROLE_ARN}" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1
        log_success "  CloudWatch Logs attached"
    fi
    
    # Start logging
    log_info "  Starting logging..."
    aws cloudtrail start-logging --name "${TRAIL_NAME}" --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
    log_success "  Logging started"
}

# Step 5: Configure event selectors (data events)
configure_event_selectors() {
    log_info "[5/5] Configuring event selectors (management + data events)..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would configure event selectors for all management events"
        return 0
    fi
    
    aws cloudtrail put-event-selectors \
        --trail-name "${TRAIL_NAME}" \
        --event-selectors '[
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": true,
                "DataResources": []
            }
        ]' \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1
    
    log_success "  Event selectors configured"
}

# Verification
verify_trail() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  VERIFICATION"
    echo "═══════════════════════════════════════════"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  Skipping verification in dry-run mode."
        return 0
    fi
    
    echo ""
    local trail_info
    trail_info=$(aws cloudtrail describe-trails \
        --trail-name-list "${TRAIL_NAME}" \
        --query 'trailList[0]' \
        --output json \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}")
    
    echo "${trail_info}" | python3 -m json.tool 2>/dev/null || echo "${trail_info}"
    
    echo ""
    local trail_status
    trail_status=$(aws cloudtrail get-trail-status \
        --name "${TRAIL_NAME}" \
        --profile "${AWS_PROFILE}" --region "${AWS_REGION}")
    
    local is_logging
    is_logging=$(echo "${trail_status}" | jq -r '.IsLogging' 2>/dev/null || echo "unknown")
    
    if [[ "${is_logging}" == "true" ]]; then
        log_success "✅ Trail is active and logging"
    else
        log_error "❌ Trail is NOT logging!"
    fi
    
    local is_multi
    is_multi=$(echo "${trail_info}" | jq -r '.IsMultiRegionTrail' 2>/dev/null || echo "unknown")
    if [[ "${is_multi}" == "true" ]]; then
        log_success "✅ Multi-region trail enabled"
    fi
    
    local has_validation
    has_validation=$(echo "${trail_info}" | jq -r '.LogFileValidationEnabled' 2>/dev/null || echo "unknown")
    if [[ "${has_validation}" == "true" ]]; then
        log_success "✅ Log file validation enabled"
    fi
    
    echo ""
}

#===============================================================================
# Main
#===============================================================================

main() {
    echo "==========================================="
    echo "  CloudTrail Enablement Script"
    echo "==========================================="
    echo ""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)          DRY_RUN=true; shift ;;
            --trail-name)       TRAIL_NAME="$2"; shift 2 ;;
            --bucket)           CUSTOM_BUCKET="$2"; shift 2 ;;
            --no-cloudwatch)    ENABLE_CLOUDWATCH=false; shift ;;
            --profile)          AWS_PROFILE="$2"; shift 2 ;;
            --region)           AWS_REGION="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --dry-run              Preview changes without applying"
                echo "  --trail-name NAME      Custom trail name"
                echo "  --bucket BUCKET        Custom S3 bucket name"
                echo "  --no-cloudwatch        Skip CloudWatch Logs integration"
                echo "  --profile PROFILE      AWS CLI profile"
                echo "  --region REGION        AWS region for trail"
                echo "  --help, -h             Show this help"
                exit 0 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "*** DRY-RUN MODE — No changes applied ***"
    fi
    
    check_prerequisites
    initialize_names
    create_s3_bucket
    attach_bucket_policy
    create_cloudwatch_role
    create_trail
    configure_event_selectors
    verify_trail
    
    echo ""
    echo "==========================================="
    echo "  Complete"
    echo "==========================================="
    echo "  Trail: ${TRAIL_NAME}"
    echo "  Bucket: ${CUSTOM_BUCKET}"
    echo "  Errors: ${ERRORS}"
    echo "==========================================="
    echo ""
    
    return ${ERRORS}
}

main "$@"
