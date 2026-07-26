#!/bin/bash
#===============================================================================
# fix_rds_encryption.sh
#
# Description: Identify unencrypted RDS instances and remediate by creating
#              encrypted snapshots and restoring as encrypted instances.
#              Handles Multi-AZ and deletion protection configurations.
#
# Usage:
#   ./fix_rds_encryption.sh                          # Normal mode
#   ./fix_rds_encryption.sh --dry-run                 # Preview only
#   ./fix_rds_encryption.sh --instance DB-ID          # Target specific instance
#   ./fix_rds_encryption.sh --kms-key-id KEY-ID       # Use specific KMS key
#   ./fix_rds_encryption.sh --skip-multi-az           # Don'"'t enable Multi-AZ
#   ./fix_rds_encryption.sh --no-deletion-protection  # Don'"'t enable del protection
#   ./fix_rds_encryption.sh --profile PROFILE         # AWS profile
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
LOG_FILE="${SCRIPT_DIR}/logs/rds-remediation-$(date +%Y%m%d-%H%M%S).log"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

# Default configuration
DRY_RUN=false
TARGET_INSTANCE=""
KMS_KEY_ID="alias/aws/rds"  # Default AWS managed key
ENABLE_MULTI_AZ=true
ENABLE_DELETION_PROTECTION=true
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Stats
TOTAL_UNENCRYPTED=0
TOTAL_PROCESSED=0
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
    if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" &> /dev/null; then log_error "AWS auth failed."; exit 1; fi
    mkdir -p "${SCRIPT_DIR}/logs"
    log_info "Account: $(aws sts get-caller-identity --query Account --output text --profile "${AWS_PROFILE}")"
}

# Find unencrypted RDS instances
find_unencrypted_rds() {
    log_info "Searching for unencrypted RDS instances..."
    
    local instances
    if [[ -n "${TARGET_INSTANCE}" ]]; then
        instances=$(aws rds describe-db-instances \
            --db-instance-identifier "${TARGET_INSTANCE}" \
            --query 'DBInstances[?StorageEncrypted==`false`]' \
            --output json \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>/dev/null || echo "[]")
    else
        instances=$(aws rds describe-db-instances \
            --query 'DBInstances[?StorageEncrypted==`false`]' \
            --output json \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}")
    fi
    
    local count
    count=$(echo "${instances}" | jq '. | length' 2>/dev/null || echo "0")
    
    if [[ "${count}" -eq 0 ]]; then
        log_success "No unencrypted RDS instances found."
        return 0
    fi
    
    TOTAL_UNENCRYPTED=${count}
    log_warn "Found ${count} unencrypted RDS instance(s)!"
    
    echo ""
    echo "${instances}" | jq -r '.[] | [.DBInstanceIdentifier, .Engine, .DBInstanceClass, .MultiAZ, .DeletionProtection, .Endpoint.Address] | @tsv' | while IFS=$'\t' read -r id engine cls multi_az del_prot endpoint; do
        log_warn "  Instance: ${id} | Engine: ${engine} | Class: ${cls} | Multi-AZ: ${multi_az}"
        process_instance "${id}" "${engine}" "${cls}" "${multi_az}" "${del_prot}" "${endpoint}"
    done
}

# Process a single unencrypted RDS instance
process_instance() {
    local db_id="$1"
    local engine="$2"
    local instance_class="$3"
    local multi_az="$4"
    local del_protection="$5"
    local endpoint="$6"
    
    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)
    local snapshot_name="${db_id}-pre-encryption-${timestamp}"
    local encrypted_snapshot="${db_id}-encrypted-${timestamp}"
    local new_db_id="${db_id}-encrypted-v2"
    
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  Processing: ${db_id}"
    echo "  Engine: ${engine}"
    echo "  Current Multi-AZ: ${multi_az}"
    echo "  Current Endpoint: ${endpoint}"
    echo "═══════════════════════════════════════════"
    echo ""
    
    # Step 1: Create snapshot
    log_info "[1/5] Creating unencrypted snapshot: ${snapshot_name}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would create snapshot: ${snapshot_name}"
    else
        if ! aws rds create-db-snapshot \
            --db-instance-identifier "${db_id}" \
            --db-snapshot-identifier "${snapshot_name}" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" &> /dev/null; then
            log_error "  Failed to create snapshot for ${db_id}"
            return 1
        fi
        log_success "  Snapshot created: ${snapshot_name}"
        
        # Wait for snapshot to complete
        log_info "  Waiting for snapshot to complete..."
        if ! aws rds wait db-snapshot-completed \
            --db-snapshot-identifier "${snapshot_name}" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}"; then
            log_error "  Snapshot did not complete"
            return 1
        fi
        log_success "  Snapshot completed"
    fi
    
    # Step 2: Copy snapshot with encryption
    log_info "[2/5] Creating encrypted copy of snapshot..."
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would copy snapshot with encryption (KMS: ${KMS_KEY_ID})"
    else
        local source_arn
        source_arn=$(aws rds describe-db-snapshots \
            --db-snapshot-identifier "${snapshot_name}" \
            --query 'DBSnapshots[0].DBSnapshotArn' --output text \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}")
        
        if ! aws rds copy-db-snapshot \
            --source-db-snapshot-identifier "${source_arn}" \
            --target-db-snapshot-identifier "${encrypted_snapshot}" \
            --kms-key-id "${KMS_KEY_ID}" \
            --copy-tags \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" &> /dev/null; then
            log_error "  Failed to copy snapshot with encryption"
            return 1
        fi
        log_success "  Encrypted snapshot: ${encrypted_snapshot}"
        
        log_info "  Waiting for encrypted snapshot..."
        aws rds wait db-snapshot-completed \
            --db-snapshot-identifier "${encrypted_snapshot}" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
        log_success "  Encrypted snapshot ready"
    fi
    
    # Step 3: Restore as encrypted instance
    log_info "[3/5] Restoring encrypted instance: ${new_db_id}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would restore instance: ${new_db_id}"
        log_info "  [DRY-RUN]   Instance class: ${instance_class}"
        log_info "  [DRY-RUN]   Multi-AZ: ${ENABLE_MULTI_AZ}"
        log_info "  [DRY-RUN]   Public accessibility: false"
    else
        local restore_cmd
        restore_cmd="aws rds restore-db-instance-from-db-snapshot"
        restore_cmd+=" --db-instance-identifier ${new_db_id}"
        restore_cmd+=" --db-snapshot-identifier ${encrypted_snapshot}"
        restore_cmd+=" --db-instance-class ${instance_class}"
        restore_cmd+=" --no-publicly-accessible"
        
        if [[ "${ENABLE_MULTI_AZ}" == "true" ]]; then
            restore_cmd+=" --multi-az"
        else
            restore_cmd+=" --no-multi-az"
        fi
        
        restore_cmd+=" --profile ${AWS_PROFILE} --region ${AWS_REGION}"
        
        if ! eval "${restore_cmd}" &> /dev/null; then
            log_error "  Failed to restore encrypted instance"
            return 1
        fi
        log_success "  Instance restored: ${new_db_id}"
        
        log_info "  Waiting for instance to be available..."
        aws rds wait db-instance-available \
            --db-instance-identifier "${new_db_id}" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}"
        log_success "  Instance is available"
    fi
    
    # Step 4: Configure protection
    log_info "[4/5] Configuring protection settings..."
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would configure deletion protection: ${ENABLE_DELETION_PROTECTION}"
        log_info "  [DRY-RUN] Would configure backup retention: 35 days"
    else
        local modify_cmd="aws rds modify-db-instance"
        modify_cmd+=" --db-instance-identifier ${new_db_id}"
        modify_cmd+=" --backup-retention-period 35"
        
        if [[ "${ENABLE_DELETION_PROTECTION}" == "true" ]]; then
            modify_cmd+=" --deletion-protection"
        else
            modify_cmd+=" --no-deletion-protection"
        fi
        
        modify_cmd+=" --apply-immediately"
        modify_cmd+=" --profile ${AWS_PROFILE} --region ${AWS_REGION}"
        
        if ! eval "${modify_cmd}" &> /dev/null; then
            log_error "  Failed to configure protection"
            return 1
        fi
        log_success "  Protection settings applied"
    fi
    
    # Step 5: Print connection info
    log_info "[5/5] Connection information"
    local new_endpoint
    if [[ "${DRY_RUN}" == "true" ]]; then
        new_endpoint="${new_db_id}.DRY-RUN.REGION.rds.amazonaws.com"
    else
        new_endpoint=$(aws rds describe-db-instances \
            --db-instance-identifier "${new_db_id}" \
            --query 'DBInstances[0].Endpoint.Address' --output text \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}")
    fi
    
    echo ""
    echo "  ───────────────────────────────────────────"
    echo "  NEW INSTANCE DETAILS:"
    echo "  ID:       ${new_db_id}"
    echo "  Endpoint: ${new_endpoint}"
    echo "  Encrypted: true"
    echo "  Multi-AZ:  ${ENABLE_MULTI_AZ}"
    echo "  ───────────────────────────────────────────"
    echo ""
    log_warn "  ACTION REQUIRED: Update application connection strings!"
    
    TOTAL_PROCESSED=$((TOTAL_PROCESSED + 1))
}

#===============================================================================
# Main
#===============================================================================

main() {
    echo "==========================================="
    echo "  RDS Encryption Remediation Script"
    echo "==========================================="
    echo ""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)              DRY_RUN=true; shift ;;
            --instance)             TARGET_INSTANCE="$2"; shift 2 ;;
            --kms-key-id)           KMS_KEY_ID="$2"; shift 2 ;;
            --skip-multi-az)        ENABLE_MULTI_AZ=false; shift ;;
            --no-deletion-protection) ENABLE_DELETION_PROTECTION=false; shift ;;
            --profile)              AWS_PROFILE="$2"; shift 2 ;;
            --region)               AWS_REGION="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
                echo "Options:"
                echo "  --dry-run                 Preview mode"
                echo "  --instance DB-ID          Target specific instance"
                echo "  --kms-key-id KEY-ID       KMS key for encryption"
                echo "  --skip-multi-az           Don'"'t enable Multi-AZ"
                echo "  --no-deletion-protection  Don'"'t enable deletion protection"
                echo "  --profile PROFILE         AWS profile"
                echo "  --region REGION           AWS region"
                exit 0 ;;
            *) log_error "Unknown: $1"; exit 1 ;;
        esac
    done
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "*** DRY-RUN MODE — No changes will be applied ***"
    fi
    
    check_prerequisites
    find_unencrypted_rds
    
    echo ""
    echo "==========================================="
    echo "  Summary"
    echo "==========================================="
    echo "  Unencrypted instances found: ${TOTAL_UNENCRYPTED}"
    echo "  Processed:                   ${TOTAL_PROCESSED}"
    echo "  Errors:                      ${ERRORS}"
    echo "==========================================="
    echo ""
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "Dry-run complete. Run without --dry-run to apply changes."
    fi
    
    return ${ERRORS}
}

main "$@"
