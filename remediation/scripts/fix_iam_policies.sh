#!/bin/bash
#===============================================================================
# fix_iam_policies.sh
#
# Description: Identify and remediate over-permissive IAM policies,
#              remove unused credentials, and enforce MFA.
#
# Usage:
#   ./fix_iam_policies.sh                           # Normal mode
#   ./fix_iam_policies.sh --dry-run                 # Preview only
#   ./fix_iam_policies.sh --enforce-mfa             # Enforce MFA policy
#   ./fix_iam_policies.sh --rotate-keys             # Rotate old access keys
#   ./fix_iam_policies.sh --remove-unused           # Remove unused keys/users
#   ./fix_iam_policies.sh --analyze-permissions     # Analyze over-permissive policies
#   ./fix_iam_policies.sh --all                     # Run all checks and fixes
#   ./fix_iam_policies.sh --profile PROFILE         # AWS profile
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
LOG_FILE="${SCRIPT_DIR}/logs/iam-remediation-$(date +%Y%m%d-%H%M%S).log"
REPORT_DIR="${SCRIPT_DIR}/reports/iam-$(date +%Y%m%d-%H%M%S)"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

# Defaults
DRY_RUN=false
ENFORCE_MFA=false
ROTATE_KEYS=false
REMOVE_UNUSED=false
ANALYZE_PERMISSIONS=false
RUN_ALL=false
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"
KEY_AGE_THRESHOLD=90  # days
UNUSED_THRESHOLD=90    # days

# Stats
TOTAL_USERS=0
TOTAL_ROLES=0
TOTAL_ADMIN_USERS=0
TOTAL_NO_MFA=0
TOTAL_OLD_KEYS=0
TOTAL_UNUSED_KEYS=0
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
    mkdir -p "${SCRIPT_DIR}/logs" "${REPORT_DIR}"
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --profile "${AWS_PROFILE}")
    log_info "Account: ${ACCOUNT_ID}"
    log_info "Reports: ${REPORT_DIR}"
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FINDING-009: Identify over-permissive policies
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

analyze_admin_access() {
    log_info "───────────────────────────────────────────"
    log_info "Analyzing AdministratorAccess assignments..."
    
    local admin_policy_arn="arn:aws:iam::aws:policy/AdministratorAccess"
    
    # Find all users/roles with AdministratorAccess
    local entities
    entities=$(aws iam list-entities-for-policy \
        --policy-arn "${admin_policy_arn}" \
        --profile "${AWS_PROFILE}" --output json 2>&1 || echo "{}")
    
    local user_count
    user_count=$(echo "${entities}" | jq '.PolicyUsers | length' 2>/dev/null || echo "0")
    local role_count
    role_count=$(echo "${entities}" | jq '.PolicyRoles | length' 2>/dev/null || echo "0")
    
    TOTAL_ADMIN_USERS=$((user_count + role_count))
    
    if [[ "${TOTAL_ADMIN_USERS}" -eq 0 ]]; then
        log_success "No users/roles with AdministratorAccess found."
        return 0
    fi
    
    log_warn "Found ${user_count} user(s) and ${role_count} role(s) with AdministratorAccess!"
    
    # List users with AdminAccess
    if [[ "${user_count}" -gt 0 ]]; then
        echo "" > "${REPORT_DIR}/admin-users.txt"
        echo "${entities}" | jq -r '.PolicyUsers[] | [.UserName, .UserId] | @tsv' | while IFS=$'\t' read -r uname uid; do
            log_warn "  USER: ${uname} (${uid})"
            echo "${uname}" >> "${REPORT_DIR}/admin-users.txt"
            
            # Get Access Advisor data
            local last_used
            last_used=$(aws iam generate-service-last-accessed-details \
                --arn "arn:aws:iam::${ACCOUNT_ID}:user/${uname}" \
                --profile "${AWS_PROFILE}" --query 'JobId' --output text 2>/dev/null || echo "")
            if [[ -n "${last_used}" ]]; then
                log_info "    Access Advisor Job: ${last_used}"
            fi
        done
    fi
    
    # List roles with AdminAccess
    if [[ "${role_count}" -gt 0 ]]; then
        echo "${entities}" | jq -r '.PolicyRoles[] | [.RoleName, .RoleId] | @tsv' | while IFS=$'\t' read -r rname rid; do
            log_warn "  ROLE: ${rname} (${rid})"
            echo "${rname}" >> "${REPORT_DIR}/admin-roles.txt"
        done
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would recommend replacing with least-privilege policies"
        return 0
    fi
    
    log_info "  Report saved to: ${REPORT_DIR}/admin-*.txt"
    log_info "  Review each user'
    s access needs and create custom policies."
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FINDING-006: Enforce MFA
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

enforce_mfa_compliance() {
    log_info "───────────────────────────────────────────"
    log_info "Enforcing MFA compliance..."
    
    # Generate credential report
    log_info "  Generating credential report..."
    aws iam generate-credential-report --profile "${AWS_PROFILE}" &> /dev/null || true
    sleep 2
    
    local report_content
    report_content=$(aws iam get-credential-report --query 'Content' --output text --profile "${AWS_PROFILE}" 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [[ -z "${report_content}" ]]; then
        log_warn "  Could not generate credential report. Listing users directly."
        # Fallback: list users directly
        local users
        users=$(aws iam list-users --query 'Users[*].UserName' --output text --profile "${AWS_PROFILE}")
        
        for user in ${users}; do
            TOTAL_USERS=$((TOTAL_USERS + 1))
            local mfa_count
            mfa_count=$(aws iam list-mfa-devices --user-name "${user}" --query 'length(MFADevices)' --output text --profile "${AWS_PROFILE}" 2>/dev/null || echo "0")
            
            if [[ "${mfa_count}" -eq 0 ]]; then
                log_warn "  ⚠  NO MFA: ${user}"
                TOTAL_NO_MFA=$((TOTAL_NO_MFA + 1))
            else
                log_success "  ✓ MFA OK: ${user}"
            fi
        done
    else
        # Parse credential report
        echo "${report_content}" > "${REPORT_DIR}/credential-report.csv"
        
        while IFS=',' read -r user pwd_enabled pwd_last_changed mfa_active key1_active key2_active cert1_active; do
            if [[ "${user}" == "user" ]] || [[ -z "${user}" ]]; then continue; fi
            TOTAL_USERS=$((TOTAL_USERS + 1))
            
            if [[ "${mfa_active}" == "false" ]]; then
                log_warn "  ⚠  NO MFA: ${user}"
                TOTAL_NO_MFA=$((TOTAL_NO_MFA + 1))
            else
                log_success "  ✓ MFA OK: ${user}"
            fi
        done <<< "${report_content}"
    fi
    
    log_info "  ${TOTAL_USERS} total users, ${TOTAL_NO_MFA} without MFA"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would attach MFA enforcement policy"
        return 0
    fi
    
    # Create and attach MFA enforcement policy
    if [[ "${TOTAL_NO_MFA}" -gt 0 ]]; then
        cat > /tmp/enforce-mfa-policy.json << 'POLICY'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyAllExceptListedIfNoMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:ListMFADevices",
                "iam:ListUsers",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "sts:GetSessionToken"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}
POLICY
        
        local policy_arn
        policy_arn=$(aws iam create-policy \
            --policy-name "EnforceMFAPolicy-${ACCOUNT_ID}" \
            --policy-document file:///tmp/enforce-mfa-policy.json \
            --description "Denies access to non-MFA authenticated users" \
            --profile "${AWS_PROFILE}" --query 'Policy.Arn' --output text 2>/dev/null || echo "")
        
        if [[ -n "${policy_arn}" ]]; then
            log_success "  MFA enforcement policy created: ${policy_arn}"
        else
            log_warn "  Policy may already exist. Attaching existing policy..."
            policy_arn="arn:aws:iam::${ACCOUNT_ID}:policy/EnforceMFAPolicy-${ACCOUNT_ID}"
        fi
        
        # Attach to all users/groups (example: attach to all groups)
        local groups
        groups=$(aws iam list-groups --query 'Groups[*].GroupName' --output text --profile "${AWS_PROFILE}")
        for group in ${groups}; do
            aws iam attach-group-policy \
                --group-name "${group}" \
                --policy-arn "${policy_arn}" \
                --profile "${AWS_PROFILE}" 2>/dev/null || true
            log_info "    Attached to group: ${group}"
        done
        
        rm -f /tmp/enforce-mfa-policy.json
    fi
    
    # Update password policy
    log_info "  Updating password policy..."
    aws iam update-account-password-policy \
        --minimum-password-length 14 \
        --require-symbols \
        --require-numbers \
        --require-uppercase-characters \
        --require-lowercase-characters \
        --allow-users-to-change-password \
        --max-password-age 90 \
        --password-reuse-prevention 24 \
        --hard-expiry \
        --profile "${AWS_PROFILE}" 2>&1 || log_warn "  Could not update password policy (may require higher privileges)"
    
    log_success "  Password policy updated"
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FINDING-008: Rotate old access keys
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

rotate_access_keys() {
    log_info "───────────────────────────────────────────"
    log_info "Checking access key rotation status..."
    
    local cutoff_date
    cutoff_date=$(date -d "-${KEY_AGE_THRESHOLD} days" +%Y-%m-%d 2>/dev/null || date -v-${KEY_AGE_THRESHOLD}d +%Y-%m-%d)
    log_info "  Keys older than ${cutoff_date} (${KEY_AGE_THRESHOLD} days) will be flagged"
    
    local users
    users=$(aws iam list-users --query 'Users[*].UserName' --output text --profile "${AWS_PROFILE}")
    
    for user in ${users}; do
        local keys
        keys=$(aws iam list-access-keys --user-name "${user}" --query 'AccessKeyMetadata[?Status==`Active`]' --output json --profile "${AWS_PROFILE}" 2>/dev/null || echo "[]")
        local key_count
        key_count=$(echo "${keys}" | jq '. | length' 2>/dev/null || echo "0")
        
        if [[ "${key_count}" -eq 0 ]]; then continue; fi
        
        echo "${keys}" | jq -c '.[]' | while read -r key; do
            local key_id
            key_id=$(echo "${key}" | jq -r '.AccessKeyId')
            local create_date
            create_date=$(echo "${key}" | jq -r '.CreateDate')
            
            if [[ "${create_date}" < "${cutoff_date}" ]]; then
                TOTAL_OLD_KEYS=$((TOTAL_OLD_KEYS + 1))
                log_warn "  ⚠  OLD KEY: ${user} / ${key_id} (created: ${create_date})"
                
                if [[ "${DRY_RUN}" == "true" ]]; then
                    log_info "    [DRY-RUN] Would rotate key: ${key_id}"
                else
                    log_info "    Creating new key for ${user}..."
                    local new_key
                    new_key=$(aws iam create-access-key --user-name "${user}" --profile "${AWS_PROFILE}" 2>&1 || echo "ERROR")
                    
                    if [[ "${new_key}" != "ERROR" ]]; then
                        local new_key_id
                        new_key_id=$(echo "${new_key}" | jq -r '.AccessKey.AccessKeyId')
                        local new_secret
                        new_secret=$(echo "${new_key}" | jq -r '.AccessKey.SecretAccessKey')
                        
                        log_success "    New key created: ${new_key_id}"
                        log_warn "    ACTION: Update applications with new key credentials"
                        
                        # Deactivate old key
                        aws iam update-access-key \
                            --user-name "${user}" \
                            --access-key-id "${key_id}" \
                            --status Inactive \
                            --profile "${AWS_PROFILE}"
                        log_info "    Old key deactivated: ${key_id}"
                    else
                        log_error "    Failed to rotate key for ${user}"
                    fi
                fi
            fi
        done
    done
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FINDING-016: Remove unused credentials
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

remove_unused_credentials() {
    log_info "───────────────────────────────────────────"
    log_info "Identifying unused access keys..."
    
    local users
    users=$(aws iam list-users --query 'Users[*].UserName' --output text --profile "${AWS_PROFILE}")
    
    for user in ${users}; do
        local keys
        keys=$(aws iam list-access-keys --user-name "${user}" --query 'AccessKeyMetadata[?Status==`Active`]' --output json --profile "${AWS_PROFILE}" 2>/dev/null || echo "[]")
        
        echo "${keys}" | jq -c '.[]' 2>/dev/null | while read -r key; do
            local key_id
            key_id=$(echo "${key}" | jq -r '.AccessKeyId')
            
            # Get last used date
            local last_used
            last_used=$(aws iam get-access-key-last-used \
                --access-key-id "${key_id}" \
                --query 'AccessKeyLastUsed.LastUsedDate' \
                --output text --profile "${AWS_PROFILE}" 2>/dev/null || echo "N/A")
            
            if [[ "${last_used}" == "N/A" ]] || [[ -z "${last_used}" ]]; then
                log_warn "  ⚠  NEVER USED: ${user} / ${key_id}"
                TOTAL_UNUSED_KEYS=$((TOTAL_UNUSED_KEYS + 1))
                
                if [[ "${REMOVE_UNUSED}" == "true" ]] && [[ "${DRY_RUN}" == "false" ]]; then
                    aws iam update-access-key \
                        --user-name "${user}" \
                        --access-key-id "${key_id}" \
                        --status Inactive \
                        --profile "${AWS_PROFILE}"
                    log_info "    Key deactivated: ${key_id}"
                elif [[ "${DRY_RUN}" == "true" ]]; then
                    log_info "    [DRY-RUN] Would deactivate unused key: ${key_id}"
                fi
            fi
        done
    done
}

#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Summary & Report
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_summary() {
    echo ""
    echo "==========================================="
    echo "  IAM Remediation Summary"
    echo "==========================================="
    echo "  Total users scanned:        ${TOTAL_USERS}"
    echo "  AdminAccess users/roles:    ${TOTAL_ADMIN_USERS}"
    echo "  Users without MFA:          ${TOTAL_NO_MFA}"
    echo "  Old access keys:            ${TOTAL_OLD_KEYS}"
    echo "  Unused access keys:         ${TOTAL_UNUSED_KEYS}"
    echo "  Errors:                     ${ERRORS}"
    echo "==========================================="
    echo "  Report: ${REPORT_DIR}/"
    echo "  Log:    ${LOG_FILE}"
    echo "==========================================="
    echo ""
    
    # Output action items
    echo "═══════════════════════════════════════════"
    echo "  ACTION ITEMS"
    echo "═══════════════════════════════════════════"
    if [[ "${TOTAL_ADMIN_USERS}" -gt 2 ]]; then
        echo "  ⚠  Review ${TOTAL_ADMIN_USERS} AdminAccess assignments — create custom policies"
    fi
    if [[ "${TOTAL_NO_MFA}" -gt 0 ]]; then
        echo "  ⚠  Enforce MFA for ${TOTAL_NO_MFA} user(s) without MFA"
    fi
    if [[ "${TOTAL_OLD_KEYS}" -gt 0 ]]; then
        echo "  ⚠  Rotate ${TOTAL_OLD_KEYS} old access key(s)"
    fi
    if [[ "${TOTAL_UNUSED_KEYS}" -gt 0 ]]; then
        echo "  ⚠  Remove ${TOTAL_UNUSED_KEYS} unused access key(s)"
    fi
    echo "═══════════════════════════════════════════"
    echo ""
}

#===============================================================================
# Main
#===============================================================================

main() {
    echo "==========================================="
    echo "  IAM Policy Remediation Script"
    echo "==========================================="
    echo ""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)              DRY_RUN=true; shift ;;
            --enforce-mfa)          ENFORCE_MFA=true; shift ;;
            --rotate-keys)          ROTATE_KEYS=true; shift ;;
            --remove-unused)        REMOVE_UNUSED=true; shift ;;
            --analyze-permissions)  ANALYZE_PERMISSIONS=true; shift ;;
            --all)                  ENFORCE_MFA=true; ROTATE_KEYS=true; REMOVE_UNUSED=true; ANALYZE_PERMISSIONS=true; shift ;;
            --profile)              AWS_PROFILE="$2"; shift 2 ;;
            --region)               AWS_REGION="$2"; shift 2 ;;
            --key-age-threshold)    KEY_AGE_THRESHOLD="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --dry-run                Preview changes"
                echo "  --enforce-mfa            Apply MFA enforcement policy"
                echo "  --rotate-keys            Rotate old access keys"
                echo "  --remove-unused          Remove unused credentials"
                echo "  --analyze-permissions    Analyze over-permissive policies"
                echo "  --all                    Run all checks and fixes"
                echo "  --profile PROFILE        AWS CLI profile"
                echo "  --region REGION          AWS region"
                echo "  --key-age-threshold DAYS Key age threshold (default: 90)"
                echo "  --help, -h               Show this help"
                exit 0 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "*** DRY-RUN MODE — No changes applied ***"
    fi
    
    check_prerequisites
    
    if [[ "${ANALYZE_PERMISSIONS}" == "true" ]] || [[ "${RUN_ALL}" == "true" ]]; then
        analyze_admin_access
    fi
    
    if [[ "${ENFORCE_MFA}" == "true" ]] || [[ "${RUN_ALL}" == "true" ]]; then
        enforce_mfa_compliance
    fi
    
    if [[ "${ROTATE_KEYS}" == "true" ]] || [[ "${RUN_ALL}" == "true" ]]; then
        rotate_access_keys
    fi
    
    if [[ "${REMOVE_UNUSED}" == "true" ]] || [[ "${RUN_ALL}" == "true" ]]; then
        remove_unused_credentials
    fi
    
    print_summary
    
    if [[ "${ERRORS}" -gt 0 ]]; then
        log_warn "Completed with ${ERRORS} error(s)."
        return 1
    fi
    
    log_success "IAM remediation complete."
    return 0
}

main "$@"
