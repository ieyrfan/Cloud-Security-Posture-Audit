#!/bin/bash
#===============================================================================
# fix_security_groups.sh
#
# Description: Identify and remediate overly permissive security group ingress
#              rules. Finds security groups with 0.0.0.0/0 on ports 22 (SSH),
#              3389 (RDP), and 443 (HTTPS/HTTP) and restricts them.
#
# Usage:
#   ./fix_security_groups.sh                  # Normal mode
#   ./fix_security_groups.sh --dry-run         # Preview only
#   ./fix_security_groups.sh --port 22         # Target specific port only
#   ./fix_security_groups.sh --cidr 10.0.0.0/8 # Replace with specific CIDR
#   ./fix_security_groups.sh --sg-id SG-ID     # Target specific SG only
#   ./fix_security_groups.sh --profile PROFILE # AWS profile
#
# Requirements:
#   - AWS CLI v2.x
#   - IAM: ec2:Describe*, ec2:Revoke*, ec2:Authorize*
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
LOG_FILE="${SCRIPT_DIR}/logs/sg-remediation-$(date +%Y%m%d-%H%M%S).log"
TIMESTAMP_FORMAT="+%Y-%m-%d %H:%M:%S"

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

# Default configuration
DRY_RUN=false
REPLACEMENT_CIDR="10.0.0.0/8"  # Default corporate CIDR
TARGET_PORT=""
TARGET_SG=""
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Ports to check
RESTRICTED_PORTS=(22 3389 443 80)
PORT_DESCRIPTIONS=(
    "22:SSH"
    "3389:RDP"
    "443:HTTPS"
    "80:HTTP"
)

# Stats
TOTAL_OVERRULES=0
FIXED_RULES=0
ERRORS=0

#===============================================================================
# Functions
#===============================================================================

log() {
    local level="$1"
    local message="$2"
    echo -e "$(date "${TIMESTAMP_FORMAT}") [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info()    { log "INFO"    "${BLUE}${1}${NC}"; }
log_success() { log "SUCCESS" "${GREEN}${1}${NC}"; }
log_warn()    { log "WARN"    "${YELLOW}${1}${NC}"; }
log_error()   { log "ERROR"   "${RED}${1}${NC}"; ERRORS=$((ERRORS + 1)); }

print_banner() {
    echo "==========================================="
    echo "  Security Group Remediation Script"
    echo "  Version 1.0.0"
    echo "==========================================="
    echo ""
}

print_summary() {
    echo ""
    echo "==========================================="
    echo "  Remediation Summary"
    echo "==========================================="
    echo "  Overly permissive rules found: ${TOTAL_OVERRULES}"
    echo "  Rules remediated:              ${FIXED_RULES}"
    echo "  Errors:                        ${ERRORS}"
    echo "==========================================="
}

check_prerequisites() {
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not installed."
        exit 1
    fi
    
    if ! aws sts get-caller-identity --profile "${AWS_PROFILE}" --region "${AWS_REGION}" &> /dev/null; then
        log_error "AWS authentication failed."
        exit 1
    fi
    
    mkdir -p "${SCRIPT_DIR}/logs"
    log_info "AWS Profile: ${AWS_PROFILE}, Region: ${AWS_REGION}"
}

# Find security groups with 0.0.0.0/0 on a given port
find_overly_permissive_sgs() {
    local port="$1"
    local port_name="$2"
    
    log_info "Searching for SGs with 0.0.0.0/0 on port ${port} (${port_name})..."
    
    local sg_list
    sg_list=$(aws ec2 describe-security-groups \
        --filters "Name=ip-permission.from-port,Values=${port}" "Name=ip-permission.cidr,Values=0.0.0.0/0" \
        --query 'SecurityGroups[*].[GroupId,GroupName,VpcId,Description]' \
        --output text \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}" 2>/dev/null || true)
    
    if [[ -z "${sg_list}" ]]; then
        log_info "  No over-permissive SGs found for port ${port}."
        return 0
    fi
    
    echo "${sg_list}" | while read -r sg_id sg_name vpc_id sg_desc; do
        if [[ -z "${sg_id}" ]]; then
            continue
        fi
        TOTAL_OVERRULES=$((TOTAL_OVERRULES + 1))
        echo "  ⚠  ${RED}SG: ${sg_id}${NC} | Name: ${sg_name} | VPC: ${vpc_id}"
        process_security_group "${sg_id}" "${sg_name}" "${port}"
    done
    
    return 0
}

# Process a single security group
process_security_group() {
    local sg_id="$1"
    local sg_name="$2"
    local port="$3"
    
    echo ""
    echo "───────────────────────────────────────────"
    echo "  Processing SG: ${sg_id} (${sg_name})"
    echo "  Port: ${port}"
    echo "───────────────────────────────────────────"
    
    # Get detailed info on the specific rule
    local current_rules
    current_rules=$(aws ec2 describe-security-groups \
        --group-ids "${sg_id}" \
        --query "SecurityGroups[0].IpPermissions[?ToPort==\`${port}\`]" \
        --output json \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}")
    
    # Check if this SG is attached to any EC2 instances
    local attached_instances
    attached_instances=$(aws ec2 describe-network-interfaces \
        --filters "Name=group-id,Values=${sg_id}" \
        --query 'NetworkInterfaces[*].{InstanceId:Attachment.InstanceId,PrivateIp:PrivateIpAddress}' \
        --output text \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}" 2>/dev/null || echo "None")
    
    if [[ "${attached_instances}" != "None" ]] && [[ -n "${attached_instances}" ]]; then
        log_info "  Attached to instances:"
        echo "${attached_instances}" | while read -r line; do
            echo "    - ${line}"
        done
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "  [DRY-RUN] Would remove 0.0.0.0/0 ingress on port ${port}"
        log_info "  [DRY-RUN] Would add ${REPLACEMENT_CIDR} ingress on port ${port}"
        return 0
    fi
    
    # Revoke the permissive rule
    log_info "  Revoking 0.0.0.0/0 ingress on port ${port}..."
    if aws ec2 revoke-security-group-ingress \
        --group-id "${sg_id}" \
        --protocol tcp \
        --port "${port}" \
        --cidr 0.0.0.0/0 \
        --profile "${AWS_PROFILE}" \
        --region "${AWS_REGION}" 2>&1; then
        log_success "  ✓ Removed 0.0.0.0/0 on port ${port}"
        
        # Add restricted CIDR
        log_info "  Adding ${REPLACEMENT_CIDR} ingress on port ${port}..."
        if aws ec2 authorize-security-group-ingress \
            --group-id "${sg_id}" \
            --protocol tcp \
            --port "${port}" \
            --cidr "${REPLACEMENT_CIDR}" \
            --profile "${AWS_PROFILE}" \
            --region "${AWS_REGION}" 2>&1; then
            log_success "  ✓ Added ${REPLACEMENT_CIDR} on port ${port}"
            FIXED_RULES=$((FIXED_RULES + 1))
        else
            log_error "  ✗ Failed to add restricted CIDR"
        fi
    else
        log_error "  ✗ Failed to revoke permissive rule"
    fi
    
    echo ""
}

#===============================================================================
# Main
#===============================================================================

main() {
    print_banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)    DRY_RUN=true; shift ;;
            --cidr)       REPLACEMENT_CIDR="$2"; shift 2 ;;
            --port)       TARGET_PORT="$2"; shift 2 ;;
            --sg-id)      TARGET_SG="$2"; shift 2 ;;
            --profile)    AWS_PROFILE="$2"; shift 2 ;;
            --region)     AWS_REGION="$2"; shift 2 ;;
            --help|-h)
                echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
                echo "Options:"
                echo "  --dry-run           Preview changes"
                echo "  --cidr CIDR         Replacement CIDR (default: 10.0.0.0/8)"
                echo "  --port PORT         Target specific port (22, 3389, 443, 80)"
                echo "  --sg-id SG-ID       Target specific security group"
                echo "  --profile PROFILE   AWS profile"
                echo "  --region REGION     AWS region"
                exit 0 ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_warn "*** DRY-RUN MODE — No changes applied ***"
    fi
    
    check_prerequisites
    
    # Determine which ports to process
    if [[ -n "${TARGET_PORT}" ]]; then
        # Validate port
        case ${TARGET_PORT} in
            22|80|443|3389) ;;
            *) log_error "Unsupported port: ${TARGET_PORT}. Supported: 22, 80, 443, 3389"; exit 1 ;;
        esac
        find_overly_permissive_sgs "${TARGET_PORT}" "PORT_${TARGET_PORT}"
    else
        for port_desc in "${PORT_DESCRIPTIONS[@]}"; do
            port="${port_desc%%:*}"
            name="${port_desc#*:}"
            find_overly_permissive_sgs "${port}" "${name}"
        done
    fi
    
    print_summary
    
    if [[ "${ERRORS}" -gt 0 ]]; then
        log_warn "Completed with ${ERRORS} error(s)"
        return 1
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "Dry-run complete. Run without --dry-run to apply changes."
    else
        log_success "Remediation complete."
    fi
}

main "$@"
