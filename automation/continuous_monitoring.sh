#!/usr/bin/env bash
# ============================================================================
# continuous_monitoring.sh - Continuous cloud security monitoring pipeline
# ============================================================================
# Runs Prowler scans, parses results, compares against baselines, generates
# diff reports, sends notifications, and archives results.
#
# Usage:
#   ./continuous_monitoring.sh                    # Full pipeline run
#   ./continuous_monitoring.sh --dry-run          # Simulation only
#   ./continuous_monitoring.sh --baseline-only    # Create/update baseline
#   ./continuous_monitoring.sh --quick            # Skip full re-scan if recent
#   ./continuous_monitoring.sh --help             # Show this help
#
# Environment:
#   AWS_PROFILE        - AWS profile to use (default: default)
#   AWS_REGION         - AWS region (default: us-east-1)
#   REPORT_BUCKET      - S3 bucket for reports (optional)
#   SNS_TOPIC_ARN      - SNS topic for alerts (optional)
#   SLACK_WEBHOOK_URL  - Slack webhook for notifications (optional)
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- Constants & Defaults --------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DATE_STR="$(date +%Y-%m-%d)"
RESULTS_DIR="${PROJECT_ROOT}/findings"
BASELINE_DIR="${PROJECT_ROOT}/reports/baselines"
ARCHIVE_DIR="${PROJECT_ROOT}/reports/archives/${DATE_STR}"
REPORT_DIR="${PROJECT_ROOT}/reports"

AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-east-1}"
REPORT_BUCKET="${REPORT_BUCKET:-}"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

PROWLER_BIN="prowler"
PROWLER_ARGS=(
    "--output-modes" "json"
    "--output-directory" "${RESULTS_DIR}"
    "--output-filename" "prowler_${TIMESTAMP}"
)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# --- Helper Functions ------------------------------------------------------
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()    { echo -e "${CYAN}[STEP]${NC}  $*"; }

usage() {
    sed -n 's/^# \?//p' "${BASH_SOURCE[0]}" | head -50
    exit 0
}

cleanup() {
    local exit_code=$?
    log_info "Cleanup completed (exit: ${exit_code})"
    exit "${exit_code}"
}
trap cleanup EXIT

check_dependencies() {
    local missing=0
    local deps=("aws" "jq" "python3" "grep" "diff" "curl")
    for cmd in "${deps[@]}"; do
        if ! command -v "${cmd}" &>/dev/null; then
            log_error "Missing required dependency: ${cmd}"
            missing=1
        fi
    done
    if ! command -v "${PROWLER_BIN}" &>/dev/null; then
        log_warn "Prowler not found; attempting pip install..."
        if python3 -m pip install prowler --quiet; then
            log_info "Prowler installed successfully"
        else
            log_error "Failed to install Prowler. Run: pip install prowler"
            missing=1
        fi
    fi
    if [[ ${missing} -eq 1 ]]; then
        log_error "Missing dependencies. Install them and retry."
        exit 1
    fi
    log_info "All dependencies satisfied"
}

run_prowler_scan() {
    log_step "Running Prowler CIS benchmark scan..."
    mkdir -p "${RESULTS_DIR}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would execute: ${PROWLER_BIN} ${PROWLER_ARGS[*]}"
        return 0
    fi
    echo "y" | "${PROWLER_BIN}" "${PROWLER_ARGS[@]}" 2>&1 || {
        log_warn "Prowler scan exited non-zero; continuing"
    }
    log_info "Prowler scan completed"
}

find_latest_prowler_output() {
    local json_files
    json_files=$(find "${RESULTS_DIR}" -name "prowler_*.json" -type f 2>/dev/null | sort -r)
    if [[ -z "${json_files}" ]]; then
        log_error "No Prowler output JSON found in ${RESULTS_DIR}"
        return 1
    fi
    echo "${json_files}" | head -1
}

parse_results() {
    log_step "Parsing Prowler results..."
    local prowler_file
    prowler_file=$(find_latest_prowler_output) || return 1
    log_info "Processing: ${prowler_file}"
    mkdir -p "${REPORT_DIR}"
    local parsed_file="${REPORT_DIR}/parsed_findings_${TIMESTAMP}.json"

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would parse ${prowler_file} -> ${parsed_file}"
        echo "${parsed_file}"
        return 0
    fi

    python3 -c "
import json, sys
try:
    with open('${prowler_file}') as f:
        data = json.load(f)
    findings = data if isinstance(data, list) else data.get('findings', data.get('results', []))
    output = {
        'timestamp': '${TIMESTAMP}',
        'total_findings': len(findings),
        'severity_counts': {},
        'findings': []
    }
    for f in findings:
        sev = f.get('severity', f.get('Status', 'UNKNOWN')).upper()
        output['severity_counts'][sev] = output['severity_counts'].get(sev, 0) + 1
        output['findings'].append({
            'id': f.get('Id', f.get('id', 'unknown')),
            'title': f.get('Title', f.get('title', 'unknown')),
            'severity': sev,
            'status': f.get('Status', f.get('status', 'UNKNOWN')),
            'resource': f.get('ResourceArn', f.get('resource_arn', '')),
            'region': f.get('Region', f.get('region', '')),
        })
    with open('${parsed_file}', 'w') as out:
        json.dump(output, out, indent=2)
    print(f'Parsed {len(findings)} findings')
except Exception as e:
    print(f'Parse error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1 || log_warn "Parsing produced errors; continuing"
    echo "${parsed_file}"
}

compare_with_baseline() {
    log_step "Comparing results with baseline..."
    mkdir -p "${BASELINE_DIR}"
    local baseline_file="${BASELINE_DIR}/latest_baseline.json"
    local parsed_file="${1}"

    if [[ ! -f "${baseline_file}" ]]; then
        log_info "No baseline found; creating baseline from current scan"
        if [[ "${DRY_RUN}" != "true" ]] && [[ -f "${parsed_file}" ]]; then
            cp "${parsed_file}" "${baseline_file}"
            log_info "Baseline created: ${baseline_file}"
        else
            log_info "[DRY-RUN] Would create baseline: ${baseline_file}"
        fi
        return 0
    fi

    local diff_file="${REPORT_DIR}/diff_report_${TIMESTAMP}.md"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would compare ${parsed_file} vs ${baseline_file}"
        echo "${diff_file}"
        return 0
    fi

    python3 -c "
import json, sys
with open('${baseline_file}') as f:
    baseline = json.load(f)
with open('${parsed_file}') as f:
    current = json.load(f)
baseline_ids = {f['id'] for f in baseline.get('findings', [])}
current_ids = {f['id'] for f in current.get('findings', [])}
new_findings = current_ids - baseline_ids
resolved_findings = baseline_ids - current_ids
ongoing_findings = baseline_ids & current_ids
report_lines = [
    '# Compliance Diff Report',
    '',
    f'**Generated**: ${TIMESTAMP}',
    f'**Baseline**: ${baseline_file}',
    f'**Current**: ${parsed_file}',
    '',
    '## Summary',
    '',
    f'- **New Findings**: {len(new_findings)}',
    f'- **Resolved Findings**: {len(resolved_findings)}',
    f'- **Ongoing Findings**: {len(ongoing_findings)}',
    '',
]
if new_findings:
    report_lines.extend(['## New Findings', ''])
    for f in current.get('findings', []):
        if f['id'] in new_findings:
            report_lines.append(f'- **{f[\"title\"]}** ({f[\"severity\"]}) - {f[\"resource\"]}')
if resolved_findings:
    report_lines.extend(['## Resolved Findings', ''])
    for f in baseline.get('findings', []):
        if f['id'] in resolved_findings:
            report_lines.append(f'- ~~{f[\"title\"]}~~ ({f[\"severity\"]})')
with open('${diff_file}', 'w') as out:
    out.write('\n'.join(report_lines))
print(f'Diff: {len(new_findings)} new, {len(resolved_findings)} resolved')
" 2>&1 || log_warn "Baseline comparison encountered errors"
    cp "${parsed_file}" "${baseline_file}"
    log_info "Baseline updated"
    echo "${diff_file}"
}


send_notifications() {
    local diff_file="${1:-}"
    log_step "Sending notifications..."
    if [[ -z "${diff_file}" ]] || [[ ! -f "${diff_file}" ]]; then
        log_info "No diff report to notify about"
        return 0
    fi
    local summary
    summary=$(head -20 "${diff_file}")

    if [[ -n "${SNS_TOPIC_ARN}" ]]; then
        log_info "Sending SNS notification to ${SNS_TOPIC_ARN}"
        if [[ "${DRY_RUN}" != "true" ]]; then
            aws sns publish \
                --profile "${AWS_PROFILE}" \
                --region "${AWS_REGION}" \
                --topic-arn "${SNS_TOPIC_ARN}" \
                --subject "Security Monitoring Report - ${DATE_STR}" \
                --message "${summary}" 2>&1 || log_warn "SNS publish failed"
        else
            log_info "[DRY-RUN] Would send SNS notification"
        fi
    fi

    if [[ -n "${SLACK_WEBHOOK_URL}" ]]; then
        log_info "Sending Slack notification..."
        if [[ "${DRY_RUN}" != "true" ]]; then
            local slack_payload
            slack_payload=$(cat <<EOF
{
    "text": ":shield: *Security Monitoring Report - ${DATE_STR}*",
    "attachments": [
        {
            "color": "#36a64f",
            "text": \`\`\`${summary}\`\`\`,
            "footer": "Cloud Security Posture Audit"
        }
    ]
}
EOF
)
            curl -s -X POST -H "Content-type: application/json" \
                --data "${slack_payload}" \
                "${SLACK_WEBHOOK_URL}" 2>&1 || log_warn "Slack notification failed"
        else
            log_info "[DRY-RUN] Would send Slack notification"
        fi
    fi
    log_info "Notifications sent successfully"
}

archive_results() {
    log_step "Archiving results..."
    mkdir -p "${ARCHIVE_DIR}"
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "[DRY-RUN] Would archive results to ${ARCHIVE_DIR}"
        return 0
    fi
    find "${REPORT_DIR}" -maxdepth 1 -name "*_${TIMESTAMP}.*" -type f 2>/dev/null | while read -r f; do
        cp "${f}" "${ARCHIVE_DIR}/"
        log_info "Archived: $(basename "${f}")"
    done
    find "${RESULTS_DIR}" -name "prowler_${TIMESTAMP}*" -type f 2>/dev/null | while read -r f; do
        cp "${f}" "${ARCHIVE_DIR}/"
        log_info "Archived: $(basename "${f}")"
    done
    if [[ -n "${REPORT_BUCKET}" ]]; then
        log_info "Uploading archive to s3://${REPORT_BUCKET}/monitoring/${DATE_STR}/"
        aws s3 sync "${ARCHIVE_DIR}" "s3://${REPORT_BUCKET}/monitoring/${DATE_STR}/" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" 2>&1 || log_warn "S3 upload failed"
        aws s3 cp "${ARCHIVE_DIR}" "s3://${REPORT_BUCKET}/monitoring/latest/" \
            --profile "${AWS_PROFILE}" --region "${AWS_REGION}" \
            --recursive 2>&1 || log_warn "S3 latest upload failed"
    fi
    log_info "Archiving complete: ${ARCHIVE_DIR}"
}

main() {
    local diff_report=""
    log_info "=== Continuous Security Monitoring Pipeline ==="
    log_info "Started at: $(date)"
    log_info "AWS Profile: ${AWS_PROFILE}, Region: ${AWS_REGION}"
    echo ""
    check_dependencies

    if [[ "${QUICK_MODE}" == "true" ]]; then
        local recent_file
        recent_file=$(find "${RESULTS_DIR}" -name "prowler_*.json" -mmin -60 -type f 2>/dev/null | head -1)
        if [[ -n "${recent_file}" ]]; then
            log_info "Quick mode: using recent scan from ${recent_file}"
        else
            log_warn "Quick mode: no recent scan (<60 min), running full scan"
            run_prowler_scan
        fi
    else
        run_prowler_scan
    fi

    local parsed_file
    parsed_file=$(parse_results) || { log_error "Failed to parse results"; exit 1; }

    if [[ "${BASELINE_ONLY}" == "true" ]]; then
        log_info "Baseline-only mode; skipping comparison and notifications"
        cp "${parsed_file}" "${BASELINE_DIR}/latest_baseline.json" 2>/dev/null || true
        exit 0
    fi

    diff_report=$(compare_with_baseline "${parsed_file}") || log_warn "Baseline comparison incomplete"
    send_notifications "${diff_report}"
    archive_results
    echo ""
    log_info "=== Monitoring Pipeline Complete ==="
    log_info "Reports: ${REPORT_DIR}"
    log_info "Archive: ${ARCHIVE_DIR}"
}

# --- Argument Parsing ------------------------------------------------------
DRY_RUN="false"; BASELINE_ONLY="false"; QUICK_MODE="false"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)       DRY_RUN="true" ;;
        --baseline-only) BASELINE_ONLY="true" ;;
        --quick)         QUICK_MODE="true" ;;
        --help)          usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
    shift
done
main

