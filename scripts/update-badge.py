#!/usr/bin/env python3
"""
Update compliance badge in README.md based on latest scan results.
"""

import re
import sys
import os
from pathlib import Path
from datetime import datetime

def get_latest_compliance_score(reports_dir: str = "reports") -> float:
    """Extract compliance score from latest report"""
    reports_path = Path(reports_dir)

    # Find latest security audit report
    json_files = sorted(
        reports_path.glob("security-audit-*.json"),
        reverse=True
    )

    if not json_files:
        print("[!] No scan reports found. Run security-scan.py first.")
        return 0.0

    import json
    with open(json_files[0]) as f:
        data = json.load(f)

    return data.get("compliance_score", 0.0)


def update_readme_badge(score: float, readme_path: str = "README.md") -> bool:
    """Update compliance badge in README.md"""
    readme_file = Path(readme_path)

    if not readme_file.exists():
        print(f"[!] README not found at {readme_path}")
        return False

    content = readme_file.read_text()

    # Badge color based on score
    if score >= 90:
        color = "brightgreen"
    elif score >= 80:
        color = "green"
    elif score >= 70:
        color = "yellowgreen"
    elif score >= 60:
        color = "orange"
    else:
        color = "red"

    # New badge markdown
    new_badge = f"![Compliance Score](https://img.shields.io/badge/CIS_Compliance-{score:.0f}%25-{color})"

    # Pattern to match existing compliance badge
    badge_pattern = r'!\[Compliance Score\]\(https://img\.shields\.io/badge/CIS_Compliance-.*?\)'

    if re.search(badge_pattern, content):
        # Update existing badge
        updated_content = re.sub(badge_pattern, new_badge, content)
        readme_file.write_text(updated_content)
        print(f"[+] Updated compliance badge: {score:.0f}% ({color})")
        return True
    else:
        # Add badge after title if not exists
        lines = content.split('\n')
        insert_index = 0

        # Find where to insert (after first header)
        for i, line in enumerate(lines):
            if line.startswith('# Cloud Security Posture'):
                insert_index = i + 1
                break

        if insert_index > 0:
            lines.insert(insert_index, "")
            lines.insert(insert_index + 1, new_badge)
            readme_file.write_text('\n'.join(lines))
            print(f"[+] Added compliance badge: {score:.0f}% ({color})")
            return True

    print("[!] Could not update badge")
    return False


def update_badge_line(score: float, readme_path: str = "README.md") -> bool:
    """Update badge line (non-markdown) in README"""
    readme_file = Path(readme_path)

    if not readme_file.exists():
        return False

    content = readme_file.read_text()

    # Badge color based on score
    if score >= 90:
        color = "brightgreen"
    elif score >= 80:
        color = "green"
    elif score >= 70:
        color = "yellowgreen"
    elif score >= 60:
        color = "orange"
    else:
        color = "red"

    badge_line = f"![Compliance Score](https://img.shields.io/badge/CIS_Compliance-{score:.0f}%25-{color})"

    # Pattern to match any badge line
    badge_pattern = r'!\[.*?\]\(https://img\.shields\.io/badge/.*?\)'

    if re.search(badge_pattern, content):
        updated_content = re.sub(badge_pattern, badge_line, content)
        readme_file.write_text(updated_content)
        return True

    return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Update README badge with latest compliance score')
    parser.add_argument('--reports-dir', default='reports', help='Directory containing scan reports')
    parser.add_argument('--readme', default='README.md', help='Path to README.md')
    parser.add_argument('--dry-run', action='store_true', help='Print changes without writing')

    args = parser.parse_args()

    score = get_latest_compliance_score(args.reports_dir)

    if args.dry_run:
        print(f"[DRY-RUN] Would update badge with score: {score:.1f}%")
        sys.exit(0)

    success = update_readme_badge(score, args.readme)

    if success:
        print(f"[+] README badge updated successfully: {score:.1f}%")
        sys.exit(0)
    else:
        print("[!] Failed to update badge")
        sys.exit(1)


if __name__ == '__main__':
    main()
