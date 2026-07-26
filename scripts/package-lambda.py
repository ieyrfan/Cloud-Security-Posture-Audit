#!/usr/bin/env python3
"""
Package Lambda functions for deployment.
Creates ZIP files that Terraform can reference.
"""

import zipfile
import os
import sys
from pathlib import Path


def package_lambda(lambda_dir: str, output_zip: str) -> str:
    """Package Lambda function into a ZIP file."""
    lambda_path = Path(lambda_dir)
    output_path = Path(output_zip)

    if not lambda_path.exists():
        print(f"[!] Lambda directory not found: {lambda_dir}")
        sys.exit(1)

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in lambda_path.rglob('*.py'):
            if file_path.name != __file__:  # Skip this script
                arcname = file_path.relative_to(lambda_path)
                zf.write(file_path, arcname)
                print(f"    [+] {arcname}")

        # Include requirements if exists
        req_file = lambda_path / 'requirements.txt'
        if req_file.exists():
            zf.write(req_file, 'requirements.txt')
            print(f"    [+] requirements.txt")

    print(f"[+] Package created: {output_path}")
    return str(output_path)


def main():
    lambda_dir = sys.argv[1] if len(sys.argv) > 1 else 'lambda'
    output_zip = sys.argv[2] if len(sys.argv) > 2 else 'lambda/slack_alert.zip'

    print(f"[*] Packaging Lambda from {lambda_dir}...")
    package_lambda(lambda_dir, output_zip)


if __name__ == '__main__':
    main()
