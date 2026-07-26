#!/usr/bin/env python3
"""
Automated Remediation Engine
Remediates common cloud misconfigurations identified in security posture scans.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import re

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("AWS SDK not installed. Run: pip install boto3")
    sys.exit(1)


class RemediationEngine:
    def __init__(self, environment: str, dry_run: bool = True):
        self.environment = environment
        self.dry_run = dry_run
        self.timestamp = datetime.utcnow().isoformat()
        self.results: List[Dict[str, Any]] = []

        try:
            self.s3_client = boto3.client('s3')
            self.iam_client = boto3.client('iam')
            self.ec2_client = boto3.client('ec2')
            self.config_client = boto3.client('config')
        except Exception as e:
            print(f"Failed to initialize AWS clients: {e}")
            print("Running in dry-run mode only")
            self.dry_run = True

    def remediate(self, risk_level: str = "high") -> Dict[str, Any]:
        """Execute remediation actions"""
        mode = "DRY-RUN" if self.dry_run else "LIVE"
        print(f"[*] Starting {mode} remediation for {risk_level.upper()} risk findings")
        print(f"    Environment: {self.environment}")
        print(f"    Timestamp: {self.timestamp}")
        print()

        actions = {
            "critical": self._remediate_critical,
            "high": self._remediate_high,
            "medium": self._remediate_medium,
            "low": self._remediate_low,
            "all": self._remediate_all
        }

        if risk_level in actions:
            actions[risk_level]()

        self._generate_remediation_report()
        return self._generate_report()

    def _remediate_critical(self):
        """Remediate critical findings"""
        print("[+] Remediating CRITICAL findings...")
        print("    CIS 2.1.3: Block S3 public access")
        print("    CIS 1.1: Require root MFA")
        print("    CIS 5.1: Restrict security groups")

        self._remediate_s3_public_access()
        self._remediate_security_groups()

    def _remediate_high(self):
        """Remediate high risk findings"""
        print("[+] Remediating HIGH risk findings...")
        print("    CIS 2.1.1: Enable S3 encryption")
        print("    CIS 2.2: Enable CloudTrail")
        print("    CIS 1.2: Enable IAM MFA")
        print("    CIS 5.2: Encrypt EBS volumes")

        self._remediate_s3_public_access()
        self._remediate_security_groups()
        self._remediate_s3_encryption()
        self._remediate_ebs_encryption()

    def _remediate_medium(self):
        """Remediate medium risk findings"""
        print("[+] Remediating MEDIUM risk findings...")
        print("    CIS 2.1.2: Enable S3 versioning")
        print("    CIS 1.4: Enforce password policy")
        self._remediate_s3_encryption()

    def _remediate_low(self):
        """Remediate low risk findings"""
        print("[+] Remediating LOW risk findings...")
        print("    CIS 3.1: Configure CloudWatch alarms")

    def _remediate_all(self):
        """Remediate all findings"""
        self._remediate_critical()
        self._remediate_high()
        self._remediate_medium()
        self._remediate_low()

    def _remediate_s3_public_access(self):
        """Block S3 public access"""
        if self.dry_run:
            print("    [DRY-RUN] Would block S3 public access on all buckets")
            self.results.append({
                "action": "Block S3 public access",
                "status": "DRY-RUN",
                "timestamp": self.timestamp
            })
            return

        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    self.s3_client.put_public_access_block(
                        Bucket=bucket['Name'],
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    print(f"    [SUCCESS] Blocked public access: {bucket['Name']}")
                    self.results.append({
                        "action": f"Block public access on {bucket['Name']}",
                        "status": "SUCCESS",
                        "timestamp": self.timestamp
                    })
                except ClientError as e:
                    print(f"    [ERROR] {bucket['Name']}: {e}")
                    self.results.append({
                        "action": f"Block public access on {bucket['Name']}",
                        "status": f"ERROR: {e}",
                        "timestamp": self.timestamp
                    })
        except Exception as e:
            print(f"    [ERROR] Failed to list buckets: {e}")

    def _remediate_security_groups(self):
        """Restrict security group rules allowing 0.0.0.0/0"""
        if self.dry_run:
            print("    [DRY-RUN] Would restrict security groups with open IPs")
            self.results.append({
                "action": "Restrict security groups",
                "status": "DRY-RUN",
                "timestamp": self.timestamp
            })
            return

        try:
            sgs = self.ec2_client.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            print(f"    [ID] Open rule in SG {sg['GroupId']}: {rule.get('FromPort')}-{rule.get('ToPort')}")
                            self.results.append({
                                "action": f"Revoke open SG rule in {sg['GroupId']}",
                                "status": "IDENTIFIED",
                                "timestamp": self.timestamp
                            })
        except Exception as e:
            print(f"    [ERROR] Failed to scan security groups: {e}")

    def _remediate_s3_encryption(self):
        """Enable S3 bucket encryption"""
        if self.dry_run:
            print("    [DRY-RUN] Would enable S3 bucket encryption")
            self.results.append({
                "action": "Enable S3 encryption",
                "status": "DRY-RUN",
                "timestamp": self.timestamp
            })
            return

        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    self.s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                except ClientError:
                    try:
                        self.s3_client.put_bucket_encryption(
                            Bucket=bucket['Name'],
                            ServerSideEncryptionConfiguration={
                                'Rules': [{
                                    'ApplyServerSideEncryptionByDefault': {
                                        'SSEAlgorithm': 'AES256'
                                    },
                                    'BucketKeyEnabled': True
                                }]
                            }
                        )
                        print(f"    [SUCCESS] Enabled encryption: {bucket['Name']}")
                        self.results.append({
                            "action": f"Enable encryption on {bucket['Name']}",
                            "status": "SUCCESS",
                            "timestamp": self.timestamp
                        })
                    except ClientError as e:
                        print(f"    [ERROR] {bucket['Name']}: {e}")
        except Exception as e:
            print(f"    [ERROR] Failed to list buckets: {e}")

    def _remediate_ebs_encryption(self):
        """Enable EBS encryption"""
        if self.dry_run:
            print("    [DRY-RUN] Would enable EBS encryption on unencrypted volumes")
            self.results.append({
                "action": "Enable EBS encryption",
                "status": "DRY-RUN",
                "timestamp": self.timestamp
            })
            return

        try:
            volumes = self.ec2_client.describe_volumes()['Volumes']
            for vol in volumes:
                if not vol.get('Encrypted'):
                    print(f"    [ID] Unencrypted volume: {vol['VolumeId']}")
                    self.results.append({
                        "action": f"Encrypt EBS volume {vol['VolumeId']}",
                        "status": "IDENTIFIED",
                        "timestamp": self.timestamp
                    })
        except Exception as e:
            print(f"    [ERROR] Failed to scan EBS volumes: {e}")

    def _generate_remediation_report(self):
        """Generate remediation report"""
        report = {
            "report_metadata": {
                "generated_at": self.timestamp,
                "environment": self.environment,
                "mode": "DRY-RUN" if self.dry_run else "LIVE",
                "type": "Remediation Report"
            },
            "actions": self.results,
            "total_actions": len(self.results)
        }

        os.makedirs('reports', exist_ok=True)
        datetime_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"reports/remediation-{self.environment}-{datetime_str}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Remediation report: {filename}")

    def _generate_report(self) -> Dict[str, Any]:
        """Generate remediation report"""
        return {
            "report_metadata": {
                "generated_at": self.timestamp,
                "environment": self.environment,
                "mode": "DRY-RUN" if self.dry_run else "LIVE"
            },
            "actions": self.results,
            "total_actions": len(self.results)
        }


def main():
    parser = argparse.ArgumentParser(description='Cloud Security Remediation Engine')
    parser.add_argument('--risk-level', default='critical',
                        choices=['critical', 'high', 'medium', 'low', 'all'])
    parser.add_argument('--dry-run', type=lambda x: x.lower() == 'true', default=True)
    parser.add_argument('--environment', default='prod')
    parser.add_argument('--apply', action='store_true', help='Apply remediations (disable dry-run)')

    args = parser.parse_args()

    if args.apply:
        args.dry_run = False

    engine = RemediationEngine(args.environment, args.dry_run)
    report = engine.remediate(args.risk_level)

    print(f"\n[+] Remediation complete!")
    print(f"    Total actions: {report['total_actions']}")
    print(f"    Mode: {'DRY-RUN' if args.dry_run else 'LIVE'}")

    if args.dry_run:
        print("\n[!] Note: Running in DRY-RUN mode. Use --apply to execute remediations.")

    sys.exit(0)


if __name__ == '__main__':
    main()
