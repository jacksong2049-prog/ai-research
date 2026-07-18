"""
fix_s3_bucket_misconfig.py — Fix for Issue #1248: S3 Bucket Misconfiguration → Mass Data Leak

VULNERABILITY:
S3 bucket policies configured with overly permissive access controls (e.g.,
Principal: "*" with s3:GetObject or s3:ListBucket actions) expose stored data
to the public internet. Attackers can enumerate bucket contents and download
sensitive data without authentication. Common misconfigurations include:
- Public-read ACL on buckets containing sensitive data
- Bucket policy granting s3:GetObject to anyone ("Principal": "*")
- Lack of bucket-level encryption (SSE-S3 or SSE-KMS)
- No access logging or monitoring enabled

FIX:
This module validates S3 bucket policies and detects dangerous configurations.
It provides corrected policy templates that enforce least-privilege access
and implements bucket security best practices.

SECURITY_FIX = True
"""

import re
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


# Known-dangerous IAM principals that indicate public access
PUBLIC_PRINCIPALS = frozenset({"*", "arn:aws:iam::*:root", "arn:aws:iam::*:user/*"})

# Actions that should never be granted publicly
DANGEROUS_PUBLIC_ACTIONS = frozenset({
    "s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket",
    "s3:ListBucketVersions", "s3:GetBucketAcl", "s3:GetBucketPolicy",
    "s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl",
    "s3:*", "*",
})

# Approved encryption algorithms
APPROVED_ENCRYPTION = frozenset({"AES256", "aws:kms", "aws:kms:dsse"})


@dataclass
class BucketPolicyFinding:
    """Security finding for S3 bucket policy analysis."""
    severity: str  # critical, high, medium, low
    rule_id: str
    description: str
    resource: str
    remediation: str


class S3BucketPolicyValidator:
    """Validates S3 bucket policies for security misconfigurations."""

    def __init__(self):
        self.findings: List[BucketPolicyFinding] = []

    def validate_policy(self, policy_document: dict, bucket_name: str = "") -> List[BucketPolicyFinding]:
        """Validate an S3 bucket policy for dangerous configurations."""
        self.findings = []

        if not isinstance(policy_document, dict):
            self.findings.append(BucketPolicyFinding(
                severity="error",
                rule_id="S3-001",
                description="Invalid policy document format",
                resource=bucket_name,
                remediation="Provide a valid JSON policy document"
            ))
            return self.findings

        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for i, stmt in enumerate(statements):
            self._validate_statement(stmt, i, bucket_name)

        return self.findings

    def _validate_statement(self, stmt: dict, index: int, bucket_name: str):
        """Validate a single policy statement."""
        effect = stmt.get("Effect", "Deny")
        if effect != "Allow":
            return  # Deny statements are generally safe

        principal = stmt.get("Principal", {})
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])

        # Normalize to lists
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        # Check for public principal
        if self._is_public_principal(principal):
            dangerous = [a for a in action if a in DANGEROUS_PUBLIC_ACTIONS]
            if dangerous:
                self.findings.append(BucketPolicyFinding(
                    severity="critical",
                    rule_id="S3-002",
                    description=f"Statement[{index}]: Public principal granted dangerous actions: {', '.join(dangerous)}",
                    resource=bucket_name,
                    remediation=(
                        "Remove public access. Replace 'Principal': '*' with specific "
                        "IAM roles/users. Use CloudFront OAC or pre-signed URLs for "
                        "controlled public access."
                    )
                ))

        # Check for wildcard resource with sensitive actions
        for r in resource:
            if r == "*" or r.endswith("/*"):
                sensitive = [a for a in action if "Delete" in a or "Put" in a]
                if sensitive:
                    self.findings.append(BucketPolicyFinding(
                        severity="high",
                        rule_id="S3-003",
                        description=f"Statement[{index}]: Wildcard resource with write actions: {', '.join(sensitive)}",
                        resource=str(r),
                        remediation="Restrict resource ARN to specific bucket/prefix. Avoid wildcard resources with write permissions."
                    ))

        # Check for missing conditions
        if self._is_public_principal(principal) and not stmt.get("Condition"):
            self.findings.append(BucketPolicyFinding(
                severity="medium",
                rule_id="S3-004",
                description=f"Statement[{index}]: Public access without conditions (no IP restriction, no MFA, no referer check)",
                resource=bucket_name,
                remediation="Add conditions: aws:SourceIp, aws:MultiFactorAuthPresent, or s3:x-amz-server-side-encryption."
            ))

    def _is_public_principal(self, principal) -> bool:
        """Check if principal grants public access."""
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_princ = principal.get("AWS", "")
            if aws_princ == "*":
                return True
            if isinstance(aws_princ, list) and "*" in aws_princ:
                return True
        return False

    @staticmethod
    def generate_secure_policy(bucket_name: str, allowed_roles: List[str]) -> dict:
        """Generate a secure S3 bucket policy with least-privilege access."""
        if not allowed_roles:
            raise ValueError("At least one allowed role must be specified")

        aws_principals = [f"arn:aws:iam::*:role/{role}" for role in allowed_roles]

        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyPublicAccess",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:*"],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ],
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"}
                    }
                },
                {
                    "Sid": "AllowSecureRoleAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": aws_principals},
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ],
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "true"}
                    }
                }
            ]
        }


class S3BucketSecurityAuditor:
    """Comprehensive S3 bucket security auditor."""

    @staticmethod
    def check_encryption(encryption_config: Optional[dict]) -> List[BucketPolicyFinding]:
        """Check bucket encryption configuration."""
        findings = []
        if not encryption_config:
            findings.append(BucketPolicyFinding(
                severity="high",
                rule_id="S3-005",
                description="Default encryption is not enabled on the bucket",
                resource="",
                remediation="Enable default encryption with SSE-S3 or SSE-KMS."
            ))
            return findings

        rules = encryption_config.get("Rules", [])
        for rule in rules:
            algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
            if algo not in APPROVED_ENCRYPTION:
                findings.append(BucketPolicyFinding(
                    severity="medium",
                    rule_id="S3-006",
                    description=f"Non-standard encryption algorithm: {algo}",
                    resource="",
                    remediation=f"Use one of: {', '.join(sorted(APPROVED_ENCRYPTION))}"
                ))

        return findings

    @staticmethod
    def check_public_access_block(config: Optional[dict]) -> List[BucketPolicyFinding]:
        """Check public access block configuration."""
        findings = []
        if not config:
            findings.append(BucketPolicyFinding(
                severity="high",
                rule_id="S3-007",
                description="Public access block is not configured",
                resource="",
                remediation=(
                    "Enable all public access block settings: "
                    "BlockPublicAcls=True, IgnorePublicAcls=True, "
                    "BlockPublicPolicy=True, RestrictPublicBuckets=True"
                )
            ))
            return findings

        required = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        for setting, required_value in required.items():
            if config.get(setting) != required_value:
                findings.append(BucketPolicyFinding(
                    severity="high",
                    rule_id="S3-008",
                    description=f"Public access block setting {setting} is not enabled",
                    resource="",
                    remediation=f"Set {setting}=True in public access block configuration."
                ))

        return findings

    @staticmethod
    def check_logging_enabled(logging_config: Optional[dict]) -> List[BucketPolicyFinding]:
        """Check if access logging is enabled."""
        findings = []
        if not logging_config or not logging_config.get("LoggingEnabled"):
            findings.append(BucketPolicyFinding(
                severity="medium",
                rule_id="S3-009",
                description="Server access logging is not enabled",
                resource="",
                remediation="Enable S3 server access logging to track all requests to the bucket."
            ))
        return findings

    @staticmethod
    def check_versioning(versioning_config: Optional[dict]) -> List[BucketPolicyFinding]:
        """Check if versioning is enabled for data protection."""
        findings = []
        status = (versioning_config or {}).get("Status", "Suspended")
        if status != "Enabled":
            findings.append(BucketPolicyFinding(
                severity="low",
                rule_id="S3-010",
                description="Bucket versioning is not enabled",
                resource="",
                remediation="Enable versioning to protect against accidental deletion and overwrites."
            ))
        return findings


# === Usage Example ===
if __name__ == "__main__":
    # Example: vulnerable policy
    vulnerable_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::sensitive-data-bucket/*"]
        }]
    }

    validator = S3BucketPolicyValidator()
    findings = validator.validate_policy(vulnerable_policy, "sensitive-data-bucket")

    print("=== S3 Bucket Policy Security Scan ===")
    for f in findings:
        print(f"[{f.severity.upper()}] {f.rule_id}: {f.description}")
        print(f"  Remediation: {f.remediation}")

    if not findings:
        print("No issues found. Bucket policy is secure.")

    print()
    print("=== Secure Policy Template ===")
    secure_policy = S3BucketPolicyValidator.generate_secure_policy(
        "my-secure-bucket",
        ["DataProcessor", "AppServer"]
    )
    print(json.dumps(secure_policy, indent=2))
