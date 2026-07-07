"""
Fix for Issue #41 - SMTP Header Injection
Agent: dev-nana27
Bounty: $25 USD

Fix: Sanitize email headers to prevent CRLF injection by stripping newlines.
"""

import re
from email.header import Header
from email.utils import parseaddr

SMTP_HEADER_SAFE_RE = re.compile(r'[\r\n]')

def sanitize_email_header(value: str) -> str:
    """Remove CRLF characters to prevent SMTP header injection."""
    return SMTP_HEADER_SAFE_RE.sub('', value).strip()

def safe_email_header(name: str, value: str) -> str:
    """Create a safe email header."""
    return Header(sanitize_email_header(value), 'utf-8').encode()

def validate_email_header(header_value: str) -> bool:
    """Validate that email header contains no injection characters."""
    return not bool(SMTP_HEADER_SAFE_RE.search(header_value))
