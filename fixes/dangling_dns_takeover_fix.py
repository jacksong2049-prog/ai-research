"""Detect unresolved domains that may indicate a dangling DNS record."""
import logging
import socket
logger = logging.getLogger(__name__)
SUSPICIOUS_CNAME_PATTERNS = (".cloudfront.net", ".s3.amazonaws.com", ".azureedge.net", ".herokuapp.com")

def check_cname_for_takeover(domain: str) -> bool:
    if not domain or "." not in domain or any(c in domain for c in " /\\\r\n"):
        raise ValueError(f"Invalid domain: {domain}")
    try:
        socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        return False
    except socket.gaierror:
        logger.warning("Domain %s does not resolve", domain)
        return True

def mitigate_cookie_theft():
    """Return cookie hardening guidance for callers to apply at the web layer."""
    return {"prefix": "__Host-", "secure": True, "httponly": True, "samesite": "Strict"}
