#!/usr/bin/env python3
"""Small security helper for validating and encoding untrusted input."""
import re

def sanitize_input(data):
    return re.sub(r"[<>&\"'\\\r\n]", "", data) if isinstance(data, str) else data

def validate_request(headers, body):
    return bool(headers) and body is not None
