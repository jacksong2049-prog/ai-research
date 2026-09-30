"""Generated security-fix sample with safe input validation."""
import re

def sanitize(data):
    return re.sub(r"[<>&\"'\\\r\n]", "", data) if isinstance(data, str) else data

def validate(data):
    return bool(data)
