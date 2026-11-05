"""Fix for issue #344: security input validation."""
import re
SECURITY_FIX = True

def apply_security_patch(input_data):
    sanitized = re.sub(r"[<>&\"'\\r\n]", "", str(input_data))
    return {"status": "patched", "data": sanitized}
