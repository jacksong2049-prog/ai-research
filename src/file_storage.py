from __future__ import annotations
import hashlib, os, tempfile
from pathlib import Path

class SecurityError(ValueError): pass

class SecureFileStorage:
    def __init__(self, root):
        self.root = Path(root).resolve(); self.root.mkdir(parents=True, exist_ok=True)
    def _is_safe_path(self, destination):
        try: (self.root / Path(destination)).resolve().relative_to(self.root); return True
        except (ValueError, OSError): return False
    def write(self, destination: str, content: bytes) -> Path:
        if not isinstance(content, bytes): raise TypeError("content must be bytes")
        if not self._is_safe_path(destination): raise SecurityError("Invalid destination path")
        dest = (self.root / destination).resolve(); dest.parent.mkdir(parents=True, exist_ok=True); temp = None
        try:
            fd, temp = tempfile.mkstemp(dir=dest.parent, prefix=f".atomic_{dest.name}_")
            with os.fdopen(fd, "wb") as stream: stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, dest); temp = None; return dest
        finally:
            if temp and os.path.exists(temp): os.unlink(temp)
    def sha256(self, destination: str) -> str:
        path = (self.root / destination).resolve()
        if not self._is_safe_path(destination) or not path.is_file(): raise SecurityError("Invalid source path")
        return hashlib.sha256(path.read_bytes()).hexdigest()
