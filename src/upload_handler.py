from __future__ import annotations
import os, re, tempfile, uuid
from pathlib import Path

class FileUploadHandler:
    def __init__(self, upload_dir, allowed_extensions=None, max_bytes=10 * 1024 * 1024):
        self.upload_dir = Path(upload_dir).resolve(); self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.allowed_extensions = {e.lower() if e.startswith('.') else f'.{e.lower()}' for e in (allowed_extensions or set())}; self.max_bytes = max_bytes
    def _validate_file(self, file):
        name, content = getattr(file, 'filename', ''), getattr(file, 'content', b'')
        return bool(name and re.fullmatch(r'[A-Za-z0-9._-]+', name) and isinstance(content, bytes) and 0 < len(content) <= self.max_bytes and (not self.allowed_extensions or Path(name).suffix.lower() in self.allowed_extensions))
    def save(self, file):
        if not self._validate_file(file): raise ValueError('File validation failed')
        final, temp = self.upload_dir / f'{uuid.uuid4()}_{Path(file.filename).name}', None
        try:
            fd, temp = tempfile.mkstemp(dir=self.upload_dir, prefix='.upload_')
            with os.fdopen(fd, 'wb') as stream: stream.write(file.content); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, final); temp = None; return str(final)
        except OSError as exc: raise IOError(f'Failed to save file: {exc}') from exc
        finally:
            if temp and os.path.exists(temp): os.unlink(temp)
