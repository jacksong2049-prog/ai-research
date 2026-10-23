from __future__ import annotations
import os, tempfile
from pathlib import Path

def atomic_write(destination, data: bytes) -> str:
    if not isinstance(data, bytes): raise TypeError('data must be bytes')
    dest = Path(destination).resolve(); dest.parent.mkdir(parents=True, exist_ok=True); temp = None
    try:
        fd, temp = tempfile.mkstemp(dir=dest.parent, prefix=f'.atomic_write_{dest.name}_')
        with os.fdopen(fd, 'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, dest); temp = None; return str(dest)
    finally:
        if temp and os.path.exists(temp): os.unlink(temp)
