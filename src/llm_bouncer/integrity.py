"""Snapshot files that run code later before a sandboxed command, revert unapproved changes after.

The sandbox lets commands write anywhere in the project, and it already protects .claude/,
.git/hooks, .git/config and shell rc files. It does not know that `.github/workflows/ci.yml`,
`package.json` or `conftest.py` decide what runs on the next `git push`, `npm install` or `pytest`.
Rather than guess from the command text whether it writes them, look at the files before and after.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import ledger

MAX_FILE = 1 << 20  # larger files are left alone (and reported, not reverted)
MAX_FILES = 300


def _files(cwd: str, patterns: List[str]) -> Dict[str, Path]:
    root = Path(cwd)
    out: Dict[str, Path] = {}
    for pat in patterns:
        for p in root.glob(pat):
            if p.is_file() and not p.is_symlink():
                out[str(p.relative_to(root))] = p
                if len(out) >= MAX_FILES:
                    return out
    return out


def _snap_path(session_id: str, tool_use_id: Optional[str]) -> Path:
    tid = "".join(c if c.isalnum() or c in "_-" else "_" for c in (tool_use_id or "last"))[:80]
    return ledger.ledger_dir() / f"{ledger._safe(session_id)}.{tid}.snap.json"


def snapshot(session_id: str, tool_use_id: Optional[str], cwd: str, patterns: List[str]) -> Path:
    files = {}
    for rel, p in _files(cwd, patterns).items():
        try:
            data = p.read_bytes() if p.stat().st_size <= MAX_FILE else None
        except OSError:
            continue
        files[rel] = None if data is None else base64.b64encode(data).decode("ascii")
    path = _snap_path(session_id, tool_use_id)
    ledger._ensure_dir()
    ledger._write_atomic(path, {"ts": time.time(), "cwd": cwd, "files": files})
    return path


def check_and_revert(session_id: str, tool_use_id: Optional[str], allowed: Any, patterns: List[str]) -> Tuple[List[str], List[str], float]:
    """Compare with the snapshot; revert changes `allowed(path)` does not permit.

    Returns (reverted paths, changed-but-could-not-revert paths, snapshot time). No snapshot
    means the command ran in a clean session: nothing to do.
    """
    path = _snap_path(session_id, tool_use_id)
    try:
        snap = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], [], 0.0
    try:
        path.unlink()
    except OSError:
        pass
    cwd, before = snap.get("cwd", "."), snap.get("files") or {}
    now = _files(cwd, patterns)
    reverted, stuck = [], []
    for rel in sorted(set(before) | set(now)):
        p = Path(cwd) / rel
        old = before.get(rel)
        if rel in before and rel in now and old is not None:
            try:
                if p.stat().st_size <= MAX_FILE and p.read_bytes() == base64.b64decode(old):
                    continue  # unchanged
            except OSError:
                pass
        elif rel in before and rel in now:
            continue  # too large to snapshot; cannot tell whether it changed
        if allowed(rel):
            continue
        if rel in before and old is None:
            stuck.append(rel)  # deleted, but too large to have been snapshotted
            continue
        try:
            if rel in before:
                p.parent.mkdir(parents=True, exist_ok=True)
                tmp = p.with_name(f".{p.name}.llm-bouncer.{os.getpid()}")
                tmp.write_bytes(base64.b64decode(old))
                os.replace(tmp, p)
            else:
                p.unlink()  # created by the command
            reverted.append(rel)
        except OSError:
            stuck.append(rel)
    return reverted, stuck, float(snap.get("ts") or 0)
