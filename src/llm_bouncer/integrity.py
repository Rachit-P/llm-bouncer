"""Snapshot files that run code later before a sandboxed command, revert unapproved changes after.

The sandbox lets commands write anywhere in the project, and it already protects .claude/,
.git/hooks, .git/config and shell rc files. It does not know that `.github/workflows/ci.yml`,
`package.json` or `conftest.py` decide what runs on the next `git push`, `npm install` or `pytest`.
Rather than guess from the command text whether it writes them, look at the files before and after.

Paths are relative to the project root, not the hook's cwd, so `cd src && ...` changes nothing.
Symlinks count too: a `conftest.py` turned into a link to /tmp/evil.py is a change.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import ledger

MAX_FILE = 1 << 20  # larger files are left alone (and reported, not reverted)
MAX_FILES = 300
MAX_AGE = 24 * 3600  # a snapshot older than this is stale (its post-tool-use never ran)


def _entries(root: Path, patterns: List[str]) -> Dict[str, Path]:
    out: Dict[str, Path] = {}
    for pat in patterns:
        for p in root.glob(pat):
            if p.is_symlink() or p.is_file():
                out[p.relative_to(root).as_posix()] = p
                if len(out) >= MAX_FILES:
                    return out
    return out


def _read(p: Path) -> Optional[dict]:
    """What a path holds: {"link": target} or {"data": base64}; None if too large or unreadable."""
    try:
        if p.is_symlink():
            return {"link": os.readlink(p)}
        if p.stat().st_size > MAX_FILE:
            return None
        return {"data": base64.b64encode(p.read_bytes()).decode("ascii")}
    except OSError:
        return None


def _snap_path(session_id: str, tool_use_id: Optional[str]) -> Path:
    tid = "".join(c if c.isalnum() or c in "_-" else "_" for c in (tool_use_id or "last"))[:80]
    return ledger.ledger_dir() / f"{ledger._safe(session_id)}.{tid}.snap.json"


def snapshot(session_id: str, tool_use_id: Optional[str], root: Path, patterns: List[str]) -> Path:
    files = {rel: _read(p) for rel, p in _entries(root, patterns).items()}
    path = _snap_path(session_id, tool_use_id)
    ledger._ensure_dir()
    ledger._write_atomic(path, {"ts": time.time(), "root": str(root), "files": files})
    return path


def _restore(p: Path, old: dict) -> None:
    if p.is_symlink() or p.exists():
        p.unlink()
    p.parent.mkdir(parents=True, exist_ok=True)
    if "link" in old:
        os.symlink(old["link"], p)
        return
    tmp = p.with_name(f".{p.name}.llm-bouncer.{os.getpid()}")
    tmp.write_bytes(base64.b64decode(old["data"]))
    os.replace(tmp, p)


def check_and_revert(session_id: str, tool_use_id: Optional[str], allowed: Callable[[str], bool],
                     patterns: List[str]) -> Tuple[List[str], List[str], float]:
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
    ts = float(snap.get("ts") or 0)
    if time.time() - ts > MAX_AGE:
        return [], [], 0.0
    root, before = Path(snap.get("root") or snap.get("cwd") or "."), snap.get("files") or {}
    now = _entries(root, patterns)
    reverted: List[str] = []
    stuck: List[str] = []
    for rel in sorted(set(before) | set(now)):
        old = before.get(rel)
        if rel in before and rel in now:
            if old is None:
                continue  # too large to snapshot: cannot tell whether it changed
            if _read(now[rel]) == old:
                continue
        if allowed(rel):
            continue
        if rel in before and old is None:
            stuck.append(rel)  # deleted, but too large to have been snapshotted
            continue
        try:
            if rel in before:
                _restore(root / rel, old)
            else:
                (root / rel).unlink()  # created by the command
            reverted.append(rel)
        except OSError:
            stuck.append(rel)
    return reverted, stuck, ts
