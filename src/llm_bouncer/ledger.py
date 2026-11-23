"""Append-only per-session ledger of labels, stored as JSON Lines."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import List

from .labels import Label


def ledger_dir(cwd: str | None = None) -> Path:
    override = os.environ.get("LLM_BOUNCER_DIR")
    if override:
        return Path(override)
    return Path(cwd or os.getcwd()) / ".llm-bouncer"


def _safe(session_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", session_id) or "unknown"


def ledger_path(session_id: str, cwd: str | None = None) -> Path:
    return ledger_dir(cwd) / f"{_safe(session_id)}.jsonl"


def append(label: Label, cwd: str | None = None) -> Path:
    path = ledger_path(label.session_id, cwd)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(label.to_dict(), ensure_ascii=False) + "\n")
    return path


def read_all(session_id: str, cwd: str | None = None) -> List[dict]:
    path = ledger_path(session_id, cwd)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def next_turn(session_id: str, cwd: str | None = None) -> int:
    return len(read_all(session_id, cwd)) + 1


def append_decision(session_id: str, record: dict, cwd: str | None = None) -> Path:
    """Decisions go to a separate file so the label ledger stays one-row-per-text."""
    path = ledger_dir(cwd) / f"{_safe(session_id)}.decisions.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path
