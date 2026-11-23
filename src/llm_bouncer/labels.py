"""Label data model and the deterministic source -> trust mapping."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SourceType(str, Enum):
    USER_TYPED = "user_typed"  # written by the developer in the prompt box
    USER_PASTED = "user_pasted"  # inside the prompt, but not necessarily written by them (v0: reserved)
    WEB = "web"  # WebFetch / WebSearch results
    FILE = "file"  # Read / Grep / Glob results
    COMMAND = "command"  # Bash / shell output
    MCP = "mcp"  # any MCP tool result
    TOOL = "tool"  # any other tool result (subagents, unknown tools)
    INTERNAL = "internal"  # the agent's own bookkeeping (todo lists, plan mode); never taints


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


# Deterministic: the source type alone decides the trust level. No guessing.
_TRUST = {
    SourceType.USER_TYPED: Trust.TRUSTED,
    SourceType.USER_PASTED: Trust.UNTRUSTED,
    SourceType.WEB: Trust.UNTRUSTED,
    SourceType.FILE: Trust.UNTRUSTED,
    SourceType.COMMAND: Trust.UNTRUSTED,
    SourceType.MCP: Trust.UNTRUSTED,
    SourceType.TOOL: Trust.UNTRUSTED,
    SourceType.INTERNAL: Trust.UNTRUSTED,
}

_TOOL_SOURCE = {
    "WebFetch": SourceType.WEB,
    "WebSearch": SourceType.WEB,
    "Read": SourceType.FILE,
    "Grep": SourceType.FILE,
    "Glob": SourceType.FILE,
    "NotebookRead": SourceType.FILE,
    # Edit/Write results echo file contents back, so they are file text, not an unknown tool.
    "Write": SourceType.FILE,
    "Edit": SourceType.FILE,
    "MultiEdit": SourceType.FILE,
    "NotebookEdit": SourceType.FILE,
    "LS": SourceType.FILE,
    "Bash": SourceType.COMMAND,
    "BashOutput": SourceType.COMMAND,
    "TodoWrite": SourceType.INTERNAL,
    "ExitPlanMode": SourceType.INTERNAL,
    "KillShell": SourceType.INTERNAL,
    "KillBash": SourceType.INTERNAL,
}


def source_for_tool(tool_name: str) -> SourceType:
    if tool_name.startswith("mcp__"):
        return SourceType.MCP
    return _TOOL_SOURCE.get(tool_name, SourceType.TOOL)


def trust_for(source: SourceType) -> Trust:
    return _TRUST[source]


@dataclass
class Label:
    """One ledger entry: a fact about one piece of text the agent saw."""

    session_id: str
    turn: int
    source_type: str
    trust: str
    origin: str  # e.g. URL, file path, command, MCP tool name
    tool_name: Optional[str]
    chars: int
    sha256: str
    flags: List[str] = field(default_factory=list)  # deterministic findings (hidden text, ...)
    hints: List[dict] = field(default_factory=list)  # heuristic instruction-like spans (hint only)
    indicators: Dict[str, List[str]] = field(default_factory=dict)  # URLs, emails, commands (untrusted only)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
