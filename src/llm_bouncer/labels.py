"""Label data model and the deterministic source -> trust mapping."""

from __future__ import annotations

import hashlib
import time
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


class Label:
    """One ledger entry: a fact about one piece of text the agent saw.

    A plain class rather than a dataclass: `dataclasses` pulls in `inspect`, which cost about a
    sixth of every hook's start-up time.
    """

    __slots__ = ("session_id", "turn", "source_type", "trust", "origin", "tool_name", "chars", "sha256",
                 "flags", "hints", "indicators", "ts")

    def __init__(
        self,
        session_id: str,
        turn: int,
        source_type: str,
        trust: str,
        origin: str,  # e.g. URL, file path, command, MCP tool name
        tool_name: Optional[str],
        chars: int,
        sha256: str,
        flags: Optional[List[str]] = None,  # deterministic findings (hidden text, ...)
        hints: Optional[List[dict]] = None,  # heuristic instruction-like spans (hint only)
        indicators: Optional[Dict[str, List[str]]] = None,  # URLs, emails, commands (untrusted only)
        ts: Optional[float] = None,
    ) -> None:
        self.session_id = session_id
        self.turn = turn
        self.source_type = source_type
        self.trust = trust
        self.origin = origin
        self.tool_name = tool_name
        self.chars = chars
        self.sha256 = sha256
        self.flags = flags or []
        self.hints = hints or []
        self.indicators = indicators or {}
        self.ts = time.time() if ts is None else ts

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}

    def __repr__(self) -> str:
        return f"Label({self.to_dict()!r})"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
