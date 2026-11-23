"""Fixed rules that decide what an agent may do after it has read untrusted text.

Everything here is deterministic: regexes and set lookups over the tool call and the ledger.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml

ALLOW, ASK, DENY = "allow", "ask", "deny"


@dataclass
class Decision:
    action: str  # allow | ask | deny
    reason: str = ""
    risk: List[str] = field(default_factory=list)
    echoes: List[str] = field(default_factory=list)


def _policy_path(cwd: Optional[str]) -> Optional[Path]:
    env = os.environ.get("LLM_BOUNCER_POLICY")
    if env:
        return Path(env)
    local = Path(cwd or os.getcwd()) / ".llm-bouncer" / "policy.yaml"
    return local if local.exists() else None


@lru_cache(maxsize=8)
def _load(path: Optional[str]) -> Dict[str, Any]:
    if path:
        text = Path(path).read_text(encoding="utf-8")
    else:
        text = resources.files("llm_bouncer").joinpath("policies/default.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text) or {}


def load_policy(cwd: Optional[str] = None) -> Dict[str, Any]:
    p = _policy_path(cwd)
    return _load(str(p) if p else None)


def _any(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text, re.I) for p in patterns or [])


def _input_text(tool_input: Any) -> str:
    if isinstance(tool_input, dict):
        return "\n".join(str(v) for v in tool_input.values() if isinstance(v, (str, int, float)))
    return str(tool_input or "")


def classify(tool_name: str, tool_input: Any, policy: Dict[str, Any]) -> List[str]:
    """Return the risk categories of a tool call (empty list = not risky)."""
    ti = tool_input if isinstance(tool_input, dict) else {}
    risks: List[str] = []
    if tool_name == "Bash":
        cmd = str(ti.get("command", ""))
        for category, patterns in (policy.get("bash_risky") or {}).items():
            if _any(patterns, cmd):
                risks.append(category)
    elif tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = str(ti.get("file_path") or ti.get("notebook_path") or "")
        if _any(policy.get("sensitive_paths"), path):
            risks.append("sensitive_file_write")
    elif tool_name == "Read":
        if _any(policy.get("secret_paths"), str(ti.get("file_path", ""))):
            risks.append("secrets_read")
    elif tool_name == "WebFetch":
        query = urlparse(str(ti.get("url", ""))).query
        if len(query) > int(policy.get("max_fetch_query_chars", 120)):
            risks.append("data_in_url")
    elif tool_name.startswith("mcp__"):
        action = tool_name.split("__")[-1]
        if re.search(policy.get("mcp_risky_name", r"$^"), action, re.I):
            risks.append("mcp_external_action")
    return risks


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def find_echoes(tool_input: Any, tainted_rows: List[dict]) -> List[str]:
    """Indicators from tainted text that reappear in this tool call."""
    haystack = _norm(_input_text(tool_input))
    hits: List[str] = []
    for row in tainted_rows:
        for kind in ("commands", "urls", "emails"):
            for ind in (row.get("indicators") or {}).get(kind, []):
                n = _norm(ind)
                if len(n) >= 6 and n in haystack and ind not in hits:
                    hits.append(ind)
    return hits


def decide(tool_name: str, tool_input: Any, ledger_rows: List[dict], policy: Dict[str, Any]) -> Decision:
    risks = classify(tool_name, tool_input, policy)
    if not risks:
        return Decision(ALLOW)
    taint_sources = set(policy.get("taint_sources") or [])
    tainted = [r for r in ledger_rows if r.get("source_type") in taint_sources]
    if not tainted:
        return Decision(ALLOW, risk=risks)
    origins = ", ".join(dict.fromkeys(r.get("origin", "?") for r in tainted[-3:]))
    echoes = find_echoes(tool_input, tainted)
    if echoes:
        action = policy.get("on_echo", DENY)
        reason = (
            f"llm-bouncer: this {', '.join(risks)} action repeats text that came from untrusted content "
            f"({echoes[0]!r}), not from you. Untrusted sources this session: {origins}."
        )
        return Decision(action, reason, risks, echoes)
    action = policy.get("on_risky_after_taint", ASK)
    reason = (
        f"llm-bouncer: risky action ({', '.join(risks)}) after the agent read untrusted content "
        f"this session ({origins}). Approve only if you asked for this."
    )
    return Decision(action, reason, risks)
