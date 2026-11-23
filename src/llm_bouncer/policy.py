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
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import parse_qsl, urlparse

import yaml

from .textnorm import norm, one_line

ALLOW, ASK, DENY = "allow", "ask", "deny"
_ACTIONS = (ALLOW, ASK, DENY)


@dataclass
class Decision:
    action: str  # allow | ask | deny
    reason: str = ""
    risk: List[str] = field(default_factory=list)
    echoes: List[str] = field(default_factory=list)


class PolicyError(ValueError):
    pass


# ---------------------------------------------------------------- loading


def _policy_path() -> Optional[Path]:
    """The user's own policy: $LLM_BOUNCER_POLICY, else ~/.llm-bouncer/policy.yaml.

    A policy inside the project is deliberately NOT read: a cloned repo (or the agent itself)
    could ship one that switches the gate off.
    """
    env = os.environ.get("LLM_BOUNCER_POLICY")
    if env:
        return Path(env)  # missing file -> error -> fail closed, so a typo is noticed
    user = Path.home() / ".llm-bouncer" / "policy.yaml"
    return user if user.exists() else None


def _default_text() -> str:
    return resources.files("llm_bouncer").joinpath("policies/default.yaml").read_text(encoding="utf-8")


def _validate(pol: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("on_echo", "on_risky_after_taint"):
        if pol.get(key) not in _ACTIONS:
            raise PolicyError(f"{key} must be one of {_ACTIONS}, got {pol.get(key)!r}")
    try:
        for patterns in (pol.get("bash_risky") or {}).values():
            for p in patterns or []:
                re.compile(p)
        for key in ("sensitive_paths", "secret_paths", "bouncer_paths"):
            for p in pol.get(key) or []:
                re.compile(p)
    except re.error as exc:
        raise PolicyError(f"bad regex in policy: {exc}") from exc
    return pol


@lru_cache(maxsize=8)
def _load(path: Optional[str]) -> Dict[str, Any]:
    pol = yaml.safe_load(_default_text()) or {}
    if path:
        user = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(user, dict):
            raise PolicyError(f"{path}: policy must be a mapping")
        # Top-level keys override the defaults, so a short file only changes what it names
        # instead of silently dropping every rule it leaves out.
        pol.update(user)
    return _validate(pol)


def load_policy(cwd: Optional[str] = None) -> Dict[str, Any]:
    """`cwd` is accepted for backwards compatibility and ignored (see _policy_path)."""
    p = _policy_path()
    return _load(str(p) if p else None)


# ---------------------------------------------------------------- classifying


def _any(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text, re.I) for p in patterns or [])


def _strings(value: Any) -> Iterator[str]:
    """Every string inside a tool input, however deeply nested (MCP args, MultiEdit edits)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield str(value)


_WRITE_OP = re.compile(r"(>>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\bsed\s+-i|\binstall\b|\bdd\b|\btruncate\b|\brm\b)")


def _bash_write_targets(cmd: str) -> List[str]:
    if not _WRITE_OP.search(cmd):
        return []
    return [t.strip("'\"") for t in re.split(r"[\s;&|<>]+", cmd) if t]


def _name_tokens(name: str) -> List[str]:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", name.lower()) if t]


def classify(tool_name: str, tool_input: Any, policy: Dict[str, Any]) -> List[str]:
    """Return the risk categories of a tool call (empty list = not risky)."""
    ti = tool_input if isinstance(tool_input, dict) else {}
    risks: List[str] = []
    bouncer = policy.get("bouncer_paths")
    if tool_name == "Bash":
        cmd = str(ti.get("command", ""))
        for category, patterns in (policy.get("bash_risky") or {}).items():
            if _any(patterns, cmd):
                risks.append(category)
        targets = _bash_write_targets(cmd)
        if any(_any(policy.get("sensitive_paths"), t) for t in targets):
            risks.append("sensitive_file_write")
        if _any(bouncer, cmd):
            risks.append("bouncer_tamper")
    elif tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = str(ti.get("file_path") or ti.get("notebook_path") or "")
        if _any(policy.get("sensitive_paths"), path):
            risks.append("sensitive_file_write")
        if _any(bouncer, path):
            risks.append("bouncer_tamper")
    elif tool_name in ("Read", "Grep", "Glob", "NotebookRead"):
        path = str(ti.get("file_path") or ti.get("path") or ti.get("notebook_path") or "")
        if _any(policy.get("secret_paths"), path):
            risks.append("secrets_read")
    elif tool_name == "WebFetch":
        url = urlparse(str(ti.get("url", "")))
        pieces = [url.query, url.fragment] + url.path.split("/") + [v for _, v in parse_qsl(url.query)]
        limit = int(policy.get("max_fetch_query_chars", 120))
        if len(url.query) > limit or max((len(p) for p in pieces), default=0) > limit:
            risks.append("data_in_url")
    elif tool_name.startswith("mcp__"):
        tokens = _name_tokens(tool_name.split("__")[-1])
        readonly = set(policy.get("mcp_readonly_verbs") or [])
        risky = set(policy.get("mcp_risky_verbs") or [])
        # "get_messages" or "list_posts" read; "send_message" or "post_comment" act.
        if tokens and tokens[0] not in readonly and risky.intersection(tokens):
            risks.append("mcp_external_action")
    return risks


# ---------------------------------------------------------------- echo check

_GENERIC = {
    "git", "push", "pull", "origin", "upstream", "main", "master", "head", "curl", "wget", "bash",
    "sh", "zsh", "sudo", "npm", "npx", "pip", "pip3", "python", "python3", "node", "publish",
    "install", "run", "rm", "chmod", "ssh", "scp", "rsync", "eval", "export", "gh", "pr", "create",
    "release", "gist", "repo", "env", "printenv", "base64", "nc", "ncat", "netcat",
}


def _distinctive(indicator: str) -> bool:
    """Does this command name something specific (a host, path, address, payload)?

    `git push` or `npm publish` appear in every set of docs; copying them is not evidence of an
    attack, so they alone must not turn an ask into a deny.
    """
    for tok in re.split(r"[\s|;&()'\"]+", indicator.lower()):
        if not tok or tok.startswith("-") or tok in _GENERIC:
            continue
        if re.search(r"[/.@:=~$]", tok) or re.search(r"\d", tok) or len(tok) >= 12:
            return True
    return False


def _url_key(url: str) -> str:
    u = norm(url)
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u)  # http and https are the same destination
    return u.rstrip("/.,;:")


def find_echoes(tool_input: Any, tainted_rows: List[dict]) -> List[str]:
    """Indicators from tainted text that reappear in this tool call."""
    haystack = norm("\n".join(_strings(tool_input)))
    hits: List[str] = []
    for row in tainted_rows:
        ind = row.get("indicators") or {}
        for kind in ("commands", "urls", "emails"):
            for item in ind.get(kind, []):
                if kind == "commands":
                    if not _distinctive(item):
                        continue
                    key = norm(item)
                elif kind == "urls":
                    key = _url_key(item)
                else:
                    key = norm(item)
                if len(key) >= 6 and key in haystack and item not in hits:
                    hits.append(item)
    return hits


# ---------------------------------------------------------------- decision


def decide(tool_name: str, tool_input: Any, ledger_rows: List[dict], policy: Dict[str, Any]) -> Decision:
    risks = classify(tool_name, tool_input, policy)
    if not risks:
        return Decision(ALLOW)
    always = set(policy.get("always_ask_risks") or []).intersection(risks)
    taint_sources = set(policy.get("taint_sources") or [])
    tainted = [r for r in ledger_rows if r.get("source_type") in taint_sources]
    if not tainted:
        if always:
            return Decision(
                ASK,
                f"llm-bouncer: this call touches llm-bouncer's own files or settings ({', '.join(sorted(always))}). "
                "Approve only if you asked for this.",
                risks,
            )
        return Decision(ALLOW, risk=risks)
    origins = ", ".join(dict.fromkeys(one_line(r.get("origin", "?"), 80) for r in tainted[-3:]))
    echoes = find_echoes(tool_input, tainted)
    if echoes:
        reason = (
            f"llm-bouncer: this {', '.join(risks)} action repeats text that came from untrusted content "
            f"(\"{one_line(echoes[0], 100)}\"), not from you. Untrusted sources this session: {origins}."
        )
        return Decision(policy.get("on_echo", DENY), reason, risks, echoes)
    action = policy.get("on_risky_after_taint", ASK)
    if action == ALLOW and always:
        action = ASK
    reason = (
        f"llm-bouncer: risky action ({', '.join(risks)}) after the agent read untrusted content "
        f"this session ({origins}). Approve only if you asked for this."
    )
    return Decision(action, reason, risks)
