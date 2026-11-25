"""Fixed rules that decide what an agent may do after it has read untrusted text.

Everything here is deterministic: regexes and set lookups over the tool call and the ledger.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import parse_qsl, urlparse

from .textnorm import key_hash, norm, one_line, url_keys

ALLOW, ASK, DENY = "allow", "ask", "deny"
_ACTIONS = (ALLOW, ASK, DENY)


class Decision:
    __slots__ = ("action", "reason", "risk", "echoes")

    def __init__(self, action: str, reason: str = "", risk: Optional[List[str]] = None,
                 echoes: Optional[List[str]] = None) -> None:
        self.action = action  # allow | ask | deny
        self.reason = reason
        self.risk = risk or []
        self.echoes = echoes or []

    def __repr__(self) -> str:
        return f"Decision({self.action!r}, risk={self.risk!r}, echoes={self.echoes!r})"


class PolicyError(ValueError):
    pass


BUILTIN = ":builtin:"  # LLM_BOUNCER_POLICY value meaning "ignore any user policy" (used by eval)
_DEFAULT_PATH = Path(__file__).parent / "policies" / "default.yaml"


# ---------------------------------------------------------------- loading


def _policy_path() -> Optional[Path]:
    """The user's own policy: $LLM_BOUNCER_POLICY, else ~/.llm-bouncer/policy.yaml.

    A policy inside the project is deliberately NOT read: a cloned repo (or the agent itself)
    could ship one that switches the gate off.
    """
    env = os.environ.get("LLM_BOUNCER_POLICY")
    if env == BUILTIN:
        return None
    if env:
        return Path(env)  # missing file -> error -> fail closed, so a typo is noticed
    user = Path.home() / ".llm-bouncer" / "policy.yaml"
    return user if user.exists() else None


def _default_text() -> str:
    return _DEFAULT_PATH.read_text(encoding="utf-8")


def _validate(pol: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("on_echo", "on_risky_after_taint", "on_unlisted_after_taint"):
        if pol.get(key, ASK) not in _ACTIONS:
            raise PolicyError(f"{key} must be one of {_ACTIONS}, got {pol.get(key)!r}")
    if pol.get("tainted_mode", "allowlist") not in ("allowlist", "denylist"):
        raise PolicyError(f"tainted_mode must be allowlist or denylist, got {pol.get('tainted_mode')!r}")
    if pol.get("gate", "auto") not in ("auto", "commands"):
        raise PolicyError(f"gate must be auto or commands, got {pol.get('gate')!r}")
    eg = pol.get("egress") or {}
    if not isinstance(eg, dict) or not isinstance(eg.get("proxy_port", 18877), int) \
            or not all(isinstance(eg.get(k, []), list) for k in ("always_allow", "always_deny")):
        raise PolicyError("egress must be a mapping with an integer proxy_port and always_allow/always_deny lists")
    if not all(isinstance(p, str) for p in pol.get("integrity_paths") or []):
        raise PolicyError("integrity_paths must be a list of glob strings")
    for intent in pol.get("intents") or []:
        if not isinstance(intent, dict) or not isinstance(intent.get("grants", []), list):
            raise PolicyError(f"each intent needs a match regex and a grants list, got {intent!r}")
        try:
            re.compile(str(intent.get("match", "")))
        except re.error as exc:
            raise PolicyError(f"bad intent regex {intent.get('match')!r}: {exc}") from exc
        for g in intent.get("grants") or []:
            if not isinstance(g, str) or g.split(":", 1)[0] not in ("egress", "write", "read", "mcp") or ":" not in g:
                raise PolicyError(f"intent grant must look like egress:HOST, write:PATH, read:PATH or mcp:TOOL, got {g!r}")
    try:
        for patterns in (pol.get("bash_risky") or {}).values():
            for p in patterns or []:
                re.compile(p)
        for key in ("sensitive_paths", "secret_paths", "bouncer_paths", "secret_patterns"):
            for p in pol.get(key) or []:
                re.compile(p)
    except re.error as exc:
        raise PolicyError(f"bad regex in policy: {exc}") from exc
    return pol


def _parse(path: Optional[str]) -> Dict[str, Any]:
    import yaml  # imported only on a cache miss: it is the slowest import in the package

    pol = yaml.safe_load(_default_text()) or {}
    if path:
        user = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(user, dict):
            raise PolicyError(f"{path}: policy must be a mapping")
        # Top-level keys override the defaults, so a short file only changes what it names
        # instead of silently dropping every rule it leaves out.
        pol.update(user)
    return _validate(pol)


def _cache_key(path: Optional[str]) -> str:
    # Content hash, not mtime: an edit within the same timestamp tick, or a file restored with
    # its old mtime, must not serve a stale policy. Both files are a few KB, so this is cheap.
    import hashlib

    h = hashlib.sha256()
    for f in (str(_DEFAULT_PATH), path):
        if f:
            h.update(f.encode() + b"\0" + Path(f).read_bytes() + b"\0")  # missing user policy -> fail closed
    return h.hexdigest()


@lru_cache(maxsize=8)
def _load(path: Optional[str]) -> Dict[str, Any]:
    """Parsed, merged, validated policy, cached as JSON next to the ledgers.

    Every hook is a fresh process, so without this each tool call imported PyYAML and parsed
    and validated the policy again. The cache is keyed on a hash of the files' contents.
    """
    key = _cache_key(path)
    from .ledger import ledger_dir

    cache = ledger_dir() / "policy.cache.json"
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached.get("key") == key:
            return cached["policy"]
    except (OSError, ValueError, AttributeError, KeyError):
        pass
    pol = _parse(path)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = cache.with_name(f".policy.cache.{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"key": key, "policy": pol}), encoding="utf-8")
        os.replace(tmp, cache)
    except OSError:
        pass  # caching is an optimisation only
    return pol


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




_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-_@")
_URL_CHARS = _HOST_CHARS | set("/~%+=:")


def _occurs(key: str, haystack: str) -> bool:
    """`key` appears in `haystack` as a whole item, not as part of a longer host, path or address.

    Plain substring matching let "github.com" from a docs page match a push to
    "github.com/me/repo", and "example.com" match "notexample.com". A query string or fragment
    after a URL ("?", "#") still counts as the same URL.
    """
    start = haystack.find(key)
    while start != -1:
        end = start + len(key)
        before = haystack[start - 1] if start else ""
        after = haystack[end] if end < len(haystack) else ""
        if (not before or before not in _HOST_CHARS) and (not after or after not in _URL_CHARS):
            return True
        start = haystack.find(key, start + 1)
    return False


def find_echoes(tool_input: Any, tainted: List[dict]) -> List[str]:
    """Indicators from tainted text that reappear in this tool call.

    `tainted` holds state source summaries (see ledger). Ledger rows are accepted too.
    * URLs and emails: every one in the call is looked up, exactly, in the hashed set of those
      seen in tainted text. Exact lookup has no cap to flood and no substring confusion.
    * Commands: a specific command from tainted text must appear in the call as a whole.
    """
    from . import indicators
    from .ledger import state_from_rows

    if any("indicators" in t for t in tainted):
        tainted = list(state_from_rows([t for t in tainted if "indicators" in t])["sources"].values())
    raw = "\n".join(_strings(tool_input))
    haystack = norm(raw)
    found = indicators.extract(raw)
    url_h = set().union(*(t.get("url_h", []) for t in tainted)) if tainted else set()
    email_h = set().union(*(t.get("email_h", []) for t in tainted)) if tainted else set()
    hits: List[str] = []
    for url in found.get("urls", []):
        if any(key_hash(k) in url_h for k in url_keys(url)) and url not in hits:
            hits.append(url)
    for email in found.get("emails", []):
        if key_hash(norm(email)) in email_h and email not in hits:
            hits.append(email)
    for t in tainted:
        for item in t.get("commands", []):
            if item in hits or not _distinctive(item):
                continue
            key = norm(item)
            if len(key) >= 6 and _occurs(key, haystack):
                hits.append(item)
    return hits


# ---------------------------------------------------------------- decision


def decide(tool_name: str, tool_input: Any, ledger_rows: List[dict], policy: Dict[str, Any]) -> Decision:
    """Decide from raw ledger rows (kept for callers and tests that have rows)."""
    from .ledger import state_from_rows

    return decide_from_state(tool_name, tool_input, state_from_rows(ledger_rows), policy)


# ---------------------------------------------------------------- allowlist (tainted sessions)

_SEPARATORS = {";", "&&", "||", "|", "&", "|&"}
_SAFE_REDIRECTS = re.compile(r"\s\d?>&\d\b|\s(?:\d|&)?>\s*/dev/null\b")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def bash_is_safe(command: str, policy: Dict[str, Any]) -> bool:
    """Is every part of this command on the allowlist?

    Deliberately strict: command substitution, process substitution, heredocs, redirections
    (other than to /dev/null or between streams), subshells, env assignments and paths to
    binaries all make the command "not safe", which only means the developer is asked.
    """
    import shlex

    if any(t in command for t in ("$(", "`", "<(", ">(", "<<")):
        return False
    text = _SAFE_REDIRECTS.sub(" ", " " + command).replace("\n", " ; ")
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:  # unbalanced quotes
        return False
    safe = set(policy.get("bash_safe_commands") or [])
    prefixes = [p.split() for p in policy.get("bash_safe_prefixes") or []]
    unsafe_args = policy.get("bash_unsafe_args") or {}
    segments: List[List[str]] = [[]]
    for tok in tokens:
        if tok in _SEPARATORS:
            segments.append([])
        elif tok and set(tok) <= set("<>&|;()"):
            return False  # redirection or subshell
        else:
            segments[-1].append(tok)
    segments = [seg for seg in segments if seg]
    if not segments:
        return False
    for seg in segments:
        first = seg[0]
        if _ASSIGNMENT.match(first) or "/" in first:
            return False  # VAR=x cmd (e.g. PAGER=...) or ./script, /tmp/x
        if not (first in safe or any(seg[: len(p)] == p for p in prefixes)):
            return False
        bad = unsafe_args.get(first) or []
        for arg in seg[1:]:
            if arg in bad or any(arg.startswith(b + "=") for b in bad if b.startswith("--")):
                return False
            if first == "git" and arg.startswith("-c") and len(arg) > 2:
                return False
    return True


def mcp_is_safe(tool_name: str, policy: Dict[str, Any]) -> bool:
    tokens = _name_tokens(tool_name.split("__")[-1])
    return bool(tokens) and tokens[0] in set(policy.get("mcp_readonly_verbs") or [])


def _entropy(s: str) -> float:
    import math
    from collections import Counter

    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def looks_secret(text: str, policy: Dict[str, Any]) -> bool:
    if _any(policy.get("secret_patterns"), text):
        return True
    limit = float(policy.get("min_secret_entropy", 3.5))
    for tok in re.findall(r"[A-Za-z0-9+=_-]{20,}", text):  # split on "/" and ".": paths are not secrets
        classes = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+=_-]"))
        if classes >= 3 and _entropy(tok) >= limit:
            return True
    return False


def _unlisted(tool_name: str, tool_input: Any, policy: Dict[str, Any]) -> Optional[str]:
    """Why a non-risky call still needs approval in a tainted session (None = it does not)."""
    if policy.get("tainted_mode", "allowlist") != "allowlist":
        return None
    ti = tool_input if isinstance(tool_input, dict) else {}
    if tool_name == "Bash" and not bash_is_safe(str(ti.get("command", "")), policy):
        return "command_not_on_allowlist"
    if tool_name.startswith("mcp__") and not mcp_is_safe(tool_name, policy):
        return "mcp_tool_not_read_only"
    if tool_name == "WebFetch" and looks_secret(str(ti.get("url", "")), policy):
        return "secret_in_url"
    if tool_name == "WebSearch" and looks_secret(str(ti.get("query", "")), policy):
        return "secret_in_search"
    return None


CLEAN, TAINTED, REVIEWED = "clean", "tainted", "reviewed"


def session_status(state: Dict[str, Any], policy: Dict[str, Any]):
    """The session's state and the source summaries that put it there.

        clean --(tainting content read)--> tainted --(developer runs `review`)--> reviewed
                                              ^                                      |
                                              +------(tainting content read)---------+

    Taint is one-way except through `review`, which only the developer should run (it is a
    bouncer_tamper action, so the agent asking to run it always needs approval). A source taints
    if the current policy lists it, if it was stamped as tainting when it was read (so changing
    the policy later does not clean old sessions), or if it is "unknown" (lost or unreadable
    labels, a deleted ledger). Only content read after the last review counts.
    """
    taint_sources = set(policy.get("taint_sources") or []) | {"unknown"} | set(state.get("taints") or [])
    reviewed = int(state.get("reviewed_turn") or 0)
    tainted = [
        v for k, v in (state.get("sources") or {}).items()
        if k in taint_sources and v.get("count") and int(v.get("last_turn", reviewed + 1)) > reviewed
    ]
    if tainted:
        return TAINTED, tainted
    return (REVIEWED if reviewed else CLEAN), []


def decide_from_state(tool_name: str, tool_input: Any, state: Dict[str, Any], policy: Dict[str, Any]) -> Decision:
    """The decision table, first matching row wins.

    | session  | call                          | decision                    |
    |----------|-------------------------------|-----------------------------|
    | clean    | touches llm-bouncer itself    | ask                         |
    | clean    | anything else                 | allow                       |
    | tainted  | listed and not risky          | allow                       |
    | tainted  | repeats a tainted URL/email/command | on_echo (deny)        |
    | tainted  | risky                         | on_risky_after_taint (ask)  |
    | tainted  | not risky but unlisted        | on_unlisted_after_taint (ask) |

    "touches llm-bouncer itself" (always_ask_risks) is never downgraded to allow.
    "reviewed" sessions are treated as clean until new tainting content arrives.
    """
    risks = classify(tool_name, tool_input, policy)
    always = set(policy.get("always_ask_risks") or []).intersection(risks)
    _, tainted = session_status(state, policy)
    if not tainted:
        if always:
            return Decision(ASK, f"llm-bouncer: touches llm-bouncer itself ({', '.join(sorted(always))}). Approve only if you asked.", risks)
        return Decision(ALLOW, risk=risks)
    if risks:
        why, knob = risks, "on_risky_after_taint"
    else:
        unlisted = _unlisted(tool_name, tool_input, policy)
        if unlisted is None:
            return Decision(ALLOW)
        why, knob = [unlisted], "on_unlisted_after_taint"
    origins = ", ".join(dict.fromkeys(one_line(o, 60) for v in tainted for o in v.get("origins", [])[-2:]))
    echoes = find_echoes(tool_input, tainted)
    if echoes:
        reason = f"llm-bouncer: {', '.join(why)} repeats untrusted text (\"{one_line(echoes[0], 80)}\") from {origins}."
        return Decision(policy.get("on_echo", DENY), reason, why, echoes)
    action = policy.get(knob, ASK)
    if action == ALLOW and always:
        action = ASK
    reason = f"llm-bouncer: {', '.join(why)} after reading untrusted content ({origins}). Approve only if you asked."
    return Decision(action, reason, why)
