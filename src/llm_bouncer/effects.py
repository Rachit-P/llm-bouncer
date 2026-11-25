"""The effects gate: mediate what a command does, not what it says.

A shell can spell anything, so a list of dangerous (or safe) command texts is never complete. But an
injected agent can only hurt you through a few effects:

* egress     data leaves the machine (network, DNS)
* integrity  writes to files that run code later (CI, builds, test setup, agent instructions)
* secrets    reading credentials
* authority  acting as you (publishing, sending, MCP writes)

With Claude Code's sandbox on and `llm-bouncer proxy` as its network proxy, any Bash command may
run: the proxy decides egress, protected paths and the snapshot/revert in `integrity` decide
writes. After untrusted content an effect needs a capability ("grant"). Capabilities come only from
the trusted channel: the developer's typed prompt (see `intents` in the policy) or
`llm-bouncer grant`. Untrusted text can supply data, never capabilities.

Calls that run outside the sandbox (no sandbox, unsandboxed retries, excludedCommands) fall back to
the command rules in policy.py, because there nothing contains the effects.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from . import ledger, policy
from .policy import ALLOW, ASK, DENY, Decision

EFFECTS, COMMANDS = "effects", "commands"


# ---------------------------------------------------------------- sandbox detection


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def sandbox_settings(cwd: Optional[str]) -> dict:
    """The merged `sandbox` settings Claude Code would use (user, then project, then local)."""
    files = [Path.home() / ".claude" / "settings.json"]
    if cwd:
        files += [Path(cwd) / ".claude" / "settings.json", Path(cwd) / ".claude" / "settings.local.json"]
    merged: Dict[str, Any] = {}
    for f in files:
        sb = _read_json(f).get("sandbox")
        if isinstance(sb, dict):
            for k, v in sb.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                elif isinstance(v, list) and isinstance(merged.get(k), list):
                    merged[k] = merged[k] + v
                else:
                    merged[k] = v
    return merged


def runs_sandboxed(event: dict, pol: Dict[str, Any]) -> bool:
    """Will this Bash call run in the sandbox, behind llm-bouncer's proxy?

    Any doubt means no: the command rules then apply, as before v0.7. A repository's settings can
    only push a call towards the stricter command rules (turn the sandbox off, exclude commands,
    change the proxy port), never towards the effects gate.
    """
    ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    if ti.get("dangerouslyDisableSandbox"):
        return False
    sb = sandbox_settings(event.get("cwd"))
    if not sb.get("enabled"):
        return False
    net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
    if net.get("httpProxyPort") != int((pol.get("egress") or {}).get("proxy_port", 0)):
        return False
    cmd = str(ti.get("command", ""))
    for pat in sb.get("excludedCommands") or []:
        if isinstance(pat, str) and (fnmatch.fnmatchcase(cmd, pat) or fnmatch.fnmatchcase(cmd.split(" ")[0], pat)):
            return False
    return True


def gate_mode(event: dict, pol: Dict[str, Any]) -> str:
    mode = os.environ.get("LLM_BOUNCER_GATE") or pol.get("gate", "auto")
    if mode in (EFFECTS, COMMANDS):
        return mode
    return EFFECTS if runs_sandboxed(event, pol) else COMMANDS


# ---------------------------------------------------------------- grants


def _host(target: str) -> str:
    return target.lower().rstrip(".")


def host_granted(host: str, grants: Iterable[str]) -> bool:
    host = _host(host)
    for g in grants:
        if g.startswith("egress:"):
            pat = _host(g[len("egress:"):])
            if fnmatch.fnmatchcase(host, pat) or host == pat:
                return True
    return False


def path_granted(path: str, grants: Iterable[str], kind: str = "write") -> bool:
    path = str(path).replace("\\", "/")
    base = path.rsplit("/", 1)[-1]
    for g in grants:
        if not g.startswith(kind + ":"):
            continue
        pat = g[len(kind) + 1:]
        if pat.startswith("./"):
            pat = pat[2:]
        if fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(path, "*/" + pat) or fnmatch.fnmatchcase(base, pat):
            return True
    return False


def tool_granted(tool_name: str, grants: Iterable[str]) -> bool:
    return any(g.startswith("mcp:") and fnmatch.fnmatchcase(tool_name, g[4:]) for g in grants)


def _git_remote_hosts(cwd: Optional[str]) -> List[str]:
    try:
        out = subprocess.run(["git", "-C", cwd or ".", "remote", "-v"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    hosts = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        url = parts[1]
        m = re.match(r"^[\w.+-]+@([^:/]+):", url)  # git@github.com:me/app.git
        h = m.group(1) if m else (urlparse(url).hostname or "")
        if h and h not in hosts:
            hosts.append(h.lower())
    return hosts


_DOMAIN = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}))\b", re.I)
_FILE = re.compile(r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.(?:ya?ml|json|toml|py|cfg|ini|lock|txt|md|rs|mk|sh|js|ts))\b|\b(Makefile|GNUmakefile|Dockerfile)\b")
_NOT_HOST_SUFFIX = {"py", "md", "txt", "json", "yml", "yaml", "toml", "cfg", "ini", "lock", "js", "ts", "rs", "sh", "mk"}


def grants_from_prompt(prompt: str, pol: Dict[str, Any], cwd: Optional[str] = None) -> List[str]:
    """Capabilities the developer's own prompt grants."""
    grants: List[str] = []

    def add(g: str) -> None:
        if g not in grants:
            grants.append(g)

    for m in _DOMAIN.finditer(prompt):
        dom = m.group(1).lower()
        if dom.rsplit(".", 1)[-1] not in _NOT_HOST_SUFFIX:
            add("egress:" + dom)
    for m in _FILE.finditer(prompt):
        add("write:" + (m.group(1) or m.group(2)))
    for intent in pol.get("intents") or []:
        if re.search(str(intent.get("match", "(?!)")), prompt, re.I):
            for g in intent.get("grants") or []:
                if g == "egress:@git-remotes":
                    for h in _git_remote_hosts(cwd):
                        add("egress:" + h)
                else:
                    add(str(g))
    return grants


def session_grants(state: Dict[str, Any]) -> List[str]:
    return list(state.get("grants") or []) + ledger.global_grants()


# ---------------------------------------------------------------- egress (used by the proxy)


def egress_decision(host: str, url: Optional[str], states: Dict[str, dict], pol: Dict[str, Any]) -> Decision:
    """May a sandboxed command connect to `host`? `states` are the recently active sessions.

    The proxy cannot tell which session a connection comes from, so it is conservative: if any
    recent session is tainted, connections need a capability from some recent session or a
    global grant. `url` is only known for plain-HTTP requests (HTTPS is not decrypted).
    """
    eg = pol.get("egress") or {}
    host = _host(host)
    if any(fnmatch.fnmatchcase(host, _host(p)) for p in eg.get("always_deny") or []):
        return Decision(DENY, f"llm-bouncer: {host} is in egress.always_deny.", ["egress"])
    if any(fnmatch.fnmatchcase(host, _host(p)) for p in eg.get("always_allow") or []):
        return Decision(ALLOW)
    tainted, grants = [], list(ledger.global_grants())
    for st in states.values():
        status, srcs = policy.session_status(st, pol)
        tainted += srcs
        grants += st.get("grants") or []
    if not tainted:
        return Decision(ALLOW)
    if url and policy.looks_secret(url, pol):
        return Decision(DENY, f"llm-bouncer: request to {host} carries something that looks like a secret.", ["egress", "secret_in_url"])
    if host_granted(host, grants):
        return Decision(ALLOW, risk=["egress"])
    origins = ", ".join(dict.fromkeys(o for v in tainted for o in v.get("origins", [])[-2:]))
    return Decision(
        DENY,
        f"llm-bouncer: blocked a connection to {host} after untrusted content ({origins[:200]}). "
        f"If you asked for it, run: llm-bouncer grant {host}",
        ["egress"],
    )


# ---------------------------------------------------------------- the hook gate


def decide(event: dict, state: Dict[str, Any], pol: Dict[str, Any]) -> Decision:
    """Pre-tool-use decision under the effects model."""
    tool = str(event.get("tool_name", ""))
    ti = event.get("tool_input")
    if tool == "Bash" and gate_mode(event, pol) == EFFECTS:
        risks = policy.classify(tool, ti, pol)
        if "bouncer_tamper" in risks:
            return Decision(ASK, "llm-bouncer: touches llm-bouncer itself. Approve only if you asked.", ["bouncer_tamper"])
        # Runs in the sandbox: egress is decided by the proxy, writes by the sandbox and the
        # integrity snapshot. Nothing to predict from the command text.
        return Decision(ALLOW, risk=["sandboxed"])
    d = policy.decide_from_state(tool, ti, state, pol)
    if d.action != ASK or "bouncer_tamper" in d.risk:
        return d
    grants = session_grants(state)
    if not grants:
        return d
    tin = ti if isinstance(ti, dict) else {}
    covered = True
    for r in d.risk:
        if r == "sensitive_file_write":
            covered &= path_granted(str(tin.get("file_path") or tin.get("notebook_path") or ""), grants, "write")
        elif r == "secrets_read":
            covered &= path_granted(str(tin.get("file_path") or tin.get("path") or ""), grants, "read")
        elif r in ("mcp_external_action", "mcp_tool_not_read_only"):
            covered &= tool_granted(tool, grants)
        elif tool == "WebFetch" and r in ("data_in_url",):
            covered = False  # a granted host does not make a data-carrying URL safe
        else:
            covered = False
    if covered:
        return Decision(ALLOW, risk=d.risk + ["granted"])
    return d
