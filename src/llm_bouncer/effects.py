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

Calls the sandbox cannot contain (no sandbox, unsandboxed retries, excludedCommands, background
commands) fall back to the command rules in policy.py.
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
GRANT_KINDS = ("egress", "write", "read", "mcp")


# ---------------------------------------------------------------- where the project is


def project_root(cwd: Optional[str]) -> Path:
    """The project Claude Code runs in, even when a hook's cwd is a subfolder.

    $CLAUDE_PROJECT_DIR when the cwd is inside it, else the nearest folder above the cwd that
    holds `.claude` or `.git`, else the cwd.
    """
    here = Path(cwd or os.getcwd()).resolve()
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        root = Path(env).resolve()
        if here == root or root in here.parents:
            return root
    for d in (here, *here.parents):
        if (d / ".claude").is_dir() or (d / ".git").exists():
            return d
    return here


# ---------------------------------------------------------------- sandbox detection


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def sandbox_settings(cwd: Optional[str]) -> dict:
    """The merged `sandbox` settings Claude Code would use (user, then project, then local)."""
    root = project_root(cwd)
    files = [Path.home() / ".claude" / "settings.json", root / ".claude" / "settings.json",
             root / ".claude" / "settings.local.json"]
    merged: Dict[str, Any] = {}
    for f in files:
        sb = _read_json(f).get("sandbox")
        if not isinstance(sb, dict):
            continue
        for k, v in sb.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                merged[k] = {**merged[k], **v}
            elif isinstance(v, list) and isinstance(merged.get(k), list):
                merged[k] = merged[k] + v
            else:
                merged[k] = v
    return merged


def proxy_port(pol: Dict[str, Any]) -> int:
    return int((pol.get("egress") or {}).get("proxy_port", 18877))


def proxy_configured(cwd: Optional[str], pol: Dict[str, Any]) -> bool:
    """Is the sandbox on, with every sandboxed connection going through llm-bouncer's proxy?

    Both ports must be ours: a SOCKS port left to Claude Code's built-in proxy would be a second,
    taint-blind way out. The ledger must also be out of reach of sandboxed commands, which may
    write anywhere in the project: otherwise a command could edit its own grants.
    """
    sb = sandbox_settings(cwd)
    net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
    port = proxy_port(pol)
    if not sb.get("enabled") or net.get("httpProxyPort") != port or net.get("socksProxyPort") != port + 1:
        return False
    fs = sb.get("filesystem") if isinstance(sb.get("filesystem"), dict) else {}
    if fs.get("disabled"):
        return False
    root, ledger_dir = project_root(cwd), ledger.ledger_dir().resolve()
    if ledger_dir == root or root in ledger_dir.parents:
        denied = [Path(os.path.expanduser(str(p))).resolve() for p in fs.get("denyWrite") or []]
        if not any(d == ledger_dir or d in ledger_dir.parents for d in denied):
            return False
    return True


_SEGMENT = re.compile(r"\s*(?:&&|\|\||[;|&\n])\s*")


def runs_sandboxed(event: dict, pol: Dict[str, Any]) -> bool:
    """Will this Bash call run in the sandbox, behind llm-bouncer's proxy, so its effects can be checked?

    Any doubt means no, and the command rules apply. A repository's settings can only push a call
    towards the command rules (turn the sandbox off, exclude commands, change a port), never away.
    """
    ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    if ti.get("dangerouslyDisableSandbox") or ti.get("run_in_background"):
        # Unsandboxed: nothing contains it. Background: it outlives the post-tool-use hook, so its
        # writes cannot be checked when it ends.
        return False
    if not proxy_configured(event.get("cwd"), pol):
        return False
    cmd = str(ti.get("command", ""))
    parts = [cmd] + [p for p in _SEGMENT.split(cmd) if p]
    for pat in sandbox_settings(event.get("cwd")).get("excludedCommands") or []:
        if not isinstance(pat, str):
            continue
        for part in parts:
            if fnmatch.fnmatchcase(part, pat) or fnmatch.fnmatchcase(part.split(" ")[0], pat):
                return False
    return True


def gate_mode(event: dict, pol: Dict[str, Any]) -> str:
    """effects or commands for this Bash call.

    `gate: commands` in the policy turns the effects gate off. LLM_BOUNCER_GATE=effects (used by
    `eval --gate effects`) skips the settings check but never treats an unsandboxed or background
    call as contained.
    """
    if (pol.get("gate") or "auto") == COMMANDS:
        return COMMANDS
    if os.environ.get("LLM_BOUNCER_GATE") == EFFECTS:
        ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
        return COMMANDS if ti.get("dangerouslyDisableSandbox") or ti.get("run_in_background") else EFFECTS
    if os.environ.get("LLM_BOUNCER_GATE") == COMMANDS:
        return COMMANDS
    return EFFECTS if runs_sandboxed(event, pol) else COMMANDS


# ---------------------------------------------------------------- grants


def _host(target: str) -> str:
    return target.lower().rstrip(".")


def normalize_target(target: str) -> Optional[str]:
    """`pypi.org`, `https://pypi.org/x`, `egress:*.npmjs.org`, `write:Makefile`... -> a grant, or None."""
    target = target.strip()
    kind, sep, rest = target.partition(":")
    if sep and kind in GRANT_KINDS:
        return f"{kind}:{rest}" if rest else None
    if "://" in target:
        host = urlparse(target).hostname
        return f"egress:{host}" if host else None
    if re.fullmatch(r"(\*\.)?[A-Za-z0-9.-]+", target):
        return "egress:" + target
    m = re.fullmatch(r"((?:\*\.)?[A-Za-z0-9.-]+):\d+", target) or re.fullmatch(r"\[?([0-9a-fA-F:]+)\]?", target)
    return "egress:" + m.group(1) if m else None


def host_granted(host: str, grants: Iterable[str]) -> bool:
    host = _host(host)
    for g in grants:
        if g.startswith("egress:") and fnmatch.fnmatchcase(host, _host(g[len("egress:"):])):
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
        out = subprocess.run(["git", "-C", str(project_root(cwd)), "remote", "-v"], capture_output=True, text=True,
                             timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    hosts: List[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        m = re.match(r"^[\w.+-]+@([^:/]+):", parts[1])  # git@github.com:me/app.git
        h = (m.group(1) if m else (urlparse(parts[1]).hostname or "")).lower()
        if h and h not in hosts:
            hosts.append(h)
    return hosts


_DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.I)
_FILE = re.compile(r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.(?:ya?ml|json|toml|py|cfg|ini|lock|txt|md|rs|mk|sh|js|ts))\b"
                   r"|\b(Makefile|GNUmakefile|Dockerfile)\b")
_NOT_TLD = {"py", "md", "txt", "json", "yml", "yaml", "toml", "cfg", "ini", "lock", "js", "ts", "rs", "sh", "mk", "html",
            "css", "lock", "log", "csv", "xml", "sql", "go", "rb", "java", "kt", "swift", "c", "h", "cpp", "env"}


def grants_from_prompt(prompt: str, pol: Dict[str, Any], cwd: Optional[str] = None) -> List[str]:
    """Capabilities the developer's own prompt grants."""
    grants: List[str] = []

    def add(g: str) -> None:
        if g not in grants:
            grants.append(g)

    for m in _DOMAIN.finditer(prompt):
        dom = m.group(1).lower()
        if dom.rsplit(".", 1)[-1] not in _NOT_TLD:
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
    """Every capability this session holds (yours, your prompts', and global ones)."""
    return list(state.get("grants") or []) + list(state.get("prompt_grants") or []) + ledger.global_grants()


# ---------------------------------------------------------------- egress (used by the proxy)


def egress_decision(host: str, url: Optional[str], states: Dict[str, dict], pol: Dict[str, Any]) -> Decision:
    """May a sandboxed command connect to `host`? `states` are the recently active sessions.

    The proxy cannot tell which session a connection comes from, so it is conservative: if any
    recent session is tainted, connections need a capability from some recent session or a
    global grant. `url` is only known for plain-HTTP requests (HTTPS is not decrypted).

    A host granted only by a prompt does not count if untrusted content was read *from* it:
    "summarise https://blog.example/post" lets the agent read that page, not send your files
    back to the site that wrote it. `llm-bouncer grant` overrides this.
    """
    eg = pol.get("egress") or {}
    host = _host(host)
    if any(fnmatch.fnmatchcase(host, _host(p)) for p in eg.get("always_deny") or []):
        return Decision(DENY, f"llm-bouncer: {host} is in egress.always_deny.", ["egress"])
    if any(fnmatch.fnmatchcase(host, _host(p)) for p in eg.get("always_allow") or []):
        return Decision(ALLOW)
    tainted: List[dict] = []
    strong, prompt = list(ledger.global_grants()), []
    for st in states.values():
        tainted += policy.session_status(st, pol)[1]
        strong += st.get("grants") or []
        prompt += st.get("prompt_grants") or []
    if not tainted:
        return Decision(ALLOW)
    if url and policy.looks_secret(url, pol):
        return Decision(DENY, f"llm-bouncer: request to {host} carries something that looks like a secret.",
                        ["egress", "secret_in_url"])
    if host_granted(host, strong):
        return Decision(ALLOW, risk=["egress", "granted"])
    untrusted_from = {h for v in tainted for h in v.get("hosts", [])}
    if host_granted(host, prompt) and host not in untrusted_from:
        return Decision(ALLOW, risk=["egress", "granted"])
    origins = ", ".join(dict.fromkeys(o for v in tainted for o in v.get("origins", [])[-2:]))
    why = " (it is also where the untrusted content came from)" if host in untrusted_from else ""
    return Decision(
        DENY,
        f"llm-bouncer: blocked a connection to {host}{why} after untrusted content ({origins[:200]}). "
        f"If you asked for it, run: llm-bouncer grant {host}",
        ["egress"],
    )


# ---------------------------------------------------------------- the hook gate

# Which grant kind lifts an "ask" for each risk, and where the call names what it touches.
_COVERS = {
    "sensitive_file_write": ("write", ("file_path", "notebook_path")),
    "secrets_read": ("read", ("file_path", "path", "notebook_path")),
    "mcp_external_action": ("mcp", ()),
    "mcp_tool_not_read_only": ("mcp", ()),
}


def _covered(tool: str, tool_input: Dict[str, Any], risks: List[str], grants: List[str]) -> bool:
    for r in risks:
        if r not in _COVERS:
            return False  # data in a URL, unlisted commands...: no grant makes those safe
        kind, keys = _COVERS[r]
        if kind == "mcp":
            if not tool_granted(tool, grants):
                return False
        else:
            target = next((str(tool_input[k]) for k in keys if tool_input.get(k)), "")
            if not target or not path_granted(target, grants, kind):
                return False
    return bool(risks)


def decide(event: dict, state: Dict[str, Any], pol: Dict[str, Any]) -> Decision:
    """Pre-tool-use decision under the effects model."""
    tool = str(event.get("tool_name", ""))
    ti = event.get("tool_input")
    if tool == "Bash" and gate_mode(event, pol) == EFFECTS:
        if "bouncer_tamper" in policy.classify(tool, ti, pol):
            return Decision(ASK, "llm-bouncer: touches llm-bouncer itself. Approve only if you asked.", ["bouncer_tamper"])
        # Runs in the sandbox: egress is decided by the proxy, writes by the sandbox and the
        # integrity snapshot. Nothing to predict from the command text.
        return Decision(ALLOW, risk=["sandboxed"])
    d = policy.decide_from_state(tool, ti, state, pol)
    if d.action == ASK and "bouncer_tamper" not in d.risk and \
            _covered(tool, ti if isinstance(ti, dict) else {}, d.risk, session_grants(state)):
        return Decision(ALLOW, risk=d.risk + ["granted"])
    return d
