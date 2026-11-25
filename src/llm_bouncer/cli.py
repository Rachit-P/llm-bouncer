"""Commands for people (not hooks): review, grant, grants, setup, show, doctor.

Unlike the hooks, these fail loudly: a typo should be seen, not swallowed.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

from . import effects, ledger, messages, policy
from .textnorm import one_line


def _usage(text: str) -> int:
    print(f"usage: {text}", file=sys.stderr)
    return 2


def _take(args: List[str], flag: str) -> Tuple[Optional[str], List[str], bool]:
    """Remove `flag VALUE` from args. Returns (value, rest, ok)."""
    if flag not in args:
        return None, args, True
    i = args.index(flag)
    if i + 1 >= len(args) or args[i + 1].startswith("--"):
        return None, args, False
    return args[i + 1], args[:i] + args[i + 2:], True


def _tainted_by_type(state: dict, pol: dict) -> List[Tuple[str, dict]]:
    _, tainted = policy.session_status(state, pol)
    return [(k, v) for k, v in (state.get("sources") or {}).items() if any(v is t for t in tainted)]


def _status(sid: str, pol: dict) -> Tuple[str, dict]:
    state = ledger.read_state(sid)
    status, _ = policy.session_status(state, pol)
    if ledger.is_dirty(sid):
        status = "tainted (lost writes)"  # counted as unknown content by the hooks
    return status, state


def review(args: List[str]) -> int:
    if len(args) != 1:
        return _usage("llm-bouncer review SESSION_ID  (see `llm-bouncer show` for session ids)")
    sid, pol = args[0], policy.load_policy()
    state = ledger.read_state(sid)
    status, _ = policy.session_status(state, pol)
    if status != policy.TAINTED:
        print(f"{sid}: {status}, nothing to review")
        return 0
    rows = [[stype, str(v.get("count", 0)), messages.origins([v])] for stype, v in _tainted_by_type(state, pol)]
    print(f"Untrusted content read in {sid}:\n")
    print(messages.table(["SOURCE", "ITEMS", "MOST RECENT"], rows))
    ledger.record_review(sid)
    print("\nMarked reviewed: this content no longer counts. Anything read from now on taints the session again.")
    return 0


def grant(args: List[str]) -> int:
    usage = "llm-bouncer grant TARGET... [--session SESSION_ID] [--hours N]\n" \
            "  TARGET: a host (pypi.org, *.npmjs.org, a URL), write:PATH, read:PATH or mcp:TOOL"
    session, args, ok1 = _take(args, "--session")
    hours_s, args, ok2 = _take(args, "--hours")
    if not (ok1 and ok2) or not args or any(a.startswith("--") for a in args):
        return _usage(usage)
    targets = []
    for a in args:
        t = effects.normalize_target(a)
        if t is None:
            print(f"llm-bouncer grant: not a host, URL, write:, read: or mcp: target: {a!r}", file=sys.stderr)
            return 2
        targets.append(t)
    if session:
        ledger.record_grants(session, targets, "cli")
        print(f"Granted until session {session} ends: {', '.join(targets)}")
        return 0
    try:
        hours = float(hours_s) if hours_s is not None else float((policy.load_policy().get("egress") or {}).get("grant_hours", 8))
    except ValueError:
        return _usage(usage)
    if hours <= 0:
        return _usage(usage)
    ledger.add_global_grants(targets, hours)
    until = time.strftime("%H:%M", time.localtime(time.time() + hours * 3600))
    print(f"Granted to all sessions for {hours:g} hours (until {until}): {', '.join(targets)}")
    return 0


def _by_kind(targets: List[str]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for t in targets:
        kind, _, value = t.partition(":")
        out.setdefault(kind, []).append(value)
    return out


def grants(args: List[str]) -> int:
    """Active grants, one row per scope and kind, so a long prompt grant stays readable."""
    now = time.time()
    rows = []
    for g in sorted(ledger.global_grant_rows(now), key=lambda g: g["expires"]):
        kind, _, value = g["target"].partition(":")
        rows.append(["global", kind, f"expires {messages.until(g['expires'] - now)}", value])
    if args:
        state = ledger.read_state(args[0])
        for kind, values in _by_kind(state.get("grants") or []).items():
            rows.append(["session", kind, "until the session ends", ", ".join(values)])
        for kind, values in _by_kind(state.get("prompt_grants") or []).items():
            note = "from your prompt; not for a host the session read from" if kind == "egress" else "from your prompt"
            rows.append(["prompt", kind, note, ", ".join(values)])
    if not rows:
        print("No active grants." + ("" if args else " Pass a session id to include its grants."))
        return 0
    print(messages.table(["SCOPE", "KIND", "VALID", "TARGETS"], rows))
    return 0


def setup(args: List[str]) -> int:
    port = effects.proxy_port(policy.load_policy())
    settings = {
        "sandbox": {
            "enabled": True,
            "network": {"httpProxyPort": port, "socksProxyPort": port + 1},
            # Sandboxed commands may read most of the machine by default; keep credentials out,
            # and keep llm-bouncer's own state out of reach even if the project is your home folder.
            "filesystem": {
                "denyRead": ["~/.ssh", "~/.aws", "~/.config/gcloud", "~/.netrc", "~/.git-credentials"],
                "denyWrite": [str(ledger.ledger_dir())],
            },
        }
    }
    print("Add this to ~/.claude/settings.json (merge with your existing \"sandbox\" and \"hooks\" keys):\n")
    print(json.dumps(settings, indent=2))
    print("\nThe hooks start the proxy when needed; or run `llm-bouncer proxy` yourself.")
    print("Sandboxed Bash calls then run without command rules; llm-bouncer decides their network and file effects.")
    print("Both proxy ports must point at llm-bouncer, or Bash falls back to the command rules.")
    print("Then run `llm-bouncer doctor` in your project to check that the effects gate is on.")
    return 0


def _sessions_table(show_all: bool) -> int:
    pol, now = policy.load_policy(), time.time()
    sids = sorted(ledger.sessions(), key=ledger.last_active, reverse=True)
    shown = sids if show_all else sids[:20]
    rows = []
    for sid in shown:
        status, state = _status(sid, pol)
        read = ", ".join(f"{k} {v.get('count', 0)}" for k, v in _tainted_by_type(state, pol)) or "-"
        actions = [d.get("action") for d in ledger.read_decisions(sid) if d.get("mode") != "monitor"]
        rows.append([sid, status, messages.ago(now - ledger.last_active(sid)), read,
                     str(actions.count(policy.ASK)), str(actions.count(policy.DENY))])
    if not rows:
        print("No sessions yet.")
        return 0
    print(messages.table(["SESSION", "STATE", "LAST ACTIVE", "UNTRUSTED READ", "ASKED", "BLOCKED"], rows))
    if len(sids) > len(shown):
        print(f"\n{len(sids) - len(shown)} older sessions hidden; `llm-bouncer show --all` lists them.")
    print("\n`llm-bouncer show SESSION_ID` shows one session's timeline.")
    return 0


def _event(row: dict) -> Tuple[str, str]:
    """(event, detail) for one ledger or decision row."""
    if row.get("event") == "review":
        return "review", "you marked everything so far as reviewed"
    if row.get("event") == "grant":
        parts = []
        for kind, values in _by_kind(row.get("grants") or []).items():
            parts.append(f"{kind} {', '.join(values[:3])}" + (f" +{len(values) - 3} more" if len(values) > 3 else ""))
        src = "your prompt" if row.get("source") == "prompt" else "llm-bouncer grant"
        return "grant", f"{'; '.join(parts)} (from {src})"
    if "action" in row and "source_type" not in row:
        risk = row.get("risk") or []
        mode = " (monitor only)" if row.get("mode") == "monitor" else ""
        what = messages.risk_phrase(risk) if risk else "could not be checked"
        return str(row.get("action")).upper() + mode, f"{row.get('tool_name')} {what}"
    if row.get("source_type") == "user_typed":
        return "prompt", "you"
    extras = []
    if row.get("flags"):
        extras.append("hidden: " + ", ".join(messages.FLAGS.get(f, f) for f in row["flags"]))
    if row.get("hints"):
        extras.append(messages.count(len(row["hints"]), "instruction-like sentence"))
    taint = "untrusted" if row.get("taints") else "read"
    detail = f"{row.get('source_type')}  {one_line(row.get('origin', '?'), 70)}"
    return taint, detail + (f"  [{'; '.join(extras)}]" if extras else "")


def _timeline(sid: str, show_all: bool) -> int:
    pol = policy.load_policy()
    rows = ledger.read_all(sid) + ledger.read_decisions(sid)
    if not rows:
        print(f"No ledger for session {sid!r}. `llm-bouncer show` lists sessions.")
        return 1
    rows.sort(key=lambda r: float(r.get("ts") or 0))
    status, state = _status(sid, pol)
    print(f"Session {sid}: {status}, last active {messages.ago(time.time() - ledger.last_active(sid))}")
    for stype, v in _tainted_by_type(state, pol):
        print(f"  untrusted {stype}: {v.get('count', 0)} item(s), most recent {messages.origins([v])}")
    print()
    shown = rows if show_all else rows[-50:]
    table = []
    for r in shown:
        event, detail = _event(r)
        ts = float(r.get("ts") or 0)
        table.append([time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "-", str(r.get("turn", "")), event, detail])
    print(messages.table(["TIME", "TURN", "EVENT", "DETAIL"], table))
    if state.get("grants") or state.get("prompt_grants"):
        print(f"\n`llm-bouncer grants {sid}` lists every grant in full.")
    if len(rows) > len(shown):
        print(f"\n{len(rows) - len(shown)} earlier events hidden; add --all to see them, or --json for raw rows.")
    return 0


def show(args: List[str]) -> int:
    as_json, show_all = "--json" in args, "--all" in args
    args = [a for a in args if a not in ("--json", "--all")]
    if len(args) > 1 or any(a.startswith("--") for a in args):
        return _usage("llm-bouncer show [SESSION_ID] [--all] [--json]")
    if not args:
        if as_json:
            for sid in ledger.sessions():
                print(sid)
            return 0
        return _sessions_table(show_all)
    if as_json:
        for row in ledger.read_all(args[0]):
            print(json.dumps(row, ensure_ascii=False))
        return 0
    return _timeline(args[0], show_all)


def doctor(args: List[str]) -> int:
    """Explain, check by check, whether the effects gate is on for this project."""
    cwd = os.getcwd()
    ok = True
    try:
        pol = policy.load_policy()
        print(f"✓ policy loads ({policy._policy_path() or 'built-in default'})")
    except policy.PolicyError as exc:
        print(f"✗ policy does not load: {exc}")
        return 1
    print(f"  project root: {effects.project_root(cwd)}")
    print(f"  ledger: {ledger.ledger_dir()}")
    problems = effects.sandbox_problems(cwd, pol)
    if problems:
        ok = False
        print("✗ effects gate is off: sandboxed Bash uses the command rules (more approval prompts)")
        for problem, fix in problems:
            print(f"    - {problem}\n      fix: {fix}")
    else:
        print("✓ effects gate is on: sandboxed Bash is judged by what it reaches and writes")
    port = effects.proxy_port(pol)
    from . import proxy

    if proxy.is_running(port):
        print(f"✓ egress proxy is listening on 127.0.0.1:{port} (SOCKS {port + 1})")
    elif problems:
        print("  egress proxy is not running (not needed while the effects gate is off)")
    else:
        print("  egress proxy is not running; the hooks start it on your next prompt, or run `llm-bouncer proxy`")
    n = len(ledger.global_grant_rows())
    print(f"  {messages.count(n, 'global grant')} active" + ("; `llm-bouncer grants` lists them" if n else ""))
    return 0 if ok else 1


COMMANDS: Dict[str, Callable[[List[str]], int]] = {
    "review": review, "grant": grant, "grants": grants, "setup": setup, "show": show, "doctor": doctor,
}
