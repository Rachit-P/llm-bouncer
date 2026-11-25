"""Commands for people (not hooks): review, grant, grants, setup, show.

Unlike the hooks, these fail loudly: a typo should be seen, not swallowed.
"""

from __future__ import annotations

import json
import sys
from typing import Callable, Dict, List, Optional, Tuple

from . import effects, ledger, policy


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


def review(args: List[str]) -> int:
    if len(args) != 1:
        return _usage("llm-bouncer review SESSION_ID  (see `llm-bouncer show` for session ids)")
    sid = args[0]
    state = ledger.read_state(sid)
    status, tainted = policy.session_status(state, policy.load_policy())
    if status != policy.TAINTED:
        print(f"{sid}: {status}, nothing to review")
        return 0
    for stype, v in state["sources"].items():
        if any(v is t for t in tainted):
            print(f"  {stype}: {v.get('count')} item(s), e.g. {', '.join(v.get('origins', []))}")
    ledger.record_review(sid)
    print(f"{sid}: marked reviewed. Content read from now on taints the session again.")
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
        print(f"granted for session {session}: {', '.join(targets)}")
        return 0
    try:
        hours = float(hours_s) if hours_s is not None else float((policy.load_policy().get("egress") or {}).get("grant_hours", 8))
    except ValueError:
        return _usage(usage)
    if hours <= 0:
        return _usage(usage)
    ledger.add_global_grants(targets, hours)
    print(f"granted for {hours:g} hours: {', '.join(targets)}")
    return 0


def grants(args: List[str]) -> int:
    for g in ledger.global_grants():
        print(f"global   {g}")
    if args:
        state = ledger.read_state(args[0])
        for g in state.get("grants") or []:
            print(f"session  {g}")
        for g in state.get("prompt_grants") or []:
            print(f"prompt   {g}")
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
    return 0


def show(args: List[str]) -> int:
    if not args:
        for sid in ledger.sessions():
            print(sid)
        return 0
    for row in ledger.read_all(args[0]):
        print(json.dumps(row, ensure_ascii=False))
    return 0


COMMANDS: Dict[str, Callable[[List[str]], int]] = {
    "review": review, "grant": grant, "grants": grants, "setup": setup, "show": show,
}
