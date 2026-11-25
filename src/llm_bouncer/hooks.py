"""Claude Code hook entry points.

Claude Code runs a hook as a command, passes JSON on stdin, and reads JSON from stdout.

    llm-bouncer post-tool-use     # PostToolUse: label what a tool just returned
    llm-bouncer user-prompt       # UserPromptSubmit: label the developer's prompt
    llm-bouncer pre-tool-use      # PreToolUse: allow, ask or deny the next tool call
    llm-bouncer show [SESSION_ID] [--all] [--json]  # sessions table, or one session's timeline
    llm-bouncer doctor            # is the effects gate on here? what to fix if not
    llm-bouncer review SESSION_ID # you checked the session: content read so far stops tainting it
    llm-bouncer grant TARGET... [--session ID] [--hours N]  # allow an effect after untrusted content
                                  # TARGET: a host (pypi.org, *.npmjs.org), write:PATH, read:PATH, mcp:TOOL
    llm-bouncer grants [SESSION_ID]   # list active grants
    llm-bouncer proxy [--port N]  # the egress proxy for Claude Code's sandbox (see `setup`)
    llm-bouncer setup             # print the sandbox settings that turn on the effects gate
    llm-bouncer eval [PATH] [--policy FILE] [--json] [--check]  # score the gate on attack/harmless scenarios

Set LLM_BOUNCER_MODE=monitor to log pre-tool-use decisions without enforcing them.

If pre-tool-use itself fails (bad policy file, unreadable ledger), it answers "ask" rather than
staying silent, because silence lets the call through. Set LLM_BOUNCER_FAIL_OPEN=1 to stay silent.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import effects, indicators, integrity, ledger, messages, policy
from .labels import Label, SourceType, digest, source_for_tool, trust_for
from .scan import scan_text
from .textnorm import one_line

_TEXT_KEYS = ("content", "output", "stdout", "result", "text", "stderr", "data")
# Hints are advisory and only worth computing (and showing) for content from outside the project.
_HINT_SOURCES = {SourceType.WEB, SourceType.MCP, SourceType.TOOL, SourceType.USER_PASTED}


# ---------------------------------------------------------------- labelling


def _walk(value: Any) -> Iterator[str]:
    # Iterative, not recursive: a malicious MCP server could nest a result thousands of levels
    # deep to crash a recursive walk, and a crashed labeller recorded nothing.
    stack = [value]
    while stack:
        v = stack.pop()
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, str):
            if v:
                yield v
        elif isinstance(v, dict):
            # the usual text keys first, then everything else: attacker text can sit in any field
            keys = [k for k in _TEXT_KEYS if k in v] + [k for k in v if k not in _TEXT_KEYS]
            stack.extend(v[k] for k in reversed(keys))
        elif isinstance(v, (list, tuple)):
            stack.extend(reversed(v))
        else:
            yield str(v)


def _flatten(value: Any) -> str:
    """Every piece of text in a tool_response of unknown shape."""
    return "\n".join(_walk(value))


def _origin(tool_name: str, tool_input: Any) -> str:
    if not isinstance(tool_input, dict):
        return tool_name
    for key in ("url", "file_path", "path", "command", "pattern", "query"):
        if tool_input.get(key):
            return str(tool_input[key])[:300]
    return tool_name


def _label(event: dict, source: SourceType, origin: str, tool_name: Optional[str], text: str) -> Label:
    trust = trust_for(source)
    flags, hints = scan_text(text, hints=source in _HINT_SOURCES)
    return Label(
        session_id=str(event.get("session_id", "unknown")),
        turn=0,  # set by ledger.record under the session lock
        source_type=source.value,
        trust=trust.value,
        origin=origin,
        tool_name=tool_name,
        chars=len(text),
        sha256=digest(text),
        flags=flags,
        hints=hints,
        indicators=indicators.extract(text) if trust.value == "untrusted" else {},
    )


def label_tool_result(event: dict) -> Label:
    tool_name = str(event.get("tool_name", ""))
    text = _flatten(event.get("tool_response"))
    return _label(event, source_for_tool(tool_name), _origin(tool_name, event.get("tool_input")), tool_name, text)


def label_user_prompt(event: dict) -> Label:
    return _label(event, SourceType.USER_TYPED, "prompt", None, str(event.get("prompt", "")))


def build_note(label: Label, first_of_source: bool = True, tainting: Optional[bool] = None) -> str:
    """Short note for the model, or "" when there is nothing worth the tokens.

    * The "untrusted" reminder is sent once per source type per session, and only for sources that
      taint the session (web, MCP, ...). Earlier versions sent ~50 tokens after every Read, Grep and
      Bash call, which in a normal session is most calls.
    * Hidden-content flags are always reported; instruction-like hints only for tainting sources.
    * Untrusted text is never quoted: the note reaches the model through the hook channel, so
      quoting the page there would give the attacker's words more authority.
    """
    if tainting is None:
        tainting = label.source_type in {s.value for s in _HINT_SOURCES}
    parts: List[str] = []
    if label.trust == "untrusted" and tainting and first_of_source:
        parts.append(messages.untrusted_note(label.source_type, label.origin))
    if label.flags:
        parts.append(messages.hidden_note("It" if parts else label.origin, label.flags))
    if label.hints and tainting:
        parts.append(messages.hints_note(label.hints))
    return messages.note(parts)


# ---------------------------------------------------------------- gate


_RESULT = re.compile(rb'"tool_result"')


def _earlier_results(event: dict) -> int:
    """How many tool results Claude Code's transcript holds, not counting this call's own.

    Strings inside the transcript are JSON-escaped, so page text that says "tool_result" cannot
    inflate the count.
    """
    path = event.get("transcript_path")
    if not path:
        return 0
    try:
        with open(os.path.expanduser(str(path)), "rb") as fh:
            data = fh.read()
    except OSError:
        return 0
    n = len(_RESULT.findall(data))
    own = event.get("tool_use_id")
    if own and re.search(rb'"tool_use_id"\s*:\s*"' + re.escape(str(own).encode()) + rb'"', data):
        n -= 1
    return n


def _check_ledger_vanished(event: dict, in_flight: int = 0) -> None:
    """Make "the ledger was deleted" a permanent part of the session.

    If the ledger is empty but the transcript shows earlier tool results, the record of what the
    agent read is gone: deleted (e.g. `find ~ -path '*bouncer*' -delete`) or pruned after a long
    pause. Before, this was only re-derived while the ledger stayed empty, so the first harmless
    call after the deletion wrote a row and wiped the suspicion. Now a tainting row is written.

    `in_flight` is how many results may belong to the current call when its tool_use_id is not
    known (PostToolUse: 1).
    """
    sid = str(event.get("session_id", "unknown"))
    if ledger.read_state(sid)["turn"] != 0:
        return
    if _earlier_results(event) > (0 if event.get("tool_use_id") else in_flight):
        ledger.record(_tamper_label(sid), taints=True)


def _tamper_label(sid: str) -> Label:
    return Label(session_id=sid, turn=0, source_type=SourceType.UNKNOWN.value, trust="untrusted",
                 origin="ledger missing for a session with earlier tool calls", tool_name=None,
                 chars=0, sha256="", flags=["ledger_missing"])


def session_state(event: dict) -> dict:
    """The session summary every gate decision is made from.

    Includes what the summary alone does not show: a deleted ledger (recorded first), a label that
    could not be saved, and echo hashes moved to the overflow file. Used for the decision and for
    the integrity snapshot alike, so they can never disagree about whether the session is tainted.
    """
    sid = str(event.get("session_id", "unknown"))
    _check_ledger_vanished(event)
    state = ledger.read_state(sid, persist=True)
    if ledger.is_dirty(sid):  # a label was lost: the session cannot be shown to be clean
        state["sources"].setdefault("unknown", {"count": 1, "origins": ["a label that could not be saved"]})
    overflow = ledger.overflow_hashes(sid) if state["sources"] else {}
    for stype, kinds in overflow.items():
        src = state["sources"].get(stype)
        if src:
            src["url_h"] = list(src.get("url_h", [])) + list(kinds["u"])
            src["email_h"] = list(src.get("email_h", [])) + list(kinds["e"])
    return state


def decide_tool_call(event: dict, state: Optional[dict] = None) -> policy.Decision:
    return effects.decide(event, session_state(event) if state is None else state, policy.load_policy())


def _emit_decision(decision: policy.Decision) -> None:
    # Only speak up for ask/deny. Emitting "allow" would skip Claude Code's own permission checks.
    if decision.action in (policy.ASK, policy.DENY):
        _write(
            {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.action,
                "permissionDecisionReason": decision.reason,
            }
        )


# ---------------------------------------------------------------- io


def _write(hook_output: dict, user_message: str = "") -> None:
    out: Dict[str, Any] = {"hookSpecificOutput": hook_output}
    if user_message:
        out["systemMessage"] = user_message  # shown to the developer, not the model
    json.dump(out, sys.stdout, ensure_ascii=False, separators=(",", ":"))


def _emit(event_name: str, note: str, user_message: str = "") -> None:
    if note or user_message:
        out: Dict[str, Any] = {"hookEventName": event_name}
        if note:
            out["additionalContext"] = note
        _write(out, user_message)


def _read_event(raw: Optional[str] = None) -> dict:
    raw = sys.stdin.read() if raw is None else raw
    event = json.loads(raw) if raw.strip() else {}
    if not isinstance(event, dict):
        raise ValueError("hook input must be a JSON object")
    return event


def _field(raw: str, name: str) -> str:
    import re

    m = re.search(r'"%s"\s*:\s*"([^"\\]{1,200})"' % name, raw)
    return m.group(1) if m else "unknown"


def _fail_closed_label(raw: str, exc: BaseException) -> Label:
    """A row that taints the session when the real label could not be made.

    Before, a labelling crash (malformed or deeply nested input) recorded nothing, so the session
    looked clean: the attacker's text was read but never counted.
    """
    tool = _field(raw, "tool_name")
    return Label(
        session_id=_field(raw, "session_id"),
        turn=0,
        source_type=SourceType.UNKNOWN.value,
        trust="untrusted",
        origin=tool,
        tool_name=tool,
        chars=len(raw),
        sha256=digest(raw),
        flags=["label_error"],
        hints=[{"reason": "label_error", "text": one_line(type(exc).__name__, 60), "start": 0, "end": 0}],
    )


# ---------------------------------------------------------------- commands


def _taints(label: Label) -> bool:
    if label.source_type == SourceType.UNKNOWN.value:
        return True
    try:
        return label.source_type in set(policy.load_policy().get("taint_sources") or [])
    except Exception:  # a broken policy must not lose the label; untrusted content taints
        return label.trust == "untrusted" and label.source_type != SourceType.INTERNAL.value


def _save(label: Label) -> tuple:
    """Record a label; if that fails, leave a marker so the session fails closed."""
    tainting = _taints(label)
    try:
        label, _, first = ledger.record(label, taints=tainting)
    except BaseException:
        ledger.mark_dirty(label.session_id)
        raise
    return label, first, tainting


def _cmd_post_tool_use(args: List[str]) -> int:
    raw = sys.stdin.read()
    error: Optional[BaseException] = None
    try:
        event = _read_event(raw)
        label = label_tool_result(event)
    except (Exception, RecursionError) as exc:
        event, label, error = {}, _fail_closed_label(raw, exc), exc
    if event:
        try:
            _check_ledger_vanished(event, in_flight=1)
        except OSError:
            ledger.mark_dirty(label.session_id)
    label, first, tainting = _save(label)
    if error is not None:
        raise error
    note, user = build_note(label, first_of_source=first, tainting=tainting), ""
    if event.get("tool_name") == "Bash":
        extra, user = _after_sandboxed_bash(event)
        note = " ".join(p for p in (note, extra.replace(messages.NOTE + " ", "", 1) if note else extra) if p)
    _emit("PostToolUse", note, user)
    return 0


def _after_sandboxed_bash(event: dict) -> Tuple[str, str]:
    """Revert unapproved integrity changes and report blocked connections (effects gate).

    Returns (note for the agent, message for the user). The user hears it directly, so a revert
    or a block is never known only to the agent.
    """
    sid = str(event.get("session_id", "unknown"))
    pol = policy.load_policy()
    grants = effects.session_grants(ledger.read_state(sid))
    reverted, stuck, since = integrity.check_and_revert(
        sid, event.get("tool_use_id"), lambda rel: effects.path_granted(rel, grants, "write"), pol.get("integrity_paths") or [])
    if not since:
        return "", ""
    blocked = _blocked_hosts(since)
    return messages.after_bash_note(reverted, stuck, blocked), messages.after_bash_user(reverted, stuck, blocked, sid)


def _blocked_hosts(since: float) -> List[str]:
    path = ledger.ledger_dir() / "egress.log"
    try:
        with path.open("rb") as fh:
            fh.seek(max(0, path.stat().st_size - 256 * 1024))
            tail = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    hosts: List[str] = []
    for line in tail:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("action") == "deny" and float(row.get("ts", 0)) >= since and row.get("host") not in hosts:
            hosts.append(str(row.get("host")))
    return hosts


def _cmd_user_prompt(args: List[str]) -> int:
    event = _read_event()
    _check_ledger_vanished(event)
    label, _, _ = _save(label_user_prompt(event))
    pol = policy.load_policy()
    if not label.flags:  # a prompt with hidden content may be pasted attacker text: it grants nothing
        grants = effects.grants_from_prompt(str(event.get("prompt", "")), pol, event.get("cwd"))
        if grants:
            ledger.record_grants(label.session_id, grants, "prompt")
    _ensure_proxy(event, pol)
    _emit("UserPromptSubmit", build_note(label))
    return 0


def _ensure_proxy(event: dict, pol: dict) -> None:
    """Start the egress proxy if the sandbox is set to use it and nothing is listening.

    Without it, sandboxed commands simply cannot connect anywhere (fail closed), so this is about
    usability, not safety. Called on each prompt and before each sandboxed command.
    """
    if not effects.proxy_configured(event.get("cwd"), pol):
        return
    port = effects.proxy_port(pol)
    from . import proxy  # asyncio is only imported when the effects gate is configured

    if proxy.is_running(port):
        return
    import subprocess

    subprocess.Popen([sys.executable, "-m", "llm_bouncer.hooks", "proxy", "--port", str(port)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def _cmd_pre_tool_use(args: List[str]) -> int:
    event = _read_event()
    state = session_state(event)
    decision = decide_tool_call(event, state)
    mode = os.environ.get("LLM_BOUNCER_MODE", "enforce")
    if decision.risk == ["sandboxed"]:
        pol = policy.load_policy()
        _ensure_proxy(event, pol)
        if policy.session_status(state, pol)[0] == policy.TAINTED:
            integrity.snapshot(str(event.get("session_id", "unknown")), event.get("tool_use_id"),
                               effects.project_root(event.get("cwd")), pol.get("integrity_paths") or [])
    elif decision.action != policy.ALLOW or decision.risk:
        ledger.append_decision(
            str(event.get("session_id", "unknown")),
            {
                "ts": time.time(),
                "mode": mode,
                "tool_name": event.get("tool_name"),
                "action": decision.action,
                "risk": decision.risk,
                "echoes": decision.echoes,
                "reason": decision.reason,
            },
        )
    if mode != "monitor":
        _emit_decision(decision)
    return 0


_HOOKS: Dict[str, Callable[[List[str]], int]] = {
    "post-tool-use": _cmd_post_tool_use,
    "user-prompt": _cmd_user_prompt,
    "pre-tool-use": _cmd_pre_tool_use,
}


def main(argv: Optional[list] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else ""
    if cmd == "eval":  # outside the try: eval failures must fail loudly (CI), unlike the hooks
        from .evals import runner

        return runner.main(args[1:])
    from . import cli

    if cmd in cli.COMMANDS:  # commands for people: errors should be seen, not swallowed
        return cli.COMMANDS[cmd](args[1:])
    if cmd == "proxy":
        from . import proxy

        return proxy.main(args[1:])
    handler = _HOOKS.get(cmd)
    if handler is None:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        return handler(args[1:])
    except Exception as exc:
        print(f"llm-bouncer: {exc}", file=sys.stderr)
        # A labelling failure must never break the agent. A gate failure must not wave the call
        # through either: ask the developer instead (unless they opted out).
        if (
            cmd == "pre-tool-use"
            and os.environ.get("LLM_BOUNCER_MODE", "enforce") != "monitor"
            and os.environ.get("LLM_BOUNCER_FAIL_OPEN") != "1"
        ):
            _emit_decision(policy.Decision(policy.ASK, messages.gate_error(exc)))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
