"""Per-session storage.

Two files per session, in ~/.llm-bouncer/sessions/ (or $LLM_BOUNCER_DIR):

* ``<session>.jsonl``: append-only audit log, one label per line. Never read on the hot path.
* ``<session>.state.json``: a small summary the hooks actually use: turn counter, and per source
  type the count, last turn, last origins and the indicators seen. Reading it costs the same on
  turn 5 and turn 5,000, unlike re-reading the whole log on every tool call.
* ``<session>.hashes``: URL/email hashes pushed out of the summary by its size cap. Append-only and
  read only for echo checks, so flooding a session with decoys cannot make it forget the payload.
* ``<session>.dirty``: an empty marker meaning "a label could not be saved". It taints the
  session until the next successful write turns it into a ledger row.

The session's states (clean, tainted, reviewed) are described in docs/state-machines.md.

Writes take a per-session lock, because Claude Code runs hooks for parallel tool calls at the same
time. Files are created private (0600) since they hold URLs and commands the agent saw.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # Windows: no advisory locks; writes are still single os.write calls
    fcntl = None

from .labels import Label
from .textnorm import key_hash, norm, url_key

STATE_VERSION = 2  # 2: per-source last_turn, stamped taint, review rows
MAX_ORIGINS = 3
MAX_COMMANDS = 5000  # per source type; the oldest are dropped first
MAX_READABLE = 50  # recent URLs/emails kept as text, for `show` and reasons
MAX_HASHES = 20_000  # URL/email key hashes per kind and source type kept in the summary; older ones
# move to the append-only <session>.hashes file instead of being forgotten
_KINDS = ("commands", "urls", "emails")


# ---------------------------------------------------------------- paths


def ledger_dir(cwd: str | None = None) -> Path:
    """Where ledgers live. Keyed by session only, never by the working directory.

    `cwd` is accepted for backwards compatibility and ignored.
    """
    override = os.environ.get("LLM_BOUNCER_DIR")
    if override:
        return Path(override)
    return Path.home() / ".llm-bouncer" / "sessions"


def _safe(session_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:100] or "unknown"
    if safe != session_id:
        # "a/b" and "a_b" must not share a file
        safe += "-" + hashlib.sha256(session_id.encode("utf-8", "replace")).hexdigest()[:10]
    return safe


def ledger_path(session_id: str, cwd: str | None = None) -> Path:
    return ledger_dir() / f"{_safe(session_id)}.jsonl"


def _state_path(session_id: str) -> Path:
    return ledger_dir() / f"{_safe(session_id)}.state.json"


def _hashes_path(session_id: str) -> Path:
    return ledger_dir() / f"{_safe(session_id)}.hashes"


def _dirty_path(session_id: str) -> Path:
    return ledger_dir() / f"{_safe(session_id)}.dirty"


def _decisions_path(session_id: str) -> Path:
    return ledger_dir() / f"{_safe(session_id)}.decisions.jsonl"


def _ensure_dir() -> Path:
    d = ledger_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


# ---------------------------------------------------------------- low-level io


def _ends_mid_line(path: Path) -> bool:
    """True if the file's last write was cut off before its newline (a crash or a full disk)."""
    try:
        with path.open("rb") as fh:
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) != b"\n"
    except OSError:  # missing or empty
        return False


def _append_line(path: Path, obj: dict, newline_first: bool = False) -> None:
    # One os.write on an O_APPEND fd: parallel hooks cannot interleave half-lines,
    # which buffered file writes over 8 KB could. newline_first closes a torn last line so it
    # does not swallow this row too.
    data = (("\n" if newline_first else "") + json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _write_atomic(path: Path, obj: dict) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)  # readers see the old state or the new one, never half of it


@contextmanager
def _locked(session_id: str) -> Iterator[None]:
    _ensure_dir()
    if fcntl is None:
        yield
        return
    path = ledger_dir() / f"{_safe(session_id)}.lock"
    while True:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        # If prune() unlinked the lock file while we waited, we hold a lock on a file nobody else
        # will open: a second hook would create a new one and both would write at once. Retry
        # until the locked file is the one at the path.
        try:
            same = os.fstat(fd).st_ino == os.stat(path).st_ino
        except FileNotFoundError:
            same = False
        if same:
            break
        os.close(fd)
    try:
        yield
    finally:
        os.close(fd)  # closing releases the lock


# ---------------------------------------------------------------- state


def empty_state() -> dict:
    # taints: source types that tainted the session under the policy in force when they were
    # read. Kept so that later removing a source from taint_sources cannot un-taint old sessions.
    # reviewed_turn: the developer marked everything up to this turn as reviewed (`review`).
    return {"v": STATE_VERSION, "turn": 0, "sources": {}, "taints": [], "reviewed_turn": 0}


def _fold(state: dict, row: dict, evicted: Optional[List[str]] = None) -> None:
    """Add one ledger row to a state summary.

    Hashes pushed out by the cap are added to `evicted` as "<source> <u|e> <hash>" lines.
    """
    turn = int(row.get("turn") or 0)
    state["turn"] = max(int(state.get("turn", 0)), turn)
    if row.get("event") == "review":
        state["reviewed_turn"] = max(int(state.get("reviewed_turn", 0)), turn)
        return
    stype = str(row.get("source_type"))
    if row.get("taints") and stype not in state["taints"]:
        state["taints"].append(stype)
    src = state["sources"].setdefault(stype, {"count": 0, "origins": []})
    src["count"] += 1
    src["last_turn"] = max(int(src.get("last_turn", 0)), turn)
    origin = str(row.get("origin", "?"))
    origins = [o for o in src["origins"] if o != origin] + [origin]
    src["origins"] = origins[-MAX_ORIGINS:]
    for kind, items in (row.get("indicators") or {}).items():
        if kind not in _KINDS:
            continue
        # Keep the most recent, de-duplicated. The old cap (first 200 kept, later ones dropped)
        # let a page fill the list with decoys so the real payload was never stored.
        cap = MAX_COMMANDS if kind == "commands" else MAX_READABLE
        src[kind] = _recent(src.get(kind, []), items, cap)
        if kind != "commands":
            # Every URL and email is kept as a short hash, so decoys cannot push the payload out.
            keyf = url_key if kind == "urls" else norm
            dropped = [] if evicted is not None else None
            src[kind[:-1] + "_h"] = _recent(src.get(kind[:-1] + "_h", []), [key_hash(keyf(i)) for i in items], MAX_HASHES, dropped)
            if dropped:
                evicted.extend(f"{stype} {kind[0]} {h}" for h in dropped)


def _recent(have: List[str], new: List[str], cap: int, dropped: Optional[List[str]] = None) -> List[str]:
    d = dict.fromkeys(have)
    for item in new:
        d.pop(item, None)
        d[item] = None
    out = list(d)
    if dropped is not None and len(out) > cap:
        dropped.extend(out[:-cap])
    return out[-cap:]


def state_from_rows(rows: List[dict]) -> dict:
    # Rebuilding never writes the overflow file: hashes evicted here were already saved there
    # when their rows were first recorded.
    state = empty_state()
    for row in rows:
        _fold(state, row)
    return state


def overflow_hashes(session_id: str) -> Dict[str, Dict[str, set]]:
    """Hashes evicted from the summary, by source type: {"web": {"u": {...}, "e": {...}}}."""
    out: Dict[str, Dict[str, set]] = {}
    try:
        with _hashes_path(session_id).open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 3 and parts[1] in ("u", "e"):
                    out.setdefault(parts[0], {"u": set(), "e": set()})[parts[1]].add(parts[2])
    except OSError:
        pass
    return out


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def read_state(session_id: str, cwd: str | None = None, persist: bool = False) -> dict:
    """The session summary. Rebuilt from the log if it is missing or damaged.

    With persist=True a rebuilt summary is saved, so the next hook does not re-read the whole log
    again. Callers already holding the session lock must leave it False (flock is per open file).
    """
    path = _state_path(session_id)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if (
            isinstance(state, dict)
            and state.get("v") == STATE_VERSION
            and isinstance(state.get("sources"), dict)
            # The summary must describe the log as it is now. If a hook died between appending a
            # row and saving the summary (or the log was edited), the summary is stale: rebuild.
            and state.get("ledger_bytes") == _size(ledger_path(session_id))
        ):
            return state
    except FileNotFoundError:
        if not ledger_path(session_id).exists():
            return empty_state()
    except (OSError, ValueError):
        pass
    state = state_from_rows(read_all(session_id))
    state["ledger_bytes"] = _size(ledger_path(session_id))
    if persist:
        try:
            with _locked(session_id):
                # Save only if no hook appended in the meantime; otherwise its own save wins.
                if state["ledger_bytes"] == _size(ledger_path(session_id)):
                    _write_atomic(_state_path(session_id), state)
        except OSError:
            pass  # saving the summary is an optimisation only
    return state


def is_dirty(session_id: str) -> bool:
    return _dirty_path(session_id).exists() or _fallback_dirty_path(session_id).exists()


def _fallback_dirty_path(session_id: str) -> Path:
    import tempfile

    uid = os.getuid() if hasattr(os, "getuid") else 0
    return Path(tempfile.gettempdir()) / f"llm-bouncer-{uid}-{_safe(session_id)}.dirty"


def mark_dirty(session_id: str) -> bool:
    """Record that a label was lost, so the session fails closed. True if a marker was written.

    Creating an empty file usually still works when appending to the ledger does not (a full
    disk); if the ledger folder itself is unusable, the system temp folder is tried.
    """
    for path in (_dirty_path(session_id), _fallback_dirty_path(session_id)):
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
            return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------- public api


def _add_row(session_id: str, state: dict, row: dict, evicted: List[str]) -> None:
    log = ledger_path(session_id)
    _append_line(log, row, newline_first=_ends_mid_line(log))
    _fold(state, row, evicted)


def record(label: Label, cwd: str | None = None, taints: Optional[bool] = None) -> Tuple[Label, dict, bool]:
    """Append a label and update the state, atomically per session.

    `taints` stamps whether the current policy counts this source as tainting, so the session
    stays tainted even if the policy later changes. Returns (label with its turn set, new state,
    whether this is the session's first label from this source type).
    """
    sid = label.session_id
    with _locked(sid):
        state = read_state(sid)
        new_session = state["turn"] == 0 and not _state_path(sid).exists()
        evicted: List[str] = []
        dirty = [p for p in (_dirty_path(sid), _fallback_dirty_path(sid)) if p.exists()]
        if dirty:
            # An earlier label was lost: turn the marker into a permanent tainting row.
            state["turn"] = int(state["turn"]) + 1
            _add_row(sid, state, {"session_id": sid, "turn": state["turn"], "source_type": "unknown",
                                  "trust": "untrusted", "origin": "a label that could not be saved",
                                  "flags": ["write_error"], "taints": True, "ts": time.time()}, evicted)
        first_of_source = label.source_type not in state["sources"]
        label.turn = int(state["turn"]) + 1
        row = label.to_dict()
        if taints is not None:
            row["taints"] = bool(taints)
        _add_row(sid, state, row, evicted)
        if evicted:
            _append_text(_hashes_path(sid), "\n".join(evicted) + "\n")
        state["ledger_bytes"] = _size(ledger_path(sid))
        _write_atomic(_state_path(sid), state)
        for p in dirty:
            try:
                p.unlink()
            except OSError:
                pass
    if new_session:
        prune()
    return label, state, first_of_source


def record_review(session_id: str) -> dict:
    """The developer reviewed the session: content read so far no longer taints it.

    Anything tainting read after this point taints the session again. Written as a ledger row so
    a rebuilt summary keeps it.
    """
    with _locked(session_id):
        state = read_state(session_id)
        state["turn"] = int(state["turn"]) + 1
        _add_row(session_id, state, {"event": "review", "session_id": session_id, "turn": state["turn"], "ts": time.time()}, [])
        state["ledger_bytes"] = _size(ledger_path(session_id))
        _write_atomic(_state_path(session_id), state)
    return state


def _append_text(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def append(label: Label, cwd: str | None = None) -> Path:
    """Backwards-compatible wrapper around record()."""
    record(label)
    return ledger_path(label.session_id)


def read_all(session_id: str, cwd: str | None = None) -> List[dict]:
    path = ledger_path(session_id)
    if not path.exists():
        return []
    out = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue  # a torn or hand-edited line must not break the session
            if isinstance(row, dict):
                out.append(row)
    return out


def next_turn(session_id: str, cwd: str | None = None) -> int:
    return int(read_state(session_id)["turn"]) + 1


def append_decision(session_id: str, record_: dict, cwd: str | None = None) -> Path:
    """Decisions go to a separate file so the label log stays one-row-per-text."""
    _ensure_dir()
    path = _decisions_path(session_id)
    _append_line(path, record_)
    return path


def sessions() -> List[str]:
    d = ledger_dir()
    if not d.exists():
        return []
    return sorted(p.name[: -len(".jsonl")] for p in d.glob("*.jsonl") if not p.name.endswith(".decisions.jsonl"))


_OWN_FILE = re.compile(
    r"^(?:[A-Za-z0-9_.-]+\.(?:jsonl|decisions\.jsonl|state\.json|lock|hashes|dirty)"
    r"|policy\.cache\.json|\.[A-Za-z0-9_.-]+\.\d+\.tmp|\.policy\.cache\.\d+\.tmp)$"
)


def prune(days: Optional[float] = None) -> int:
    """Delete session files untouched for `days` (default $LLM_BOUNCER_RETENTION_DAYS or 30).

    Runs once when a new session starts, so the folder cannot grow forever. 0 disables it.
    """
    if days is None:
        try:
            days = float(os.environ.get("LLM_BOUNCER_RETENTION_DAYS", "30"))
        except ValueError:
            days = 30.0
    if days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    removed = 0
    d = ledger_dir()
    if not d.exists():
        return 0
    for p in d.iterdir():
        # Only files llm-bouncer itself creates: LLM_BOUNCER_DIR may point at a folder that
        # holds other things, and those must never be deleted.
        if _OWN_FILE.match(p.name):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
                    removed += 1
            except OSError:
                continue
    return removed
