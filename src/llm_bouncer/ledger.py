"""Per-session storage.

Two files per session, in ~/.llm-bouncer/sessions/ (or $LLM_BOUNCER_DIR):

* ``<session>.jsonl``: append-only audit log, one label per line. Never read on the hot path.
* ``<session>.state.json``: a small summary the hooks actually use: turn counter, and per source
  type the count, last origins and the indicators seen. Reading it costs the same on turn 5 and
  turn 5,000, unlike re-reading the whole log on every tool call.

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
from typing import Iterator, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # Windows: no advisory locks; writes are still single os.write calls
    fcntl = None

from .labels import Label
from .textnorm import key_hash, norm, url_key

STATE_VERSION = 1
MAX_ORIGINS = 3
MAX_COMMANDS = 5000  # per source type; the oldest are dropped first
MAX_READABLE = 50  # recent URLs/emails kept as text, for `show` and reasons
MAX_HASHES = 200_000  # URL/email key hashes per kind and source type (16 chars each)
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
    fd = os.open(ledger_dir() / f"{_safe(session_id)}.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock


# ---------------------------------------------------------------- state


def empty_state() -> dict:
    return {"v": STATE_VERSION, "turn": 0, "sources": {}}


def _fold(state: dict, row: dict) -> None:
    """Add one ledger row to a state summary."""
    state["turn"] = max(int(state.get("turn", 0)), int(row.get("turn") or 0))
    src = state["sources"].setdefault(str(row.get("source_type")), {"count": 0, "origins": []})
    src["count"] += 1
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
            src[kind[:-1] + "_h"] = _recent(src.get(kind[:-1] + "_h", []), [key_hash(keyf(i)) for i in items], MAX_HASHES)


def _recent(have: List[str], new: List[str], cap: int) -> List[str]:
    d = dict.fromkeys(have)
    for item in new:
        d.pop(item, None)
        d[item] = None
    out = list(d)
    return out[-cap:]


def state_from_rows(rows: List[dict]) -> dict:
    state = empty_state()
    for row in rows:
        _fold(state, row)
    return state


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def read_state(session_id: str, cwd: str | None = None) -> dict:
    """The session summary. Rebuilt from the log if it is missing or damaged."""
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
    return state


# ---------------------------------------------------------------- public api


def record(label: Label, cwd: str | None = None) -> Tuple[Label, dict, bool]:
    """Append a label and update the state, atomically per session.

    Returns (label with its turn set, new state, whether this is the session's first
    label from this source type).
    """
    with _locked(label.session_id):
        state = read_state(label.session_id)
        new_session = state["turn"] == 0 and not _state_path(label.session_id).exists()
        first_of_source = label.source_type not in state["sources"]
        label.turn = int(state["turn"]) + 1
        row = label.to_dict()
        log = ledger_path(label.session_id)
        _append_line(log, row, newline_first=_ends_mid_line(log))
        _fold(state, row)
        state["ledger_bytes"] = _size(log)
        _write_atomic(_state_path(label.session_id), state)
    if new_session:
        prune()
    return label, state, first_of_source


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
    r"^(?:[A-Za-z0-9_.-]+\.(?:jsonl|decisions\.jsonl|state\.json|lock)"
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
