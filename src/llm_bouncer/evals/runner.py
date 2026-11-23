"""Replay scenarios through the real hooks and score the gate.

A scenario is a short session: what the agent read (tool results, prompts), then one tool call.
Each case says what the gate should do (`expect`). The runner reports how many attacks were
blocked, asked about or missed, and how many harmless calls were let through, asked about or blocked.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .. import hooks, ledger, policy

ACTIONS = (policy.DENY, policy.ASK, policy.ALLOW)


def load_cases(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load cases from a YAML file or a directory of them (default: the bundled scenarios)."""
    if path:
        root = Path(path)
        files = sorted(root.glob("*.yaml")) if root.is_dir() else [root]
        texts = [(f.stem, f.read_text(encoding="utf-8")) for f in files]
    else:
        pkg = resources.files("llm_bouncer").joinpath("evals/scenarios")
        texts = sorted(
            (f.name.rsplit(".", 1)[0], f.read_text(encoding="utf-8"))
            for f in pkg.iterdir()
            if f.name.endswith(".yaml")
        )
    cases: List[Dict[str, Any]] = []
    for group, text in texts:
        for case in yaml.safe_load(text) or []:
            case.setdefault("group", group)
            cases.append(case)
    return cases


def run_case(case: Dict[str, Any], workdir: str) -> policy.Decision:
    session_id = str(case["id"])
    for step in case.get("steps", []):
        if "prompt" in step:
            label = hooks.label_user_prompt({"session_id": session_id, "cwd": workdir, "prompt": step["prompt"]})
        else:
            label = hooks.label_tool_result(
                {
                    "session_id": session_id,
                    "cwd": workdir,
                    "tool_name": step["tool"],
                    "tool_input": step.get("input", {}),
                    "tool_response": {"output": step.get("output", "")},
                }
            )
        if label is not None:
            ledger.append(label, workdir)
    action = case["action"]
    return hooks.decide_tool_call(
        {"session_id": session_id, "cwd": workdir, "tool_name": action["tool"], "tool_input": action.get("input", {})}
    )


def run(path: Optional[str] = None, policy_path: Optional[str] = None) -> Dict[str, Any]:
    saved = {k: os.environ.get(k) for k in ("LLM_BOUNCER_DIR", "LLM_BOUNCER_POLICY")}
    results = []
    try:
        if policy_path:
            os.environ["LLM_BOUNCER_POLICY"] = str(Path(policy_path).resolve())
        else:
            os.environ.pop("LLM_BOUNCER_POLICY", None)
        policy._load.cache_clear()
        for case in load_cases(path):
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["LLM_BOUNCER_DIR"] = str(Path(tmp) / "ledger")
                d = run_case(case, tmp)
            results.append(
                {
                    "id": case["id"],
                    "group": case["group"],
                    "kind": case["kind"],
                    "known_gap": bool(case.get("known_gap")),
                    "expect": case.get("expect"),
                    "got": d.action,
                    "risk": d.risk,
                    "echoes": d.echoes,
                    "ok": case.get("expect") in (None, d.action),
                    "description": case.get("description", ""),
                }
            )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        policy._load.cache_clear()
    return {"summary": summarise(results), "results": results}


def summarise(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for kind in ("attack", "benign"):
        rows = [r for r in results if r["kind"] == kind]
        c = Counter(r["got"] for r in rows)
        out[kind] = {"total": len(rows), **{a: c.get(a, 0) for a in ACTIONS}}
    a, b = out["attack"], out["benign"]
    out["attack_caught_rate"] = round((a["deny"] + a["ask"]) / a["total"], 3) if a["total"] else None
    out["attack_blocked_rate"] = round(a["deny"] / a["total"], 3) if a["total"] else None
    out["benign_ask_rate"] = round(b["ask"] / b["total"], 3) if b["total"] else None
    out["benign_block_rate"] = round(b["deny"] / b["total"], 3) if b["total"] else None
    out["expectation_mismatches"] = [r["id"] for r in results if not r["ok"]]
    return out


def _pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def format_report(report: Dict[str, Any]) -> str:
    s = report["summary"]
    a, b = s["attack"], s["benign"]
    lines = [
        f"{'id':<34} {'kind':<7} {'expect':<6} {'got':<6} note",
        "-" * 78,
    ]
    for r in report["results"]:
        note = "KNOWN GAP" if r["known_gap"] else ("" if r["ok"] else "MISMATCH")
        lines.append(f"{r['id']:<34} {r['kind']:<7} {str(r['expect']):<6} {r['got']:<6} {note}")
    lines += [
        "",
        f"Attacks: {a['total']}  blocked {a['deny']}  asked {a['ask']}  missed {a['allow']}"
        f"  (caught {_pct(s['attack_caught_rate'])}, blocked outright {_pct(s['attack_blocked_rate'])})",
        f"Harmless: {b['total']}  passed {b['allow']}  asked {b['ask']}  blocked {b['deny']}"
        f"  (asked {_pct(s['benign_ask_rate'])}, wrongly blocked {_pct(s['benign_block_rate'])})",
    ]
    if s["expectation_mismatches"]:
        lines.append("Mismatches vs expected: " + ", ".join(s["expectation_mismatches"]))
    return "\n".join(lines)


def main(args: List[str]) -> int:
    as_json = "--json" in args
    policy_path = None
    if "--policy" in args:
        policy_path = args[args.index("--policy") + 1]
    rest = [x for i, x in enumerate(args) if not x.startswith("--") and (i == 0 or args[i - 1] != "--policy")]
    report = run(rest[0] if rest else None, policy_path)
    print(json.dumps(report, indent=2) if as_json else format_report(report))
    # --check: fail when results drift from the expected outcomes (used in CI)
    return 1 if "--check" in args and report["summary"]["expectation_mismatches"] else 0
