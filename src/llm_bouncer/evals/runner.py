"""Replay scenarios through the real hooks and score the gate.

A scenario is a short session: what the agent read (tool results, prompts), then one tool call.
Each case says what the gate should do (`expect`). The runner reports how many attacks were
blocked, asked about or missed, and how many harmless calls were let through, asked about or blocked.

`--gate effects` scores the effects gate (v0.7): Bash runs in Claude Code's sandbox, so the
outcome depends on what the command *does*. Those effects are simulated: each case may list them
(`effects: {egress: [hosts], write: [paths]}`); otherwise they are read from the URLs, write
targets and a few well-known tools in the command. Expected outcomes are `expect_effects`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

import fnmatch
import re

from .. import effects, hooks, ledger, policy
from ..indicators import extract

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


# Paths Claude Code's sandbox itself keeps commands from writing (see its "protected paths").
_SANDBOX_PROTECTED = re.compile(r"(^|/)(\.claude(/|$)|\.claude\.json$|\.mcp\.json$|\.git/(hooks|config)\b|\.gitconfig$"
                                r"|\.(bash|zsh)rc$|\.profile$|\.vscode/|\.idea/)")
_IMPLIED_HOSTS = [
    (re.compile(r"\bgit\b[^|;&]*\bpush\b"), "github.com"),  # the scenarios' origin is on GitHub
    (re.compile(r"\bgh\s"), "api.github.com"),
    (re.compile(r"\b(npm\s+(install|i|ci|add|publish)|yarn|pnpm)\b"), "registry.npmjs.org"),
    (re.compile(r"\b(pip3?\s+install|uv\s+(add|pip))\b"), "pypi.org"),
]


def simulated_effects(case: Dict[str, Any]) -> Dict[str, List[str]]:
    given = case.get("effects") or {}
    cmd = str((case["action"].get("input") or {}).get("command", ""))
    egress = list(given.get("egress") or [])
    if "egress" not in given:
        egress += [h for u in extract(cmd).get("urls", []) for h in [effects.urlparse(u).hostname] if h]
        egress += [h for rx, h in _IMPLIED_HOSTS if rx.search(cmd) and not extract(cmd).get("urls")]
        egress += [m.group(2) for m in re.finditer(r"\b(dig|nslookup|host)\s+(\S+)", cmd)]
    write = list(given.get("write") or [])
    if "write" not in given:
        write += [t for t in policy._bash_write_targets(cmd) if "/" in t or "." in t]
    return {"egress": egress, "write": write}


def effect_outcome(case: Dict[str, Any], session_id: str, workdir: str, pol: Dict[str, Any]) -> policy.Decision:
    """What happens when the sandboxed command runs: blocked by the sandbox, the proxy or a revert."""
    state = ledger.read_state(session_id)
    tainted = policy.session_status(state, pol)[0] == policy.TAINTED
    grants = effects.session_grants(state)
    eff = simulated_effects(case)
    for w in eff["write"]:
        rel = w[len("/repo/"):] if w.startswith("/repo/") else w
        if _SANDBOX_PROTECTED.search(rel) or rel.startswith(("~", "/")) and not rel.startswith("/tmp"):
            return policy.Decision(policy.DENY, f"sandbox: write to {w} denied", ["sandbox_write"])
        if tainted and any(fnmatch.fnmatchcase(rel, p) for p in pol.get("integrity_paths") or []) \
                and not effects.path_granted(rel, grants, "write"):
            return policy.Decision(policy.DENY, f"integrity: change to {rel} reverted", ["integrity"])
    for h in eff["egress"]:
        d = effects.egress_decision(h, None, {session_id: state}, pol)
        if d.action != policy.ALLOW:
            return d
    return policy.Decision(policy.ALLOW, risk=["sandboxed"])


def run_case(case: Dict[str, Any], workdir: str, gate: str = "commands") -> policy.Decision:
    session_id = str(case["id"])
    pol = policy.load_policy()
    for step in case.get("steps", []):
        if "prompt" in step:
            label = hooks.label_user_prompt({"session_id": session_id, "cwd": workdir, "prompt": step["prompt"]})
            ledger.record(label)
            if gate == "effects" and not label.flags:
                grants = effects.grants_from_prompt(step["prompt"], pol, workdir)
                if grants:
                    ledger.record_grants(session_id, grants, "prompt")
            continue
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
        ledger.record(label)
    action = case["action"]
    d = hooks.decide_tool_call(
        {"session_id": session_id, "cwd": workdir, "tool_name": action["tool"], "tool_input": action.get("input", {})}
    )
    if gate == "effects" and d.risk == ["sandboxed"]:
        return effect_outcome(case, session_id, workdir, pol)
    return d


def run(path: Optional[str] = None, policy_path: Optional[str] = None, gate: str = "commands") -> Dict[str, Any]:
    saved = {k: os.environ.get(k) for k in ("LLM_BOUNCER_DIR", "LLM_BOUNCER_POLICY", "LLM_BOUNCER_GATE")}
    results = []
    try:
        # Without --policy, score the built-in rules: a personal ~/.llm-bouncer/policy.yaml
        # must not change the published numbers or make `eval --check` fail in CI.
        os.environ["LLM_BOUNCER_POLICY"] = str(Path(policy_path).resolve()) if policy_path else policy.BUILTIN
        os.environ["LLM_BOUNCER_GATE"] = gate
        policy._load.cache_clear()
        for case in load_cases(path):
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["LLM_BOUNCER_DIR"] = str(Path(tmp) / "ledger")
                d = run_case(case, tmp, gate)
            expect = case.get("expect_effects", case.get("expect")) if gate == "effects" else case.get("expect")
            results.append(
                {
                    "id": case["id"],
                    "group": case["group"],
                    "kind": case["kind"],
                    "known_gap": bool(case.get("known_gap")),
                    "expect": expect,
                    "got": d.action,
                    "risk": d.risk,
                    "echoes": d.echoes,
                    "ok": expect in (None, d.action),
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
    return {"gate": gate, "summary": summarise(results), "results": results}


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
        f"{'id':<46} {'kind':<7} {'expect':<6} {'got':<6} note",
        "-" * 90,
    ]
    for r in report["results"]:
        note = "KNOWN GAP" if r["known_gap"] else ("" if r["ok"] else "MISMATCH")
        lines.append(f"{r['id']:<46} {r['kind']:<7} {str(r['expect']):<6} {r['got']:<6} {note}")
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
        i = args.index("--policy")
        if i + 1 >= len(args):
            print("llm-bouncer eval: --policy needs a file", file=sys.stderr)
            return 2
        policy_path = args[i + 1]
    gates = ["commands"]
    if "--gate" in args:
        i = args.index("--gate")
        choice = args[i + 1] if i + 1 < len(args) else ""
        if choice not in ("commands", "effects", "both"):
            print("llm-bouncer eval: --gate needs commands, effects or both", file=sys.stderr)
            return 2
        gates = ["commands", "effects"] if choice == "both" else [choice]
    rest = [x for i, x in enumerate(args) if not x.startswith("--") and (i == 0 or args[i - 1] not in ("--policy", "--gate"))]
    failed = False
    for gate in gates:
        report = run(rest[0] if rest else None, policy_path, gate)
        if as_json:
            print(json.dumps(report, indent=2))
        else:
            print(f"== {gate} gate" + (" (Bash effects simulated)" if gate == "effects" else ""))
            print(format_report(report) + "\n")
        failed |= bool(report["summary"]["expectation_mismatches"])
    # --check: fail when results drift from the expected outcomes (used in CI)
    return 1 if "--check" in args and failed else 0
