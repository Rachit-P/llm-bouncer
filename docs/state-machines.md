# State machines

llm-bouncer's security decisions depend on a few pieces of state. Until v0.6 they were implicit:
derived on the fly from counts, file existence and byte sizes. A state that is only *derived* can
be reset by an unrelated side effect (see "Tamper suspicion" below, which was a real bypass), so
each one is now written down here and stored explicitly where it matters.

## 1. Session taint

```
            tainting content read                 developer runs `llm-bouncer review`
  CLEAN ───────────────────────────▶ TAINTED ─────────────────────────────────────▶ REVIEWED
                                        ▲                                              │
                                        └──────────── tainting content read ───────────┘
```

* Code: `policy.session_status(state, policy)`.
* **Tainting content**: a source listed in `taint_sources` (default web, mcp, tool, user_pasted),
  any source stamped as tainting when it was read (`taints` in the summary), and `unknown`
  (unlabelled, lost or tampered records) always.
* **Monotonic**: the only way out of TAINTED is `review`. Removing a source from `taint_sources`
  later does not clean sessions that were tainted under the old policy, because each ledger row
  records whether it tainted when it was written.
* **Review** is a ledger row (`{"event": "review"}`), so a rebuilt summary keeps it. Only
  content read *after* the review counts. Running `llm-bouncer review` is a `bouncer_tamper`
  action, so if the agent tries it the developer is always asked.

## 2. Tamper suspicion

```
  ledger empty AND transcript shows earlier tool results ──▶ write an `unknown` row (ledger_missing)
```

* Code: `hooks._check_ledger_vanished`, run by every hook.
* Before v0.6 this state was recomputed only while the ledger had zero rows. The first harmless
  call after a deletion wrote a row, so the suspicion vanished and the next `curl` ran without a
  prompt. Now the suspicion is written to the ledger and joins state machine 1 as `unknown`.
* The current call's own result is excluded by `tool_use_id`, so a new session's first call is
  not mistaken for tampering. Strings in the transcript are JSON-escaped, so page text saying
  `"tool_result"` cannot fake a count.
* Also covers sessions resumed after the 30-day retention pruned their ledger.

## 3. Lost writes

```
  record() fails ──▶ <session>.dirty marker ──▶ next successful record() ──▶ `unknown` row (write_error), marker removed
```

* Code: `hooks._save`, `ledger.mark_dirty`, `ledger.record`.
* Labelling already failed closed; persistence did not: a full disk meant no row, so the
  session looked clean. While the marker exists the gate treats the session as tainted. If the
  ledger folder is unusable the marker goes to the system temp folder.

## 4. Summary consistency

```
  NO FILES ──record──▶ CONSISTENT ──log size ≠ ledger_bytes (crash, edit)──▶ STALE ──rebuild──▶ CONSISTENT
                           │                                                     ▲
                           └──── unreadable / old version / not a dict ──────────┘
```

* Code: `ledger.read_state`. `ledger_bytes` is the summary's version stamp.
* The gate now saves a rebuilt summary (`persist=True`, under the lock, only if nobody appended
  meanwhile), so a stale summary costs one log read instead of one per tool call.
* A torn last line (crash mid-write) is closed with a newline before the next append.

## 5. Session files

```
  ACTIVE ──untouched 30 days──▶ PRUNED (on the next new session)
```

* Code: `ledger.prune`. Resuming a pruned session lands in state machine 2.
* The lock is re-checked after it is acquired: if `prune` unlinked the lock file meanwhile, the
  hook retries on the new file, so two hooks can never hold "the" lock at once.

## 6. Echo memory

* Each source keeps its most recent 20,000 URL and email hashes in the summary. Hashes pushed out
  go to the append-only `<session>.hashes` file, which the gate reads only for echo checks. Before,
  a few pages of decoys pushed the payload's hash out and turned a **deny** into an **ask**.

## 7. The decision table

Not a state machine, but the thing the states feed. First matching row wins:

| Session | Call | Decision |
|---|---|---|
| clean or reviewed | touches llm-bouncer itself | ask |
| clean or reviewed | anything else | allow |
| tainted | on the allowlist and not risky | allow |
| tainted | repeats a tainted URL, email or command | `on_echo` (deny) |
| tainted | risky | `on_risky_after_taint` (ask) |
| tainted | not risky but not on the allowlist | `on_unlisted_after_taint` (ask) |

`always_ask_risks` (touching llm-bouncer) is never downgraded to allow. Code:
`policy.decide_from_state`. When pre-tool-use itself fails, the answer is ask (fail closed)
unless `LLM_BOUNCER_FAIL_OPEN=1` or monitor mode.
